package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// metering.go — WAVE24-RELAY-BILLING: per-account byte + session metering and
// periodic DELTA flush to the CP's POST /api/relay/usage.
//
// The meter accumulates in-memory per-account deltas as traffic flows. A
// background loop drains the deltas every FlushInterval (and on shutdown) and
// POSTs them to the CP with a monotonic report_id (idempotent) and an X-Pop-Sig
// HMAC. It NEVER blocks the data path: proxy code calls addBytes/addSession
// which only touch cheap in-memory counters; the network flush happens off the
// hot path with retry/backoff and bounded memory.

// meterDelta is the pending, not-yet-flushed usage for one account.
type meterDelta struct {
	bytes    int64
	sessions int
}

// meter accumulates per-account deltas and flushes them to the CP.
type meter struct {
	cp            *CPClient
	flushInterval time.Duration

	// onOverQuota is invoked (if set) for each account the CP reports as over
	// quota in a usage-report response, so the entitlement gate can cut that
	// account promptly on its NEXT request instead of waiting a full gate TTL.
	// Nil when metering is disabled / no gate is wired.
	onOverQuota func(accountID string)

	mu      sync.Mutex
	pending map[string]*meterDelta // accountID -> pending delta
	// maxAccounts bounds memory: if we somehow exceed it we drop the oldest by
	// simply not adding NEW accounts until a flush clears space (existing accounts
	// keep accumulating). Traffic is never blocked.
	maxAccounts int

	seq    atomic.Uint64 // monotonic report_id source (within this boot)
	bootID string        // per-process nonce so report_ids never collide across restarts

	// retry holds batches that were assigned a report_id and drained but whose flush
	// FAILED, so they are retried on a later tick REUSING THE SAME report_id. Reusing
	// the id is what makes the CP's idempotent dedup correct: a batch the CP already
	// applied but whose HTTP response we lost is a no-op on retry (not double-billed),
	// and a batch the CP never received is applied exactly once. Guarded by mu; only
	// the flush goroutine appends/drains it, but addBytes/drain share mu.
	retry           []pendingReport
	maxRetryBatches int

	stop   chan struct{}
	doneWG sync.WaitGroup
}

// pendingReport is one drained, immutable usage batch plus its STABLE report_id.
// The id is generated once when the batch is drained and is reused verbatim on
// every retry so the CP dedups a re-sent batch instead of re-applying it.
type pendingReport struct {
	id    string
	items []usageItem
}

// newMeter constructs a meter. A nil cp disables flushing (metering is a no-op),
// which is the self-host-without-account path.
func newMeter(cp *CPClient, flushInterval time.Duration) *meter {
	if flushInterval <= 0 {
		flushInterval = 45 * time.Second
	}
	return &meter{
		cp:            cp,
		flushInterval: flushInterval,
		pending:       make(map[string]*meterDelta),
		maxAccounts:   50_000,
		bootID:        newBootID(),
		// Bound retained retry batches under a prolonged CP outage. At the default
		// 45s flush cadence this holds ~12h of failed batches before the oldest are
		// shed, which is far longer than any real CP blip.
		maxRetryBatches: 1024,
		stop:            make(chan struct{}),
	}
}

// newBootID returns a short random per-process nonce mixed into every report_id.
// Without it, report_ids restart at <pop>-1 after a process restart and would
// COLLIDE with ids the CP already applied before the restart, so the CP's dedup
// would silently drop the first post-restart batches (under-billing). A random
// boot nonce makes ids globally unique across restarts while staying stable within
// a boot (so in-boot retries still dedup correctly).
func newBootID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a time-based nonce; uniqueness across restarts is still met.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// enabled reports whether flushing is active (a CP client is configured).
func (m *meter) enabled() bool { return m != nil && m.cp != nil }

// addBytes records n relayed bytes for accountID. Cheap, non-blocking, safe on a
// nil meter or empty account (unbilled tokens are simply not metered).
func (m *meter) addBytes(accountID string, n int64) {
	if m == nil || accountID == "" || n <= 0 {
		return
	}
	m.mu.Lock()
	d := m.pending[accountID]
	if d == nil {
		if len(m.pending) >= m.maxAccounts {
			m.mu.Unlock()
			return // bounded: drop metering for a new account rather than grow unbounded
		}
		d = &meterDelta{}
		m.pending[accountID] = d
	}
	d.bytes += n
	m.mu.Unlock()
}

// addSession records one new session (tunnel request) for accountID.
func (m *meter) addSession(accountID string) {
	if m == nil || accountID == "" {
		return
	}
	m.mu.Lock()
	d := m.pending[accountID]
	if d == nil {
		if len(m.pending) >= m.maxAccounts {
			m.mu.Unlock()
			return
		}
		d = &meterDelta{}
		m.pending[accountID] = d
	}
	d.sessions++
	m.mu.Unlock()
}

// drain atomically removes and returns the pending deltas as usage items.
func (m *meter) drain() []usageItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pending) == 0 {
		return nil
	}
	items := make([]usageItem, 0, len(m.pending))
	for acct, d := range m.pending {
		if d.bytes == 0 && d.sessions == 0 {
			continue
		}
		items = append(items, usageItem{AccountID: acct, Bytes: d.bytes, Sessions: d.sessions})
	}
	m.pending = make(map[string]*meterDelta)
	return items
}

// takeRetry atomically removes and returns the queued failed batches.
func (m *meter) takeRetry() []pendingReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.retry) == 0 {
		return nil
	}
	out := m.retry
	m.retry = nil
	return out
}

// requeue puts failed batches back for the next tick, bounded so a prolonged CP
// outage cannot grow memory without limit. On overflow the OLDEST batches are
// dropped (favouring fresher usage) and the drop is logged.
func (m *meter) requeue(batches []pendingReport) {
	if len(batches) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retry = append(m.retry, batches...)
	if len(m.retry) > m.maxRetryBatches {
		drop := len(m.retry) - m.maxRetryBatches
		m.retry = m.retry[drop:]
		slog.Warn("usage retry queue overflow; dropping oldest batches",
			"component", "relay", "dropped", drop)
	}
}

// nextReportID returns a monotonic, per-PoP, per-boot report id for idempotency.
// The boot nonce prevents cross-restart collisions (see newBootID).
func (m *meter) nextReportID() string {
	return fmt.Sprintf("%s-%s-%d", m.cp.PoPID, m.bootID, m.seq.Add(1))
}

// run starts the background flush loop. Call stopAndFlush to end it.
func (m *meter) run() {
	if !m.enabled() {
		return
	}
	m.doneWG.Add(1)
	go func() {
		defer m.doneWG.Done()
		t := time.NewTicker(m.flushInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				m.flushOnce()
			case <-m.stop:
				m.flushOnce() // final flush on shutdown
				return
			}
		}
	}()
}

// flushOnce posts any previously-failed batches (reusing their report_ids) plus a
// fresh batch of newly-accumulated deltas, and requeues whatever fails. It never
// blocks the data path (addBytes/addSession only touch cheap counters) and never
// double-counts: each batch carries a STABLE report_id, so a batch the CP already
// applied but whose response we lost is a dedup no-op on retry rather than being
// re-billed under a fresh id (the previous restore-into-pending path lost that
// idempotency and could double-bill on a response-lost flush).
func (m *meter) flushOnce() {
	if !m.enabled() {
		return
	}
	// Retry the older failed batches first, then the freshly-drained delta.
	batches := m.takeRetry()
	if newItems := m.drain(); len(newItems) > 0 {
		batches = append(batches, pendingReport{id: m.nextReportID(), items: newItems})
	}
	if len(batches) == 0 {
		return
	}

	var failed []pendingReport
	for _, b := range batches {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		overQuota, err := m.cp.ReportUsage(ctx, b.id, b.items)
		cancel()
		if err != nil {
			// CP unreachable or rejected — keep the batch (with its id) for retry.
			// Server-side fault, not a client event: warn level. No account/secret in
			// the message — just the transport error.
			failed = append(failed, b)
			slog.Warn("usage flush failed (will retry)", "component", "relay", "err", err.Error())
			continue
		}
		// WAVE34-RELAY-HARDEN: consume the over-quota signal the CP returns on the
		// usage report. Previously this was dropped, so an over-cap tenant kept
		// tunnelling until the next entitlement-gate TTL (~30s) lapsed. Pushing it
		// into the gate now makes the account get cut with 402 on its NEXT request.
		if m.onOverQuota != nil {
			for _, acct := range overQuota {
				m.onOverQuota(acct)
			}
		}
	}
	m.requeue(failed)
}

// stopAndFlush stops the loop after a final flush.
func (m *meter) stopAndFlush() {
	if !m.enabled() {
		return
	}
	close(m.stop)
	m.doneWG.Wait()
}

// countingReadCloser meters bytes read from an inbound request body. It updates
// both the per-account usage meter (when account != "") and the direction-bucketed
// observability metric (WAVE50). Either may be nil / empty independently.
type countingReadCloser struct {
	rc      io.ReadCloser
	meter   *meter
	account string
	metrics *metrics

	// overLimit is set when a read observed a *http.MaxBytesError, i.e. the inbound
	// body exceeded MaxRequestBytes. The proxy checks this after a failed body
	// forward to surface a clean 413 instead of a generic 502 (CONSOLIDATION A-1).
	// req.Write wraps the read error in an unexported http.requestBodyReadError that
	// does NOT unwrap to MaxBytesError, so we detect it at the source here.
	overLimit bool
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		if c.account != "" {
			c.meter.addBytes(c.account, int64(n))
		}
		c.metrics.proxiedBytes(dirInbound, int64(n))
	}
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.overLimit = true
		}
	}
	return n, err
}

func (c *countingReadCloser) Close() error { return c.rc.Close() }

// meterReader wraps a reader and reports bytes to the per-account usage meter AND
// the direction-bucketed observability metric AS THEY ARE READ (per Read call),
// so a long-lived stream is metered INCREMENTALLY while it flows rather than only
// when the surrounding io.Copy finally returns.
//
// This closes a revenue hole on the two EGRESS paths (the HTTP response body and
// the WebSocket duplex splice). Both carry exactly the traffic a relay
// specializes in — SSE, large downloads, hours-long WebSockets. If bytes were only
// added at io.Copy completion (the previous behaviour), a connection still open at
// a periodic flush contributed NOTHING until it closed, and a connection killed by
// a drain/redeploy (Fly sends SIGTERM then hard-kills; http.Server.Shutdown does
// not even wait for hijacked WebSocket conns) or a crash lost ALL its bytes. Metering
// per-Read means every flush — including the final shutdown drain — captures the
// bytes moved so far, and nothing rides unmetered on a long connection.
//
// account may be "" (metering disabled / unbilled token) and the meter or metrics
// may be nil; each update is independently guarded (addBytes / proxiedBytes are
// nil/empty-safe), so a wrapped reader is always safe to construct.
type meterReader struct {
	r       io.Reader
	meter   *meter
	account string
	metrics *metrics
	dir     byteDirection
}

func (mr *meterReader) Read(p []byte) (int, error) {
	n, err := mr.r.Read(p)
	if n > 0 {
		if mr.account != "" {
			mr.meter.addBytes(mr.account, int64(n))
		}
		mr.metrics.proxiedBytes(mr.dir, int64(n))
	}
	return n, err
}
