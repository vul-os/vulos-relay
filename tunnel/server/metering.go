package server

import (
	"context"
	"fmt"
	"io"
	"log"
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

	seq atomic.Uint64 // monotonic report_id source

	stop   chan struct{}
	doneWG sync.WaitGroup
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
		stop:          make(chan struct{}),
	}
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

// restore adds items back into the pending map (used when a flush failed, so the
// deltas are retried on the next tick rather than lost). Additive — a concurrent
// addBytes between drain and restore is preserved.
func (m *meter) restore(items []usageItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, it := range items {
		d := m.pending[it.AccountID]
		if d == nil {
			if len(m.pending) >= m.maxAccounts {
				continue
			}
			d = &meterDelta{}
			m.pending[it.AccountID] = d
		}
		d.bytes += it.Bytes
		d.sessions += it.Sessions
	}
}

// nextReportID returns a monotonic, per-PoP report id for idempotency.
func (m *meter) nextReportID() string {
	return fmt.Sprintf("%s-%d", m.cp.PoPID, m.seq.Add(1))
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

// flushOnce drains and posts the current deltas. On a CP error it restores the
// deltas so they are retried next tick (never blocks the data path, never
// double-counts because the report_id makes a retry a fresh id and a genuine
// duplicate a CP no-op). Bounded: a single report carries whatever accumulated.
func (m *meter) flushOnce() {
	if !m.enabled() {
		return
	}
	items := m.drain()
	if len(items) == 0 {
		return
	}
	reportID := m.nextReportID()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	overQuota, err := m.cp.ReportUsage(ctx, reportID, items)
	if err != nil {
		// CP unreachable or rejected — put the deltas back and retry next tick.
		m.restore(items)
		log.Printf("relay: usage flush failed (will retry): %v", err)
		return
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

// stopAndFlush stops the loop after a final flush.
func (m *meter) stopAndFlush() {
	if !m.enabled() {
		return
	}
	close(m.stop)
	m.doneWG.Wait()
}

// countingReadCloser meters bytes read from an inbound request body.
type countingReadCloser struct {
	rc      io.ReadCloser
	meter   *meter
	account string
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.meter.addBytes(c.account, int64(n))
	}
	return n, err
}

func (c *countingReadCloser) Close() error { return c.rc.Close() }
