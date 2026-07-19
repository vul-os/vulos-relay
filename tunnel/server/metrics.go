package server

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

// metrics.go — WAVE50-RELAY-OBSERVABILITY: Prometheus text-format metrics for the
// sovereign relay.
//
// The relay had no metrics/structured-logging story despite being the public,
// internet-facing half of the reverse tunnel. This adds a tiny, dependency-free
// Prometheus text-exposition registry (the repo intentionally keeps a minimal
// dependency set — only coder/websocket + hashicorp/yamux — so we do NOT pull in
// prometheus/client_golang for a handful of counters).
//
// SECURITY POSTURE (see admin.go for where these are served):
//
//   - /metrics is served on a SEPARATE admin listener that is loopback-only or
//     metrics-token-gated. It is NEVER mounted on the public tunnel Handler(), so a
//     flood on the internet-facing listener cannot reach it and it cannot leak
//     operational internals to the public.
//
//   - LABEL CARDINALITY IS BOUNDED. Every label value here is drawn from a small,
//     FIXED enum (request outcomes, proxy-byte directions, auth-fail reasons). No
//     per-request attacker-controlled value (raw Host, path, tunnel name, account,
//     source IP, token) is ever used as a label — that would let a flood of
//     distinct hostnames/paths explode the series count (a metrics-cardinality
//     DoS). Unbounded dimensions are aggregated into these fixed buckets instead.
//
//   - NO SECRETS. Tokens/secrets/PII never appear in a metric name, label, or
//     value. Metrics are pure counts and gauges.

// ---- bounded label enums --------------------------------------------------
//
// These are the ONLY label values any metric may carry. They are compile-time
// constants, so the cardinality of every labelled series is fixed and small.

// reqOutcome buckets an inbound public request result. Fixed set — never a raw
// status code, path, or host (which would be unbounded).
type reqOutcome string

const (
	outcomeOK          reqOutcome = "ok"           // proxied, agent responded
	outcomeNoTunnel    reqOutcome = "no_tunnel"    // 404: no such tunnel name
	outcomeOffline     reqOutcome = "offline"      // 502: name known but no live session
	outcomeRateLimited reqOutcome = "rate_limited" // 429: per-tunnel or global bucket
	outcomeOverQuota   reqOutcome = "over_quota"   // 402: entitlement/quota deny mid-session
	outcomeBusy        reqOutcome = "busy"         // 503: per-agent stream cap hit
	outcomeBadGateway  reqOutcome = "bad_gateway"  // 502: stream/open/read/write failure
	outcomeUpgrade     reqOutcome = "ws_upgrade"   // websocket upgrade proxied
	outcomeSlowBody    reqOutcome = "slow_body"    // 408: client request body ingestion timed out (slow-body DoS guard)
)

// allReqOutcomes is used to pre-register every series at zero so scrapers see a
// stable set from the first scrape (and so cardinality is provably bounded).
var allReqOutcomes = []reqOutcome{
	outcomeOK, outcomeNoTunnel, outcomeOffline, outcomeRateLimited,
	outcomeOverQuota, outcomeBusy, outcomeBadGateway, outcomeUpgrade,
	outcomeSlowBody,
}

// byteDirection buckets proxied bytes. Fixed set.
type byteDirection string

const (
	dirInbound  byteDirection = "inbound"  // public client -> agent (request bodies)
	dirOutbound byteDirection = "outbound" // agent -> public client (response bodies)
	dirDuplex   byteDirection = "duplex"   // spliced WS bytes (both directions)
)

var allByteDirections = []byteDirection{dirInbound, dirOutbound, dirDuplex}

// authFailReason buckets a control-connection rejection. Fixed set — never the
// token, name, or account (all unbounded / secret).
type authFailReason string

const (
	authFailRateLimited  authFailReason = "rate_limited"     // 429 before upgrade
	authFailNoBearer     authFailReason = "no_bearer"        // missing Authorization
	authFailBadRegister  authFailReason = "bad_register"     // malformed/invalid register frame
	authFailUnauthorized authFailReason = "unauthorized"     // token/name authorize failed
	authFailEntitlement  authFailReason = "entitlement"      // CP entitlement denied at connect
	authFailNameTaken    authFailReason = "name_unavailable" // collision
	authFailCapacity     authFailReason = "at_capacity"      // hard MaxAgents cap reached (shed)
	authFailSaturation   authFailReason = "saturation_shed"  // soft saturation shed (shed)
	authFailDraining     authFailReason = "draining"         // PoP draining (shed)
)

var allAuthFailReasons = []authFailReason{
	authFailRateLimited, authFailNoBearer, authFailBadRegister,
	authFailUnauthorized, authFailEntitlement, authFailNameTaken,
	authFailCapacity, authFailSaturation, authFailDraining,
}

// ctrlLimitSurface buckets which rate limiter rejected. Fixed set.
type ctrlLimitSurface string

const (
	limitControl     ctrlLimitSurface = "control" // control-conn attempts (per source IP)
	limitPerReq      ctrlLimitSurface = "per_tunnel"
	limitGlobal      ctrlLimitSurface = "global"
	limitGlobalConn  ctrlLimitSurface = "global_conn"  // aggregate NEW control-connection rate
	limitAccountConn ctrlLimitSurface = "account_conn" // per-account NEW control-connection rate
)

var allLimitSurfaces = []ctrlLimitSurface{
	limitControl, limitPerReq, limitGlobal, limitGlobalConn, limitAccountConn,
}

// cutReason buckets why a live tunnel was cut. Fixed set.
type cutReason string

const (
	cutRevocation cutReason = "revocation"
	cutOverQuota  cutReason = "over_quota"
)

var allCutReasons = []cutReason{cutRevocation, cutOverQuota}

// ---- registry -------------------------------------------------------------

// counter is a monotonic uint64 counter (Prometheus "counter" type).
type counter struct{ v atomic.Uint64 }

func (c *counter) add(n uint64) { c.v.Add(n) }
func (c *counter) inc()         { c.v.Add(1) }
func (c *counter) get() uint64  { return c.v.Load() }

// gauge is a settable/inc/dec int64 (Prometheus "gauge" type). We use signed so a
// transient release-before-acquire ordering can't wedge it, but it is clamped at
// render time to avoid emitting a nonsensical negative.
type gauge struct{ v atomic.Int64 }

func (g *gauge) inc()        { g.v.Add(1) }
func (g *gauge) dec()        { g.v.Add(-1) }
func (g *gauge) set(n int64) { g.v.Store(n) }
func (g *gauge) get() int64  { return g.v.Load() }

// metrics holds every relay metric. All fields are safe for concurrent use.
// Labelled metrics are maps keyed by a FIXED enum, pre-populated in newMetrics so
// no code path ever inserts an attacker-controlled key (cardinality is bounded by
// construction, not by runtime input).
type metrics struct {
	// Gauges — current state.
	activeAgents  gauge // live agent sessions
	activeStreams gauge // in-flight proxied streams across all tunnels
	yamuxSessions gauge // live yamux sessions (== active agents, tracked separately for clarity)

	// AUTOSCALE-ON-SATURATION: this node's most-recently-sampled saturation ratio
	// (0..1+) against its configured soft capacity, stored x1000 so it fits an
	// int64 atomic and renders as a float gauge. Published by the server's
	// saturation sampler so an external orchestrator scraping /metrics can drive
	// pool scaling even without the in-process Autoscaler. 0 when no soft capacity
	// is configured (saturation undefined).
	saturationMilli atomic.Int64

	// Counters — lifecycle totals.
	agentConnects    counter // successful agent registrations
	agentDisconnects counter // agent sessions ended
	reconnects       counter // an add() that replaced a just-departed name (best-effort)
	revocationCuts   counter // live tunnels cut by the revocation sweep
	overQuotaCuts    counter // requests cut for over-quota (402)

	// DIRECT-IP: direct-endpoint negotiation outcomes. Bounded (two counters, no
	// labels). No endpoint/host/IP is ever recorded — only the pass/fail count.
	directVerifiedCt counter // advertised direct endpoints that passed reachability+ownership
	directRejectedCt counter // advertised direct endpoints that failed verification

	// Labelled counters (bounded enums only).
	requests    map[reqOutcome]*counter       // inbound public requests by outcome
	authFails   map[authFailReason]*counter   // control-conn rejections by reason
	rateLimited map[ctrlLimitSurface]*counter // 429 rejections by surface
	cuts        map[cutReason]*counter        // live-tunnel cuts by reason
	bytes       map[byteDirection]*counter    // bytes proxied by direction

	// RENDEZVOUS ROLE: the rendezvous service keeps its own counters (it is a
	// standalone, mountable handler that must work without the tunnel server), so
	// rather than double-counting from the request path we snapshot them at scrape
	// time — the same shape as setActiveAgents reading the registry.
	//
	// nil pointer == the rendezvous role is not enabled on this node, in which
	// case NO rendezvous series are emitted at all. That is deliberate: a scraper
	// can tell "role off" from "role on, zero traffic", and a tunnel-only relay's
	// exposition is unchanged.
	rdv atomic.Pointer[rendezvousSnapshot]

	// readiness (set once background loops are up).
	ready atomic.Bool
}

// rendezvousSnapshot is a scrape-time copy of the rendezvous service's counters.
// It is a local struct rather than the rendezvous package's Stats so metrics.go
// stays independent of that package's evolution; server.go does the translation.
//
// Cardinality: these are all plain unlabelled counters/gauges. No key, endpoint,
// origin, or IP is ever recorded — the rendezvous service is content-blind and its
// metrics must not become the place its soft-state leaks.
type rendezvousSnapshot struct {
	announces       uint64
	announceRejects uint64
	resolves        uint64
	signalDeposits  uint64
	signalPickups   uint64
	mailboxDeposits uint64
	mailboxPickups  uint64
	authFailures    uint64
	rateLimited     uint64
	livePresence    int64
}

// setRendezvous publishes a scrape-time rendezvous snapshot. Called from
// handleMetrics when the role is enabled.
func (m *metrics) setRendezvous(s rendezvousSnapshot) {
	if m == nil {
		return
	}
	m.rdv.Store(&s)
}

func newMetrics() *metrics {
	m := &metrics{
		requests:    make(map[reqOutcome]*counter, len(allReqOutcomes)),
		authFails:   make(map[authFailReason]*counter, len(allAuthFailReasons)),
		rateLimited: make(map[ctrlLimitSurface]*counter, len(allLimitSurfaces)),
		cuts:        make(map[cutReason]*counter, len(allCutReasons)),
		bytes:       make(map[byteDirection]*counter, len(allByteDirections)),
	}
	// Pre-register every labelled series at zero. This both (a) gives scrapers a
	// stable series set from the first scrape and (b) makes the maps read-only
	// after construction, so no runtime code path can insert a new (unbounded) key.
	for _, o := range allReqOutcomes {
		m.requests[o] = &counter{}
	}
	for _, r := range allAuthFailReasons {
		m.authFails[r] = &counter{}
	}
	for _, s := range allLimitSurfaces {
		m.rateLimited[s] = &counter{}
	}
	for _, c := range allCutReasons {
		m.cuts[c] = &counter{}
	}
	for _, d := range allByteDirections {
		m.bytes[d] = &counter{}
	}
	return m
}

// ---- event helpers (called from the server; nil-safe) ---------------------

func (m *metrics) agentConnected() {
	if m == nil {
		return
	}
	m.agentConnects.inc()
	m.activeAgents.inc()
	m.yamuxSessions.inc()
}

func (m *metrics) agentDisconnected() {
	if m == nil {
		return
	}
	m.agentDisconnects.inc()
	m.activeAgents.dec()
	m.yamuxSessions.dec()
}

func (m *metrics) reconnected() {
	if m == nil {
		return
	}
	m.reconnects.inc()
}

// directVerified / directRejected count DIRECT-IP endpoint verification outcomes.
func (m *metrics) directVerified() {
	if m == nil {
		return
	}
	m.directVerifiedCt.inc()
}

func (m *metrics) directRejected() {
	if m == nil {
		return
	}
	m.directRejectedCt.inc()
}

func (m *metrics) request(o reqOutcome) {
	if m == nil {
		return
	}
	if c := m.requests[o]; c != nil {
		c.inc()
	}
}

func (m *metrics) authFail(r authFailReason) {
	if m == nil {
		return
	}
	if c := m.authFails[r]; c != nil {
		c.inc()
	}
}

func (m *metrics) rateLimitReject(s ctrlLimitSurface) {
	if m == nil {
		return
	}
	if c := m.rateLimited[s]; c != nil {
		c.inc()
	}
}

func (m *metrics) tunnelCut(r cutReason) {
	if m == nil {
		return
	}
	if c := m.cuts[r]; c != nil {
		c.inc()
	}
	switch r {
	case cutRevocation:
		m.revocationCuts.inc()
	case cutOverQuota:
		m.overQuotaCuts.inc()
	}
}

func (m *metrics) streamOpened() {
	if m == nil {
		return
	}
	m.activeStreams.inc()
}

func (m *metrics) streamClosed() {
	if m == nil {
		return
	}
	m.activeStreams.dec()
}

func (m *metrics) proxiedBytes(d byteDirection, n int64) {
	if m == nil || n <= 0 {
		return
	}
	if c := m.bytes[d]; c != nil {
		c.add(uint64(n))
	}
}

// totalBytes returns the cumulative bytes proxied across every direction since
// boot. AUTOSCALE-ON-SATURATION uses it as the monotonic byte counter from which a
// bytes/sec throughput rate is derived (by differencing consecutive samples).
func (m *metrics) totalBytes() int64 {
	if m == nil {
		return 0
	}
	var sum uint64
	for _, c := range m.bytes {
		sum += c.get()
	}
	// Clamp to the int64 range (cumulative bytes will not realistically overflow a
	// signed 64-bit counter, but be defensive rather than emit a negative).
	if sum > 1<<62 {
		return 1 << 62
	}
	return int64(sum)
}

// setSaturation records this node's latest saturation ratio (0..1+) for the
// vulos_relay_saturation_ratio gauge. Nil-safe.
func (m *metrics) setSaturation(ratio float64) {
	if m == nil {
		return
	}
	if ratio < 0 {
		ratio = 0
	}
	m.saturationMilli.Store(int64(ratio * 1000))
}

// saturation returns the last-sampled saturation ratio.
func (m *metrics) saturation() float64 {
	if m == nil {
		return 0
	}
	return float64(m.saturationMilli.Load()) / 1000.0
}

func (m *metrics) setReady(v bool) {
	if m == nil {
		return
	}
	m.ready.Store(v)
}

func (m *metrics) isReady() bool { return m != nil && m.ready.Load() }

// setActiveAgents lets the render path reconcile the gauge with the registry's
// authoritative count (defends against a missed dec on an abnormal teardown).
func (m *metrics) setActiveAgents(n int) {
	if m == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	m.activeAgents.set(int64(n))
	m.yamuxSessions.set(int64(n))
}

// ---- Prometheus text rendering --------------------------------------------

const metricPrefix = "vulos_relay_"

func nonNeg(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// writeTo renders the metrics in Prometheus text-exposition format (v0.0.4). The
// output is deterministic (labels are sorted) so it is diffable and testable.
func (m *metrics) writeTo(w io.Writer) {
	var mu sync.Mutex // guards ordered writes; cheap, off any data path
	mu.Lock()
	defer mu.Unlock()

	writeGauge(w, "active_agents", "Live agent sessions currently registered.", nonNeg(m.activeAgents.get()))
	writeGauge(w, "active_streams", "In-flight proxied streams across all tunnels.", nonNeg(m.activeStreams.get()))
	writeGauge(w, "yamux_sessions", "Live yamux sessions (one per registered agent).", nonNeg(m.yamuxSessions.get()))
	writeFloatGauge(w, "saturation_ratio", "This node's load (0..1+) vs its soft capacity; an orchestrator scales the pool when this stays high.", m.saturation())

	writeCounter(w, "agent_connects_total", "Successful agent registrations.", m.agentConnects.get())
	writeCounter(w, "agent_disconnects_total", "Agent sessions ended.", m.agentDisconnects.get())
	writeCounter(w, "reconnects_total", "Agent reconnections observed (name re-registered right after departing).", m.reconnects.get())
	writeCounter(w, "revocation_cuts_total", "Live tunnels cut by the revocation sweep.", m.revocationCuts.get())
	writeCounter(w, "over_quota_cuts_total", "Requests cut for over-quota (402).", m.overQuotaCuts.get())
	writeCounter(w, "direct_verified_total", "Advertised direct endpoints that passed reachability+ownership verification.", m.directVerifiedCt.get())
	writeCounter(w, "direct_rejected_total", "Advertised direct endpoints that failed verification.", m.directRejectedCt.get())

	writeReadiness(w, m.isReady())

	// Labelled series — emitted in a stable, sorted order.
	writeLabelledReq(w, "requests_total", "Inbound public requests by outcome.", m.requests)
	writeLabelledAuth(w, "auth_failures_total", "Control-connection rejections by reason.", m.authFails)
	writeLabelledLimit(w, "rate_limited_total", "429 rate-limit rejections by surface.", m.rateLimited)
	writeLabelledCut(w, "tunnel_cuts_total", "Live tunnels cut, by reason.", m.cuts)
	writeLabelledBytes(w, "proxied_bytes_total", "Bytes proxied by direction.", m.bytes)

	// RENDEZVOUS ROLE — emitted only when the role is enabled (see the rdv field).
	// Until this existed the tunnel was the only instrumented role, so an operator
	// running a rendezvous node had no relay-side ground truth at all: no way to
	// tell announces from resolves, a dead signalling path from an idle one, or a
	// rate-limit wall from a client bug.
	if r := m.rdv.Load(); r != nil {
		writeGauge(w, "rendezvous_live_presence", "Presence entries currently live (not yet expired) in the rendezvous directory.", nonNeg(r.livePresence))

		writeCounter(w, "rendezvous_announces_total", "Accepted signed presence announces.", r.announces)
		writeCounter(w, "rendezvous_announce_rejects_total", "Presence announces refused (bad signature, stale timestamp, replayed nonce, or caps).", r.announceRejects)
		writeCounter(w, "rendezvous_resolves_total", "Presence resolve reads served.", r.resolves)
		writeCounter(w, "rendezvous_signal_deposits_total", "WebRTC signalling blobs deposited by senders.", r.signalDeposits)
		writeCounter(w, "rendezvous_signal_pickups_total", "WebRTC signalling blobs picked up by recipients.", r.signalPickups)
		writeCounter(w, "rendezvous_mailbox_deposits_total", "Encrypted relay-circuit blobs deposited by senders.", r.mailboxDeposits)
		writeCounter(w, "rendezvous_mailbox_pickups_total", "Encrypted relay-circuit blobs picked up by recipients.", r.mailboxPickups)
		writeCounter(w, "rendezvous_auth_failures_total", "Rendezvous writes refused for a failed signature/freshness/replay check.", r.authFailures)
		writeCounter(w, "rendezvous_rate_limited_total", "Rendezvous requests refused by a per-key or global rate limiter.", r.rateLimited)
	}
}

func writeGauge(w io.Writer, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s%s %s\n", metricPrefix, name, help)
	fmt.Fprintf(w, "# TYPE %s%s gauge\n", metricPrefix, name)
	fmt.Fprintf(w, "%s%s %d\n", metricPrefix, name, v)
}

func writeFloatGauge(w io.Writer, name, help string, v float64) {
	fmt.Fprintf(w, "# HELP %s%s %s\n", metricPrefix, name, help)
	fmt.Fprintf(w, "# TYPE %s%s gauge\n", metricPrefix, name)
	fmt.Fprintf(w, "%s%s %g\n", metricPrefix, name, v)
}

func writeCounter(w io.Writer, name, help string, v uint64) {
	fmt.Fprintf(w, "# HELP %s%s %s\n", metricPrefix, name, help)
	fmt.Fprintf(w, "# TYPE %s%s counter\n", metricPrefix, name)
	fmt.Fprintf(w, "%s%s %d\n", metricPrefix, name, v)
}

func writeReadiness(w io.Writer, ready bool) {
	v := 0
	if ready {
		v = 1
	}
	fmt.Fprintf(w, "# HELP %sready Whether the relay's background loops are up (1) or not (0).\n", metricPrefix)
	fmt.Fprintf(w, "# TYPE %sready gauge\n", metricPrefix)
	fmt.Fprintf(w, "%sready %d\n", metricPrefix, v)
}

func writeLabelledReq(w io.Writer, name, help string, ms map[reqOutcome]*counter) {
	keys := make([]string, 0, len(ms))
	idx := make(map[string]*counter, len(ms))
	for k, c := range ms {
		keys = append(keys, string(k))
		idx[string(k)] = c
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "# HELP %s%s %s\n", metricPrefix, name, help)
	fmt.Fprintf(w, "# TYPE %s%s counter\n", metricPrefix, name)
	for _, k := range keys {
		fmt.Fprintf(w, "%s%s{outcome=%q} %d\n", metricPrefix, name, k, idx[k].get())
	}
}

func writeLabelledAuth(w io.Writer, name, help string, ms map[authFailReason]*counter) {
	keys := make([]string, 0, len(ms))
	idx := make(map[string]*counter, len(ms))
	for k, c := range ms {
		keys = append(keys, string(k))
		idx[string(k)] = c
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "# HELP %s%s %s\n", metricPrefix, name, help)
	fmt.Fprintf(w, "# TYPE %s%s counter\n", metricPrefix, name)
	for _, k := range keys {
		fmt.Fprintf(w, "%s%s{reason=%q} %d\n", metricPrefix, name, k, idx[k].get())
	}
}

func writeLabelledLimit(w io.Writer, name, help string, ms map[ctrlLimitSurface]*counter) {
	keys := make([]string, 0, len(ms))
	idx := make(map[string]*counter, len(ms))
	for k, c := range ms {
		keys = append(keys, string(k))
		idx[string(k)] = c
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "# HELP %s%s %s\n", metricPrefix, name, help)
	fmt.Fprintf(w, "# TYPE %s%s counter\n", metricPrefix, name)
	for _, k := range keys {
		fmt.Fprintf(w, "%s%s{surface=%q} %d\n", metricPrefix, name, k, idx[k].get())
	}
}

func writeLabelledCut(w io.Writer, name, help string, ms map[cutReason]*counter) {
	keys := make([]string, 0, len(ms))
	idx := make(map[string]*counter, len(ms))
	for k, c := range ms {
		keys = append(keys, string(k))
		idx[string(k)] = c
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "# HELP %s%s %s\n", metricPrefix, name, help)
	fmt.Fprintf(w, "# TYPE %s%s counter\n", metricPrefix, name)
	for _, k := range keys {
		fmt.Fprintf(w, "%s%s{reason=%q} %d\n", metricPrefix, name, k, idx[k].get())
	}
}

func writeLabelledBytes(w io.Writer, name, help string, ms map[byteDirection]*counter) {
	keys := make([]string, 0, len(ms))
	idx := make(map[string]*counter, len(ms))
	for k, c := range ms {
		keys = append(keys, string(k))
		idx[string(k)] = c
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "# HELP %s%s %s\n", metricPrefix, name, help)
	fmt.Fprintf(w, "# TYPE %s%s counter\n", metricPrefix, name)
	for _, k := range keys {
		fmt.Fprintf(w, "%s%s{direction=%q} %d\n", metricPrefix, name, k, idx[k].get())
	}
}
