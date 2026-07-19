// Package server is the sovereign Vulos relay: the public half of the reverse
// tunnel. It replaces a third-party frp server with our own, self-hostable relay.
//
// It runs TWO logical surfaces on one HTTPS listener:
//
//  1. Control endpoint (wire.ControlPath): agents dial in over wss, authenticate
//     with a bearer token, and register a token-authorized name. The server then
//     becomes the yamux CLIENT over that connection and opens one stream per
//     inbound public request.
//
//  2. Public proxy: inbound HTTPS requests are routed to an agent session by
//     subdomain (<name>.<relay-domain>, the primary mode, needs wildcard DNS) or by
//     path prefix (/t/<name>/…, the fallback when no wildcard DNS). Matched
//     requests are forwarded over a fresh yamux stream and the response streamed
//     back, including WebSocket-upgrade passthrough.
//
// The server is internet-facing and fails closed: no token store => refuses to
// run; unknown/unauthorized tokens are rejected; names cannot be hijacked; request
// sizes, header sizes, stream counts, and agent counts are all bounded.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/autoscale"
	"github.com/vul-os/vulos-relay/tunnel/pubcache"
	"github.com/vul-os/vulos-relay/tunnel/rendezvous"
)

// Config configures a relay Server.
type Config struct {
	// Domain is the base relay domain, e.g. "relay.vulos.dev". In subdomain mode a
	// name "box1" is served at "box1.relay.vulos.dev". Used to derive names from the
	// inbound Host and to build public URLs. Required.
	Domain string
	// Tokens is the authorization store. Required — a nil store means "run open",
	// which is refused.
	Tokens TokenStore

	// EnablePathMode serves the /t/<name>/ fallback in addition to subdomain mode.
	// Enable when you cannot provision wildcard DNS. Default false.
	EnablePathMode bool

	// TrustProxyHeaders controls how the forwarding headers (X-Forwarded-For /
	// -Proto) the box's app sees are built. It is a SECURITY toggle for the ingress
	// choke point:
	//
	//   false (default) — the relay is DIRECTLY internet-facing. The public client
	//     is untrusted, so any X-Forwarded-For / X-Real-IP / X-Forwarded-Proto it
	//     sends is DISCARDED and OVERWRITTEN with the relay's observed peer. This
	//     prevents a client forging its apparent source IP for the box's app.
	//
	//   true — the relay runs behind ITS OWN trusted TLS-terminating edge/CDN (the
	//     fly.toml deployment: Fly's proxy terminates TLS and sets XFF). In that one
	//     topology the incoming XFF is trustworthy, so the peer (the edge) is
	//     appended to preserve the real client chain, and the edge's
	//     X-Forwarded-Proto is honored.
	//
	// Enable ONLY when a trusted proxy actually fronts the relay; enabling it while
	// directly exposed re-opens the IP spoof.
	TrustProxyHeaders bool

	// TLS is the public listener's TLS. If nil, ServeTLS/certFile is expected, or
	// the caller runs behind a TLS-terminating proxy and uses Serve (plain h1). For
	// a directly-internet-facing relay, provide TLS or use ListenAndServeTLS.
	TLSConfig *tls.Config

	// Public URL scheme for building agent-facing URLs. Default "https".
	PublicScheme string

	// Limits (0 => sane defaults applied in New).
	MaxAgents          int           // max concurrent agents
	MaxStreamsPerAgent int           // max concurrent in-flight streams per agent
	MaxHeaderBytes     int           // request header size cap
	MaxRequestBytes    int64         // request body size cap
	IdleTimeout        time.Duration // control-conn idle timeout / keepalive budget
	RequestTimeout     time.Duration // per public request forward timeout

	// RequestBodyTimeout bounds how long the relay will spend INGESTING a public
	// client's request body for a NON-STREAMING request (MEDIUM-2 slow-body DoS
	// guard). ReadHeaderTimeout only covers the request line + headers; without a
	// body deadline a client that dribbles a large body one byte at a time ties up a
	// goroutine AND a per-agent yamux stream slot indefinitely, and MaxStreamsPerAgent
	// such trickles brick the whole tunnel. This is applied as a read deadline on the
	// client connection covering only the request-body forward step; it is CLEARED
	// before the agent's response is streamed back, so long-lived SSE / downloads / WS
	// (all response-side, deadline-free) are unaffected. A slow-but-steady large upload
	// still succeeds if it completes within the window; a stalled/dribbling one is cut
	// with 408 and its slot freed. 0 => default 30s; a negative value DISABLES it.
	RequestBodyTimeout time.Duration

	// CP (WAVE24-RELAY-BILLING, optional) links this relay to Vulos Cloud so that
	// account-bound tokens are gated against their relay entitlement and their
	// traffic is metered to POST /api/relay/usage. When nil, the relay runs
	// UNBILLED (self-host): tokens are still authorized (name grants) but no
	// account gating or metering happens.
	CP *CPClient
	// GateTTL is the entitlement-cache TTL (default 30s). EntitlementFlush is the
	// usage-report cadence (default 45s).
	GateTTL          time.Duration
	MeterFlushPeriod time.Duration

	// Rate limiting (WAVE34-RELAY-HARDEN). All optional; 0 => sane defaults are
	// applied in New. Set a rate to a negative value to DISABLE that limiter
	// (useful for tests or a trusted-edge deployment). These are ON TOP OF the
	// existing hard caps (MaxAgents, MaxStreamsPerAgent), which stay intact.

	// ControlConnRate / ControlConnBurst throttle control-connection attempts per
	// source IP (token bucket). Defaults: 5/s, burst 20.
	ControlConnRate  float64
	ControlConnBurst float64
	// PublicReqRate / PublicReqBurst throttle inbound public requests per
	// agent/session (token bucket). Defaults: 50/s, burst 100.
	PublicReqRate  float64
	PublicReqBurst float64
	// GlobalReqRate / GlobalReqBurst cap the AGGREGATE inbound public request rate
	// across all tunnels. Defaults: 500/s, burst 1000.
	GlobalReqRate  float64
	GlobalReqBurst float64

	// CONNECTION-FLOOD ADMISSION (per-account + global NEW-connection rate + shed).
	// All optional; 0 => sane defaults are applied in New; a negative value DISABLES
	// that limiter. These sit ON TOP OF the per-IP ControlConn* limiter and the hard
	// MaxAgents cap, and exist to keep a control-connection FLOOD — malicious DoS or a
	// self-inflicted reconnect storm — from spending CPU/memory on tunnel/yamux setup
	// before it is rejected.

	// ConnPerAccountRate / ConnPerAccountBurst throttle NEW control connections per
	// Vulos ACCOUNT (token bucket, checked after the token authorizes so the account
	// is known but BEFORE yamux setup). A single account normally holds a handful of
	// tunnels; a burst of reconnects from one account is bounded here so one tenant
	// cannot flood a PoP. Defaults: 4/s, burst 20. Empty (unbilled) accounts are not
	// keyed (self-host is unchanged).
	ConnPerAccountRate  float64
	ConnPerAccountBurst float64
	// GlobalConnRate / GlobalConnBurst cap the AGGREGATE rate of NEW control-connection
	// attempts across ALL sources, checked on the CHEAP path BEFORE the WS upgrade so a
	// distributed flood (many source IPs, each under the per-IP limit) cannot make the
	// PoP spend an upgrade + register-read per attempt. Excess attempts get a fast 429.
	// Defaults: 100/s, burst 200. A legitimate mass-reconnect that trips this simply
	// backs off + re-resolves (the agent jitters and the CP routes it elsewhere).
	GlobalConnRate  float64
	GlobalConnBurst float64
	// SheddingThreshold is the saturation ratio (0..1+) at/above which this PoP SHEDS
	// new tunnels — refusing a NEW registration with a retryable "at capacity, try
	// another PoP" ack so the agent re-resolves elsewhere and the CP stops routing
	// here — WHILE keeping every live tunnel up. It is a self-protection valve that
	// fires before the hard MaxAgents cap and gives the autoscaler time to add a node.
	// Only active when a SoftCapacity is configured (saturation is otherwise 0). 0 =>
	// default 0.95; a negative value DISABLES shedding (the hard cap still applies).
	SheddingThreshold float64

	// DIRECT-PROBE BUDGET (probe-reflection guard). DirectProbeRate / DirectProbeBurst
	// throttle how often the relay will PROBE a box's advertised direct endpoint, keyed
	// per ACCOUNT (per NAME for unbilled self-host). The register-time probe is an
	// outbound GET the relay emits on the box's behalf; without a budget an authenticated
	// box could re-register in a loop, each time advertising a fresh public endpoint, and
	// use the relay as a reflector to emit a stream of GETs at arbitrary public targets
	// (already SSRF-screened to public hosts, but still an amplification vector). When the
	// budget is exceeded the endpoint is simply NOT probed this connect (treated as
	// unverified: the tunnel still comes up on the relay path, the box just doesn't get
	// its direct fast-path until it slows down). Defaults: 1/s, burst 5. A negative value
	// DISABLES the budget.
	DirectProbeRate  float64
	DirectProbeBurst float64

	// RateLimitIdleTTL evicts a per-key bucket unused for this long (bounds
	// memory). Default 10m.
	RateLimitIdleTTL time.Duration
	// RateLimitMaxKeys caps distinct buckets per limiter (bounds memory).
	// Default 100_000.
	RateLimitMaxKeys int

	// Revocation (WAVE41-RELAY-REVOCATION).

	// DIRECT-IP: direct-connect endpoint negotiation. When a box advertises a
	// direct endpoint in its Register frame, the relay VERIFIES it (reachable +
	// ownership-proven via a probe) before surfacing it to clients. Direct traffic
	// then bypasses the relay entirely (near-native latency + full bandwidth); a
	// client falls back to the relay tunnel when direct fails.

	// DisableDirect turns off direct-endpoint negotiation entirely: advertised
	// endpoints are ignored and every box is served purely over the relay tunnel
	// (the pre-DIRECT-IP behavior). Default false (direct negotiation is ON, but a
	// box still has to opt in by advertising an endpoint AND passing verification).
	DisableDirect bool
	// directVerifier overrides the reachability/ownership probe — TEST-ONLY (the
	// real one performs a live internet GET). nil => the default httpDirectVerifier.
	directVerifier directEndpointVerifier

	// AUTOSCALE-ON-SATURATION + MULTI-NODE POOL.

	// NodeID / Region make a relay SELF-AWARE as one node of a geo-distributed pool
	// (Hetzner primary, Vultr edge). They are surfaced on /healthz and used when this
	// node registers itself into an autoscale.Pool. Both optional — a single-node
	// self-host leaves them empty and behaves exactly as before. Region is a coarse
	// geo tag (e.g. "eu-central", "af-south") a router uses to steer a client to the
	// nearest node; Provider is an informational host tag ("hetzner"/"vultr").
	NodeID   string
	Region   string
	Provider string

	// SMART-AUTOSCALE (PoP registration + load heartbeat). All optional and
	// CP-OPTIONAL: unless a CP is configured AND PublicEndpoint is set, the relay
	// does none of this (self-host runs unchanged).

	// PublicEndpoint is this PoP's agent-facing base URL (e.g.
	// "wss://hel1.relay.vulos.org") announced to the CP so it can hand this PoP to
	// an agent as its assigned nearest/least-loaded node. Empty => the PoP is not
	// registered with the CP (no heartbeat loop runs).
	PublicEndpoint string
	// HeartbeatPeriod is the PoP load-heartbeat cadence. 0 => default 12s; a
	// negative value DISABLES the heartbeat even when a CP + PublicEndpoint are set.
	HeartbeatPeriod time.Duration
	// SysSampler overrides the host CPU%/mem% source in the load heartbeat (an
	// operator wires cgroup/proc stats). nil => a runtime-derived best-effort
	// sampler (see defaultSysSampler); the autoscaler's exact signals are
	// active_tunnels / bytes_per_sec / saturation regardless.
	SysSampler SysSampler
	// HostMemLimitBytes, when >0, lets the default sampler report mem_pct as a
	// fraction of the host/cgroup memory limit. 0 => mem_pct is reported as 0.
	HostMemLimitBytes int64

	// SoftCapacity is the per-node soft limit at which this node is considered
	// "full" for SCALING purposes (distinct from the hard MaxAgents /
	// MaxStreamsPerAgent / rate caps, which still bound abuse independently). When
	// any dimension is set, the server samples its load against it and publishes a
	// vulos_relay_saturation_ratio gauge on /metrics, so an orchestrator (or the
	// in-process autoscale.Autoscaler) can grow/shrink the pool. All-zero => the
	// saturation gauge stays 0 and no sampler runs (feature is opt-in).
	SoftCapacity autoscale.Capacity
	// SaturationSamplePeriod is how often the saturation gauge is recomputed
	// (throughput rate is derived across one period). 0 => default 15s; a negative
	// value disables the sampler even if SoftCapacity is set.
	SaturationSamplePeriod time.Duration

	// RENDEZVOUS ROLE (open reachability substrate). When EnableRendezvous is set,
	// the relay ALSO serves the key-addressed announce/resolve/signal/mailbox +
	// ICE surface (tunnel/rendezvous) on its OWN apex domain — so apps get
	// P2P/discovery from this relay with no Vulos OS required. It is CP-OPTIONAL and
	// fully self-hostable: the rendezvous service holds only soft-state (presence +
	// short-TTL opaque blobs), needs no CP, and is content-blind. The routes are
	// mounted under Rendezvous.PathPrefix (default "/rendezvous") and served ONLY on
	// the relay's apex host, so a tunnel subdomain's own paths are never shadowed.
	// Default OFF (a plain reverse-tunnel relay is unchanged).
	EnableRendezvous bool
	// Rendezvous configures the rendezvous service (ICE STUN/TURN, caps, rate
	// limits). Ignored unless EnableRendezvous is true.
	Rendezvous rendezvous.Config

	// CACHE/PIN ROLE (DMTAP-PUB public objects, dmtap substrate/ROLES.md § 6).
	// When EnablePubCache is set, the relay ALSO serves the § 22.5.1 well-known
	// read surface (tunnel/pubcache) on its OWN apex host, as a verifying
	// read-through cache in front of operator-configured upstream gateways.
	//
	// UNLIKE every other role this relay serves, THIS ONE IS NOT CONTENT-BLIND:
	// public objects are plaintext the operator can read, which shifts the
	// operator's moderation and liability posture, so § 22.6.1 makes it explicit
	// opt-in and this flag defaults OFF. Nothing is ever stored unverified — see
	// tunnel/pubcache — so the cache can only fail to serve, never forge.
	EnablePubCache bool
	// PubCache configures the cache/pin service (upstreams, size caps, TTL, rate
	// limits). Ignored unless EnablePubCache is true.
	PubCache pubcache.Config

	// RevokeSweepPeriod is how often the server rechecks every LIVE session against
	// the revocation sources (static revoked-list + CP revoked/404 via the
	// entitlement poll) and drops any that are now definitively revoked. This
	// bounds the mid-session revocation latency: a revoke takes at most one sweep
	// period (plus, for the CP path, up to one gate TTL for the poll to observe it)
	// to cut a live tunnel. 0 => default 20s. A negative value DISABLES the sweep
	// (connect-time revocation still applies).
	RevokeSweepPeriod time.Duration
}

// rateLimitField resolves a configured rate: 0 => the supplied default, a
// negative value => 0 (disabled).
func rateLimitField(v, def float64) float64 {
	switch {
	case v < 0:
		return 0
	case v == 0:
		return def
	default:
		return v
	}
}

func (c *Config) applyDefaults() {
	if c.PublicScheme == "" {
		c.PublicScheme = "https"
	}
	if c.MaxAgents == 0 {
		c.MaxAgents = 256
	}
	if c.MaxStreamsPerAgent == 0 {
		c.MaxStreamsPerAgent = 128
	}
	if c.MaxHeaderBytes == 0 {
		c.MaxHeaderBytes = 64 << 10 // 64 KiB
	}
	if c.MaxRequestBytes == 0 {
		// 256 MiB. Covers the overwhelming majority of single-file uploads in one
		// shot. The relay STREAMS the body (MaxBytesReader is a streaming wrapper,
		// see proxy.go) so a bigger cap costs no relay RAM per request — it only
		// bounds how long one stream may hold a slot. Unbounded is intentionally
		// NOT offered: 0 keeps meaning "apply this default". (CONSOLIDATION A-1)
		c.MaxRequestBytes = 256 << 20 // 256 MiB
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 90 * time.Second
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 60 * time.Second
	}
	// MEDIUM-2 slow-body DoS guard: 0 => default 30s body-ingestion deadline; a
	// negative value DISABLES it (normalized to 0 so the proxy skips setting a
	// deadline). The knob is separate from RequestTimeout (which bounds the AGENT's
	// time-to-headers on the yamux stream): this one bounds the CLIENT-side body read.
	switch {
	case c.RequestBodyTimeout < 0:
		c.RequestBodyTimeout = 0
	case c.RequestBodyTimeout == 0:
		c.RequestBodyTimeout = 30 * time.Second
	}
	// Rate-limit defaults (WAVE34-RELAY-HARDEN). A negative value means "disabled"
	// and is normalized to 0 by rateLimitField at construction time.
	c.ControlConnRate = rateLimitField(c.ControlConnRate, 5)
	c.ControlConnBurst = rateLimitField(c.ControlConnBurst, 20)
	c.PublicReqRate = rateLimitField(c.PublicReqRate, 50)
	c.PublicReqBurst = rateLimitField(c.PublicReqBurst, 100)
	c.GlobalReqRate = rateLimitField(c.GlobalReqRate, 500)
	c.GlobalReqBurst = rateLimitField(c.GlobalReqBurst, 1000)
	// CONNECTION-FLOOD ADMISSION defaults (same negative=disabled convention).
	c.ConnPerAccountRate = rateLimitField(c.ConnPerAccountRate, 4)
	c.ConnPerAccountBurst = rateLimitField(c.ConnPerAccountBurst, 20)
	c.GlobalConnRate = rateLimitField(c.GlobalConnRate, 100)
	c.GlobalConnBurst = rateLimitField(c.GlobalConnBurst, 200)
	// DIRECT-PROBE BUDGET (probe-reflection guard). Same negative=disabled convention.
	c.DirectProbeRate = rateLimitField(c.DirectProbeRate, 1)
	c.DirectProbeBurst = rateLimitField(c.DirectProbeBurst, 5)
	// Saturation shed threshold: 0 => default 0.95, negative => disabled (0).
	switch {
	case c.SheddingThreshold < 0:
		c.SheddingThreshold = 0
	case c.SheddingThreshold == 0:
		c.SheddingThreshold = 0.95
	}
	if c.RateLimitIdleTTL == 0 {
		c.RateLimitIdleTTL = 10 * time.Minute
	}
	if c.RateLimitMaxKeys == 0 {
		c.RateLimitMaxKeys = 100_000
	}
	// WAVE41-RELAY-REVOCATION: 0 => default 20s live-session recheck; a negative
	// value disables the sweep and is normalized to 0 so startRevocationSweep skips.
	switch {
	case c.RevokeSweepPeriod < 0:
		c.RevokeSweepPeriod = 0
	case c.RevokeSweepPeriod == 0:
		c.RevokeSweepPeriod = 20 * time.Second
	}
}

// Server is the relay. Construct with New, then use Handler() / ListenAndServe*.
type Server struct {
	cfg      Config
	registry *registry
	gate     *entitlementGate // account relay-entitlement gate (no-op when CP nil)
	meter    *meter           // per-account usage meter (no-op when CP nil)

	// Rate limiters (WAVE34-RELAY-HARDEN). Nil => disabled (allow all).
	ctrlLimiter   *rateLimiter       // control-conn attempts per source IP
	reqLimiter    *rateLimiter       // public requests per agent/session
	globalLimiter *globalRateLimiter // aggregate public request cap

	// CONNECTION-FLOOD ADMISSION. Nil => disabled (allow all).
	acctConnLimiter   *rateLimiter       // NEW control connections per account
	globalConnLimiter *globalRateLimiter // aggregate NEW control-connection rate (cheap pre-upgrade gate)

	// DIRECT-PROBE BUDGET (probe-reflection guard). Nil => disabled. Keyed per
	// account (per name for unbilled) — bounds how often a box can make the relay
	// emit an outbound endpoint-verification GET on its behalf.
	directProbeLimiter *rateLimiter

	// Revocation (WAVE41-RELAY-REVOCATION).
	revoke       revocationSource // static revoked-list + CP revoked/404 signal
	revokePeriod time.Duration    // live-session recheck cadence (0 => sweep disabled)
	revokeStop   chan struct{}
	revokeWG     sync.WaitGroup

	// AUTOSCALE-ON-SATURATION: background loop that samples this node's load against
	// SoftCapacity and publishes the saturation gauge. satStop is nil when no
	// sampler runs (no soft capacity, or disabled).
	satStop chan struct{}
	satWG   sync.WaitGroup

	// SMART-AUTOSCALE: draining is set by Drain() (CP-driven graceful scale-down) —
	// while set, new tunnels are refused and every agent has been signaled to
	// reconnect elsewhere. popLink holds the CP registration + load-heartbeat loop;
	// nil when the relay is not a CP-registered PoP (self-host / CP-optional).
	draining atomic.Bool
	popLink  *popLinkState

	// DIRECT-IP: verifier for box-advertised direct endpoints (nil when
	// DisableDirect). directVerify is called at register time to prove an
	// advertised endpoint is reachable + owned before it is surfaced to clients.
	directVerifier directEndpointVerifier

	// RENDEZVOUS ROLE: the announce/resolve/signal/mailbox + ICE service, served on
	// the relay's apex host. nil unless EnableRendezvous is set (self-host default
	// is a plain reverse-tunnel relay).
	rendezvous *rendezvous.Service

	// CACHE/PIN ROLE: the DMTAP-PUB public-object read cache, served on the
	// relay's apex host. nil unless EnablePubCache is set.
	pubcache *pubcache.Service

	// Observability (WAVE50-RELAY-OBSERVABILITY). metrics is always non-nil; log is
	// the structured logger. adminSrv is the running admin/metrics *http.Server (nil
	// until ServeAdmin runs) so Close can shut it down.
	metrics  *metrics
	log      *slog.Logger
	adminSrv *http.Server

	// pubSrv is the running public tunnel *http.Server (nil until one of the
	// ListenAndServe* methods runs). Retained under srvMu so Shutdown can drain it
	// gracefully on SIGTERM/SIGINT instead of the process being hard-killed mid-flush.
	srvMu  sync.Mutex
	pubSrv *http.Server
}

// New validates config and returns a Server. It fails closed: a missing token
// store or domain is an error rather than an open relay.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.Domain) == "" {
		return nil, fmt.Errorf("relay: Domain is required")
	}
	if cfg.Tokens == nil {
		return nil, fmt.Errorf("relay: a TokenStore is required (refusing to run open)")
	}
	cfg.applyDefaults()
	gate := newEntitlementGate(cfg.CP, cfg.GateTTL)
	// WAVE41-RELAY-REVOCATION: the static revoked-list comes from the token store if
	// it implements Revoker (staticTokenStore does; CPTokenStore does not — its
	// revocation is the CP revoked/404 path). Fall back to a no-op so the sweep
	// needs no nil-checks.
	var staticRevoker Revoker = noopRevoker{}
	if rv, ok := cfg.Tokens.(Revoker); ok {
		staticRevoker = rv
	}
	// RELAY-TOKEN-TTL: if the token store exposes grant TTLs (the static store
	// does; the CP install-credential store does not), let the revocation sweep
	// cut a live tunnel whose token expires mid-session. nil when unsupported.
	var expirer Expirer
	if ex, ok := cfg.Tokens.(Expirer); ok {
		expirer = ex
	}
	s := &Server{
		cfg:      cfg,
		registry: newRegistry(cfg.MaxAgents),
		gate:     gate,
		meter:    newMeter(cfg.CP, cfg.MeterFlushPeriod),

		ctrlLimiter:   newRateLimiter(cfg.ControlConnRate, cfg.ControlConnBurst, cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
		reqLimiter:    newRateLimiter(cfg.PublicReqRate, cfg.PublicReqBurst, cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
		globalLimiter: newGlobalRateLimiter(cfg.GlobalReqRate, cfg.GlobalReqBurst),

		acctConnLimiter:   newRateLimiter(cfg.ConnPerAccountRate, cfg.ConnPerAccountBurst, cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
		globalConnLimiter: newGlobalRateLimiter(cfg.GlobalConnRate, cfg.GlobalConnBurst),

		directProbeLimiter: newRateLimiter(cfg.DirectProbeRate, cfg.DirectProbeBurst, cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),

		revoke:       revocationSource{static: staticRevoker, expirer: expirer, gate: gate},
		revokePeriod: cfg.RevokeSweepPeriod,
		revokeStop:   make(chan struct{}),

		metrics: newMetrics(),
		log:     newLogger(),
	}
	// DIRECT-IP: wire the direct-endpoint verifier unless direct negotiation is
	// disabled. A test may inject its own via cfg.directVerifier (the real one
	// performs a live internet probe, which unit tests must not do).
	if !cfg.DisableDirect {
		if cfg.directVerifier != nil {
			s.directVerifier = cfg.directVerifier
		} else {
			s.directVerifier = &httpDirectVerifier{}
		}
	}
	// WAVE34-RELAY-HARDEN: let the usage-flush loop feed the CP's over-quota
	// verdict straight into the entitlement gate, so an over-cap account is cut
	// on its next request (402) rather than surviving until the gate TTL lapses.
	// WAVE50: also surface each over-quota verdict as a structured log line (the
	// per-request 402 cut is counted in the proxy path).
	s.meter.onOverQuota = func(accountID string) {
		s.gate.markOverQuota(accountID)
		s.logInfo("account marked over quota", logFields{Account: accountID, Reason: string(cutOverQuota)})
	}
	// Start the background usage-flush loop (no-op when unbilled).
	s.meter.run()
	// WAVE41-RELAY-REVOCATION: start the live-session revocation sweep (unless
	// disabled). It periodically rechecks every session and drops revoked ones.
	s.startRevocationSweep()
	// AUTOSCALE-ON-SATURATION: start the saturation sampler (no-op unless a soft
	// capacity is configured and the period is non-negative).
	s.startSaturationSampler()
	// SMART-AUTOSCALE: start the CP PoP registration + load-heartbeat loop (no-op
	// unless a CP is configured AND a public endpoint is advertised — the
	// CP-optional / self-host contract).
	s.startPoPHeartbeat()
	// RENDEZVOUS ROLE: construct the open reachability service when enabled. It is
	// CP-optional and self-contained (soft-state only); it inherits the relay's
	// structured logger unless the caller set one. Mounted in Handler() and dispatched
	// on the apex host in handlePublic.
	if cfg.EnableRendezvous {
		rcfg := cfg.Rendezvous
		if rcfg.Logger == nil {
			rcfg.Logger = s.log
		}
		s.rendezvous = rendezvous.New(rcfg)
		s.logInfo("rendezvous role enabled", logFields{Reason: s.rendezvous.Prefix()})
	}
	// CACHE/PIN ROLE: construct the DMTAP-PUB public-object cache when enabled.
	// It inherits the relay's logger and its trusted-proxy-aware client-IP
	// extractor (so its anonymous-read rate limits key on the same identity the
	// rest of the relay uses). Mounted in Handler() and dispatched on the apex
	// host in handlePublic, exactly like the rendezvous role.
	if cfg.EnablePubCache {
		pcfg := cfg.PubCache
		if pcfg.Logger == nil {
			pcfg.Logger = s.log
		}
		if pcfg.ClientIP == nil {
			pcfg.ClientIP = s.clientIP
		}
		pc, err := pubcache.New(pcfg)
		if err != nil {
			return nil, err
		}
		s.pubcache = pc
		s.logInfo("pubcache (DMTAP-PUB cache/pin) role enabled", logFields{Reason: pc.Prefix()})
	}
	// WAVE50-RELAY-OBSERVABILITY: background loops are up ⇒ mark ready for /readyz.
	s.metrics.setReady(true)
	return s, nil
}

// Close stops background loops and performs a final usage flush. Safe to call
// once after the HTTP server has stopped accepting new connections.
func (s *Server) Close() {
	s.metrics.setReady(false) // /readyz reports draining
	if s.adminSrv != nil {
		_ = s.adminSrv.Close()
	}
	s.stopRevocationSweep()
	s.stopSaturationSampler()
	s.stopPoPHeartbeat()
	if s.rendezvous != nil {
		s.rendezvous.Close()
	}
	if s.pubcache != nil {
		s.pubcache.Close()
	}
	if s.meter != nil {
		s.meter.stopAndFlush()
	}
}

// Handler returns the http.Handler serving BOTH the control endpoint and the
// public proxy. Mount it directly, or wrap it (e.g. access logging).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(wireControlPath, s.handleControl)
	mux.HandleFunc("/", s.handlePublic)
	return mux
}

// httpServer builds an *http.Server with the security-relevant timeouts/caps set
// and retains it so Shutdown can drain it gracefully.
func (s *Server) httpServer(addr string) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		TLSConfig:         s.cfg.TLSConfig,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       s.cfg.IdleTimeout,
		// No WriteTimeout: tunneled responses (SSE, WS, downloads) are long-lived.
	}
	s.srvMu.Lock()
	s.pubSrv = srv
	s.srvMu.Unlock()
	return srv
}

// ListenAndServeTLS runs the relay as a directly-internet-facing HTTPS server,
// terminating TLS itself from certFile/keyFile.
func (s *Server) ListenAndServeTLS(addr, certFile, keyFile string) error {
	srv := s.httpServer(addr)
	// Self-terminating path: pin an explicit TLS floor + ALPN instead of inheriting
	// whatever the Go stdlib happens to default to. An operator-supplied
	// cfg.TLSConfig is honored verbatim (pass-through).
	srv.TLSConfig = s.tlsConfigForSelfTerminate()
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// tlsConfigForSelfTerminate resolves the TLS config used when the relay
// terminates TLS itself (ListenAndServeTLS with -cert/-key). It returns the
// operator-supplied cfg.TLSConfig verbatim when set (pass-through, untouched),
// otherwise a hardened default.
func (s *Server) tlsConfigForSelfTerminate() *tls.Config {
	if s.cfg.TLSConfig != nil {
		return s.cfg.TLSConfig
	}
	return hardenedTLSConfig()
}

// hardenedTLSConfig is the explicit floor applied when the relay TERMINATES TLS
// itself and the operator supplied no tls.Config of their own. It pins a TLS 1.2
// minimum (the safe interop floor — TLS 1.0/1.1 are disallowed) and advertises
// HTTP/2 + HTTP/1.1 via ALPN, rather than leaning on Go-version-dependent stdlib
// defaults. On the Fly deployment the edge terminates TLS, so this path is unused
// there; it exists to give a self-hoster using -cert/-key a sane, pinned posture.
func hardenedTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// ListenAndServe runs the relay as plain HTTP — ONLY for use behind a TLS-
// terminating proxy/CDN (which is the recommended edge-friendly deployment) or in
// tests. Do not expose this directly to the internet.
func (s *Server) ListenAndServe(addr string) error {
	return s.httpServer(addr).ListenAndServe()
}

// Shutdown gracefully drains the relay on SIGTERM/SIGINT: it flips /readyz to
// draining, stops accepting new connections on the public + admin listeners, waits
// (bounded by ctx) for in-flight requests to finish, then stops the background
// loops and performs the final usage flush via Close. Calling it instead of letting
// the process be hard-killed is what preserves the last metered deltas and lets a
// load balancer stop routing here before connections wind down. Safe to call once.
func (s *Server) Shutdown(ctx context.Context) error {
	// Flip /readyz to draining first so a load balancer stops routing new traffic
	// here before we tear down in-flight connections.
	s.metrics.setReady(false)

	s.srvMu.Lock()
	pub := s.pubSrv
	s.srvMu.Unlock()

	var err error
	if pub != nil {
		err = pub.Shutdown(ctx)
	}
	// Stop background loops + final usage flush. Close also shuts down the admin
	// server and re-sets ready=false (both idempotent).
	s.Close()
	return err
}

// AgentCount returns the number of live agent sessions (for /healthz or metrics).
func (s *Server) AgentCount() int { return s.registry.count() }

// RevokeToken revokes a static token at runtime (no config edit / restart) and
// immediately drops any matching live session. A no-op if the token store does
// not support runtime revocation (e.g. the CP-credential store, whose revocation
// is driven by the CP's revoked/404 signal). WAVE41-RELAY-REVOCATION.
func (s *Server) RevokeToken(token string) {
	if rr, ok := s.cfg.Tokens.(RuntimeRevoker); ok {
		rr.RevokeToken(token)
		s.sweepRevoked() // cut the leaked token's live tunnel now, not on the next tick
	}
}

// RevokeName revokes a tunnel name at runtime and drops its live session now.
func (s *Server) RevokeName(name string) {
	if rr, ok := s.cfg.Tokens.(RuntimeRevoker); ok {
		rr.RevokeName(name)
		s.sweepRevoked()
	}
}

// RevokeAccount revokes an account at runtime and drops its live sessions now.
func (s *Server) RevokeAccount(account string) {
	if rr, ok := s.cfg.Tokens.(RuntimeRevoker); ok {
		rr.RevokeAccount(account)
		s.sweepRevoked()
	}
}
