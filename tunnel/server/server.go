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
	"time"
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

	// EnableSFUHostRegistry turns on the Vulos Meet SFU-host registry (Phase 2,
	// BYO/self-host). When true, a token-authorized box may register a VERIFIED SFU
	// endpoint via POST /api/meet/host/{register,heartbeat,deregister} and clients
	// resolve a reachable host via GET /api/meet/host/resolve. Default FALSE: the
	// registry rejects registers and resolve returns available=false, so a relay
	// that does not run the placement layer is byte-for-byte unchanged. Registration
	// additionally REQUIRES direct verification (DisableDirect must be false), since
	// the SFU endpoint is proven with the same directprobe verifier.
	EnableSFUHostRegistry bool

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
	// Rate-limit defaults (WAVE34-RELAY-HARDEN). A negative value means "disabled"
	// and is normalized to 0 by rateLimitField at construction time.
	c.ControlConnRate = rateLimitField(c.ControlConnRate, 5)
	c.ControlConnBurst = rateLimitField(c.ControlConnBurst, 20)
	c.PublicReqRate = rateLimitField(c.PublicReqRate, 50)
	c.PublicReqBurst = rateLimitField(c.PublicReqBurst, 100)
	c.GlobalReqRate = rateLimitField(c.GlobalReqRate, 500)
	c.GlobalReqBurst = rateLimitField(c.GlobalReqBurst, 1000)
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

	// Revocation (WAVE41-RELAY-REVOCATION).
	revoke       revocationSource // static revoked-list + CP revoked/404 signal
	revokePeriod time.Duration    // live-session recheck cadence (0 => sweep disabled)
	revokeStop   chan struct{}
	revokeWG     sync.WaitGroup

	// DIRECT-IP: verifier for box-advertised direct endpoints (nil when
	// DisableDirect). directVerify is called at register time to prove an
	// advertised endpoint is reachable + owned before it is surfaced to clients.
	directVerifier directEndpointVerifier

	// sfuHosts is the Vulos Meet SFU-host registry (Phase 2). Always non-nil (an
	// empty registry is inert: resolve returns available=false). Registration is
	// only accepted when cfg.EnableSFUHostRegistry is true.
	sfuHosts *sfuHostRegistry

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

		revoke:       revocationSource{static: staticRevoker, expirer: expirer, gate: gate},
		revokePeriod: cfg.RevokeSweepPeriod,
		revokeStop:   make(chan struct{}),

		metrics: newMetrics(),
		log:     newLogger(),

		sfuHosts: newSFUHostRegistry(),
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
