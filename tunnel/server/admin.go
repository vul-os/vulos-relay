package server

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// admin.go — WAVE50-RELAY-OBSERVABILITY: the ADMIN/control-plane HTTP surface.
//
// This surface is DELIBERATELY SEPARATE from the public tunnel Handler(). It
// serves /metrics, /healthz, and /readyz and must NEVER be reachable from the
// internet-facing tunnel listener:
//
//   - /metrics would leak operational internals (agent counts, byte volumes,
//     auth-failure rates) and is a scrape target, not a public endpoint.
//   - It is gated two ways, in order of preference:
//       1. loopback-only  — served on 127.0.0.1 / ::1 by binding the admin
//          listener to a loopback address (the recommended default); AND/OR
//       2. metrics-token   — a bearer token required on the request, so a metrics
//          scraper reaching the admin port over a private network still must
//          authenticate. When a token is set, non-loopback requests MUST present
//          it; loopback requests may skip it (local scrape convenience).
//
// The public Handler() intentionally does NOT mount /metrics or /readyz. It keeps
// only the pre-existing lightweight /healthz convenience (a liveness ping that
// exposes nothing beyond an agent count), preserved for backward compatibility.

// AdminConfig configures the admin/metrics surface.
type AdminConfig struct {
	// Addr is the admin listen address. Bind it to a loopback address
	// (e.g. "127.0.0.1:9090") for loopback-only gating, which is the recommended
	// default. Binding to a non-loopback address REQUIRES a MetricsToken (New
	// refuses otherwise) so /metrics is never exposed unauthenticated.
	Addr string
	// MetricsToken, if set, is required as "Authorization: Bearer <token>" on any
	// NON-loopback request to the admin surface. Loopback requests may omit it.
	MetricsToken string
}

// adminHandler builds the admin mux: /metrics, /healthz, /readyz. Every handler
// is gated by adminGate (loopback or token).
func (s *Server) adminHandler(tok string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.gateAdmin(tok, s.handleMetrics))
	mux.HandleFunc("/healthz", s.gateAdmin(tok, s.handleHealthz))
	mux.HandleFunc("/readyz", s.gateAdmin(tok, s.handleReadyz))
	mux.HandleFunc("/", s.gateAdmin(tok, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	return mux
}

// gateAdmin enforces loopback-or-token access. A request is allowed iff it comes
// from loopback, OR it presents the configured metrics token. When no token is
// configured, ONLY loopback is allowed (fail closed for non-loopback).
func (s *Server) gateAdmin(tok string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isLoopback(r.RemoteAddr) {
			next(w, r)
			return
		}
		if tok != "" && constEq(bearer(r), tok) {
			next(w, r)
			return
		}
		// Non-loopback without a valid token: refuse. Do not reveal whether a token
		// is even configured.
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Reconcile the agent gauge with the registry's authoritative count before the
	// scrape, so a missed dec on an abnormal teardown self-heals.
	s.metrics.setActiveAgents(s.registry.count())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.writeTo(w)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	// Surface this node's pool identity (id/region) alongside the agent count so a
	// pool health checker / operator can tell WHICH node answered. Both are omitted
	// when unset (single-node self-host), preserving the original one-line output.
	if s.cfg.NodeID != "" || s.cfg.Region != "" {
		fmt.Fprintf(w, "ok agents=%d node=%s region=%s\n", s.registry.count(), s.cfg.NodeID, s.cfg.Region)
		return
	}
	fmt.Fprintf(w, "ok agents=%d\n", s.registry.count())
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if s.metrics.isReady() {
		fmt.Fprintln(w, "ready")
		return
	}
	http.Error(w, "not ready", http.StatusServiceUnavailable)
}

// isLoopback reports whether remoteAddr (host:port) is a loopback address.
func isLoopback(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isLoopbackHost reports whether an addr's host part is a loopback/unspecified-free
// loopback binding (used to validate the admin Addr at construction).
func isLoopbackBind(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false // e.g. ":9090" binds all interfaces — NOT loopback
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func constEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ServeAdmin runs the admin/metrics surface on its own listener. Call it in a
// goroutine alongside the public ListenAndServe*. It blocks until the listener
// errors. A missing Addr is a no-op (returns nil) so the admin surface is opt-in.
//
// SECURITY: if Addr is a non-loopback bind and no MetricsToken is set, ServeAdmin
// refuses to start (an unauthenticated metrics endpoint on a routable interface is
// exactly the exposure this wave exists to prevent).
func (s *Server) ServeAdmin(cfg AdminConfig) error {
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		return nil // admin surface disabled
	}
	if !isLoopbackBind(addr) && strings.TrimSpace(cfg.MetricsToken) == "" {
		return fmt.Errorf("relay admin: refusing to serve /metrics on non-loopback %q without a metrics token", addr)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.adminHandler(strings.TrimSpace(cfg.MetricsToken)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	s.adminSrv = srv
	return srv.ListenAndServe()
}
