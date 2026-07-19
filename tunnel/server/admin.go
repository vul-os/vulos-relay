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
	// SMART-AUTOSCALE: CP→relay graceful-drain control. Gated by the CP shared
	// secret (X-Relay-Auth), NOT the metrics token, and unavailable on a relay with
	// no CP secret (self-host has nothing to drain remotely — SIGTERM suffices).
	mux.HandleFunc("/control/drain", s.gateControl(s.handleDrain))
	mux.HandleFunc("/control/undrain", s.gateControl(s.handleUndrain))
	mux.HandleFunc("/control/status", s.gateControl(s.handleControlStatus))
	mux.HandleFunc("/", s.gateAdmin(tok, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	return mux
}

// cpSharedSecret returns the CP service credential this relay shares with Vulos
// Cloud, or "" when the relay has no CP link (self-host).
func (s *Server) cpSharedSecret() string {
	if s.cfg.CP == nil {
		return ""
	}
	return s.cfg.CP.SharedSecret
}

// gateControl authenticates a CP→relay control request with the CP shared secret
// presented as "X-Relay-Auth: <secret>" (the same service credential CPClient uses
// for entitlement reads), compared in constant time. A relay with no CP secret has
// the control surface DISABLED (404) — graceful drain is a managed-relay feature.
// This is independent of the loopback/metrics-token gate so the CP can drive a
// drain over the network by presenting the shared secret it already holds.
func (s *Server) gateControl(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret := s.cpSharedSecret()
		if secret == "" {
			http.NotFound(w, r) // control surface not available on a CP-less relay
			return
		}
		if !constEq(strings.TrimSpace(r.Header.Get("X-Relay-Auth")), secret) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// handleDrain (POST /control/drain) puts the PoP into graceful-drain mode: it stops
// accepting new tunnels and proactively signals every connected agent to reconnect
// to another PoP. Returns the live status so the CP can poll active_tunnels to 0.
func (s *Server) handleDrain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	signaled := s.Drain()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"draining":       true,
		"signaled":       signaled,
		"active_tunnels": s.DrainingTunnels(),
		"pop_id":         s.popID(),
		"region":         s.cfg.Region,
	})
}

// handleUndrain (POST /control/undrain) clears drain mode (drain aborted by the CP).
func (s *Server) handleUndrain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.Undrain()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "draining": false})
}

// handleControlStatus (GET /control/status) reports live drain/load status so the
// CP-side autoscaler knows when it is safe to terminate the machine (0 tunnels).
func (s *Server) handleControlStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"draining":       s.IsDraining(),
		"active_tunnels": s.registry.count(),
		"saturation":     s.SaturationRatio(),
		"pop_id":         s.popID(),
		"region":         s.cfg.Region,
		"node_id":        s.cfg.NodeID,
	})
}

// popID returns this PoP's id as known to the CP (falls back to the node id / domain).
func (s *Server) popID() string {
	if s.cfg.CP != nil && s.cfg.CP.PoPID != "" {
		return s.cfg.CP.PoPID
	}
	if s.cfg.NodeID != "" {
		return s.cfg.NodeID
	}
	return s.cfg.Domain
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
	// RENDEZVOUS ROLE: the rendezvous service owns its counters (it is mountable
	// standalone), so pull a snapshot at scrape time. Skipped entirely when the
	// role is off, which is what keeps those series absent on a tunnel-only relay.
	if s.rendezvous != nil {
		st := s.rendezvous.Stats()
		s.metrics.setRendezvous(rendezvousSnapshot{
			announces:       st.Announces,
			announceRejects: st.AnnounceRejects,
			resolves:        st.Resolves,
			signalDeposits:  st.SignalDeposits,
			signalPickups:   st.SignalPickups,
			mailboxDeposits: st.MailboxDeposits,
			mailboxPickups:  st.MailboxPickups,
			authFailures:    st.AuthFailures,
			rateLimited:     st.RateLimited,
			livePresence:    int64(st.LivePresence),
		})
	}
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
