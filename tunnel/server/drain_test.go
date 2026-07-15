package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// drain_test.go — SMART-AUTOSCALE (relay side): the CP-authed graceful-drain control
// surface + drain-state semantics. The end-to-end "tunnels migrate with ZERO drop"
// path is proven in the tunnel_test package (drain_e2e_test.go); these pin the unit
// contract: state transitions, the control endpoint's auth, and the CP-optional rule
// that a relay with no CP secret has no remote control surface.

// drainTestServer builds a relay with a CP shared secret so the control surface is
// active, but points the CP at an unused URL and disables the heartbeat (no
// PublicEndpoint) so no network I/O happens.
func drainTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	s, err := New(Config{
		Domain:            "relay.test",
		Tokens:            store,
		RevokeSweepPeriod: -1,
		Region:            "eu-central",
		CP:                &CPClient{BaseURL: "http://cp.invalid", SharedSecret: "drain-secret", PoPID: "hel1-a"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// TestDrain_StateTransitions: Drain sets draining + flips readiness; Undrain clears.
func TestDrain_StateTransitions(t *testing.T) {
	s := drainTestServer(t)
	if s.IsDraining() {
		t.Fatal("fresh server reports draining")
	}
	if !s.metrics.isReady() {
		t.Fatal("fresh server not ready")
	}
	// No live sessions, so Drain signals 0 agents but still flips state.
	if n := s.Drain(); n != 0 {
		t.Fatalf("Drain signaled %d agents, want 0 (no sessions)", n)
	}
	if !s.IsDraining() {
		t.Fatal("Drain did not set draining")
	}
	if s.metrics.isReady() {
		t.Fatal("Drain did not flip readiness to draining")
	}
	s.Undrain()
	if s.IsDraining() {
		t.Fatal("Undrain did not clear draining")
	}
	if !s.metrics.isReady() {
		t.Fatal("Undrain did not restore readiness")
	}
}

// TestBroadcastReconnect_EmptyRegistry: no sessions => 0 signaled, no panic.
func TestBroadcastReconnect_EmptyRegistry(t *testing.T) {
	s := drainTestServer(t)
	if n := s.broadcastReconnect("drain"); n != 0 {
		t.Fatalf("broadcastReconnect on empty registry = %d, want 0", n)
	}
}

// TestControlEndpoint_RequiresSharedSecret: /control/drain is refused without the
// correct X-Relay-Auth, and accepted with it.
func TestControlEndpoint_RequiresSharedSecret(t *testing.T) {
	s := drainTestServer(t)
	h := s.adminHandler("") // no metrics token needed; control uses X-Relay-Auth

	// Missing auth → 403.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/control/drain", nil)
	req.RemoteAddr = "203.0.113.5:5555" // non-loopback: prove it's not the loopback gate
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("drain without secret = %d, want 403", rec.Code)
	}
	if s.IsDraining() {
		t.Fatal("drain took effect despite missing auth")
	}

	// Wrong secret → 403.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/control/drain", nil)
	req.Header.Set("X-Relay-Auth", "nope")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("drain with wrong secret = %d, want 403", rec.Code)
	}

	// Correct secret → 200 + draining.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/control/drain", nil)
	req.Header.Set("X-Relay-Auth", "drain-secret")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("drain with secret = %d, want 200", rec.Code)
	}
	if !s.IsDraining() {
		t.Fatal("authorized drain did not set draining")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("drain response not JSON: %v", err)
	}
	if body["draining"] != true || body["pop_id"] != "hel1-a" || body["region"] != "eu-central" {
		t.Fatalf("drain response missing status: %v", body)
	}
}

// TestControlStatus_ReportsLiveState: /control/status reflects drain + tunnel count.
func TestControlStatus_ReportsLiveState(t *testing.T) {
	s := drainTestServer(t)
	h := s.adminHandler("")

	get := func() map[string]any {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/control/status", nil)
		req.Header.Set("X-Relay-Auth", "drain-secret")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("status not JSON: %v", err)
		}
		return m
	}

	if m := get(); m["draining"] != false {
		t.Fatalf("status draining=%v, want false", m["draining"])
	}
	s.Drain()
	if m := get(); m["draining"] != true {
		t.Fatalf("status draining=%v after Drain, want true", m["draining"])
	}
}

// TestControlEndpoint_DisabledWithoutCPSecret: a self-host relay (no CP) has NO
// remote control surface — /control/* returns 404 (CP-optional).
func TestControlEndpoint_DisabledWithoutCPSecret(t *testing.T) {
	s := newTestServer(t) // no CP
	h := s.adminHandler("")
	for _, path := range []string{"/control/drain", "/control/status", "/control/undrain"} {
		rec := httptest.NewRecorder()
		method := http.MethodPost
		if path == "/control/status" {
			method = http.MethodGet
		}
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("X-Relay-Auth", "anything")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s on CP-less relay = %d, want 404 (control surface disabled)", path, rec.Code)
		}
	}
	if s.IsDraining() {
		t.Fatal("CP-less relay entered draining via a disabled endpoint")
	}
}
