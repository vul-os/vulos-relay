// observability_test.go — WAVE50-RELAY-OBSERVABILITY tests.
//
// Coverage:
//   - metrics increment on the right events (requests-by-outcome, rate-limit
//     rejects, revocation cuts, over-quota cuts, agent/stream gauges, bytes);
//   - /metrics + /readyz are NOT served on the public tunnel listener;
//   - the admin surface is loopback-gated and token-gated;
//   - label cardinality is bounded (fixed enum series, no unbounded keys);
//   - no token/secret appears in structured log output.
package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// renderMetrics scrapes the metrics into a string.
func renderMetrics(m *metrics) string {
	var b bytes.Buffer
	m.writeTo(&b)
	return b.String()
}

func TestMetrics_RequestOutcomesIncrement(t *testing.T) {
	m := newMetrics()
	m.request(outcomeOK)
	m.request(outcomeOK)
	m.request(outcomeNoTunnel)
	m.request(outcomeRateLimited)

	out := renderMetrics(m)
	if !strings.Contains(out, `vulos_relay_requests_total{outcome="ok"} 2`) {
		t.Errorf("expected ok=2 in:\n%s", out)
	}
	if !strings.Contains(out, `vulos_relay_requests_total{outcome="no_tunnel"} 1`) {
		t.Errorf("expected no_tunnel=1 in:\n%s", out)
	}
	if !strings.Contains(out, `vulos_relay_requests_total{outcome="rate_limited"} 1`) {
		t.Errorf("expected rate_limited=1 in:\n%s", out)
	}
	// A never-hit outcome must still be present at 0 (pre-registered, stable series).
	if !strings.Contains(out, `vulos_relay_requests_total{outcome="busy"} 0`) {
		t.Errorf("expected pre-registered busy=0 in:\n%s", out)
	}
}

func TestMetrics_AgentAndStreamGauges(t *testing.T) {
	m := newMetrics()
	m.agentConnected()
	m.agentConnected()
	m.agentDisconnected()
	m.streamOpened()

	out := renderMetrics(m)
	if !strings.Contains(out, "vulos_relay_active_agents 1") {
		t.Errorf("expected active_agents 1 in:\n%s", out)
	}
	if !strings.Contains(out, "vulos_relay_active_streams 1") {
		t.Errorf("expected active_streams 1 in:\n%s", out)
	}
	if !strings.Contains(out, "vulos_relay_yamux_sessions 1") {
		t.Errorf("expected yamux_sessions 1 in:\n%s", out)
	}
	if !strings.Contains(out, "vulos_relay_agent_connects_total 2") {
		t.Errorf("expected agent_connects_total 2 in:\n%s", out)
	}
}

func TestMetrics_CutsAndRateLimits(t *testing.T) {
	m := newMetrics()
	m.tunnelCut(cutRevocation)
	m.tunnelCut(cutOverQuota)
	m.tunnelCut(cutOverQuota)
	m.rateLimitReject(limitControl)
	m.rateLimitReject(limitGlobal)

	out := renderMetrics(m)
	for _, want := range []string{
		`vulos_relay_tunnel_cuts_total{reason="revocation"} 1`,
		`vulos_relay_tunnel_cuts_total{reason="over_quota"} 2`,
		"vulos_relay_revocation_cuts_total 1",
		"vulos_relay_over_quota_cuts_total 2",
		`vulos_relay_rate_limited_total{surface="control"} 1`,
		`vulos_relay_rate_limited_total{surface="global"} 1`,
		`vulos_relay_rate_limited_total{surface="per_tunnel"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestMetrics_Bytes(t *testing.T) {
	m := newMetrics()
	m.proxiedBytes(dirInbound, 100)
	m.proxiedBytes(dirOutbound, 250)
	m.proxiedBytes(dirDuplex, 40)
	m.proxiedBytes(dirInbound, -5) // ignored

	out := renderMetrics(m)
	for _, want := range []string{
		`vulos_relay_proxied_bytes_total{direction="inbound"} 100`,
		`vulos_relay_proxied_bytes_total{direction="outbound"} 250`,
		`vulos_relay_proxied_bytes_total{direction="duplex"} 40`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestMetrics_CardinalityBounded proves the label sets are fixed: the number of
// labelled series equals the number of enum values, and a flood of distinct
// request outcomes / auth reasons cannot add series (the maps are pre-populated
// and never inserted into at runtime — invalid keys are simply dropped).
func TestMetrics_CardinalityBounded(t *testing.T) {
	m := newMetrics()

	// Attempt to record 10_000 DISTINCT bogus outcomes (simulating an attacker who
	// controls the dimension). They must NOT create new series.
	for i := 0; i < 10_000; i++ {
		m.request(reqOutcome("attacker-host-" + string(rune('a'+i%26)) + "-path"))
		m.authFail(authFailReason("junk"))
		m.rateLimitReject(ctrlLimitSurface("junk"))
	}

	out := renderMetrics(m)
	if n := strings.Count(out, "vulos_relay_requests_total{"); n != len(allReqOutcomes) {
		t.Fatalf("requests_total series = %d, want fixed %d (cardinality leaked!)", n, len(allReqOutcomes))
	}
	if n := strings.Count(out, "vulos_relay_auth_failures_total{"); n != len(allAuthFailReasons) {
		t.Fatalf("auth_failures_total series = %d, want fixed %d", n, len(allAuthFailReasons))
	}
	if n := strings.Count(out, "vulos_relay_rate_limited_total{"); n != len(allLimitSurfaces) {
		t.Fatalf("rate_limited_total series = %d, want fixed %d", n, len(allLimitSurfaces))
	}
	// And the underlying maps did not grow.
	if len(m.requests) != len(allReqOutcomes) {
		t.Fatalf("requests map grew to %d (unbounded!)", len(m.requests))
	}
}

// TestMetrics_NotOnPublicListener asserts the public tunnel Handler() does NOT
// serve /metrics or /readyz (they must live only on the admin surface).
func TestMetrics_NotOnPublicListener(t *testing.T) {
	s := newTestServer(t)
	pub := httptest.NewServer(s.Handler())
	t.Cleanup(pub.Close)

	for _, path := range []string{"/metrics", "/readyz"} {
		resp, err := http.Get(pub.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body := readAll(resp)
		resp.Body.Close()
		// The public listener routes everything unknown through the tunnel router,
		// which returns 404 "no such tunnel" — it must NOT return metrics text.
		if strings.Contains(body, "vulos_relay_") {
			t.Fatalf("PUBLIC listener leaked metrics on %s:\n%s", path, body)
		}
		if resp.StatusCode == http.StatusOK && strings.Contains(body, "# TYPE") {
			t.Fatalf("PUBLIC listener served Prometheus output on %s", path)
		}
	}
}

// TestAdmin_LoopbackAndTokenGating checks the admin surface serves metrics to a
// loopback caller and refuses a non-loopback caller without the token but allows
// it with the token.
func TestAdmin_LoopbackAndTokenGating(t *testing.T) {
	s := newTestServer(t)
	const tok = "s3cr3t-metrics-token"
	h := s.adminHandler(tok)

	// Loopback caller: allowed, no token needed.
	loop := doReq(h, "GET", "/metrics", "127.0.0.1:5555", "")
	if loop.Code != http.StatusOK {
		t.Fatalf("loopback /metrics = %d, want 200", loop.Code)
	}
	if !strings.Contains(loop.Body.String(), "vulos_relay_active_agents") {
		t.Fatalf("loopback /metrics missing metric body")
	}

	// Non-loopback WITHOUT token: forbidden.
	deny := doReq(h, "GET", "/metrics", "203.0.113.7:5555", "")
	if deny.Code != http.StatusForbidden {
		t.Fatalf("non-loopback /metrics without token = %d, want 403", deny.Code)
	}
	if strings.Contains(deny.Body.String(), "vulos_relay_") {
		t.Fatalf("forbidden response leaked metrics")
	}

	// Non-loopback WITH the token: allowed.
	ok := doReq(h, "GET", "/metrics", "203.0.113.7:5555", "Bearer "+tok)
	if ok.Code != http.StatusOK {
		t.Fatalf("non-loopback /metrics with token = %d, want 200", ok.Code)
	}

	// Non-loopback with the WRONG token: forbidden.
	bad := doReq(h, "GET", "/metrics", "203.0.113.7:5555", "Bearer wrong")
	if bad.Code != http.StatusForbidden {
		t.Fatalf("non-loopback /metrics with wrong token = %d, want 403", bad.Code)
	}
}

// TestServeAdmin_RefusesUnauthenticatedPublicBind asserts ServeAdmin refuses to
// bind /metrics to a routable interface without a token.
func TestServeAdmin_RefusesUnauthenticatedPublicBind(t *testing.T) {
	s := newTestServer(t)
	if err := s.ServeAdmin(AdminConfig{Addr: "0.0.0.0:0"}); err == nil {
		t.Fatal("expected ServeAdmin to refuse a non-loopback bind without a metrics token")
	}
	// A loopback bind without a token is fine (won't actually listen here — we only
	// assert it doesn't pre-reject; use an ephemeral port and stop immediately is
	// awkward, so just check isLoopbackBind classification instead).
	if !isLoopbackBind("127.0.0.1:9090") || !isLoopbackBind("localhost:9090") || !isLoopbackBind("[::1]:9090") {
		t.Fatal("loopback binds misclassified")
	}
	if isLoopbackBind(":9090") || isLoopbackBind("0.0.0.0:9090") {
		t.Fatal("all-interface bind must NOT be treated as loopback")
	}
}

func TestReadyz_ReflectsReadiness(t *testing.T) {
	s := newTestServer(t)
	h := s.adminHandler("")

	r := doReq(h, "GET", "/readyz", "127.0.0.1:5555", "")
	if r.Code != http.StatusOK {
		t.Fatalf("/readyz after New = %d, want 200 (ready)", r.Code)
	}
	s.metrics.setReady(false)
	r2 := doReq(h, "GET", "/readyz", "127.0.0.1:5555", "")
	if r2.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz when draining = %d, want 503", r2.Code)
	}
}

// TestLogging_NoSecretLeak runs the structured logger through a lifecycle event
// carrying a name+account and asserts the token never appears. It relies on
// logFields having NO token field, but also checks the actual emitted JSON.
func TestLogging_NoSecretLeak(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	s := &Server{log: slog.New(h)}

	const secret = "SUPERSECRET-TOKEN-9f8e7d"
	// Simulate every lifecycle log the server emits, passing bounded fields only.
	s.logInfo("agent registered", logFields{Name: "box1", Account: "acct-42", Remote: "203.0.113.9"})
	s.logDebug("authorize failed", logFields{Name: "box1", Remote: "203.0.113.9", Reason: string(authFailUnauthorized)})
	s.logInfo("revoking live tunnel", logFields{Name: "box1", Account: "acct-42", Reason: string(cutRevocation)})

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked into logs:\n%s", out)
	}
	// Sanity: the intended (non-secret) fields DID make it through.
	if !strings.Contains(out, `"name":"box1"`) || !strings.Contains(out, `"account":"acct-42"`) {
		t.Fatalf("expected name/account fields in logs:\n%s", out)
	}
	// There must be no "token" key at all.
	if strings.Contains(out, `"token"`) {
		t.Fatalf("logs contain a token field:\n%s", out)
	}
}

// ---- helpers --------------------------------------------------------------

func doReq(h http.Handler, method, path, remoteAddr, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteAddr
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func readAll(resp *http.Response) string {
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			b.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return b.String()
}

// newTestServer builds a minimal server with an allow-all static token store,
// billing/CP disabled, and the revocation sweep off, suitable for the
// observability tests.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	s, err := New(Config{
		Domain:            "relay.test",
		Tokens:            store,
		RevokeSweepPeriod: -1, // disable sweep in tests
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	// Ensure the logger doesn't spew to stderr during tests.
	s.log = slog.New(slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError}))
	_ = context.Background()
	return s
}
