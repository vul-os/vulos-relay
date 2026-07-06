// revocation_e2e_test.go — WAVE41-RELAY-REVOCATION end-to-end: a real agent
// tunnels through a real relay; a revoked credential's LIVE tunnel is dropped by
// the revocation sweep and a reconnect is refused. Covers both paths:
//
//   - STATIC revoked-list: a revoked static token is refused at connect AND its
//     live session is dropped on the next sweep.
//   - CP path: an install credential whose CP entitlement flips to revoked/404 has
//     its live tunnel dropped promptly; a TRANSIENT CP error does NOT revoke
//     (fail-open); a non-revoked account is unaffected.
package tunnel_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
	"github.com/vul-os/vulos-relay/tunnel/server"
)

// ── static revoked-list E2E ─────────────────────────────────────────────────

// newRevocableRelay stands up a relay with a static revoked-list and a fast
// revocation sweep so the test does not wait long for the live-session drop. It
// returns both the httptest server (for URLs) and the *server.Server (for the
// runtime Revoke* API).
func newRevocableRelay(t *testing.T, grants []server.Grant, revoked server.RevokedSpec, sweep time.Duration) (*httptest.Server, *server.Server) {
	t.Helper()
	store, err := server.NewStaticTokenStoreWithRevoked(grants, revoked)
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	srv, err := server.New(server.Config{
		Domain:             testDomain,
		Tokens:             store,
		EnablePathMode:     true,
		MaxAgents:          4,
		MaxStreamsPerAgent: 4,
		RevokeSweepPeriod:  sweep,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts, srv
}

func TestRevocation_E2E_StaticToken_RefusedAtConnect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// The token is a valid grant but is on the revoked-list.
	relay, _ := newRevocableRelay(t,
		[]server.Grant{{Token: testToken, Names: []string{testName}}},
		server.RevokedSpec{Tokens: []string{testToken}},
		time.Hour, // sweep irrelevant here — connect must be refused outright
	)

	a := agent.New(agent.Options{
		ServerURL: relay.URL, Token: testToken, Name: testName, LocalAddr: localAddr(target.URL),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = a.Start(ctx)
	defer a.Stop()

	// A revoked token must never reach Connected.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if a.Snapshot().Status == agent.StatusConnected {
			t.Fatal("agent connected despite a revoked token")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRevocation_E2E_StaticToken_LiveSessionDroppedOnRecheck(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// Start with a CLEAN grant (nothing revoked) so the tunnel comes UP, then revoke
	// the token at runtime — modelling a leaked token being revoked WHILE live. The
	// revocation sweep must drop the live session, and a reconnect must be refused.
	relay, srv := newRevocableRelay(t,
		[]server.Grant{{Token: testToken, Names: []string{testName}}},
		server.RevokedSpec{}, // clean at connect
		50*time.Millisecond,  // fast sweep
	)

	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)
	waitAgents(t, 1, srv.AgentCount)

	// The tunnel serves normally before revocation.
	if resp, _ := getViaPath(t, relay.URL, testName, "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke request should succeed; status=%d", resp.StatusCode)
	}

	// Revoke the (leaked) token at runtime — no config edit, no restart. This drops
	// the live session immediately (RevokeToken triggers a sweep) and the agent's
	// reconnect is then refused at connect.
	srv.RevokeToken(testToken)

	// The live session is dropped.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.AgentCount() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if srv.AgentCount() != 0 {
		t.Fatalf("revoked token's live session was NOT dropped (agents=%d)", srv.AgentCount())
	}

	// A public request now finds no live tunnel.
	if resp, _ := getViaPath(t, relay.URL, testName, "/"); resp.StatusCode == http.StatusOK {
		t.Fatal("a revoked tunnel must not keep serving")
	}

	// The agent will keep retrying; it must NOT re-establish (connect is refused).
	time.Sleep(700 * time.Millisecond)
	if srv.AgentCount() != 0 {
		t.Fatalf("revoked token reconnected (agents=%d); connect must stay refused", srv.AgentCount())
	}
}

// ── CP path E2E: live drop, transient fail-open, non-revoked unaffected ──────

// revocableCP is a fake CP whose per-account entitlement can be flipped to
// revoked or to a transient error at runtime, so the test can bring a tunnel UP
// (clean) and THEN revoke it, exercising the live-session sweep.
type revocableCP struct {
	secret string
	mu     sync.Mutex
	allow  map[string]bool // account → relay_allowed (clean state)
	revoke map[string]bool // account → revoked=true
	errOn  map[string]bool // account → return 503 (transient)
}

func (f *revocableCP) setRevoked(acct string, v bool) { f.mu.Lock(); f.revoke[acct] = v; f.mu.Unlock() }
func (f *revocableCP) setErr(acct string, v bool)     { f.mu.Lock(); f.errOn[acct] = v; f.mu.Unlock() }

func (f *revocableCP) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/relay/entitlement", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Relay-Auth") != f.secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		acct := r.URL.Query().Get("account_id")
		f.mu.Lock()
		allowed, revoked, transient := f.allow[acct], f.revoke[acct], f.errOn[acct]
		f.mu.Unlock()
		if transient {
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"account_id": acct, "tier": "pro",
			"relay_allowed": allowed, "over_quota": false, "revoked": revoked,
			"byte_cap": int64(1) << 40, "turn_cap": 1000,
		})
	})
	// Usage endpoint: accept + no-op (metering is not under test here).
	mux.HandleFunc("POST /api/relay/usage", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "over_quota": []string{}})
	})
	return mux
}

// newCPRevocableRelay wires a relay to a revocableCP with a short gate TTL (so a
// flipped entitlement is observed quickly) and a fast revocation sweep.
func newCPRevocableRelay(t *testing.T, cp *server.CPClient, grants []server.Grant, gateTTL, sweep time.Duration) (*httptest.Server, *server.Server) {
	t.Helper()
	store, err := server.NewStaticTokenStore(grants)
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	srv, err := server.New(server.Config{
		Domain:             testDomain,
		Tokens:             store,
		EnablePathMode:     true,
		MaxAgents:          4,
		MaxStreamsPerAgent: 4,
		CP:                 cp,
		GateTTL:            gateTTL,
		MeterFlushPeriod:   time.Hour, // keep metering out of the way
		RevokeSweepPeriod:  sweep,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts, srv
}

func TestRevocation_E2E_CPCredential_LiveTunnelDroppedPromptly(t *testing.T) {
	const secret = "rev-secret"
	fake := &revocableCP{
		secret: secret,
		allow:  map[string]bool{"acct-live": true},
		revoke: map[string]bool{},
		errOn:  map[string]bool{},
	}
	cpSrv := httptest.NewServer(fake.handler())
	defer cpSrv.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	cp := &server.CPClient{BaseURL: cpSrv.URL, SharedSecret: secret, PoPID: "pop-rev"}
	relay, srv := newCPRevocableRelay(t, cp,
		[]server.Grant{{Token: testToken, Names: []string{testName}, AccountID: "acct-live"}},
		150*time.Millisecond, // gate TTL: revoke observed within a TTL
		100*time.Millisecond, // sweep: drop within a sweep period
	)

	// Bring the tunnel UP (clean entitlement).
	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)
	waitAgents(t, 1, srv.AgentCount)

	// Flip the account to revoked at the CP. The gate poll observes it within a TTL
	// and the sweep drops the live tunnel within a sweep period.
	fake.setRevoked("acct-live", true)

	// The live agent should be dropped promptly (well under a couple of seconds).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.AgentCount() == 0 {
			return // live tunnel cut by the sweep
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("revoked live tunnel was NOT dropped (agents=%d)", srv.AgentCount())
}

func TestRevocation_E2E_TransientCPError_DoesNotRevoke(t *testing.T) {
	const secret = "rev-secret"
	fake := &revocableCP{
		secret: secret,
		allow:  map[string]bool{"acct-ok": true},
		revoke: map[string]bool{},
		errOn:  map[string]bool{},
	}
	cpSrv := httptest.NewServer(fake.handler())
	defer cpSrv.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	cp := &server.CPClient{BaseURL: cpSrv.URL, SharedSecret: secret, PoPID: "pop-rev"}
	relay, srv := newCPRevocableRelay(t, cp,
		[]server.Grant{{Token: testToken, Names: []string{testName}, AccountID: "acct-ok"}},
		150*time.Millisecond,
		100*time.Millisecond,
	)

	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)
	waitAgents(t, 1, srv.AgentCount)

	// Simulate a TRANSIENT CP error (503) for a while. Fail-OPEN: the live tunnel
	// must stay up (a blip is not a revoke).
	fake.setErr("acct-ok", true)

	// Give several sweep + gate-TTL cycles to elapse; the tunnel must survive.
	time.Sleep(1200 * time.Millisecond)
	if got := srv.AgentCount(); got != 1 {
		t.Fatalf("transient CP error must NOT drop a live tunnel (agents=%d, want 1)", got)
	}

	// Recovery: CP heals and stays clean; the tunnel is still up.
	fake.setErr("acct-ok", false)
	time.Sleep(300 * time.Millisecond)
	if got := srv.AgentCount(); got != 1 {
		t.Fatalf("tunnel should remain up after CP recovers (agents=%d, want 1)", got)
	}
}

func TestRevocation_E2E_NonRevokedUnaffected(t *testing.T) {
	const secret = "rev-secret"
	fake := &revocableCP{
		secret: secret,
		allow:  map[string]bool{"acct-a": true, "acct-b": true},
		revoke: map[string]bool{},
		errOn:  map[string]bool{},
	}
	cpSrv := httptest.NewServer(fake.handler())
	defer cpSrv.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	cp := &server.CPClient{BaseURL: cpSrv.URL, SharedSecret: secret, PoPID: "pop-rev"}
	relay, srv := newCPRevocableRelay(t, cp,
		[]server.Grant{
			{Token: "tok-a", Names: []string{"boxa"}, AccountID: "acct-a"},
			{Token: "tok-b", Names: []string{"boxb"}, AccountID: "acct-b"},
		},
		150*time.Millisecond,
		100*time.Millisecond,
	)

	aa := startAgent(t, relay.URL, "tok-a", "boxa", localAddr(target.URL))
	ab := startAgent(t, relay.URL, "tok-b", "boxb", localAddr(target.URL))
	waitConnected(t, aa)
	waitConnected(t, ab)
	waitAgents(t, 2, srv.AgentCount)

	// Revoke ONLY acct-a. acct-b must be unaffected.
	fake.setRevoked("acct-a", true)

	// Wait for acct-a's tunnel to drop.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.AgentCount() == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := srv.AgentCount(); got != 1 {
		t.Fatalf("exactly one tunnel (acct-a) should have dropped; agents=%d", got)
	}
	// acct-b's agent is still connected and can still serve.
	if ab.Snapshot().Status != agent.StatusConnected {
		t.Fatal("non-revoked acct-b agent must remain connected")
	}
	resp, _ := getViaPath(t, relay.URL, "boxb", "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("non-revoked tunnel must still serve; status=%d", resp.StatusCode)
	}
}
