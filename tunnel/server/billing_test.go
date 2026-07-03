// billing_test.go — WAVE24-RELAY-BILLING unit tests for the account-aware token
// store, the CP client (entitlement + usage HMAC + idempotent report_id), the
// CPTokenStore (validate/resolve/fail-closed), the entitlement gate (connect
// fail-closed / mid-session fail-open), and the per-account meter deltas.
package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ── account-aware static token store ────────────────────────────────────────

func TestStaticTokenStore_ResolvesAccount(t *testing.T) {
	st, err := NewStaticTokenStore([]Grant{
		{Token: "tok-billed", Names: []string{"box1"}, AccountID: "acct-1"},
		{Token: "tok-unbilled", Names: []string{"box2"}},
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	acct, err := st.Authorize("tok-billed", "box1")
	if err != nil || acct != "acct-1" {
		t.Fatalf("billed: acct=%q err=%v", acct, err)
	}
	acct, err = st.Authorize("tok-unbilled", "box2")
	if err != nil || acct != "" {
		t.Fatalf("unbilled: acct=%q err=%v", acct, err)
	}
	if _, err := st.Authorize("tok-billed", "box2"); err == nil {
		t.Fatal("expected name-not-authorized error")
	}
	if _, err := st.Authorize("bogus", "box1"); err == nil {
		t.Fatal("expected unknown-token error")
	}
}

func TestStaticTokenStore_ConflictingAccount(t *testing.T) {
	_, err := NewStaticTokenStore([]Grant{
		{Token: "t", Names: []string{"a"}, AccountID: "acct-1"},
		{Token: "t", Names: []string{"b"}, AccountID: "acct-2"},
	})
	if err == nil {
		t.Fatal("expected conflicting account_id error")
	}
}

// ── fake CP ─────────────────────────────────────────────────────────────────

// fakeCP is an httptest server standing in for the Vulos control plane. It
// records posted usage reports (verifying the HMAC + dedup) and serves canned
// entitlements.
type fakeCP struct {
	secret string

	mu           sync.Mutex
	entByAccount map[string]Entitlement
	entByCred    map[string]Entitlement // Bearer credential → entitlement
	seenReports  map[string]bool        // report_id → seen (idempotency)
	byteTotals   map[string]int64       // account → accumulated bytes
	sessTotals   map[string]int         // account → accumulated sessions
	entErr       bool                   // when true, entitlement reads 503 (transient error)
}

func newFakeCP(secret string) *fakeCP {
	return &fakeCP{
		secret:       secret,
		entByAccount: map[string]Entitlement{},
		entByCred:    map[string]Entitlement{},
		seenReports:  map[string]bool{},
		byteTotals:   map[string]int64{},
		sessTotals:   map[string]int{},
	}
}

func (f *fakeCP) setEntErr(v bool) { f.mu.Lock(); f.entErr = v; f.mu.Unlock() }

func (f *fakeCP) totals(account string) (int64, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byteTotals[account], f.sessTotals[account]
}

func (f *fakeCP) server(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/relay/entitlement", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.entErr {
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		// Install credential (Bearer) path.
		if h := r.Header.Get("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
			cred := h[7:]
			ent, ok := f.entByCred[cred]
			if !ok {
				http.Error(w, "unknown", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(ent)
			return
		}
		// Service path.
		if r.Header.Get("X-Relay-Auth") != f.secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		acct := r.URL.Query().Get("account_id")
		ent, ok := f.entByAccount[acct]
		if !ok {
			ent = Entitlement{AccountID: acct, Tier: "free", RelayAllowed: false}
		}
		_ = json.NewEncoder(w).Encode(ent)
	})
	mux.HandleFunc("POST /api/relay/usage", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		// Verify the HMAC exactly as the real CP does.
		mac := hmac.New(sha256.New, []byte(f.secret))
		mac.Write(body)
		want := hex.EncodeToString(mac.Sum(nil))
		if r.Header.Get("X-Pop-Sig") != want {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		var env usageEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		// Idempotency: a replayed report_id is a no-op.
		if env.ReportID != "" && f.seenReports[env.ReportID] {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "applied": false})
			return
		}
		if env.ReportID != "" {
			f.seenReports[env.ReportID] = true
		}
		over := []string{}
		for _, it := range env.Items {
			f.byteTotals[it.AccountID] += it.Bytes
			f.sessTotals[it.AccountID] += it.Sessions
			if ent, ok := f.entByAccount[it.AccountID]; ok && ent.OverQuota {
				over = append(over, it.AccountID)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "applied": true, "over_quota": over})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ── CP client ───────────────────────────────────────────────────────────────

func TestCPClient_UsageHMACAndIdempotency(t *testing.T) {
	fake := newFakeCP("shh")
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}

	items := []usageItem{{AccountID: "acct-1", Bytes: 1234, Sessions: 3}}
	if _, err := cp.ReportUsage(context.Background(), "rid-1", items); err != nil {
		t.Fatalf("report: %v", err)
	}
	if b, s := fake.totals("acct-1"); b != 1234 || s != 3 {
		t.Fatalf("after first report: bytes=%d sessions=%d", b, s)
	}
	// Replay the SAME report_id → no-op (idempotent).
	if _, err := cp.ReportUsage(context.Background(), "rid-1", items); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if b, s := fake.totals("acct-1"); b != 1234 || s != 3 {
		t.Fatalf("replay must not double-count: bytes=%d sessions=%d", b, s)
	}
	// A new report_id DOES accumulate.
	if _, err := cp.ReportUsage(context.Background(), "rid-2", items); err != nil {
		t.Fatalf("report2: %v", err)
	}
	if b, _ := fake.totals("acct-1"); b != 2468 {
		t.Fatalf("second distinct report: bytes=%d want 2468", b)
	}
}

func TestCPClient_BadSecretRejected(t *testing.T) {
	fake := newFakeCP("right")
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "wrong", PoPID: "pop-1"}
	if _, err := cp.ReportUsage(context.Background(), "rid", []usageItem{{AccountID: "a", Bytes: 1}}); err == nil {
		t.Fatal("expected HMAC rejection with wrong secret")
	}
}

// ── CPTokenStore ────────────────────────────────────────────────────────────

func TestCPTokenStore_ResolvesAndFailsClosed(t *testing.T) {
	fake := newFakeCP("shh")
	fake.entByCred["cred-good"] = Entitlement{AccountID: "acct-7", Tier: "pro", RelayAllowed: true}
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	ts := NewCPTokenStore(cp, time.Second)

	acct, err := ts.Authorize("cred-good", "box1")
	if err != nil || acct != "acct-7" {
		t.Fatalf("good credential: acct=%q err=%v", acct, err)
	}
	// An unknown credential fails CLOSED.
	if _, err := ts.Authorize("cred-bad", "box1"); err == nil {
		t.Fatal("expected unknown credential to fail closed")
	}
	// A CP outage fails CLOSED at connect.
	fake.setEntErr(true)
	if _, err := ts.Authorize("cred-new", "box1"); err == nil {
		t.Fatal("expected CP outage to fail closed at connect")
	}
}

// ── entitlement gate ────────────────────────────────────────────────────────

func TestGate_ConnectFailClosed_ContinueFailOpen(t *testing.T) {
	fake := newFakeCP("shh")
	fake.entByAccount["ok"] = Entitlement{AccountID: "ok", RelayAllowed: true}
	fake.entByAccount["denied"] = Entitlement{AccountID: "denied", RelayAllowed: false}
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	g := newEntitlementGate(cp, time.Second)

	if !g.allowConnect("ok") {
		t.Fatal("allowed account should connect")
	}
	if g.allowConnect("denied") {
		t.Fatal("denied account must not connect")
	}
	// Empty account (unbilled) always allowed.
	if !g.allowConnect("") {
		t.Fatal("unbilled account should connect")
	}

	// Prime a good decision, then simulate a transient CP error and let TTL lapse.
	if !g.allowContinue("ok") {
		t.Fatal("primed ok should continue")
	}
	fake.setEntErr(true)
	time.Sleep(1100 * time.Millisecond) // expire the cached decision
	// Mid-session: fail OPEN using the stale good decision.
	if !g.allowContinue("ok") {
		t.Fatal("mid-session transient error must fail OPEN for a previously-allowed account")
	}
	// But a NEW account we never vetted, on connect, still fails closed.
	if g.allowConnect("never-seen") {
		t.Fatal("connect for an unvettable new account must fail closed")
	}
}

// ── meter deltas ────────────────────────────────────────────────────────────

func TestMeter_DrainDeltasAndFlush(t *testing.T) {
	fake := newFakeCP("shh")
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	m := newMeter(cp, time.Hour) // manual flush only

	m.addBytes("acct-1", 100)
	m.addBytes("acct-1", 50)
	m.addSession("acct-1")
	m.addBytes("acct-2", 700)

	m.flushOnce()
	if b, s := fake.totals("acct-1"); b != 150 || s != 1 {
		t.Fatalf("acct-1 flush: bytes=%d sessions=%d", b, s)
	}
	if b, _ := fake.totals("acct-2"); b != 700 {
		t.Fatalf("acct-2 flush: bytes=%d", b)
	}
	// A second flush with no new traffic sends nothing (deltas were drained).
	m.flushOnce()
	if b, _ := fake.totals("acct-1"); b != 150 {
		t.Fatalf("empty flush must not re-send: bytes=%d", b)
	}
	// New traffic after drain flushes only the new delta.
	m.addBytes("acct-1", 25)
	m.flushOnce()
	if b, _ := fake.totals("acct-1"); b != 175 {
		t.Fatalf("post-drain delta: bytes=%d want 175", b)
	}
}

func TestMeter_FlushFailureRetriesWithoutLoss(t *testing.T) {
	fake := newFakeCP("shh")
	srv := fake.server(t)
	// Wrong secret → CP rejects the flush; deltas must be restored and retried.
	cpBad := &CPClient{BaseURL: srv.URL, SharedSecret: "wrong", PoPID: "pop-1"}
	m := newMeter(cpBad, time.Hour)
	m.addBytes("acct-9", 500)
	m.flushOnce() // fails (bad HMAC)
	if b, _ := fake.totals("acct-9"); b != 0 {
		t.Fatalf("failed flush must not apply: bytes=%d", b)
	}
	// Swap in the correct secret and retry — the restored delta flushes.
	m.cp = &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	m.flushOnce()
	if b, _ := fake.totals("acct-9"); b != 500 {
		t.Fatalf("retry after fix should flush restored delta: bytes=%d", b)
	}
}
