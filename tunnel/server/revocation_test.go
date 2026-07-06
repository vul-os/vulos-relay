// revocation_test.go — WAVE41-RELAY-REVOCATION unit tests:
//   - the static revoked-list (token / name / account) and its wiring into the
//     static token store (refused at connect via Authorize; Revoker for the sweep),
//   - the CP revoked/404 path in the entitlement gate (definitive revoke cuts even
//     mid-session; a transient error does NOT revoke → fail-open),
//   - the CPTokenStore refusing a revoked credential at connect.
package server

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// hashToken mirrors the store's sha256 token key so a test can poke the cache.
func hashToken(tok string) [32]byte { return sha256.Sum256([]byte(tok)) }

// ── static revoked-list ─────────────────────────────────────────────────────

func TestRevokedList_MatchesTokenNameAccount(t *testing.T) {
	rl := newRevokedList(RevokedSpec{
		Tokens:   []string{"LEAKED"},
		Names:    []string{"OldBox"}, // normalized to "oldbox"
		Accounts: []string{"acct-9"},
	})
	cases := []struct {
		token, name, account string
		want                 bool
	}{
		{"LEAKED", "anybox", "acct-1", true},  // token match
		{"clean", "oldbox", "acct-1", true},   // name match (normalized)
		{"clean", "OLDBOX", "acct-1", true},   // name match (case-insensitive)
		{"clean", "livebox", "acct-9", true},  // account match
		{"clean", "livebox", "acct-1", false}, // nothing matches
		{"", "", "", false},                   // all empty
	}
	for _, c := range cases {
		if got := rl.IsRevoked(c.token, c.name, c.account); got != c.want {
			t.Errorf("IsRevoked(%q,%q,%q)=%v want %v", c.token, c.name, c.account, got, c.want)
		}
	}
}

func TestRevokedList_EmptyRevokesNothing(t *testing.T) {
	rl := newRevokedList(RevokedSpec{})
	if !rl.empty() {
		t.Fatal("empty spec should yield an empty list")
	}
	if rl.IsRevoked("anything", "anybox", "acct-1") {
		t.Fatal("empty revoked-list must revoke nothing")
	}
}

func TestStaticTokenStore_RefusesRevokedAtConnect(t *testing.T) {
	st, err := NewStaticTokenStoreWithRevoked(
		[]Grant{
			{Token: "tok-live", Names: []string{"live"}, AccountID: "acct-1"},
			{Token: "tok-dead", Names: []string{"dead"}, AccountID: "acct-2"},
		},
		RevokedSpec{Tokens: []string{"tok-dead"}},
	)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	// The live token authorizes normally.
	if acct, err := st.Authorize("tok-live", "live"); err != nil || acct != "acct-1" {
		t.Fatalf("live token: acct=%q err=%v", acct, err)
	}
	// The revoked token is refused at connect even though it is a valid grant.
	if _, err := st.Authorize("tok-dead", "dead"); err == nil {
		t.Fatal("revoked token must be refused at connect")
	}
	// The store implements Revoker so the sweep can recheck it mid-session.
	rv, ok := st.(Revoker)
	if !ok {
		t.Fatal("static store should implement Revoker")
	}
	if !rv.IsRevoked("tok-dead", "dead", "acct-2") {
		t.Fatal("Revoker should report the revoked token")
	}
	if rv.IsRevoked("tok-live", "live", "acct-1") {
		t.Fatal("Revoker must not report a live token")
	}
}

// ── CP revoked/404 path in the gate ─────────────────────────────────────────

func TestGate_DefinitiveRevoke_CutsEvenMidSession(t *testing.T) {
	fake := newFakeCP("shh")
	fake.entByAccount["acct-r"] = Entitlement{AccountID: "acct-r", RelayAllowed: true}
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	g := newEntitlementGate(cp, time.Hour) // long TTL: a stale "allowed" would linger

	// Prime an allowed decision (connect succeeded).
	if !g.allowConnect("acct-r") {
		t.Fatal("allowed account should connect")
	}
	if g.definitivelyRevoked("acct-r") {
		t.Fatal("account is not revoked yet")
	}

	// The CP now flags the account revoked=true. Because the gate has a fresh cached
	// "allowed" decision, the sweep forces a fresh read by observing a definitive
	// revoke only once the cache lapses — so drop the cache to model the sweep's
	// next poll after TTL. Here we set revoked directly at the CP and expire the
	// cache to force a re-read.
	fake.mu.Lock()
	fake.entByAccount["acct-r"] = Entitlement{AccountID: "acct-r", RelayAllowed: true, Revoked: true}
	fake.mu.Unlock()
	g.mu.Lock()
	delete(g.cache, "acct-r") // force the next lookup to re-read the CP
	g.mu.Unlock()

	if !g.definitivelyRevoked("acct-r") {
		t.Fatal("CP revoked=true must be a definitive revoke")
	}
	// And it is sticky + cuts mid-session (allowContinue now false). The revoke is
	// now cached; it must keep cutting.
	if g.allowContinue("acct-r") {
		t.Fatal("revoked account must be cut mid-session (fail-closed on definitive revoke)")
	}
	// Sticky: even if the CP later reads clean, a cache refresh must NOT un-revoke.
	// Flip the CP clean and force a re-read through refresh; the sticky bit wins.
	fake.mu.Lock()
	fake.entByAccount["acct-r"] = Entitlement{AccountID: "acct-r", RelayAllowed: true, Revoked: false}
	fake.mu.Unlock()
	if _, err := g.refresh("acct-r"); err != nil {
		t.Fatalf("refresh after clean read: %v", err)
	}
	if g.allowContinue("acct-r") {
		t.Fatal("a definitive revoke must stay sticky across a later clean CP read")
	}
}

func TestGate_Transient404VsError_FailOpenNotRevoke(t *testing.T) {
	fake := newFakeCP("shh")
	fake.entByAccount["acct-ok"] = Entitlement{AccountID: "acct-ok", RelayAllowed: true}
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	g := newEntitlementGate(cp, 200*time.Millisecond)

	// Prime a good decision.
	if !g.allowContinue("acct-ok") {
		t.Fatal("primed ok should continue")
	}
	// Simulate a transient CP error (503) and let the cached decision lapse.
	fake.setEntErr(true)
	time.Sleep(250 * time.Millisecond)
	// A transient error must NOT be reported as a definitive revoke (fail-open).
	if g.definitivelyRevoked("acct-ok") {
		t.Fatal("a transient CP error must NOT be treated as a revoke")
	}
	// And the live tunnel keeps serving (fail-open using the stale good decision).
	if !g.allowContinue("acct-ok") {
		t.Fatal("a transient CP error mid-session must fail OPEN")
	}
}

func TestGate_CP404_IsDefinitiveRevoke(t *testing.T) {
	// A CP that answers 404 for the account's entitlement is a definitive revoke
	// (the credential/account no longer exists), distinct from a 5xx blip.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/relay/entitlement", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	cp := &CPClient{BaseURL: ts.URL, SharedSecret: "shh", PoPID: "pop-1"}
	g := newEntitlementGate(cp, time.Hour)

	if !g.definitivelyRevoked("acct-404") {
		t.Fatal("a CP 404 must be a definitive revoke")
	}
	if g.allowConnect("acct-404") {
		t.Fatal("a CP 404 must refuse the connect (fail-closed)")
	}
}

// ── CPTokenStore refuses a revoked credential at connect ─────────────────────

func TestCPTokenStore_RefusesRevokedCredential(t *testing.T) {
	fake := newFakeCP("shh")
	fake.entByCred["cred-live"] = Entitlement{AccountID: "acct-7", RelayAllowed: true}
	fake.entByCred["cred-revoked"] = Entitlement{AccountID: "acct-8", RelayAllowed: true, Revoked: true}
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	ts := NewCPTokenStore(cp, time.Hour)

	// A good credential resolves and caches.
	if acct, err := ts.Authorize("cred-live", "box1"); err != nil || acct != "acct-7" {
		t.Fatalf("live credential: acct=%q err=%v", acct, err)
	}
	// A revoked credential is refused at connect.
	if _, err := ts.Authorize("cred-revoked", "box2"); err == nil {
		t.Fatal("a revoked credential must be refused at connect")
	}
	// A credential that first validated then goes revoked is purged from the cache
	// so it cannot ride a stale entry: seed the cache good, then flip to revoked.
	if _, err := ts.Authorize("cred-live", "box1"); err != nil {
		t.Fatalf("re-authorize live (cached): %v", err)
	}
	fake.mu.Lock()
	fake.entByCred["cred-live"] = Entitlement{AccountID: "acct-7", RelayAllowed: true, Revoked: true}
	fake.mu.Unlock()
	// Force a fresh CP read by expiring the cache entry, then confirm it is refused.
	h := hashToken("cred-live")
	ts.mu.Lock()
	ts.cache[h] = cpTokenCacheEntry{account: "acct-7", expires: time.Now().Add(-time.Second)}
	ts.mu.Unlock()
	if _, err := ts.Authorize("cred-live", "box1"); err == nil {
		t.Fatal("a credential that went revoked must be refused once the cache lapses")
	}
}
