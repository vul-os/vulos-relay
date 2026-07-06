// revocation_sweep_test.go — WAVE42 adversarial regression tests for the
// WAVE41-RELAY-REVOCATION live-session sweep and its revocation-source union.
//
// The existing revocation_test.go exercises the revokedList and the entitlement
// gate in ISOLATION. These tests close the coverage gap that mattered most for a
// bypass: they prove that a REVOKE actually reaches and CUTS a live session in
// the registry (idle-but-live included), that the CP sticky-revoke cannot be
// un-revoked, that a manufactured transient CP error fails OPEN (bounded, not a
// bypass), and that the connect-race window for a stale CPTokenStore cache is
// bounded by the store TTL — not an unbounded bypass.
package server

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// liveSession spins up a genuine yamux session over an in-memory pipe and
// registers it, mirroring what handleControl builds. It returns the session and
// a channel that closes when the server-side mux dies (i.e. the sweep cut it).
// The peer end is a yamux server that just sits there (an idle-but-live agent).
func liveSession(t *testing.T, reg *registry, name, account, token string) (*session, <-chan struct{}) {
	t.Helper()
	cliConn, srvConn := net.Pipe()
	// Server side is the yamux CLIENT (matches control.go).
	mux, err := yamux.Client(cliConn, serverYamuxConfig())
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	// Peer (agent) side: a yamux server that just holds the connection open,
	// modelling an IDLE-but-live tunnel (no traffic, keepalive only).
	peer, err := yamux.Server(srvConn, serverYamuxConfig())
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	t.Cleanup(func() { peer.Close(); mux.Close() })

	sess := &session{
		name:      normalizeName(name),
		accountID: account,
		token:     token,
		mux:       mux,
		createdAt: time.Now(),
	}
	release, _, err := reg.add(sess)
	if err != nil {
		t.Fatalf("registry add: %v", err)
	}
	t.Cleanup(release)
	return sess, mux.CloseChan()
}

func waitClosed(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal(msg)
	}
}

func mustStayOpen(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal(msg)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestSweep_CutsLiveSessionOnRuntimeTokenRevoke is the end-to-end proof that a
// runtime static-token revoke actually reaches a LIVE (idle) session in the
// registry and tears its mux down. Before WAVE41 there was no path to cut a
// leaked static token's live tunnel without a restart.
func TestSweep_CutsLiveSessionOnRuntimeTokenRevoke(t *testing.T) {
	store, err := NewStaticTokenStore([]Grant{
		{Token: "tok-live", Names: []string{"live"}, AccountID: "acct-1"},
		{Token: "tok-leak", Names: []string{"leak"}, AccountID: "acct-2"},
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	s, err := New(Config{Domain: "relay.test", Tokens: store, RevokeSweepPeriod: -1}) // sweep loop off; drive manually
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	t.Cleanup(s.Close)

	_, liveClosed := liveSession(t, s.registry, "live", "acct-1", "tok-live")
	_, leakClosed := liveSession(t, s.registry, "leak", "acct-2", "tok-leak")

	// Nothing revoked yet: a manual sweep must cut NOTHING.
	s.sweepRevoked()
	mustStayOpen(t, liveClosed, "clean session must not be cut by a no-op sweep")
	mustStayOpen(t, leakClosed, "clean session must not be cut by a no-op sweep")

	// Operator revokes the leaked token at runtime (no restart). Server.RevokeToken
	// both records the revoke AND sweeps immediately.
	s.RevokeToken("tok-leak")
	waitClosed(t, leakClosed, "revoked token's LIVE tunnel must be cut promptly by the sweep")
	mustStayOpen(t, liveClosed, "a non-revoked session must survive the sweep")
}

// TestSweep_CutsOnStaticAccountAndName proves the sweep union honours account and
// name revokes (not just token) against live idle sessions, and never cuts a
// session that matches nothing.
func TestSweep_CutsOnStaticAccountAndName(t *testing.T) {
	store, err := NewStaticTokenStore([]Grant{
		{Token: "tok-a", Names: []string{"boxa"}, AccountID: "acct-a"},
		{Token: "tok-b", Names: []string{"boxb"}, AccountID: "acct-b"},
		{Token: "tok-c", Names: []string{"boxc"}, AccountID: "acct-c"},
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	s, err := New(Config{Domain: "relay.test", Tokens: store, RevokeSweepPeriod: -1})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	t.Cleanup(s.Close)

	_, aClosed := liveSession(t, s.registry, "boxa", "acct-a", "tok-a")
	_, bClosed := liveSession(t, s.registry, "boxb", "acct-b", "tok-b")
	_, cClosed := liveSession(t, s.registry, "boxc", "acct-c", "tok-c")

	// Revoke by ACCOUNT and by NAME; the third stays clean.
	s.RevokeAccount("acct-a")
	s.RevokeName("boxb")

	waitClosed(t, aClosed, "account-revoked live session must be cut")
	waitClosed(t, bClosed, "name-revoked live session must be cut")
	mustStayOpen(t, cClosed, "unrevoked live session must survive")
}

// TestSweep_CPStickyRevoke_CutsIdleLiveSession proves the CP revoked/404 signal,
// once observed (sticky), cuts a live session via the sweep union — and that a
// clean session is untouched.
func TestSweep_CPStickyRevoke_CutsIdleLiveSession(t *testing.T) {
	fake := newFakeCP("shh")
	fake.entByAccount["acct-cut"] = Entitlement{AccountID: "acct-cut", RelayAllowed: true}
	fake.entByAccount["acct-ok"] = Entitlement{AccountID: "acct-ok", RelayAllowed: true}
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}

	store, err := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"x"}, AccountID: "acct-x"}})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	s, err := New(Config{Domain: "relay.test", Tokens: store, CP: cp, GateTTL: 50 * time.Millisecond, RevokeSweepPeriod: -1})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	t.Cleanup(s.Close)

	_, cutClosed := liveSession(t, s.registry, "cutbox", "acct-cut", "")
	_, okClosed := liveSession(t, s.registry, "okbox", "acct-ok", "")

	// Prime both as allowed (connect-time gate populates the cache).
	if !s.gate.allowConnect("acct-cut") || !s.gate.allowConnect("acct-ok") {
		t.Fatal("both accounts should be allowed at connect")
	}
	s.sweepRevoked()
	mustStayOpen(t, cutClosed, "no revoke yet")
	mustStayOpen(t, okClosed, "no revoke yet")

	// CP now flags acct-cut revoked. Let the gate cache lapse so the sweep's poll
	// observes it (this models the documented "up to one gate TTL" latency).
	fake.mu.Lock()
	fake.entByAccount["acct-cut"] = Entitlement{AccountID: "acct-cut", RelayAllowed: true, Revoked: true}
	fake.mu.Unlock()
	time.Sleep(70 * time.Millisecond) // > GateTTL

	s.sweepRevoked()
	waitClosed(t, cutClosed, "CP-revoked account's live session must be cut by the sweep")
	mustStayOpen(t, okClosed, "a clean account's session must survive the sweep")
}

// TestSweep_ManufacturedTransientCP_FailsOpen is the vector-2 probe: an attacker
// who makes the CP look TRANSIENTLY broken (503) for an account that has NOT been
// observed-revoked must NOT be able to trip a false definitive revoke — and,
// symmetrically, such an error must not be treated as "revoked" so the sweep
// leaves the (as-yet-unrevoked) tunnel up. This is the intended fail-open posture;
// it is bounded by the CP eventually returning a real revoked/404, which IS
// sticky (see TestSweep_CPRevoke_StickyBeatsTransient below).
func TestSweep_ManufacturedTransientCP_FailsOpen(t *testing.T) {
	fake := newFakeCP("shh")
	fake.entByAccount["acct-t"] = Entitlement{AccountID: "acct-t", RelayAllowed: true}
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	g := newEntitlementGate(cp, 30*time.Millisecond)

	if !g.allowConnect("acct-t") {
		t.Fatal("account allowed at connect")
	}
	// Manufacture a transient error and let the cache lapse.
	fake.setEntErr(true)
	time.Sleep(50 * time.Millisecond)

	rs := revocationSource{static: noopRevoker{}, gate: g}
	if rs.revoked("", "anybox", "acct-t") {
		t.Fatal("a manufactured transient CP error must NOT be a definitive revoke (fail-open)")
	}
}

// TestSweep_CPRevoke_StickyBeatsTransient proves the sticky revoke wins: once the
// CP has definitively said revoked, a SUBSEQUENT manufactured transient error
// cannot un-stick it — so an attacker cannot rescue an already-revoked session by
// then DoSing the CP. This is what bounds the fail-open window to "until the first
// definitive revoke is observed", closing the indefinite-bypass concern.
func TestSweep_CPRevoke_StickyBeatsTransient(t *testing.T) {
	fake := newFakeCP("shh")
	fake.entByAccount["acct-s"] = Entitlement{AccountID: "acct-s", RelayAllowed: true, Revoked: true}
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	g := newEntitlementGate(cp, 30*time.Millisecond)
	rs := revocationSource{static: noopRevoker{}, gate: g}

	// First observation: definitive revoke (sticky in cache now).
	if !rs.revoked("", "b", "acct-s") {
		t.Fatal("CP revoked=true must be a definitive revoke")
	}
	// Attacker now DoSes the CP (503) and lets the cache lapse. The sticky bit must
	// keep reporting revoked so the sweep still cuts.
	fake.setEntErr(true)
	time.Sleep(50 * time.Millisecond)
	if !rs.revoked("", "b", "acct-s") {
		t.Fatal("a sticky CP revoke must survive a subsequent transient error (no rescue by DoSing the CP)")
	}
}

// TestConnectRace_StaleCPTokenCacheBounded quantifies the vector-5 window: a
// revoked install credential can ride a still-fresh CPTokenStore cache entry, but
// only up to the store TTL; once the entry lapses the next connect re-reads the CP
// and is refused. This confirms the window is BOUNDED by TTL (documented), not an
// unbounded bypass.
func TestConnectRace_StaleCPTokenCacheBounded(t *testing.T) {
	fake := newFakeCP("shh")
	fake.entByCred["cred"] = Entitlement{AccountID: "acct-9", RelayAllowed: true}
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "shh", PoPID: "pop-1"}
	ts := NewCPTokenStore(cp, 40*time.Millisecond)

	// Connect: validated + cached.
	if acct, err := ts.Authorize("cred", "box"); err != nil || acct != "acct-9" {
		t.Fatalf("initial authorize: acct=%q err=%v", acct, err)
	}
	// CP revokes the credential.
	fake.mu.Lock()
	fake.entByCred["cred"] = Entitlement{AccountID: "acct-9", RelayAllowed: true, Revoked: true}
	fake.mu.Unlock()

	// WITHIN the TTL the stale-cache reconnect is still admitted — this is the
	// bounded window, and it is exactly why the mid-session SWEEP exists to cut the
	// live tunnel independent of this connect cache.
	if _, err := ts.Authorize("cred", "box"); err != nil {
		t.Fatal("within TTL the cached mapping is (knowingly) still served — bounded window")
	}
	// AFTER the TTL lapses the connect must be refused (fresh CP read sees revoked).
	time.Sleep(60 * time.Millisecond)
	if _, err := ts.Authorize("cred", "box"); err == nil {
		t.Fatal("after the cache TTL lapses a revoked credential MUST be refused at connect")
	}
	// And the purge is real: the cache entry is gone, not merely expired.
	ts.mu.Lock()
	_, present := ts.cache[hashToken("cred")]
	ts.mu.Unlock()
	if present {
		t.Fatal("a definitive revoke must PURGE the cached mapping, not leave a stale entry")
	}
}

// TestRevokedList_NoWhitespaceCaseEvasion is the vector-3 probe: name matching is
// normalized (case/whitespace can't evade), and token matching is on the exact
// trimmed secret. Account matching is exact by design (the CP account id is an
// opaque server-issued token), which we pin here so a future change can't silently
// loosen it.
func TestRevokedList_NoWhitespaceCaseEvasion(t *testing.T) {
	rl := newRevokedList(RevokedSpec{
		Tokens:   []string{"  SECRET  "}, // trimmed to "SECRET" at construction
		Names:    []string{"  OldBox  "}, // normalized to "oldbox"
		Accounts: []string{"acct-9"},
	})
	// Name: case + surrounding whitespace must still match (both sides normalize).
	if !rl.IsRevoked("", "  OLDBOX  ", "") {
		t.Fatal("name match must survive case + whitespace (normalized both sides)")
	}
	// Token: the trimmed secret matches; an untrimmed presentation also matches
	// because IsRevoked trims the presented token too.
	if !rl.IsRevoked("  SECRET  ", "clean", "") {
		t.Fatal("token match must survive surrounding whitespace")
	}
	if !rl.IsRevoked("SECRET", "clean", "") {
		t.Fatal("token match must hit on the trimmed secret")
	}
	// A different-case token is a DIFFERENT secret (tokens are case-sensitive) — must
	// NOT match, so we don't accidentally broaden a secret.
	if rl.IsRevoked("secret", "clean", "") {
		t.Fatal("token compare must be case-SENSITIVE (a secret is exact)")
	}
	// Account is exact-match by design.
	if !rl.IsRevoked("", "clean", "acct-9") {
		t.Fatal("exact account must match")
	}
	if rl.IsRevoked("", "clean", "ACCT-9") {
		t.Fatal("account is an opaque exact id — must not case-fold")
	}
}
