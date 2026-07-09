package server

// RELAY-TOKEN-TTL tests: agent-token expiry + _PREVIOUS-style rotation.
//
// These cover the fail-closed TTL (an expired grant authorizes nothing), the
// dual-token rotation window (old + new token both authorize the same grant),
// the config-validation guards (conflicting expiry / previous==token / previous
// already bound elsewhere), and the live-session sweep cut (Expirer) so a token
// that expires WHILE its tunnel is live is dropped, not merely refused on
// reconnect.

import (
	"encoding/json"
	"testing"
	"time"
)

// newStoreAt builds a static store with a fixed clock for deterministic TTLs.
func newStoreAt(t *testing.T, now time.Time, grants []Grant) *staticTokenStore {
	t.Helper()
	ts, err := NewStaticTokenStore(grants)
	if err != nil {
		t.Fatalf("NewStaticTokenStore: %v", err)
	}
	st := ts.(*staticTokenStore)
	st.now = func() time.Time { return now }
	return st
}

// ── TTL: fail-closed on expiry ───────────────────────────────────────────────

func TestTTL_UnexpiredAuthorizes(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	st := newStoreAt(t, now, []Grant{{
		Token:     "tok",
		Names:     []string{"box1"},
		ExpiresAt: now.Add(time.Hour),
	}})
	if _, err := st.Authorize("tok", "box1"); err != nil {
		t.Fatalf("unexpired token should authorize: %v", err)
	}
}

func TestTTL_ExpiredFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	st := newStoreAt(t, now, []Grant{{
		Token:     "tok",
		Names:     []string{"box1"},
		ExpiresAt: now.Add(-time.Second), // already expired
	}})
	if _, err := st.Authorize("tok", "box1"); err == nil {
		t.Fatal("expired token must NOT authorize (fail-closed)")
	}
}

func TestTTL_ZeroExpiryNeverExpires(t *testing.T) {
	// The pre-TTL default: a grant with no expires_at authorizes regardless of clock.
	far := time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
	st := newStoreAt(t, far, []Grant{{Token: "tok", Names: []string{"box1"}}})
	if _, err := st.Authorize("tok", "box1"); err != nil {
		t.Fatalf("no-expiry token should always authorize: %v", err)
	}
}

func TestTTL_ExpiresExactlyAtBoundaryStillValid(t *testing.T) {
	// expired() uses After(), so at the exact expiry instant the grant is still valid;
	// it fails the moment the clock is strictly past it.
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	st := newStoreAt(t, now, []Grant{{Token: "tok", Names: []string{"box1"}, ExpiresAt: now}})
	if _, err := st.Authorize("tok", "box1"); err != nil {
		t.Fatalf("token at exact expiry boundary should still authorize: %v", err)
	}
	st.now = func() time.Time { return now.Add(time.Nanosecond) }
	if _, err := st.Authorize("tok", "box1"); err == nil {
		t.Fatal("token one tick past expiry must fail closed")
	}
}

// ── Rotation: _PREVIOUS-style dual token ─────────────────────────────────────

func TestRotation_BothTokensAuthorizeSameGrant(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	st := newStoreAt(t, now, []Grant{{
		Token:         "new-tok",
		PreviousToken: "old-tok",
		Names:         []string{"box1"},
		AccountID:     "acct-1",
	}})
	// New token authorizes.
	acct, err := st.Authorize("new-tok", "box1")
	if err != nil {
		t.Fatalf("new token should authorize: %v", err)
	}
	if acct != "acct-1" {
		t.Errorf("new token account: got %q want acct-1", acct)
	}
	// Old (previous) token authorizes the SAME grant (names + account).
	acct2, err := st.Authorize("old-tok", "box1")
	if err != nil {
		t.Fatalf("previous token should authorize during rotation window: %v", err)
	}
	if acct2 != "acct-1" {
		t.Errorf("previous token account: got %q want acct-1", acct2)
	}
}

func TestRotation_PreviousTokenInheritsExpiry(t *testing.T) {
	// The rotation predecessor shares the grant's TTL — it is not a bypass of expiry.
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	st := newStoreAt(t, now, []Grant{{
		Token:         "new-tok",
		PreviousToken: "old-tok",
		Names:         []string{"box1"},
		ExpiresAt:     now.Add(-time.Second),
	}})
	if _, err := st.Authorize("old-tok", "box1"); err == nil {
		t.Fatal("expired grant's previous_token must also fail closed")
	}
}

func TestRotation_PreviousEqualsTokenRejected(t *testing.T) {
	_, err := NewStaticTokenStore([]Grant{{
		Token:         "tok",
		PreviousToken: "tok",
		Names:         []string{"box1"},
	}})
	if err == nil {
		t.Fatal("previous_token == token must be a config error")
	}
}

func TestRotation_PreviousBoundToAnotherGrantRejected(t *testing.T) {
	// "shared" is grant A's current token AND grant B's previous_token → ambiguous.
	_, err := NewStaticTokenStore([]Grant{
		{Token: "shared", Names: []string{"boxa"}},
		{Token: "other", PreviousToken: "shared", Names: []string{"boxb"}},
	})
	if err == nil {
		t.Fatal("previous_token colliding with another grant's token must be refused")
	}
}

// ── Config validation ────────────────────────────────────────────────────────

func TestTTL_ConflictingExpiryRejected(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	_, err := NewStaticTokenStore([]Grant{
		{Token: "tok", Names: []string{"a"}, ExpiresAt: now.Add(time.Hour)},
		{Token: "tok", Names: []string{"b"}, ExpiresAt: now.Add(2 * time.Hour)},
	})
	if err == nil {
		t.Fatal("same token with conflicting expires_at must be refused")
	}
}

func TestTTL_MergedGrantsSameExpiryOK(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)
	ts, err := NewStaticTokenStore([]Grant{
		{Token: "tok", Names: []string{"a"}, ExpiresAt: exp},
		{Token: "tok", Names: []string{"b"}, ExpiresAt: exp},
	})
	if err != nil {
		t.Fatalf("same token, same expiry, different names should merge: %v", err)
	}
	st := ts.(*staticTokenStore)
	st.now = func() time.Time { return now }
	if _, err := st.Authorize("tok", "a"); err != nil {
		t.Errorf("merged grant name a should authorize: %v", err)
	}
	if _, err := st.Authorize("tok", "b"); err != nil {
		t.Errorf("merged grant name b should authorize: %v", err)
	}
}

// ── Expirer: live-session sweep ──────────────────────────────────────────────

func TestExpirer_TokenExpired(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	st := newStoreAt(t, now, []Grant{
		{Token: "live", Names: []string{"a"}, ExpiresAt: now.Add(time.Hour)},
		{Token: "dead", Names: []string{"b"}, ExpiresAt: now.Add(-time.Hour)},
		{Token: "forever", Names: []string{"c"}},
	})
	if st.TokenExpired("live") {
		t.Error("unexpired token reported expired")
	}
	if !st.TokenExpired("dead") {
		t.Error("expired token NOT reported expired (sweep would miss it)")
	}
	if st.TokenExpired("forever") {
		t.Error("no-expiry token reported expired")
	}
	if st.TokenExpired("unknown") {
		t.Error("unknown token reported expired")
	}
	// Previous token of an expired grant is also expired (sweep must cut it too).
	st2 := newStoreAt(t, now, []Grant{{
		Token: "new", PreviousToken: "old", Names: []string{"a"}, ExpiresAt: now.Add(-time.Hour),
	}})
	if !st2.TokenExpired("old") {
		t.Error("previous token of an expired grant must report expired")
	}
}

func TestExpirer_SweepCutsExpiredLiveTunnel(t *testing.T) {
	// The revocationSource the sweep uses must report an expired session's token as
	// "revoked" (a definitive cut) via the Expirer, even with no static list / gate.
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	st := newStoreAt(t, now, []Grant{{Token: "tok", Names: []string{"box1"}, ExpiresAt: now.Add(-time.Second)}})
	rs := revocationSource{static: st, expirer: st, gate: newEntitlementGate(nil, 0)}
	if !rs.revoked("tok", "box1", "") {
		t.Fatal("sweep must cut a live tunnel whose grant TTL has elapsed")
	}
	// A live (unexpired) token is not cut.
	st.now = func() time.Time { return now.Add(-time.Hour) }
	if rs.revoked("tok", "box1", "") {
		t.Fatal("sweep must NOT cut an unexpired live tunnel")
	}
}

// ── backward-compat: existing grants unaffected ──────────────────────────────

func TestTTL_ExistingGrantsUnchanged(t *testing.T) {
	// A grant with none of the new fields behaves exactly as before.
	ts, err := NewStaticTokenStore([]Grant{{Token: "tok", Names: []string{"box1"}, AccountID: "a"}})
	if err != nil {
		t.Fatalf("plain grant: %v", err)
	}
	st := ts.(*staticTokenStore)
	acct, err := st.Authorize("tok", "box1")
	if err != nil {
		t.Fatalf("plain grant should authorize: %v", err)
	}
	if acct != "a" {
		t.Errorf("account: got %q want a", acct)
	}
	if st.TokenExpired("tok") {
		t.Error("plain grant token must never be reported expired")
	}
}

// ── wire format: Grant JSON round-trips the new fields ───────────────────────

func TestGrantJSON_ParsesTTLAndRotation(t *testing.T) {
	raw := `[{"token":"NEW","previous_token":"OLD","names":["box1"],` +
		`"account_id":"acct-1","expires_at":"2026-12-31T00:00:00Z"}]`
	var grants []Grant
	if err := json.Unmarshal([]byte(raw), &grants); err != nil {
		t.Fatalf("parse grants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("grants: got %d want 1", len(grants))
	}
	g := grants[0]
	if g.Token != "NEW" || g.PreviousToken != "OLD" {
		t.Errorf("token/previous_token: got %q/%q", g.Token, g.PreviousToken)
	}
	if g.ExpiresAt.IsZero() {
		t.Error("expires_at did not parse")
	}
	// And the parsed grant builds a working store: both tokens authorize before expiry.
	ts, err := NewStaticTokenStore(grants)
	if err != nil {
		t.Fatalf("build store from parsed grant: %v", err)
	}
	st := ts.(*staticTokenStore)
	st.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := st.Authorize("NEW", "box1"); err != nil {
		t.Errorf("parsed new token should authorize: %v", err)
	}
	if _, err := st.Authorize("OLD", "box1"); err != nil {
		t.Errorf("parsed previous token should authorize: %v", err)
	}
}
