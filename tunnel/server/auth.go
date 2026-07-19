package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"
)

// Grant is a single agent's authorization: a token, the exact set of names it is
// allowed to serve, and (WAVE24-RELAY-BILLING) the Vulos account the token is
// linked to. The server never lets an agent claim a name outside its grant, and
// never lets two live agents hold the same name at once.
type Grant struct {
	// Token is the bearer secret the agent presents. Compared in constant time.
	Token string `json:"token"`
	// Names is the set of names this token may serve. A name maps to
	// <name>.<relay-domain> (subdomain mode) and /t/<name>/ (path mode).
	Names []string `json:"names"`
	// AccountID (optional) is the Vulos account this token is linked to. When set,
	// the relay meters this token's traffic to that account and gates it against
	// the account's relay entitlement. Empty means "unbilled" (self-host with no
	// Vulos account) — traffic is served but not metered.
	AccountID string `json:"account_id,omitempty"`

	// RELAY-TOKEN-TTL: agent-token expiry + rotation.
	//
	// PreviousToken (optional) is the OLD bearer secret accepted DURING A ROTATION
	// WINDOW alongside Token — the relay-side mirror of the CP's
	// CP_SHARED_SECRET_PREVIOUS dual-key rotation. During a rotation the operator
	// puts the NEW secret on Token and keeps the OLD secret on PreviousToken; both
	// authorize the SAME grant (names/account/expiry), so an agent rolls to the new
	// token without a flag-day. Once the fleet is on the new token the operator
	// clears PreviousToken. Empty means "no rotation window" (Token only).
	PreviousToken string `json:"previous_token,omitempty"`

	// ExpiresAt (optional) is when this grant's tokens STOP authorizing. A zero
	// time means "no expiry" (the pre-TTL behavior — existing grants are
	// unaffected). A non-zero time in the PAST makes Authorize FAIL CLOSED for
	// every token in the grant: a leaked long-lived token can be given a bounded
	// lifetime so it self-revokes without a manual revoke. The check is against the
	// relay's wall clock at Authorize time.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// TokenStore validates a presented (token, name) pair and resolves the owning
// account. Implementations MUST use constant-time comparison and MUST fail closed.
type TokenStore interface {
	// Authorize returns the linked accountID (possibly "") if token is valid AND
	// authorized to serve name. It returns a non-nil error otherwise (never leaked
	// verbatim to clients). A "" accountID with a nil error means an authorized
	// but UNBILLED token (self-host, no Vulos account) — the caller serves it but
	// does not meter/gate it.
	Authorize(token, name string) (accountID string, err error)
}

// grantEntry is the stored per-token data: the allowed names, the linked account,
// and (RELAY-TOKEN-TTL) the grant's expiry. Both the current token hash AND a
// rotation PreviousToken hash point at the SAME grantEntry, so a rotation window
// authorizes identically under either token.
type grantEntry struct {
	names   map[string]struct{}
	account string
	// expiresAt is the grant TTL. Zero => never expires (pre-TTL behavior). A
	// non-zero time in the past makes Authorize fail closed.
	expiresAt time.Time
}

// expired reports whether the grant's TTL has elapsed as of now. A zero
// expiresAt means "no expiry" and never expires.
func (e *grantEntry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

// staticTokenStore is an in-memory store built from a fixed list of grants. It is
// the default (config-file / env driven) store for a self-hosted relay.
//
// WAVE41-RELAY-REVOCATION: it also carries an optional static revoked-list. A
// revoked token/name/account is refused at connect (in Authorize) and matched by
// the live-session revocation sweep (via the Revoker interface).
type staticTokenStore struct {
	// byHash maps sha256(token) -> grant entry. Hashing keeps raw tokens out of
	// the lookup map; the compare is still constant-time against the stored hash.
	// RELAY-TOKEN-TTL: a grant's PreviousToken hash is inserted here too, pointing
	// at the SAME entry, so a rotation window authorizes under either token.
	byHash map[[32]byte]*grantEntry
	// revoked is the static revoked-list (never nil; empty => nothing revoked).
	revoked *revokedList
	// now returns the current time; overridable in tests to exercise TTL expiry
	// deterministically. nil => time.Now.
	now func() time.Time
}

// clock returns the store's time source (time.Now unless overridden for tests).
func (s *staticTokenStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// NewStaticTokenStore builds a TokenStore from grants. Empty tokens/names are
// rejected at construction so a misconfigured relay fails closed rather than open.
//
// If the same token appears in multiple grants they are merged; a conflicting
// account_id across grants for the same token is an error (ambiguous billing).
func NewStaticTokenStore(grants []Grant) (TokenStore, error) {
	return NewStaticTokenStoreWithRevoked(grants, RevokedSpec{})
}

// NewDenyAllTokenStore returns a TokenStore that authorizes NOBODY.
//
// This is for a node that serves only the non-tunnel roles — rendezvous and/or
// pubcache — and therefore has no reverse tunnels to authorize. Such a node used
// to be unable to start at all: the static store refuses an empty grant set
// ("refusing to run open"), so operators invented a dummy token authorizing a box
// that did not exist. That is strictly worse than no grant — it is a live
// credential for a name nobody owns.
//
// This is the opposite of running open, and the distinction is the whole point:
// the empty-grant guard on the static store exists because an EMPTY MAP THERE
// would be an accident (a grants file that failed to parse into anything, a typo'd
// env var) on a relay whose job is tunnels. Here, authorizing nobody is the
// DELIBERATE, explicitly-named configuration. Every Authorize call fails closed.
func NewDenyAllTokenStore() TokenStore { return denyAllTokenStore{} }

// denyAllTokenStore implements TokenStore by refusing everything.
type denyAllTokenStore struct{}

func (denyAllTokenStore) Authorize(token, name string) (string, error) {
	return "", fmt.Errorf("relay: no agent grants configured (role-only node: the reverse-tunnel surface authorizes nobody)")
}

// NewStaticTokenStoreWithRevoked is NewStaticTokenStore plus a static revoked-list
// (WAVE41-RELAY-REVOCATION). A revoked token/name/account is refused at connect
// and dropped mid-session by the revocation sweep.
func NewStaticTokenStoreWithRevoked(grants []Grant, revoked RevokedSpec) (TokenStore, error) {
	s := &staticTokenStore{byHash: make(map[[32]byte]*grantEntry), revoked: newRevokedList(revoked)}
	for i, g := range grants {
		tok := strings.TrimSpace(g.Token)
		if tok == "" {
			return nil, fmt.Errorf("grant %d: empty token", i)
		}
		if len(g.Names) == 0 {
			return nil, fmt.Errorf("grant %d: no names authorized", i)
		}
		h := sha256.Sum256([]byte(tok))
		entry := s.byHash[h]
		if entry == nil {
			entry = &grantEntry{names: make(map[string]struct{}), account: strings.TrimSpace(g.AccountID)}
			s.byHash[h] = entry
		} else if acct := strings.TrimSpace(g.AccountID); acct != "" {
			if entry.account != "" && entry.account != acct {
				return nil, fmt.Errorf("grant %d: token bound to conflicting account_id", i)
			}
			entry.account = acct
		}
		// RELAY-TOKEN-TTL: record the grant expiry. If the same token appears in
		// multiple grants with conflicting non-zero expiries that is ambiguous
		// (which TTL governs?) — refuse rather than silently pick one. A zero
		// (no-expiry) alongside a non-zero is NOT a conflict; the explicit TTL wins
		// (fail-closed: an expiry set anywhere for the token is honored).
		if !g.ExpiresAt.IsZero() {
			if !entry.expiresAt.IsZero() && !entry.expiresAt.Equal(g.ExpiresAt) {
				return nil, fmt.Errorf("grant %d: token bound to conflicting expires_at", i)
			}
			entry.expiresAt = g.ExpiresAt
		}
		for _, n := range g.Names {
			n = normalizeName(n)
			if n == "" {
				return nil, fmt.Errorf("grant %d: empty/invalid name", i)
			}
			entry.names[n] = struct{}{}
		}
		// RELAY-TOKEN-TTL: rotation — the PreviousToken (if set) authorizes the SAME
		// grant during a rotation window (mirror of CP_SHARED_SECRET_PREVIOUS). Map
		// its hash to the SAME entry so names/account/expiry are identical. It must
		// differ from the current token (a grant rotating to itself is a config
		// error) and must not already be bound to a DIFFERENT grant entry.
		if prev := strings.TrimSpace(g.PreviousToken); prev != "" {
			if prev == tok {
				return nil, fmt.Errorf("grant %d: previous_token equals token", i)
			}
			ph := sha256.Sum256([]byte(prev))
			if existing := s.byHash[ph]; existing != nil && existing != entry {
				return nil, fmt.Errorf("grant %d: previous_token already bound to another grant", i)
			}
			s.byHash[ph] = entry
		}
	}
	if len(s.byHash) == 0 {
		return nil, fmt.Errorf("token store: no grants configured (refusing to run open)")
	}
	return s, nil
}

func (s *staticTokenStore) Authorize(token, name string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("empty token")
	}
	h := sha256.Sum256([]byte(token))
	// Constant-time membership: iterate all known hashes, compare each, so timing
	// does not reveal which (if any) token matched.
	var matched *grantEntry
	var found int
	for kh, entry := range s.byHash {
		if subtle.ConstantTimeCompare(h[:], kh[:]) == 1 {
			matched = entry
			found = 1
		}
	}
	if found == 0 {
		return "", fmt.Errorf("unknown token")
	}
	if _, ok := matched.names[normalizeName(name)]; !ok {
		return "", fmt.Errorf("token not authorized for name %q", name)
	}
	// RELAY-TOKEN-TTL: fail closed on an expired grant. A grant with a TTL that has
	// elapsed authorizes nothing — a leaked long-lived token self-revokes at its
	// expiry without a manual revoke. Zero expiry (the default) never expires.
	if matched.expired(s.clock()) {
		return "", fmt.Errorf("credential expired")
	}
	// WAVE41-RELAY-REVOCATION: refuse a revoked token/name/account at connect.
	if s.revoked.IsRevoked(token, name, matched.account) {
		return "", fmt.Errorf("credential revoked")
	}
	return matched.account, nil
}

// IsRevoked implements Revoker: reports whether token/name/account is in the
// static revoked-list. Used by the live-session revocation sweep.
func (s *staticTokenStore) IsRevoked(token, name, account string) bool {
	return s.revoked.IsRevoked(token, name, account)
}

// TokenExpired implements Expirer (RELAY-TOKEN-TTL): reports whether the grant
// matching token has a TTL that has already elapsed. Constant-time membership so
// timing does not reveal which token matched; an unknown token or a no-expiry
// grant returns false. Used by the live-session revocation sweep to cut a tunnel
// whose token expires mid-session.
func (s *staticTokenStore) TokenExpired(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	h := sha256.Sum256([]byte(token))
	var matched *grantEntry
	for kh, entry := range s.byHash {
		if subtle.ConstantTimeCompare(h[:], kh[:]) == 1 {
			matched = entry
		}
	}
	if matched == nil {
		return false
	}
	return matched.expired(s.clock())
}

// RevokeToken/RevokeName/RevokeAccount add a runtime revocation to the static
// store WITHOUT a config edit + restart — the operator-facing side of the audit
// fix. The next connect is refused and the next sweep drops any live session.
func (s *staticTokenStore) RevokeToken(token string)     { s.revoked.revokeToken(token) }
func (s *staticTokenStore) RevokeName(name string)       { s.revoked.revokeName(name) }
func (s *staticTokenStore) RevokeAccount(account string) { s.revoked.revokeAccount(account) }

// RuntimeRevoker is implemented by a token store that supports revoking a
// credential at runtime (the static store does). A management surface can type-
// assert Config.Tokens to this to revoke without a restart.
type RuntimeRevoker interface {
	RevokeToken(token string)
	RevokeName(name string)
	RevokeAccount(account string)
}

var _ Revoker = (*staticTokenStore)(nil)
var _ RuntimeRevoker = (*staticTokenStore)(nil)
var _ Expirer = (*staticTokenStore)(nil)

// normalizeName lowercases and validates a name to a DNS-label-ish safe subset so
// it can be a subdomain and a path segment. Returns "" if invalid.
func normalizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || len(name) > 63 {
		return ""
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return ""
		}
	}
	// No leading/trailing hyphen (valid DNS label).
	if name[0] == '-' || name[len(name)-1] == '-' {
		return ""
	}
	return name
}
