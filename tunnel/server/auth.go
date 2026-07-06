package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
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

// grantEntry is the stored per-token data: the allowed names + the linked account.
type grantEntry struct {
	names   map[string]struct{}
	account string
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
	byHash map[[32]byte]*grantEntry
	// revoked is the static revoked-list (never nil; empty => nothing revoked).
	revoked *revokedList
}

// NewStaticTokenStore builds a TokenStore from grants. Empty tokens/names are
// rejected at construction so a misconfigured relay fails closed rather than open.
//
// If the same token appears in multiple grants they are merged; a conflicting
// account_id across grants for the same token is an error (ambiguous billing).
func NewStaticTokenStore(grants []Grant) (TokenStore, error) {
	return NewStaticTokenStoreWithRevoked(grants, RevokedSpec{})
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
		for _, n := range g.Names {
			n = normalizeName(n)
			if n == "" {
				return nil, fmt.Errorf("grant %d: empty/invalid name", i)
			}
			entry.names[n] = struct{}{}
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
