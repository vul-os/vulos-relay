package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"strings"
	"sync"
	"time"
)

// revocation.go — WAVE41-RELAY-REVOCATION: token/credential revocation.
//
// Before this wave the token store was static + CP-resolved only, so a LEAKED
// agent token stayed valid until an operator hand-edited the grants file. This
// wave adds two revocation paths that are consulted BOTH at connect AND on a
// periodic recheck of every live session, so a revoked credential is refused on
// (re)connect and its live tunnel is dropped promptly:
//
//   1. STATIC revoked-list (this file): a file/env-driven set of revoked tokens,
//      names, and/or accounts. Honored by the static token store at connect and by
//      the revocation sweep for live sessions. Fail-closed: a match is a definitive
//      revoke.
//
//   2. CP path (see gate.go / cpclient.go): the relay already polls the CP's
//      entitlement endpoint. That response now carries `revoked:true`, and a CP
//      404 for a previously-valid credential is treated as a definitive revoke.
//      This reuses the existing entitlement poll — no new CP round trip.
//
// The connect posture stays fail-CLOSED and the mid-session posture stays
// fail-OPEN-on-transient-error (a CP blip must not cut a live tunnel). But a
// DEFINITIVE revoke (static-list match, or CP-observed revoked/404) cuts promptly,
// exactly like the WAVE34 over-quota cut — bounded, off the data path.

// Revoker answers "is this (token, name, account) definitively revoked right now?"
// It is consulted at connect and by the live-session revocation sweep. A true
// result is a DEFINITIVE revoke (fail-closed); it must NOT return true for a
// transient lookup error (that is fail-open territory, handled by the gate).
//
// A TokenStore MAY implement Revoker to contribute a static/local revoked-list.
// The staticTokenStore does. The CP revoked/404 path lives in the entitlement
// gate, not here, because it reuses the entitlement poll.
type Revoker interface {
	// IsRevoked reports whether the credential is definitively revoked. token is
	// the raw bearer secret; name is the normalized tunnel name; account is the
	// resolved account id ("" for unbilled). Any of the three matching a revoked
	// entry is a revoke.
	IsRevoked(token, name, account string) bool
}

// revokedList is a set of revoked credentials: raw tokens (matched by
// constant-time hash compare), tunnel names, and account ids. It is seeded from a
// file/env at construction and MAY also be extended at runtime (RevokeToken etc.)
// so an operator can revoke a leaked static token WITHOUT a config edit + restart
// — directly addressing the audit finding. Guarded by a mutex; reads and runtime
// revokes are both cheap and off the data path.
type revokedList struct {
	mu          sync.RWMutex
	tokenHashes map[[32]byte]struct{}
	names       map[string]struct{}
	accounts    map[string]struct{}
}

// RevokedSpec is the file/env shape of the static revoked-list. Every field is
// optional; a credential is revoked if ANY of its token, name, or account matches.
//
//	{"tokens":["LEAKED1"],"names":["oldbox"],"accounts":["acct-9"]}
type RevokedSpec struct {
	Tokens   []string `json:"tokens,omitempty"`
	Names    []string `json:"names,omitempty"`
	Accounts []string `json:"accounts,omitempty"`
}

// newRevokedList builds an immutable revoked-list from a spec. Blank entries are
// skipped. Names are normalized (so they compare equal to the store's names). An
// entirely empty spec yields a non-nil, always-false list (nothing revoked).
func newRevokedList(spec RevokedSpec) *revokedList {
	r := &revokedList{
		tokenHashes: make(map[[32]byte]struct{}),
		names:       make(map[string]struct{}),
		accounts:    make(map[string]struct{}),
	}
	for _, t := range spec.Tokens {
		if t = strings.TrimSpace(t); t != "" {
			r.tokenHashes[sha256.Sum256([]byte(t))] = struct{}{}
		}
	}
	for _, n := range spec.Names {
		if nn := normalizeName(n); nn != "" {
			r.names[nn] = struct{}{}
		}
	}
	for _, a := range spec.Accounts {
		if a = strings.TrimSpace(a); a != "" {
			r.accounts[a] = struct{}{}
		}
	}
	return r
}

// empty reports whether the list revokes nothing (lets callers skip work).
func (r *revokedList) empty() bool {
	if r == nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tokenHashes) == 0 && len(r.names) == 0 && len(r.accounts) == 0
}

// IsRevoked reports whether token/name/account matches any revoked entry. The
// token compare is constant-time over the whole set so timing does not reveal
// which (if any) token matched.
func (r *revokedList) IsRevoked(token, name, account string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.tokenHashes) == 0 && len(r.names) == 0 && len(r.accounts) == 0 {
		return false
	}
	if account != "" {
		if _, ok := r.accounts[account]; ok {
			return true
		}
	}
	if nn := normalizeName(name); nn != "" {
		if _, ok := r.names[nn]; ok {
			return true
		}
	}
	if tok := strings.TrimSpace(token); tok != "" && len(r.tokenHashes) > 0 {
		h := sha256.Sum256([]byte(tok))
		var hit int
		for kh := range r.tokenHashes {
			kh := kh
			if subtle.ConstantTimeCompare(h[:], kh[:]) == 1 {
				hit = 1
			}
		}
		if hit == 1 {
			return true
		}
	}
	return false
}

// revokeToken/revokeName/revokeAccount add a runtime revocation. These let an
// operator revoke a leaked static credential WITHOUT editing the config and
// restarting; the next connect is refused and the next sweep drops any live
// session. Idempotent and concurrency-safe.
func (r *revokedList) revokeToken(token string) {
	if token = strings.TrimSpace(token); token == "" {
		return
	}
	h := sha256.Sum256([]byte(token))
	r.mu.Lock()
	r.tokenHashes[h] = struct{}{}
	r.mu.Unlock()
}

func (r *revokedList) revokeName(name string) {
	nn := normalizeName(name)
	if nn == "" {
		return
	}
	r.mu.Lock()
	r.names[nn] = struct{}{}
	r.mu.Unlock()
}

func (r *revokedList) revokeAccount(account string) {
	if account = strings.TrimSpace(account); account == "" {
		return
	}
	r.mu.Lock()
	r.accounts[account] = struct{}{}
	r.mu.Unlock()
}

// ── revocation sweep coordination ───────────────────────────────────────────
//
// The Server runs a periodic sweep that rechecks every live session against the
// available revocation sources and drops any that are now definitively revoked.
// This is what makes a mid-session revoke cut promptly instead of surviving until
// the credential's cache/TTL naturally lapses. The recheck interval bounds the
// revocation latency (see the honest-limits note in the design doc).

// revocationSource is the union of revocation signals the sweep consults for one
// live session. It is fail-closed on a DEFINITIVE revoke and fail-open on a
// transient error (the gate distinguishes the two).
type revocationSource struct {
	static Revoker          // static revoked-list (may be nil / empty)
	gate   *entitlementGate // CP revoked/404 signal via the entitlement poll (may be disabled)
}

// revoked reports whether the given live session must be cut NOW. It returns true
// only for a DEFINITIVE revoke:
//   - a static revoked-list match (token/name/account), OR
//   - the CP entitlement poll definitively reporting the account revoked (or 404).
//
// A transient CP error is NOT a revoke (fail-open) — the gate's continueDecision
// handles that. An unbilled session (account "") with no static match is never
// revoked.
func (rs revocationSource) revoked(token, name, account string) bool {
	if rs.static != nil && rs.static.IsRevoked(token, name, account) {
		return true
	}
	if rs.gate.enabled() && account != "" {
		if rs.gate.definitivelyRevoked(account) {
			return true
		}
	}
	return false
}

// noopRevoker is a Revoker that never revokes (used when no static list is set,
// so callers need not nil-check).
type noopRevoker struct{}

func (noopRevoker) IsRevoked(string, string, string) bool { return false }

var _ Revoker = (*revokedList)(nil)
var _ Revoker = noopRevoker{}

// ── the live-session revocation sweep ───────────────────────────────────────

// startRevocationSweep launches the background loop that rechecks every live
// session against the revocation sources every revokePeriod and drops any that
// are now definitively revoked. It is a no-op when the period is 0 (disabled).
// The loop runs entirely off the data path.
func (s *Server) startRevocationSweep() {
	if s.revokePeriod <= 0 {
		return
	}
	s.revokeWG.Add(1)
	go func() {
		defer s.revokeWG.Done()
		t := time.NewTicker(s.revokePeriod)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.sweepRevoked()
			case <-s.revokeStop:
				return
			}
		}
	}()
}

// stopRevocationSweep stops the sweep loop. Safe to call once; safe if the sweep
// was never started (revokeStop is always allocated, the goroutine only exists
// when the period is > 0).
func (s *Server) stopRevocationSweep() {
	if s.revokePeriod <= 0 {
		return
	}
	close(s.revokeStop)
	s.revokeWG.Wait()
}

// sweepRevoked rechecks all live sessions and drops the revoked ones. It takes a
// registry snapshot so it never holds the registry lock while closing a mux (a
// close can block). Closing the mux tears down the control connection; the
// handleControl goroutine unblocks on mux.CloseChan and the deferred release()
// removes the session from the registry. A subsequent reconnect is refused at
// connect (Authorize / allowConnect see the revoke).
func (s *Server) sweepRevoked() {
	for _, sess := range s.registry.snapshot() {
		if s.revoke.revoked(sess.token, sess.name, sess.accountID) {
			log.Printf("relay: revoking live tunnel name=%q account=%q", sess.name, sess.accountID)
			sess.mux.Close()
		}
	}
}
