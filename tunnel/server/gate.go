package server

import (
	"context"
	"sync"
	"time"
)

// gate.go — WAVE24-RELAY-BILLING: the account relay-entitlement gate.
//
// Before serving a tunnel for a resolved account, the server checks the CP's
// GET /api/relay/entitlement (cached with a short TTL to avoid a CP round trip
// per connect). It refuses when relay_allowed=false or over_quota=true.
//
// Fail policy (matches the PoP's posture):
//   - CONNECT time: fail CLOSED. If entitlement is definitively denied
//     (relay_allowed=false / over_quota=true) the connect is refused. A transient
//     CP read error at connect also fails closed (we cannot admit an account we
//     cannot vet) UNLESS the operator runs in unbilled/self-host mode (no CP).
//   - MID-SESSION: fail OPEN. A transient CP read error for an already-connected
//     agent must not cut a live tunnel on a blip; the cached last-known decision
//     is used, and a hard "denied" is only acted on when the CP explicitly says so.

// gateDecision is a cached entitlement decision for an account.
type gateDecision struct {
	allowed   bool
	overQuota bool
	expires   time.Time
}

// entitlementGate caches per-account relay-entitlement decisions.
type entitlementGate struct {
	cp  *CPClient
	ttl time.Duration

	mu    sync.Mutex
	cache map[string]gateDecision
}

// newEntitlementGate builds a gate. A nil cp disables gating (self-host without
// a Vulos account) — every account is allowed and nothing is metered.
func newEntitlementGate(cp *CPClient, ttl time.Duration) *entitlementGate {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &entitlementGate{cp: cp, ttl: ttl, cache: make(map[string]gateDecision)}
}

func (g *entitlementGate) enabled() bool { return g != nil && g.cp != nil }

// allowConnect decides whether an account may open a new tunnel. Fail CLOSED: a
// definitive deny OR a transient CP error refuses the connect. An empty account
// (unbilled token) is always allowed.
func (g *entitlementGate) allowConnect(accountID string) bool {
	if !g.enabled() || accountID == "" {
		return true
	}
	d, ok := g.lookup(accountID)
	if !ok {
		// No fresh cached decision — must consult the CP. Fail closed on error.
		fresh, err := g.refresh(accountID)
		if err != nil {
			return false // connect-time: cannot vet ⇒ refuse
		}
		d = fresh
	}
	return d.allowed && !d.overQuota
}

// allowContinue decides whether an ALREADY-CONNECTED account may keep serving.
// Fail OPEN on a transient CP error (don't cut a live tunnel on a blip); only a
// definitive, freshly-observed deny cuts it.
func (g *entitlementGate) allowContinue(accountID string) bool {
	if !g.enabled() || accountID == "" {
		return true
	}
	d, ok := g.lookup(accountID)
	if !ok {
		fresh, err := g.refresh(accountID)
		if err != nil {
			// Mid-session blip: keep serving. Use the stale decision if we have one,
			// else optimistically allow.
			if stale, had := g.stale(accountID); had {
				return stale.allowed && !stale.overQuota
			}
			return true
		}
		d = fresh
	}
	return d.allowed && !d.overQuota
}

// lookup returns a fresh (unexpired) cached decision.
func (g *entitlementGate) lookup(accountID string) (gateDecision, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	d, ok := g.cache[accountID]
	if !ok || time.Now().After(d.expires) {
		return gateDecision{}, false
	}
	return d, true
}

// stale returns the last cached decision even if expired (for fail-open).
func (g *entitlementGate) stale(accountID string) (gateDecision, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	d, ok := g.cache[accountID]
	return d, ok
}

// refresh consults the CP and caches the result.
func (g *entitlementGate) refresh(accountID string) (gateDecision, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ent, err := g.cp.EntitlementForAccount(ctx, accountID)
	if err != nil {
		return gateDecision{}, err
	}
	d := gateDecision{allowed: ent.RelayAllowed, overQuota: ent.OverQuota, expires: time.Now().Add(g.ttl)}
	g.mu.Lock()
	g.cache[accountID] = d
	g.mu.Unlock()
	return d, nil
}

// markOverQuota lets the usage-report path push a fresh over-quota signal into
// the gate cache (the CP returns over-quota accounts on POST /api/relay/usage,
// mirroring the PoP). This makes an over-cap account get cut on its NEXT request
// without waiting for the TTL to expire.
func (g *entitlementGate) markOverQuota(accountID string) {
	if !g.enabled() || accountID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	d := g.cache[accountID]
	d.overQuota = true
	if d.expires.Before(time.Now()) {
		d.expires = time.Now().Add(g.ttl)
	}
	g.cache[accountID] = d
}
