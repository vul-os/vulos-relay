// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// accountState holds per-account metrics tracked by CappedPolicy.
type accountState struct {
	// Daily cap tracking.
	dayStart  time.Time
	sentToday int

	// reserved counts gate-time reservations awaiting a RecordResult
	// reconciliation.  Each CheckSend that returns Allow=true increments both
	// sentToday and reserved; RecordResult decrements reserved and, for
	// transient (deferred) outcomes that will be retried, also decrements
	// sentToday to release the quota.
	reserved int

	// Suspension.
	suspended bool
	suspendAt time.Time

	// Rolling bounce-rate window.  We track the last windowSize results as
	// a simple circular buffer of booleans (true = bounced/complaint).
	results    []bool
	resultHead int

	// cleanDelivered is the lifetime count of delivered messages (used to
	// derive the account's trust tier for warm-IP gating). It is not reset at
	// the day boundary — trust accrues over the account's history.
	cleanDelivered int

	// Explicit suspension reason (set by Suspend).
	suspendReason string
}

// CappedPolicy is a Policy that enforces a per-account daily send cap and
// suspends accounts whose rolling bounce or complaint rate exceeds a threshold.
//
// It is designed for simple self-hosted deployments.  Vulos's tenant-aware
// policy is an external implementation; this one is bundled as a reference.
type CappedPolicy struct {
	mu sync.Mutex

	// DailyCap is the maximum messages an account may send per calendar day
	// (UTC).  Default: 1000.
	DailyCap int

	// BounceThreshold is the rolling bounce+complaint rate above which an
	// account is suspended (0.0–1.0).  Default: 0.10.
	BounceThreshold float64

	// WindowSize is the number of recent results used to compute the rolling
	// bounce rate.  Default: 100.
	WindowSize int

	// EstablishedThreshold is the lifetime clean-delivery count at or above
	// which an account is promoted to AccountTrustEstablished (warm-IP
	// eligible). 0 → use the package default (200).
	EstablishedThreshold int

	accounts map[string]*accountState
}

// NewCappedPolicy creates a CappedPolicy with sensible defaults.
func NewCappedPolicy() *CappedPolicy {
	return &CappedPolicy{
		DailyCap:        1000,
		BounceThreshold: 0.10,
		WindowSize:      100,
		accounts:        make(map[string]*accountState),
	}
}

func (p *CappedPolicy) account(id string) *accountState {
	a, ok := p.accounts[id]
	if !ok {
		a = &accountState{
			dayStart: utcDayStart(time.Now()),
			results:  make([]bool, p.WindowSize),
		}
		p.accounts[id] = a
	}
	return a
}

func (p *CappedPolicy) dailyCap() int {
	if p.DailyCap <= 0 {
		return 1000
	}
	return p.DailyCap
}

func (p *CappedPolicy) windowSize() int {
	if p.WindowSize <= 0 {
		return 100
	}
	return p.WindowSize
}

func (p *CappedPolicy) bounceThreshold() float64 {
	if p.BounceThreshold <= 0 {
		return 0.10
	}
	return p.BounceThreshold
}

// CheckSend implements Policy.
func (p *CappedPolicy) CheckSend(_ context.Context, accountID string, _ Message) (Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	a := p.account(accountID)

	if a.suspended {
		return Decision{Allow: false, Reason: a.suspendReason}, ErrSuspended
	}

	// Roll the day counter if we've crossed midnight UTC.
	now := time.Now().UTC()
	if now.Before(a.dayStart) || now.Sub(a.dayStart) >= 24*time.Hour {
		a.dayStart = utcDayStart(now)
		a.sentToday = 0
		a.reserved = 0
	}

	cap := p.dailyCap()
	if a.sentToday >= cap {
		tomorrow := a.dayStart.Add(24 * time.Hour)
		return Decision{
			Allow:      false,
			Reason:     fmt.Sprintf("daily cap %d reached", cap),
			DelayUntil: &tomorrow,
		}, ErrRateLimited
	}

	// Reserve a slot at the gate (atomically, under p.mu) so concurrent workers
	// cannot all pass the check before any of them records a result.  The slot
	// is released by RecordResult when the attempt ends in a non-counting state
	// (deferred), or kept when the send is delivered/bounced.  Tracking the
	// reservation count separately lets RecordResult reconcile precisely.
	a.sentToday++
	a.reserved++

	return Decision{Allow: true, Reason: "within cap"}, nil
}

// RecordResult implements Policy.
func (p *CappedPolicy) RecordResult(_ context.Context, accountID string, result SendResult) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	a := p.account(accountID)

	// Reconcile the gate-time reservation.  The slot was already counted against
	// sentToday in CheckSend; here we either keep it (terminal outcome consumed
	// the quota) or release it (transient deferral that will be retried).
	if a.reserved > 0 {
		a.reserved--
		if result.State == SendDeferred {
			// Transient failure → the message will be retried and re-gated,
			// so release the reserved slot to avoid permanently burning quota.
			if a.sentToday > 0 {
				a.sentToday--
			}
		}
	} else if result.State == SendDelivered || result.State == SendBounced {
		// No outstanding reservation (e.g. a result recorded without a prior
		// CheckSend, as in unit tests or out-of-band sends) — count it directly
		// so the cap still reflects real volume.
		a.sentToday++
	}

	// Accrue trust on a clean delivery (lifetime; not reset daily).
	if result.State == SendDelivered {
		a.cleanDelivered++
	}

	// Record in the rolling window.
	isBad := result.State == SendBounced || result.State == SendComplaint
	ws := p.windowSize()
	// Grow window slice if needed (e.g. if WindowSize was changed).
	for len(a.results) < ws {
		a.results = append(a.results, false)
	}
	a.results[a.resultHead%ws] = isBad
	a.resultHead++

	// Compute current rate over the filled portion of the window.
	filled := a.resultHead
	if filled > ws {
		filled = ws
	}
	bad := 0
	for i := 0; i < filled; i++ {
		if a.results[i] {
			bad++
		}
	}
	rate := float64(bad) / float64(filled)
	if rate > p.bounceThreshold() {
		a.suspended = true
		a.suspendReason = fmt.Sprintf("bounce/complaint rate %.2f exceeds threshold %.2f", rate, p.bounceThreshold())
	}

	return nil
}

// AccountTrust classifies an account's trust/reputation tier as observed by
// CappedPolicy. It is the read side of the trust-gating that the warm-IP pool
// depends on: a new or suspended account is cold, an account that has begun
// sending cleanly is warming, and an account with enough clean volume is
// established. The numeric values match sending.TrustTier so the cmd wiring
// can map across the package boundary without an import cycle.
type AccountTrust int

const (
	// AccountTrustNew is a freshly-seen or suspended account.
	AccountTrustNew AccountTrust = iota
	// AccountTrustUntrusted is an account warming up (some clean volume).
	AccountTrustUntrusted
	// AccountTrustEstablished is an account with enough clean send history.
	AccountTrustEstablished
)

// EstablishedThreshold is the lifetime clean-delivery count at or above which
// an account is promoted to AccountTrustEstablished. Below it (but above zero)
// the account is AccountTrustUntrusted; with no history it is AccountTrustNew.
// A suspended account is always AccountTrustNew regardless of history.
//
// Default (0) uses establishedThresholdDefault.
var establishedThresholdDefault = 200

// EstablishedThreshold overrides the promotion threshold. 0 = use the default.
func (p *CappedPolicy) establishedThreshold() int {
	if p.EstablishedThreshold > 0 {
		return p.EstablishedThreshold
	}
	return establishedThresholdDefault
}

// TrustTierFor returns the current trust tier for accountID based on its
// observed delivery history. Unknown accounts and suspended accounts fail
// closed to AccountTrustNew (the coldest tier) so an untrusted sender is never
// promoted to warm IPs.
//
// Classification:
//   - suspended OR no clean deliveries          → AccountTrustNew
//   - clean deliveries below establishedThreshold → AccountTrustUntrusted
//   - clean deliveries ≥ establishedThreshold    → AccountTrustEstablished
//
// A non-trivial recent bounce/complaint rate demotes the account one tier so a
// degrading sender is pulled back toward the ramp segment.
func (p *CappedPolicy) TrustTierFor(accountID string) AccountTrust {
	p.mu.Lock()
	defer p.mu.Unlock()

	a, ok := p.accounts[accountID]
	if !ok {
		return AccountTrustNew
	}
	if a.suspended {
		return AccountTrustNew
	}

	tier := AccountTrustNew
	switch {
	case a.cleanDelivered >= p.establishedThreshold():
		tier = AccountTrustEstablished
	case a.cleanDelivered > 0:
		tier = AccountTrustUntrusted
	}

	// Demote one tier when the recent bounce/complaint rate is elevated (but
	// not yet suspension-worthy). This keeps a degrading sender off warm IPs.
	if tier > AccountTrustNew && p.recentBadRateLocked(a) > p.bounceThreshold()/2 {
		tier--
	}
	return tier
}

// recentBadRateLocked computes the rolling bounce/complaint rate. Caller holds p.mu.
func (p *CappedPolicy) recentBadRateLocked(a *accountState) float64 {
	ws := p.windowSize()
	filled := a.resultHead
	if filled > ws {
		filled = ws
	}
	if filled == 0 {
		return 0
	}
	bad := 0
	for i := 0; i < filled; i++ {
		if a.results[i] {
			bad++
		}
	}
	return float64(bad) / float64(filled)
}

// Suspend immediately suspends accountID with the given reason.
func (p *CappedPolicy) Suspend(accountID, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.account(accountID)
	a.suspended = true
	a.suspendAt = time.Now()
	a.suspendReason = reason
}

// Reinstate lifts a suspension for accountID.
func (p *CappedPolicy) Reinstate(accountID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.account(accountID)
	a.suspended = false
	a.suspendReason = ""
	// Reset the rolling bounce window so the account starts fresh.
	a.results = make([]bool, p.windowSize())
	a.resultHead = 0
}

func utcDayStart(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

var _ Policy = (*CappedPolicy)(nil)
