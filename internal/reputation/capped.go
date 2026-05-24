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
