// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package reputation_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vul-os/vulos-relay/internal/reputation"
)

var ctx = context.Background()

func TestPermissiveAlwaysAllows(t *testing.T) {
	p := reputation.Permissive{}
	for i := 0; i < 10; i++ {
		d, err := p.CheckSend(ctx, "acct1", reputation.Message{ID: "m1"})
		if err != nil {
			t.Fatalf("CheckSend error: %v", err)
		}
		if !d.Allow {
			t.Fatal("Permissive must always Allow")
		}
	}
}

func TestPermissiveRecordResultNoOp(t *testing.T) {
	p := reputation.Permissive{}
	if err := p.RecordResult(ctx, "acct1", reputation.SendResult{State: reputation.SendBounced}); err != nil {
		t.Fatal(err)
	}
}

// ---------- CappedPolicy ----------

func newCapped(cap int, threshold float64, window int) *reputation.CappedPolicy {
	p := reputation.NewCappedPolicy()
	p.DailyCap = cap
	p.BounceThreshold = threshold
	p.WindowSize = window
	return p
}

func TestCappedPolicyAllowsUnderCap(t *testing.T) {
	p := newCapped(5, 0.5, 10)
	d, err := p.CheckSend(ctx, "a", reputation.Message{})
	if err != nil || !d.Allow {
		t.Fatalf("want allow under cap, got allow=%v err=%v", d.Allow, err)
	}
}

func TestCappedPolicyDeniesAtDailyCap(t *testing.T) {
	p := newCapped(3, 0.5, 10)

	// Simulate 3 deliveries to exhaust the cap.
	for i := 0; i < 3; i++ {
		if err := p.RecordResult(ctx, "acct", reputation.SendResult{State: reputation.SendDelivered}); err != nil {
			t.Fatal(err)
		}
	}

	d, err := p.CheckSend(ctx, "acct", reputation.Message{})
	if !errors.Is(err, reputation.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got err=%v", err)
	}
	if d.Allow {
		t.Fatal("want Allow=false at cap")
	}
	if d.DelayUntil == nil {
		t.Fatal("want DelayUntil set when rate-limited")
	}
}

func TestCappedPolicySuspendsOnHighBounceRate(t *testing.T) {
	// Window of 5, threshold 0.4.  After 3 bounces out of 5, rate = 0.6 > 0.4.
	p := newCapped(1000, 0.40, 5)

	record := func(s reputation.SendState) {
		if err := p.RecordResult(ctx, "acct", reputation.SendResult{State: s}); err != nil {
			t.Fatal(err)
		}
	}

	record(reputation.SendDelivered)
	record(reputation.SendDelivered)
	record(reputation.SendBounced)
	record(reputation.SendBounced)
	record(reputation.SendBounced)

	_, err := p.CheckSend(ctx, "acct", reputation.Message{})
	if !errors.Is(err, reputation.ErrSuspended) {
		t.Fatalf("want ErrSuspended after high bounce rate, got %v", err)
	}
}

func TestCappedPolicySuspendsOnComplaint(t *testing.T) {
	p := newCapped(1000, 0.09, 5)

	// One complaint out of 5 = 0.2 > 0.09 threshold after window fills.
	for i := 0; i < 4; i++ {
		_ = p.RecordResult(ctx, "b", reputation.SendResult{State: reputation.SendDelivered})
	}
	_ = p.RecordResult(ctx, "b", reputation.SendResult{State: reputation.SendComplaint})

	_, err := p.CheckSend(ctx, "b", reputation.Message{})
	if !errors.Is(err, reputation.ErrSuspended) {
		t.Fatalf("want ErrSuspended after complaint, got %v", err)
	}
}

func TestCappedPolicyReinstateClears(t *testing.T) {
	p := newCapped(1000, 0.40, 5)

	for i := 0; i < 5; i++ {
		_ = p.RecordResult(ctx, "c", reputation.SendResult{State: reputation.SendBounced})
	}

	_, err := p.CheckSend(ctx, "c", reputation.Message{})
	if !errors.Is(err, reputation.ErrSuspended) {
		t.Fatalf("precondition: expected ErrSuspended")
	}

	p.Reinstate("c")

	d, err := p.CheckSend(ctx, "c", reputation.Message{})
	if err != nil || !d.Allow {
		t.Fatalf("want allow after reinstate, got allow=%v err=%v", d.Allow, err)
	}
}

func TestCappedPolicyManualSuspend(t *testing.T) {
	p := newCapped(1000, 0.5, 10)
	p.Suspend("d", "abuse")

	_, err := p.CheckSend(ctx, "d", reputation.Message{})
	if !errors.Is(err, reputation.ErrSuspended) {
		t.Fatalf("want ErrSuspended after manual suspend, got %v", err)
	}
}

// TestCappedPolicyCapEnforcedAtGateUnderConcurrency proves the P1 fix: the
// daily cap is reserved at the CheckSend gate (not at RecordResult), so many
// concurrent workers cannot all pass the gate before any of them records a
// result. The number of allowed sends must never exceed the cap.
func TestCappedPolicyCapEnforcedAtGateUnderConcurrency(t *testing.T) {
	const cap = 50
	const workers = 500
	p := newCapped(cap, 1.0, 1000) // high bounce threshold so it never suspends

	var allowed int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d, err := p.CheckSend(ctx, "acct", reputation.Message{})
			if err == nil && d.Allow {
				atomic.AddInt64(&allowed, 1)
				// Simulate a successful (terminal) send so the reservation is kept.
				_ = p.RecordResult(ctx, "acct", reputation.SendResult{State: reputation.SendDelivered})
			}
		}()
	}
	close(start)
	wg.Wait()

	got := atomic.LoadInt64(&allowed)
	if got != cap {
		t.Fatalf("cap enforcement under concurrency: allowed %d sends, want exactly %d", got, cap)
	}

	// The cap should now be reached: a further CheckSend must be rate-limited.
	d, err := p.CheckSend(ctx, "acct", reputation.Message{})
	if !errors.Is(err, reputation.ErrRateLimited) || d.Allow {
		t.Fatalf("expected ErrRateLimited after cap reached, got allow=%v err=%v", d.Allow, err)
	}
}

// TestCappedPolicyDeferReleasesReservation verifies that a transient (deferred)
// outcome releases the gate-time reservation so the quota is not permanently
// burned by a message that will be retried.
func TestCappedPolicyDeferReleasesReservation(t *testing.T) {
	p := newCapped(2, 1.0, 100)

	// First attempt: gate reserves, then defers → slot released.
	d, err := p.CheckSend(ctx, "acct", reputation.Message{})
	if err != nil || !d.Allow {
		t.Fatalf("first CheckSend: allow=%v err=%v", d.Allow, err)
	}
	_ = p.RecordResult(ctx, "acct", reputation.SendResult{State: reputation.SendDeferred})

	// Two more delivered sends should still fit under the cap of 2 because the
	// deferred one released its reservation.
	for i := 0; i < 2; i++ {
		d, err := p.CheckSend(ctx, "acct", reputation.Message{})
		if err != nil || !d.Allow {
			t.Fatalf("delivered CheckSend %d: allow=%v err=%v", i, d.Allow, err)
		}
		_ = p.RecordResult(ctx, "acct", reputation.SendResult{State: reputation.SendDelivered})
	}

	// Now the cap is consumed.
	d, err = p.CheckSend(ctx, "acct", reputation.Message{})
	if !errors.Is(err, reputation.ErrRateLimited) || d.Allow {
		t.Fatalf("expected rate-limit after 2 delivered, got allow=%v err=%v", d.Allow, err)
	}
}

func TestCappedPolicyRecordResultUpdatesScore(t *testing.T) {
	// Verify that RecordResult influences subsequent CheckSend.
	p := newCapped(1000, 0.40, 5)

	// First three bounces out of three => 100% > threshold.
	for i := 0; i < 3; i++ {
		_ = p.RecordResult(ctx, "e", reputation.SendResult{State: reputation.SendBounced})
	}

	_, err := p.CheckSend(ctx, "e", reputation.Message{})
	if !errors.Is(err, reputation.ErrSuspended) {
		t.Fatalf("want ErrSuspended, got %v", err)
	}
}
