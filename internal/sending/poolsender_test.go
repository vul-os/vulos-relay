// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending_test

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// recordingSender captures the SourceBinding it was handed, proving the pool
// selection actually flowed into the send path.
type recordingSender struct {
	mu       sync.Mutex
	bindings []*sending.SourceBinding
	result   sending.SendResult
}

func (r *recordingSender) Send(_ context.Context, msg sending.Message) (sending.SendResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindings = append(r.bindings, msg.Binding)
	res := r.result
	if res.State == "" {
		res.State = sending.StateDelivered
		res.Code = 250
	}
	return res, nil
}

func (r *recordingSender) lastBinding() *sending.SourceBinding {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bindings) == 0 {
		return nil
	}
	return r.bindings[len(r.bindings)-1]
}

func (r *recordingSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bindings)
}

// TestPoolSenderSelectsAndBindsIP proves the P1 wiring: PoolSender selects a
// warm IP from the Pool and binds it onto the outbound message before delegating.
func TestPoolSenderSelectsAndBindsIP(t *testing.T) {
	pool := sending.NewPool()
	ip := net.ParseIP("203.0.113.10")
	pool.AddEntry(sending.PoolEntry{IP: ip, HELOName: "mx.example.com", Segment: sending.SegmentUntrusted})

	inner := &recordingSender{}
	ps := &sending.PoolSender{Pool: pool, Inner: inner}

	msg := sending.Message{ID: "m1", AccountID: "acct", Sender: "a@example.com", Recipients: []string{"b@example.org"}}
	res, err := ps.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.State != sending.StateDelivered {
		t.Fatalf("want delivered, got %s", res.State)
	}

	b := inner.lastBinding()
	if b == nil || b.LocalIP == nil {
		t.Fatal("expected a SourceBinding with a LocalIP to be selected and bound")
	}
	if !b.LocalIP.Equal(ip) {
		t.Errorf("bound IP = %s, want %s", b.LocalIP, ip)
	}
	if b.HELOName != "mx.example.com" {
		t.Errorf("HELO = %q, want mx.example.com", b.HELOName)
	}
}

// TestPoolSenderRampCapDefers proves the ramp scheduler is wired: once the
// per-IP daily cap is exhausted, further sends defer instead of using the IP.
func TestPoolSenderRampCapDefers(t *testing.T) {
	pool := sending.NewPool()
	ip := net.ParseIP("203.0.113.20")
	pool.AddEntry(sending.PoolEntry{IP: ip, Segment: sending.SegmentUntrusted})

	ramp := sending.NewRampScheduler(sending.RampConfig{})
	// Step 0 cap is 50; pre-exhaust it.
	for i := 0; i < 50; i++ {
		ramp.Record(ip)
	}
	if ramp.CapFor(ip) != 0 {
		t.Fatalf("precondition: expected ramp cap exhausted, got %d", ramp.CapFor(ip))
	}

	inner := &recordingSender{}
	ps := &sending.PoolSender{Pool: pool, Ramp: ramp, Inner: inner}

	msg := sending.Message{ID: "m2", AccountID: "acct", Recipients: []string{"b@example.org"}}
	res, _ := ps.Send(context.Background(), msg)
	if res.State != sending.StateDeferred {
		t.Fatalf("want deferred when ramp cap exhausted, got %s", res.State)
	}
	if inner.count() != 0 {
		t.Errorf("inner sender should not be called when ramp cap is exhausted; called %d times", inner.count())
	}
}

// TestPoolSenderBlocklistQuarantineDefers proves the blocklist quarantine takes
// effect: quarantining the only pool IP (as BlocklistMonitor would) makes
// selection fail and the send defer rather than using a listed IP.
func TestPoolSenderBlocklistQuarantineDefers(t *testing.T) {
	pool := sending.NewPool()
	ip := net.ParseIP("203.0.113.30")
	pool.AddEntry(sending.PoolEntry{IP: ip, Segment: sending.SegmentUntrusted})

	// Simulate the BlocklistMonitor quarantining the IP (Pool implements the
	// reputation.IPPool interface via Quarantine/Unquarantine).
	pool.Quarantine(ip, "blocklist:spamhaus:test")

	inner := &recordingSender{}
	ps := &sending.PoolSender{Pool: pool, Inner: inner}

	msg := sending.Message{ID: "m3", AccountID: "acct", Recipients: []string{"b@example.org"}}
	res, _ := ps.Send(context.Background(), msg)
	if res.State != sending.StateDeferred {
		t.Fatalf("want deferred when only IP is quarantined, got %s", res.State)
	}
	if inner.count() != 0 {
		t.Errorf("inner sender must not be called when all IPs quarantined; called %d", inner.count())
	}

	// Releasing the quarantine restores delivery via that IP.
	pool.Unquarantine(ip)
	res, err := ps.Send(context.Background(), msg)
	if err != nil || res.State != sending.StateDelivered {
		t.Fatalf("want delivered after unquarantine, got state=%s err=%v", res.State, err)
	}
	if b := inner.lastBinding(); b == nil || !b.LocalIP.Equal(ip) {
		t.Errorf("expected delivery bound to released IP %s", ip)
	}
}
