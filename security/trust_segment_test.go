// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"net"
	"testing"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// ─── Attack class 5: trust-segment gating ────────────────────────────────────
//
// A new/untrusted sender must NEVER be placed on a warm/established IP: a fresh
// account can torch an established IP's reputation. The gating is: trust tier →
// segment hint → Pool.Select, and Pool.Select additionally refuses to hand a
// low-trust account an established IP even if it is the only one available.

// warmPool builds a pool that contains an established (warm) IP plus optional
// cold/ramp IPs.
func warmPool(withCold bool) (*sending.Pool, net.IP, net.IP, net.IP) {
	p := sending.NewPool()
	warm := net.ParseIP("203.0.113.1")
	cold := net.ParseIP("203.0.113.50")
	ramp := net.ParseIP("203.0.113.60")
	p.AddEntry(sending.PoolEntry{IP: warm, HELOName: "warm.mta", Segment: sending.SegmentEstablished})
	if withCold {
		p.AddEntry(sending.PoolEntry{IP: cold, HELOName: "cold.mta", Segment: sending.SegmentNew})
		p.AddEntry(sending.PoolEntry{IP: ramp, HELOName: "ramp.mta", Segment: sending.SegmentUntrusted})
	}
	return p, warm, cold, ramp
}

// ATTACK: a brand-new (untrusted) sender requests an IP from a pool that
// contains a warm/established IP. EXPECT: it is NOT given the established IP —
// it lands on a cold/ramp segment instead.
func TestTrustGating_NewSender_NeverRidesWarmIP(t *testing.T) {
	pool, warm, _, _ := warmPool(true)

	// A new account: TrustNew → SegmentNew hint.
	src := sending.StaticTrustSource{Tier: sending.TrustNew}
	hint := sending.SegmentForTrust(src, "brand-new-account")
	if hint != sending.SegmentNew {
		t.Fatalf("trust→segment: new account should map to SegmentNew, got %q", hint)
	}

	binding, err := pool.Select("brand-new-account", hint)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if binding.LocalIP.Equal(warm) {
		t.Fatal("VULN: a new/untrusted sender was placed on the warm/established IP")
	}
}

// ATTACK: the harder case — the pool's ONLY non-quarantined IP is the warm one.
// A low-trust account must STILL not be handed it (Pool defers instead of
// promoting). EXPECT: ErrNoAvailableIP, never the established IP.
func TestTrustGating_NewSender_DefersWhenOnlyWarmIPExists(t *testing.T) {
	pool, warm, _, _ := warmPool(false) // only the established IP exists

	src := sending.StaticTrustSource{Tier: sending.TrustUntrusted}
	hint := sending.SegmentForTrust(src, "ramp-account")

	binding, err := pool.Select("ramp-account", hint)
	if err == nil && binding.LocalIP.Equal(warm) {
		t.Fatal("VULN: low-trust account promoted onto the only (established) IP instead of deferring")
	}
	if err != sending.ErrNoAvailableIP {
		t.Fatalf("want ErrNoAvailableIP (defer) for a low-trust account with only a warm IP, got binding=%v err=%v", binding.LocalIP, err)
	}
}

// FAIL-CLOSED: a nil TrustSource must classify the account at the coldest tier,
// so a missing classifier can never accidentally promote a sender to warm IPs.
func TestTrustGating_NilTrustSource_FailsClosedToCold(t *testing.T) {
	hint := sending.SegmentForTrust(nil, "anyone")
	if hint != sending.SegmentNew {
		t.Fatalf("VULN: nil TrustSource did not fail closed; hint=%q (want %q)", hint, sending.SegmentNew)
	}
}

// CONTROL: an ESTABLISHED account rides the warm IP — proves the gate is real
// (it discriminates by trust, not a blanket deny).
func TestTrustGating_EstablishedSender_RidesWarmIP(t *testing.T) {
	pool, warm, _, _ := warmPool(true)
	src := sending.StaticTrustSource{Tier: sending.TrustEstablished}
	hint := sending.SegmentForTrust(src, "old-trusted-account")
	if hint != sending.SegmentEstablished {
		t.Fatalf("established account should map to SegmentEstablished, got %q", hint)
	}
	binding, err := pool.Select("old-trusted-account", hint)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if !binding.LocalIP.Equal(warm) {
		t.Fatalf("established account should ride the warm IP, got %v", binding.LocalIP)
	}
}
