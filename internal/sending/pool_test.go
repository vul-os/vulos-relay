// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending_test

import (
	"net"
	"testing"

	"github.com/vul-os/vulos-relay/internal/sending"
)

func mustIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("invalid IP: " + s)
	}
	return ip
}

// TestPoolSelectDedicated verifies that a dedicated-IP account always gets its
// own binding and never a shared IP.
func TestPoolSelectDedicated(t *testing.T) {
	p := sending.NewPool()
	p.AddEntry(sending.PoolEntry{
		IP:       mustIP("10.0.0.1"),
		HELOName: "mail1.example.com",
		Segment:  sending.SegmentEstablished,
	})
	p.AddEntry(sending.PoolEntry{
		IP:               mustIP("10.0.0.99"),
		HELOName:         "dedicated.example.com",
		Segment:          sending.SegmentDedicated,
		DedicatedAccount: "acct-vip",
	})

	binding, err := p.Select("acct-vip", sending.SegmentDedicated)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !binding.LocalIP.Equal(mustIP("10.0.0.99")) {
		t.Errorf("expected dedicated IP 10.0.0.99, got %s", binding.LocalIP)
	}
}

// TestPoolSelectUntrustedNeverGetsEstablished ensures low-trust accounts cannot
// receive an established segment IP.
func TestPoolSelectUntrustedNeverGetsEstablished(t *testing.T) {
	p := sending.NewPool()
	p.AddEntry(sending.PoolEntry{
		IP:       mustIP("10.0.1.1"),
		HELOName: "warm.example.com",
		Segment:  sending.SegmentEstablished,
	})
	// Only established IPs in the pool → untrusted account should fail.
	_, err := p.Select("new-acct", sending.SegmentUntrusted)
	if err == nil {
		t.Error("expected ErrNoAvailableIP for untrusted account with only established IPs")
	}

	// Add an untrusted IP → selection should succeed.
	p.AddEntry(sending.PoolEntry{
		IP:       mustIP("10.0.2.1"),
		HELOName: "ramp.example.com",
		Segment:  sending.SegmentUntrusted,
	})
	binding, err := p.Select("new-acct", sending.SegmentUntrusted)
	if err != nil {
		t.Fatalf("expected success after untrusted IP added: %v", err)
	}
	if !binding.LocalIP.Equal(mustIP("10.0.2.1")) {
		t.Errorf("expected untrusted IP 10.0.2.1, got %s", binding.LocalIP)
	}
}

// TestPoolSelectHonoursPolicyHint verifies segment-hint selection.
func TestPoolSelectHonoursPolicyHint(t *testing.T) {
	p := sending.NewPool()
	p.AddEntry(sending.PoolEntry{
		IP:       mustIP("10.0.3.1"),
		HELOName: "a.example.com",
		Segment:  sending.SegmentEstablished,
	})
	p.AddEntry(sending.PoolEntry{
		IP:       mustIP("10.0.4.1"),
		HELOName: "b.example.com",
		Segment:  sending.SegmentUntrusted,
	})

	// Established account with established hint → established IP.
	binding, err := p.Select("established-acct", sending.SegmentEstablished)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !binding.LocalIP.Equal(mustIP("10.0.3.1")) {
		t.Errorf("expected 10.0.3.1 for established hint, got %s", binding.LocalIP)
	}
}

// TestPoolQuarantineAndUnquarantine verifies quarantine removes and restores
// an IP from rotation.
func TestPoolQuarantineAndUnquarantine(t *testing.T) {
	p := sending.NewPool()
	ip := mustIP("10.0.5.1")
	p.AddEntry(sending.PoolEntry{
		IP:       ip,
		HELOName: "q.example.com",
		Segment:  sending.SegmentEstablished,
	})

	// Only IP in pool → should succeed.
	_, err := p.Select("acct1", sending.SegmentEstablished)
	if err != nil {
		t.Fatalf("expected success before quarantine: %v", err)
	}

	// Quarantine it → selection should fail.
	p.Quarantine(ip, "blocklist:spamhaus:SBL")
	_, err = p.Select("acct1", sending.SegmentEstablished)
	if err == nil {
		t.Error("expected ErrNoAvailableIP after quarantine")
	}

	// Unquarantine → selection should succeed again.
	p.Unquarantine(ip)
	_, err = p.Select("acct1", sending.SegmentEstablished)
	if err != nil {
		t.Fatalf("expected success after unquarantine: %v", err)
	}
}

// TestPoolDedicatedQuarantined verifies that a quarantined dedicated IP
// returns ErrNoAvailableIP.
func TestPoolDedicatedQuarantined(t *testing.T) {
	p := sending.NewPool()
	ip := mustIP("10.0.6.1")
	p.AddEntry(sending.PoolEntry{
		IP:               ip,
		HELOName:         "d.example.com",
		Segment:          sending.SegmentDedicated,
		DedicatedAccount: "vip",
	})

	p.Quarantine(ip, "test quarantine")
	_, err := p.Select("vip", sending.SegmentDedicated)
	if err == nil {
		t.Error("expected ErrNoAvailableIP for quarantined dedicated IP")
	}
}
