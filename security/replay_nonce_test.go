// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/peering"
)

// ─── Attack class 3: replay-nonce guard ──────────────────────────────────────
//
// The peering ReplayGuard enforces a timestamp acceptance window plus a
// per-(sender,nonce) dedup cache. Two attacks: (a) replay the same (sender,
// nonce) within the window, and (b) flood the guard with distinct nonces to
// exhaust memory. The guard must reject (a) and BOUND its cache against (b).

// ATTACK: present the same (sender, nonce, timestamp) twice within the window.
// EXPECT: the first is accepted, the second is rejected as a replay.
func TestReplayGuard_SameNonceWithinWindow_Rejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	g := &peering.ReplayGuard{Now: func() time.Time { return now }}

	sender := freshSignPub(t)
	nonce := freshNonce(t)

	if err := g.Check(sender, nonce, now); err != nil {
		t.Fatalf("first presentation should be accepted, got %v", err)
	}
	if err := g.Check(sender, nonce, now); err != peering.ErrReplay {
		t.Fatalf("VULN: replay within window not rejected, got %v", err)
	}
}

// ATTACK: present a nonce with a timestamp far outside the acceptance window
// (stale-or-future). EXPECT: rejected on the timestamp window alone, so an
// attacker cannot resurrect an old captured envelope after its window passes.
func TestReplayGuard_StaleTimestamp_Rejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	g := &peering.ReplayGuard{Skew: 5 * time.Minute, Now: func() time.Time { return now }}
	sender := freshSignPub(t)

	stale := now.Add(-1 * time.Hour)
	if err := g.Check(sender, freshNonce(t), stale); err != peering.ErrReplay {
		t.Fatalf("VULN: stale timestamp accepted, got %v", err)
	}
	future := now.Add(1 * time.Hour)
	if err := g.Check(sender, freshNonce(t), future); err != peering.ErrReplay {
		t.Fatalf("VULN: far-future timestamp accepted, got %v", err)
	}
}

// ATTACK: flood the guard with a huge number of DISTINCT (sender,nonce) pairs,
// all within the acceptance window, trying to grow the dedup cache without
// bound (memory-exhaustion DoS). EXPECT: the hard size cap (MaxSeen) holds —
// the cache never exceeds the configured maximum no matter how many distinct
// nonces are pushed.
func TestReplayGuard_NonceFlood_CacheStaysBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	const cap = 256
	g := &peering.ReplayGuard{
		Skew:    5 * time.Minute,
		MaxSeen: cap,
		Now:     func() time.Time { return now },
	}
	sender := freshSignPub(t)

	// Push 20× the cap in distinct nonces, spread across distinct seconds so the
	// guard's expiry buckets differ (the realistic flood shape).
	for i := 0; i < cap*20; i++ {
		// Advance the clock slightly so buckets differ, but keep every entry
		// inside the window by re-centering `now` as we go.
		now = now.Add(time.Millisecond * 50)
		ts := now // in-window by construction
		if err := g.Check(sender, freshNonce(t), ts); err != nil {
			// Some may fall just outside as the clock drifts; that is also a
			// rejection (fine). We only care that the cache never blows the cap.
			_ = err
		}
		if got := g.SeenLen(); got > cap {
			t.Fatalf("VULN: replay cache exceeded its cap: %d > %d (memory-exhaustion flood succeeded)", got, cap)
		}
	}
	// Final assertion: still bounded after the whole flood.
	if got := g.SeenLen(); got > cap {
		t.Fatalf("VULN: replay cache ended over cap: %d > %d", got, cap)
	}
}

// ATTACK: a replay must still be caught for an entry that is in-window even
// after the cache has churned (eviction must not weaken replay protection for
// live entries). EXPECT: replay of a still-in-window nonce is rejected.
func TestReplayGuard_ReplayStillCaughtAfterChurn(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	g := &peering.ReplayGuard{Skew: 5 * time.Minute, MaxSeen: 1 << 16, Now: func() time.Time { return now }}
	sender := freshSignPub(t)

	victimNonce := freshNonce(t)
	if err := g.Check(sender, victimNonce, now); err != nil {
		t.Fatalf("seed nonce should be accepted: %v", err)
	}
	// Churn the cache with other in-window nonces.
	for i := 0; i < 1000; i++ {
		_ = g.Check(sender, freshNonce(t), now)
	}
	// Replay the seeded nonce — still within the window — must be rejected.
	if err := g.Check(sender, victimNonce, now); err != peering.ErrReplay {
		t.Fatalf("VULN: replay of an in-window nonce not caught after churn, got %v", err)
	}
}

// freshSignPub returns a random Ed25519 public key to key the guard by sender.
func freshSignPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return pub
}

// freshNonce returns a random 12-byte AES-GCM nonce.
func freshNonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, 12)
	if _, err := rand.Read(n); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return n
}
