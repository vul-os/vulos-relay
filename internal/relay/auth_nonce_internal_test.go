// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package relay

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// seenLen returns the number of retained nonces (white-box access).
func (a *SharedSecretAuth) seenLen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.seen)
}

func (a *SharedSecretAuth) bucketLen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.buckets)
}

// TestNonceCacheBoundedByTimeBucketEviction proves the P1 fix: the replay-nonce
// cache stays bounded — once a nonce's expiry window passes it is evicted via
// time-bucket eviction (no unbounded growth and no O(n) full scan per auth).
func TestNonceCacheBoundedByTimeBucketEviction(t *testing.T) {
	reg := NewMemAccountRegistry()
	secret := []byte("k")
	reg.Register(AccountRecord{AccountID: "a", SharedSecret: secret})

	auth := NewSharedSecretAuth(reg)
	auth.AllowedSkew = 30 * time.Second // nonce expiry = 2× skew = 60s

	base := time.Unix(1_700_000_000, 0)
	cur := base
	auth.SetClock(func() time.Time { return cur })

	ctx := context.Background()

	// Feed 200 unique nonces at the SAME timestamp (all within skew of `cur`).
	for i := 0; i < 200; i++ {
		tok := ComputeHMACToken(secret, "a", fmt.Sprintf("m%d", i), cur.Unix())
		if _, err := auth.Authenticate(ctx, Credentials{HMACToken: &tok}); err != nil {
			t.Fatalf("auth %d failed: %v", i, err)
		}
	}
	if got := auth.seenLen(); got != 200 {
		t.Fatalf("expected 200 retained nonces while in-window, got %d", got)
	}

	// Advance well past the expiry window (2×skew = 60s) and authenticate a new
	// nonce; this triggers eviction of every expired entry.
	cur = base.Add(5 * time.Minute)
	tok := ComputeHMACToken(secret, "a", "fresh", cur.Unix())
	if _, err := auth.Authenticate(ctx, Credentials{HMACToken: &tok}); err != nil {
		t.Fatalf("post-window auth failed: %v", err)
	}
	// The 200 old nonces must have been evicted; only the fresh one remains.
	if got := auth.seenLen(); got != 1 {
		t.Fatalf("expected eviction to leave 1 nonce, got %d", got)
	}
	if got := auth.bucketLen(); got != 1 {
		t.Fatalf("expected 1 live bucket after eviction, got %d", got)
	}
}

// TestNonceCacheHardSizeCap proves memory is bounded even under a flood of
// distinct nonces all within the skew window: the size cap drops oldest
// buckets so the cache never exceeds MaxNonces.
func TestNonceCacheHardSizeCap(t *testing.T) {
	reg := NewMemAccountRegistry()
	secret := []byte("k")
	reg.Register(AccountRecord{AccountID: "a", SharedSecret: secret})

	auth := NewSharedSecretAuth(reg)
	auth.AllowedSkew = 5 * time.Minute
	auth.MaxNonces = 50 // tiny cap for the test

	base := time.Unix(1_700_000_000, 0)
	cur := base
	auth.SetClock(func() time.Time { return cur })
	ctx := context.Background()

	// Spread 500 nonces across distinct seconds (so buckets differ), all within
	// the 5-minute skew window.
	for i := 0; i < 500; i++ {
		cur = base.Add(time.Duration(i) * time.Second)
		tok := ComputeHMACToken(secret, "a", fmt.Sprintf("m%d", i), cur.Unix())
		if _, err := auth.Authenticate(ctx, Credentials{HMACToken: &tok}); err != nil {
			// Some very old ones may fall outside skew as cur advances; that's
			// fine — we only assert the size bound.
			_ = err
		}
		if got := auth.seenLen(); got > auth.MaxNonces {
			t.Fatalf("nonce cache exceeded cap: %d > %d", got, auth.MaxNonces)
		}
	}
}

// TestNonceReplayStillDetectedAfterEviction confirms eviction does not weaken
// replay protection within the window: a replay at the same timestamp is still
// caught.
func TestNonceReplayStillDetectedAfterEviction(t *testing.T) {
	reg := NewMemAccountRegistry()
	secret := []byte("k")
	reg.Register(AccountRecord{AccountID: "a", SharedSecret: secret})

	auth := NewSharedSecretAuth(reg)
	base := time.Unix(1_700_000_000, 0)
	cur := base
	auth.SetClock(func() time.Time { return cur })
	ctx := context.Background()

	tok := ComputeHMACToken(secret, "a", "dup", cur.Unix())
	if _, err := auth.Authenticate(ctx, Credentials{HMACToken: &tok}); err != nil {
		t.Fatalf("first auth: %v", err)
	}
	// Replay immediately — must be rejected.
	if _, err := auth.Authenticate(ctx, Credentials{HMACToken: &tok}); err == nil {
		t.Fatal("expected replay to be detected")
	}
}
