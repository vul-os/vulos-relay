// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"crypto/ed25519"
	"encoding/binary"
	"sync"
	"time"
)

// defaultSkew is the timestamp acceptance window half-width (spec/PEERING.md §7).
const defaultSkew = 5 * time.Minute

// defaultMaxSeen bounds the dedup cache so a flood of distinct (sender,nonce)
// pairs cannot grow memory without limit within the acceptance window.
const defaultMaxSeen = 1 << 20 // ~1M entries

// ReplayGuard enforces spec §7 replay protection: a timestamp acceptance window
// plus per-(sender,nonce) dedup. It is safe for concurrent use.
//
// Dedup entries are grouped into one-second expiry buckets so eviction walks
// only the handful of elapsed bucket-seconds per call (amortized O(1)) instead
// of scanning the whole set, and total memory is bounded by MaxSeen.
type ReplayGuard struct {
	// Skew is the half-width of the timestamp acceptance window. Zero uses the
	// default (5 minutes).
	Skew time.Duration
	// Now, if non-nil, overrides the clock (tests).
	Now func() time.Time
	// MaxSeen is a hard cap on retained dedup entries. Zero uses defaultMaxSeen.
	MaxSeen int

	mu sync.Mutex
	// seen maps key(sender||nonce) -> expiry-bucket second.
	seen map[string]int64
	// buckets groups keys by their expiry second for amortized eviction.
	buckets   map[int64]map[string]struct{}
	minBucket int64
}

// NewReplayGuard creates a ReplayGuard with the default skew.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{
		seen:    make(map[string]int64),
		buckets: make(map[int64]map[string]struct{}),
	}
}

// Check accepts an envelope's (sender, nonce, timestamp) once. It returns
// ErrReplay if the timestamp is outside the acceptance window or if the
// (sender, nonce) pair has already been accepted within it. A successful Check
// records the pair.
func (g *ReplayGuard) Check(senderID ed25519.PublicKey, nonce []byte, ts time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = make(map[string]int64)
	}
	if g.buckets == nil {
		g.buckets = make(map[int64]map[string]struct{})
	}

	skew := g.Skew
	if skew <= 0 {
		skew = defaultSkew
	}
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	cur := now()

	// Timestamp window.
	if ts.Before(cur.Add(-skew)) || ts.After(cur.Add(skew)) {
		return ErrReplay
	}

	// Evict entries that have aged out of the acceptance window. Once aged out
	// the timestamp check alone rejects any re-presentation (spec §7).
	g.evict(cur, skew)

	key := guardKey(senderID, nonce)
	if _, dup := g.seen[key]; dup {
		return ErrReplay
	}
	// An accepted (sender,nonce) can only be replayed while its timestamp still
	// falls inside [cur-skew, cur+skew]; the widest such window relative to the
	// time of first acceptance is the future edge, so retain until cur+2*skew.
	expiry := cur.Add(2 * skew).Unix()
	g.insert(key, expiry)
	return nil
}

func (g *ReplayGuard) maxSeen() int {
	if g.MaxSeen > 0 {
		return g.MaxSeen
	}
	return defaultMaxSeen
}

// insert records key in the index and its expiry bucket, enforcing the size cap.
func (g *ReplayGuard) insert(key string, bucket int64) {
	g.seen[key] = bucket
	b := g.buckets[bucket]
	if b == nil {
		b = make(map[string]struct{})
		g.buckets[bucket] = b
		if g.minBucket == 0 || bucket < g.minBucket {
			g.minBucket = bucket
		}
	}
	b[key] = struct{}{}

	for len(g.seen) > g.maxSeen() && len(g.buckets) > 0 {
		g.recomputeMinBucket()
		g.dropBucket(g.minBucket)
	}
	if len(g.buckets) == 0 {
		g.minBucket = 0
	}
}

// evict drops entries whose expiry bucket has passed. Eviction walks only the
// elapsed bucket-seconds rather than scanning the entire set.
func (g *ReplayGuard) evict(now time.Time, _ time.Duration) {
	if len(g.buckets) == 0 {
		g.minBucket = 0
		return
	}
	cutoff := now.Unix()
	const maxProbe = 8
	misses := 0
	for g.minBucket > 0 && g.minBucket <= cutoff {
		if _, ok := g.buckets[g.minBucket]; ok {
			g.dropBucket(g.minBucket)
			misses = 0
		} else {
			misses++
		}
		g.minBucket++
		if len(g.buckets) == 0 {
			g.minBucket = 0
			return
		}
		if misses > maxProbe {
			g.recomputeMinBucket()
			misses = 0
		}
	}
}

// dropBucket removes an entire expiry bucket and all its keys.
func (g *ReplayGuard) dropBucket(bucket int64) {
	b, ok := g.buckets[bucket]
	if !ok {
		return
	}
	for k := range b {
		delete(g.seen, k)
	}
	delete(g.buckets, bucket)
}

// recomputeMinBucket finds the lowest live bucket second.
func (g *ReplayGuard) recomputeMinBucket() {
	min := int64(0)
	for sec := range g.buckets {
		if min == 0 || sec < min {
			min = sec
		}
	}
	g.minBucket = min
}

func guardKey(senderID ed25519.PublicKey, nonce []byte) string {
	buf := make([]byte, 0, 2+len(senderID)+len(nonce))
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(senderID)))
	buf = append(buf, l[:]...)
	buf = append(buf, senderID...)
	buf = append(buf, nonce...)
	return string(buf)
}
