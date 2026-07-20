package rendezvous

import (
	"sync"
	"time"
)

// presence.go — ANNOUNCE + RESOLVE: the key-addressed presence directory.
//
// A node ANNOUNCEs (a signed, TTL'd, replay-protected record) that it is present
// and lists opaque connection hints (endpoints) under its public key. Anyone
// RESOLVEs a key to its current live presence with an unauthenticated read. The
// directory holds ONLY what the owner signed for itself — the node never dials or
// validates an endpoint (they are opaque hints for the resolving client to try), so
// storing them creates no SSRF surface.
//
// Records are soft-state: each expires at its TTL and a re-announce refreshes it. A
// background sweep drops expired records so a churny population does not leak memory.

// presence limits (all clamped, never rejected, so a client that asks for more just
// gets the cap).
const (
	// maxEndpoints caps how many connection hints one record may carry.
	maxEndpoints = 16
	// maxEndpointLen caps a single endpoint hint's length (bytes).
	maxEndpointLen = 512
	// maxMetaLen caps the opaque per-record meta blob (bytes). It is app-defined
	// (e.g. advertised capabilities); the node never parses it.
	maxMetaLen = 2 << 10 // 2 KiB
	// maxPresenceTTL is the longest a presence record lives without a re-announce.
	maxPresenceTTL = 30 * time.Minute
	// defaultPresenceTTL is used when an announce requests 0 (or an out-of-range) TTL.
	defaultPresenceTTL = 5 * time.Minute
)

// presenceRecord is one key's current announced presence.
type presenceRecord struct {
	key       string
	endpoints []string
	meta      string
	updatedAt time.Time
	expiresAt time.Time
}

// presenceStore is the in-memory presence directory. Safe for concurrent use.
type presenceStore struct {
	mu        sync.RWMutex
	byKey     map[string]*presenceRecord
	maxKeys   int
	swep      time.Time
	sweepEach time.Duration
}

func newPresenceStore(maxKeys int) *presenceStore {
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &presenceStore{byKey: make(map[string]*presenceRecord), maxKeys: maxKeys, sweepEach: time.Minute}
}

// clampTTL resolves a requested TTL (seconds) to the allowed range. 0/negative =>
// default; anything over the cap is clamped down (never rejected).
func clampPresenceTTL(seconds int) time.Duration {
	if seconds <= 0 {
		return defaultPresenceTTL
	}
	d := time.Duration(seconds) * time.Second
	if d > maxPresenceTTL {
		return maxPresenceTTL
	}
	return d
}

// sanitizeEndpoints bounds the count and per-item length of announced hints and
// drops empty / oversized / newline-bearing entries (a newline would break the
// canonical signing reconstruction and is never a valid endpoint hint).
func sanitizeEndpoints(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, e := range in {
		if e == "" || len(e) > maxEndpointLen {
			continue
		}
		bad := false
		for i := 0; i < len(e); i++ {
			if e[i] == '\n' || e[i] == '\r' {
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		out = append(out, e)
		if len(out) >= maxEndpoints {
			break
		}
	}
	return out
}

// upsert stores/refreshes a presence record for key with the given TTL. It returns
// the record's expiry. The caller has already verified the signature, freshness,
// and field caps. Returns ok=false only if the store is at its hard key cap and
// this is a brand-new key (bounds memory under a flood of distinct keys).
func (s *presenceStore) upsert(key string, endpoints []string, meta string, ttl time.Duration, now time.Time) (expiresAt time.Time, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	rec := s.byKey[key]
	if rec == nil {
		if len(s.byKey) >= s.maxKeys {
			return time.Time{}, false
		}
		rec = &presenceRecord{key: key}
		s.byKey[key] = rec
	}
	rec.endpoints = endpoints
	rec.meta = meta
	rec.updatedAt = now
	rec.expiresAt = now.Add(ttl)
	return rec.expiresAt, true
}

// resolve returns a snapshot of a key's live presence, or ok=false if there is no
// record or it has expired. The returned slice is a copy (callers must not mutate
// store state).
func (s *presenceStore) resolve(key string, now time.Time) (endpoints []string, meta string, expiresAt time.Time, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec := s.byKey[key]
	if rec == nil || !now.Before(rec.expiresAt) {
		return nil, "", time.Time{}, false
	}
	cp := make([]string, len(rec.endpoints))
	copy(cp, rec.endpoints)
	return cp, rec.meta, rec.expiresAt, true
}

// remove deletes a key's record (used by an owner-signed withdraw). Idempotent.
func (s *presenceStore) remove(key string) {
	s.mu.Lock()
	delete(s.byKey, key)
	s.mu.Unlock()
}

// count returns the number of live (non-expired) records — for metrics/tests.
func (s *presenceStore) count(now time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, rec := range s.byKey {
		if now.Before(rec.expiresAt) {
			n++
		}
	}
	return n
}

// sweepLocked drops expired records at most ~once per sweepEach. Caller holds the
// write lock.
func (s *presenceStore) sweepLocked(now time.Time) {
	if now.Sub(s.swep) < s.sweepEach {
		return
	}
	s.swep = now
	for k, rec := range s.byKey {
		if !now.Before(rec.expiresAt) {
			delete(s.byKey, k)
		}
	}
}
