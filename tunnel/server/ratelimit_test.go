// ratelimit_test.go — WAVE34-RELAY-HARDEN tests for the per-key/global token
// buckets: 429 past the cap, recovery after refill, memory bounding, and the
// end-to-end 429 on the public proxy path.
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_CapThenRecover(t *testing.T) {
	// 10 tokens/sec, burst 3: the first 3 calls pass, the 4th is denied, then a
	// short wait refills enough for another to pass.
	rl := newRateLimiter(10, 3, time.Minute, 1000)
	for i := 0; i < 3; i++ {
		if !rl.allow("ip-1") {
			t.Fatalf("call %d within burst should pass", i)
		}
	}
	if rl.allow("ip-1") {
		t.Fatal("4th call past burst should be denied (429)")
	}
	// A different key has its own bucket.
	if !rl.allow("ip-2") {
		t.Fatal("distinct key must not share ip-1's bucket")
	}
	// Wait for ~1 token to refill (10/sec => 100ms per token; wait 150ms).
	time.Sleep(150 * time.Millisecond)
	if !rl.allow("ip-1") {
		t.Fatal("after refill the bucket should allow again (recovery)")
	}
}

func TestRateLimiter_Disabled(t *testing.T) {
	// rate<=0 disables the limiter (allow all) — self-host path.
	if rl := newRateLimiter(0, 5, 0, 0); rl != nil {
		t.Fatal("rate<=0 should return a nil (disabled) limiter")
	}
	var nilRL *rateLimiter
	for i := 0; i < 1000; i++ {
		if !nilRL.allow("x") {
			t.Fatal("a nil limiter must allow everything")
		}
	}
}

func TestRateLimiter_MaxKeysBounded(t *testing.T) {
	// maxKeys=2: a 3rd distinct NEW key is refused rather than growing memory.
	rl := newRateLimiter(100, 5, time.Hour, 2)
	if !rl.allow("a") || !rl.allow("b") {
		t.Fatal("first two keys should fit")
	}
	if rl.allow("c") {
		t.Fatal("a new key past maxKeys must be refused")
	}
	if got := len(rl.buckets); got != 2 {
		t.Fatalf("bucket count should stay bounded at 2, got %d", got)
	}
}

func TestRateLimiter_IdleEviction(t *testing.T) {
	rl := newRateLimiter(100, 5, 40*time.Millisecond, 1000)
	rl.allow("stale")
	if len(rl.buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(rl.buckets))
	}
	// Wait past idleTTL, then touch a different key to trigger a sweep.
	time.Sleep(120 * time.Millisecond)
	rl.allow("fresh")
	if _, ok := rl.buckets["stale"]; ok {
		t.Fatal("idle bucket should have been evicted")
	}
}

func TestGlobalRateLimiter_CapThenRecover(t *testing.T) {
	g := newGlobalRateLimiter(10, 2)
	// Two separate draws against the global bucket; burst is 2.
	first, second := g.allow(), g.allow()
	if !first || !second {
		t.Fatal("first two within burst should pass")
	}
	if g.allow() {
		t.Fatal("3rd past burst should be denied")
	}
	time.Sleep(150 * time.Millisecond)
	if !g.allow() {
		t.Fatal("after refill the global bucket should allow again")
	}
}

// TestPublicProxy_RateLimit429 drives the real handler: a tight per-tunnel limit
// returns 429 past the cap and recovers after the bucket refills. No live agent
// is needed because the limit is checked before session lookup — a rate-limited
// request 429s, an allowed one falls through to the offline path (502).
func TestPublicProxy_RateLimit429(t *testing.T) {
	st, err := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	s, err := New(Config{
		Domain:          "relay.test",
		Tokens:          st,
		PublicReqRate:   100, // fast refill so recovery is quick
		PublicReqBurst:  2,   // only 2 requests before 429
		GlobalReqRate:   -1,  // disable the global limiter for this test
		ControlConnRate: -1,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer s.Close()
	h := s.Handler()

	do := func() int {
		r := httptest.NewRequest(http.MethodGet, "http://box1.relay.test/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// Burst of 2 passes the limiter (falls through to 502 tunnel-offline).
	if code := do(); code == http.StatusTooManyRequests {
		t.Fatalf("1st request should not be rate limited, got %d", code)
	}
	if code := do(); code == http.StatusTooManyRequests {
		t.Fatalf("2nd request should not be rate limited, got %d", code)
	}
	// 3rd exceeds the burst → 429.
	if code := do(); code != http.StatusTooManyRequests {
		t.Fatalf("3rd request should be 429, got %d", code)
	}
	// After a refill, requests are allowed again (recovery).
	time.Sleep(50 * time.Millisecond) // 100/sec => ~5 tokens back
	if code := do(); code == http.StatusTooManyRequests {
		t.Fatalf("after refill request should pass, got %d", code)
	}
}
