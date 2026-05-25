// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package relay

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// ipRateLimiter is a fixed-window per-IP request limiter used at the submission
// gate. It caps the number of submission attempts a single client IP may make
// per window, BEFORE authentication, so an unauthenticated flood from one
// source cannot exhaust the relay (the per-account daily cap only protects
// against an authenticated sender; it does nothing for an anonymous DoS).
//
// A fixed-window counter is intentionally simple and bounded: each IP holds one
// small struct, stale entries are swept on a timer, and there is no per-request
// allocation. It is safe for concurrent use.
type ipRateLimiter struct {
	mu     sync.Mutex
	limit  int           // max requests per window (<=0 disables limiting)
	window time.Duration // window length
	now    func() time.Time

	buckets map[string]*ipBucket
}

type ipBucket struct {
	windowStart time.Time
	count       int
}

// newIPRateLimiter creates a limiter allowing limit requests per window per IP.
// A limit <= 0 disables limiting (Allow always returns true).
func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &ipRateLimiter{
		limit:   limit,
		window:  window,
		now:     time.Now,
		buckets: make(map[string]*ipBucket),
	}
}

// Allow reports whether a request from ip may proceed, incrementing the IP's
// window counter when it does. When the limiter is disabled (limit <= 0) it
// always allows.
func (l *ipRateLimiter) Allow(ip string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok || now.Sub(b.windowStart) >= l.window {
		l.buckets[ip] = &ipBucket{windowStart: now, count: 1}
		// Opportunistically sweep stale buckets to bound memory.
		if len(l.buckets) > 1024 {
			l.sweepLocked(now)
		}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

// sweepLocked removes buckets whose window has fully elapsed. Caller holds l.mu.
func (l *ipRateLimiter) sweepLocked(now time.Time) {
	for ip, b := range l.buckets {
		if now.Sub(b.windowStart) >= l.window {
			delete(l.buckets, ip)
		}
	}
}

// clientIP extracts the client IP from an *http.Request. By default it uses the
// connection's RemoteAddr — it does NOT trust X-Forwarded-For, because an
// attacker could spoof that header to evade the per-IP cap. Deployments behind
// a trusted proxy that terminates connections should normalise RemoteAddr at
// that layer (or front the relay with the proxy's own rate limiting).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
