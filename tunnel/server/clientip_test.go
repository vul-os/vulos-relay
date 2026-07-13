// clientip_test.go — the per-source rate-limit / audit key resolution behind a
// trusted edge. Regression guard for the "one fleet-wide bucket" bug: with
// TrustProxyHeaders=true, RemoteAddr is the shared EDGE IP for every connection,
// so the limiter key MUST come from the left-most X-Forwarded-For entry (the real
// client) — otherwise the per-source control-plane throttle collapses into a
// single global bucket. With TrustProxyHeaders=false the peer is untrusted and a
// spoofed XFF must NOT be able to change the bucket.
package server

import (
	"net/http"
	"testing"
)

func req(remoteAddr, xff string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientIP_TrustedEdge_UsesLeftmostXFF(t *testing.T) {
	s := &Server{cfg: Config{TrustProxyHeaders: true}}

	// Same edge RemoteAddr for both requests (this is what Fly's proxy looks like),
	// but different real clients in the left-most XFF position => DIFFERENT keys, so
	// each real client gets its OWN rate-limit bucket.
	edge := "10.0.0.2:443"
	a := s.clientIP(req(edge, "198.51.100.7, 10.0.0.2"))
	b := s.clientIP(req(edge, "203.0.113.9, 10.0.0.2"))
	if a != "198.51.100.7" {
		t.Fatalf("clientIP(a) = %q, want %q (left-most XFF is the real client)", a, "198.51.100.7")
	}
	if b != "203.0.113.9" {
		t.Fatalf("clientIP(b) = %q, want %q (left-most XFF is the real client)", b, "203.0.113.9")
	}
	if a == b {
		t.Fatalf("two clients behind the same edge must get DIFFERENT keys (got %q for both) — limiter would be one fleet-wide bucket", a)
	}

	// A single trailing-space / whitespace XFF entry is trimmed.
	if got := s.clientIP(req(edge, " 192.0.2.55 ")); got != "192.0.2.55" {
		t.Fatalf("clientIP = %q, want trimmed %q", got, "192.0.2.55")
	}

	// XFF absent behind the edge => fall back to the observed peer (RemoteAddr).
	if got := s.clientIP(req(edge, "")); got != "10.0.0.2" {
		t.Fatalf("clientIP with no XFF = %q, want RemoteAddr host %q", got, "10.0.0.2")
	}
}

func TestClientIP_UntrustedPeer_IgnoresSpoofedXFF(t *testing.T) {
	s := &Server{cfg: Config{TrustProxyHeaders: false}}

	// Directly internet-facing: two requests from the SAME peer but with DIFFERENT
	// forged XFF values MUST resolve to the SAME key (the observed RemoteAddr), so a
	// client cannot dodge the throttle by rotating a spoofed XFF.
	peer := "203.0.113.50:51000"
	a := s.clientIP(req(peer, "1.1.1.1"))
	b := s.clientIP(req(peer, "2.2.2.2"))
	if a != "203.0.113.50" {
		t.Fatalf("clientIP(a) = %q, want RemoteAddr host %q (XFF must be ignored)", a, "203.0.113.50")
	}
	if a != b {
		t.Fatalf("spoofed XFF must NOT change the key: got %q vs %q for the same peer", a, b)
	}
}
