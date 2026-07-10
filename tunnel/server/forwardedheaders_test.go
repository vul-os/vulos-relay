// forwardedheaders_test.go — security-contract regression for the forwarding
// headers (X-Forwarded-For / -Proto / X-Real-IP) the relay sets on requests it
// hands to the box's app.
//
// The relay is the ingress trust boundary. A PUBLIC client is untrusted and can
// send any X-Forwarded-For / X-Real-IP / X-Forwarded-Proto. If a forged value
// survived to the box's app it would spoof "the real client IP" that IP
// allowlists, rate-limits, audit logs and geo all read.
//
// Contract:
//   - trustProxy=false (default, directly internet-facing): client-supplied
//     forwarding headers are DISCARDED and overwritten with the observed peer.
//   - trustProxy=true (behind a trusted TLS-terminating edge): the incoming XFF is
//     trusted and the peer is appended to preserve the real client chain.
package server

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// fakeTLSState is a non-nil ConnectionState used to signal "the relay terminated
// TLS itself" in tests (only its non-nilness matters to sanitizeRequestHeaders).
var fakeTLSState = tls.ConnectionState{}

func mkReq(remoteAddr string, tls bool, hdr map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://box1.relay.test/x", nil)
	r.RemoteAddr = remoteAddr
	r.Host = "box1.relay.test"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if tls {
		// A non-nil ConnectionState signals the relay terminated TLS itself.
		r.TLS = &fakeTLSState
	}
	return r
}

func TestForwardedHeaders_DirectExposure_OverwritesSpoof(t *testing.T) {
	// A malicious public client forges XFF/X-Real-IP/-Proto. Directly internet-
	// facing (trustProxy=false), all of it must be discarded and replaced with the
	// observed peer.
	orig := mkReq("203.0.113.9:5555", false, map[string]string{
		"X-Forwarded-For":   "1.2.3.4, 5.6.7.8", // forged chain
		"X-Real-IP":         "9.9.9.9",          // forged
		"X-Forwarded-Proto": "https",            // forged (relay is plain http here)
	})
	out := orig.Clone(orig.Context())

	sanitizeRequestHeaders(out, orig, false /*trustProxy*/)

	if got := out.Header.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Errorf("X-Forwarded-For = %q, want %q (forged chain must be overwritten)", got, "203.0.113.9")
	}
	if got := out.Header.Get("X-Real-IP"); got != "203.0.113.9" {
		t.Errorf("X-Real-IP = %q, want %q (forged value must be overwritten)", got, "203.0.113.9")
	}
	// Plain HTTP + untrusted client ⇒ scheme is http, NOT the client's forged https.
	if got := out.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q (forged proto must be ignored)", got, "http")
	}
}

func TestForwardedHeaders_DirectExposure_TLS_ProtoAuthoritative(t *testing.T) {
	// The relay itself terminated TLS: X-Forwarded-Proto is authoritative https
	// regardless of what the client claimed.
	orig := mkReq("203.0.113.9:5555", true, map[string]string{"X-Forwarded-Proto": "http"})
	out := orig.Clone(orig.Context())
	sanitizeRequestHeaders(out, orig, false)
	if got := out.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https (relay terminated TLS)", got)
	}
	if got := out.Header.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Errorf("X-Forwarded-For = %q, want observed peer", got)
	}
}

func TestForwardedHeaders_TrustedProxy_PreservesChain(t *testing.T) {
	// Behind a trusted edge (trustProxy=true): the edge already validated + set XFF,
	// so the real client chain is preserved and the peer (the edge) is appended.
	orig := mkReq("10.0.0.2:443", false, map[string]string{
		"X-Forwarded-For":   "198.51.100.7", // real client, set by the trusted edge
		"X-Forwarded-Proto": "https",        // edge terminated TLS
	})
	out := orig.Clone(orig.Context())

	sanitizeRequestHeaders(out, orig, true /*trustProxy*/)

	if got, want := out.Header.Get("X-Forwarded-For"), "198.51.100.7, 10.0.0.2"; got != want {
		t.Errorf("X-Forwarded-For = %q, want %q (chain preserved + peer appended)", got, want)
	}
	if got := out.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https (trusted edge's proto honored)", got)
	}
}
