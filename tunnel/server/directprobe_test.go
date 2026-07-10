// directprobe_test.go — DIRECT-IP: coverage for the relay-side reachability +
// endpoint-ownership verification and the client-facing discovery endpoint.
//
// The properties proven here:
//
//  1. REACHABLE + OWNED  ⇒ advertised. A box that serves the probe path AND
//     echoes the relay's nonce is verified and its endpoint is surfaced.
//  2. FIREWALLED/UNREACHABLE ⇒ NOT advertised. A box the relay cannot reach is
//     dropped; verification returns "unreachable".
//  3. OWNERSHIP CANNOT BE SPOOFED. A box that answers the probe but does NOT echo
//     the correct nonce (i.e. does not actually control the endpoint / cannot see
//     the relay's per-probe secret) is refused with "ownership proof failed" — so
//     a box cannot advertise a victim host it does not control.
//  4. SSRF: the probe screens the target and refuses internal/loopback/metadata
//     targets (parse-time) and DNS-rebind (connect-time resolved-IP screen).
//  5. HTTPS REQUIRED: an http:// (cleartext) endpoint is refused.
package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

func parseIPHelper(s string) net.IP { return net.ParseIP(s) }

// probeBox starts an httptest.Server that behaves like a box's public listener.
// echoNonce controls whether it echoes the relay's probe nonce (ownership proof).
// servePath controls whether it serves the probe path at all (reachability).
func probeBox(t *testing.T, echoNonce, servePath bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if servePath {
		mux.HandleFunc(wire.DirectProbePath, func(w http.ResponseWriter, r *http.Request) {
			nonce := r.Header.Get(wire.DirectProbeHeader)
			if echoNonce {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(nonce))
				return
			}
			// Answers, but with the WRONG body — does not prove ownership.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("i-do-not-know-the-nonce"))
		})
	}
	srv := httptest.NewServer(mux) // http (not TLS) — verifier runs in allowInsecure test mode
	t.Cleanup(srv.Close)
	return srv
}

// insecureVerifier is the verifier configured for loopback httptest servers: it
// permits http and skips the public-IP screen (which would reject 127.0.0.1). The
// nonce-echo ownership check is UNCHANGED — that is the property under test.
func insecureVerifier() *httpDirectVerifier {
	return &httpDirectVerifier{allowInsecure: true}
}

func TestDirect_Verify_ReachableAndOwned(t *testing.T) {
	box := probeBox(t, true /*echo*/, true /*serve*/)
	v := insecureVerifier()
	norm, err := v.verify(context.Background(), box.URL)
	if err != nil {
		t.Fatalf("reachable+owned endpoint should verify, got err=%v", err)
	}
	if norm != strings.TrimRight(box.URL, "/") {
		t.Fatalf("normalized endpoint = %q, want %q", norm, box.URL)
	}
}

func TestDirect_Verify_UnreachableNotAdvertised(t *testing.T) {
	// A box that does not serve the probe path (proxy/firewall drops it → 404).
	box := probeBox(t, true, false /*no serve*/)
	v := insecureVerifier()
	if _, err := v.verify(context.Background(), box.URL); err == nil {
		t.Fatal("unreachable/firewalled endpoint must NOT verify")
	}

	// A box that is entirely down (closed port): point at a URL nothing listens on.
	down := probeBox(t, true, true)
	down.Close() // close so the address refuses connections
	if _, err := v.verify(context.Background(), down.URL); err == nil {
		t.Fatal("a closed endpoint must fail verification (unreachable)")
	}
}

func TestDirect_Verify_OwnershipCannotBeSpoofed(t *testing.T) {
	// The box answers the probe (reachable) but does NOT echo the nonce — it does
	// not control the per-probe secret, so it cannot prove ownership. This is the
	// hijack defense: advertising a victim host you don't control fails here.
	box := probeBox(t, false /*wrong body*/, true)
	v := insecureVerifier()
	_, err := v.verify(context.Background(), box.URL)
	if err == nil {
		t.Fatal("a box that cannot echo the nonce must FAIL ownership verification")
	}
	if !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("expected an ownership-proof failure, got %v", err)
	}
}

func TestDirect_Verify_RequiresHTTPS(t *testing.T) {
	// The PRODUCTION verifier (allowInsecure=false) must refuse a cleartext http://
	// endpoint before any dial — no cleartext fast path.
	v := &httpDirectVerifier{} // production posture
	if _, err := v.verify(context.Background(), "http://example.com"); err == nil {
		t.Fatal("cleartext http:// endpoint must be refused (TLS required)")
	} else if !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected an https-required error, got %v", err)
	}
}

func TestDirect_Verify_SSRF_BlocksInternalTargets(t *testing.T) {
	// The PRODUCTION verifier must refuse internal/loopback/metadata/private targets
	// at parse time (the connect-time resolved-IP screen is the second layer).
	v := &httpDirectVerifier{}
	blocked := []string{
		"https://127.0.0.1",               // loopback
		"https://localhost",               // loopback name
		"https://10.0.0.5",                // RFC1918
		"https://192.168.1.1",             // RFC1918
		"https://172.16.0.1",              // RFC1918
		"https://169.254.169.254",         // cloud metadata (link-local)
		"https://100.64.0.1",              // CGNAT (RFC6598)
		"https://[::1]",                   // IPv6 loopback
		"https://[fd00::1]",               // IPv6 ULA
		"https://[fe80::1]",               // IPv6 link-local
		"https://0.0.0.0",                 // unspecified
		"https://box.internal",            // internal hostname suffix
		"https://foo.local",               // .local suffix
		"https://x.example.com/some/path", // path smuggling
		"https://user:pw@example.com",     // userinfo
		"http://example.com",              // cleartext
	}
	for _, ep := range blocked {
		if _, err := v.verify(context.Background(), ep); err == nil {
			t.Errorf("SSRF/validation FAILED OPEN: verify(%q) was allowed", ep)
		}
	}
}

func TestDirect_isPublicIP(t *testing.T) {
	notPublic := []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.0.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "fd00::1", "fe80::1",
		"224.0.0.1", // multicast
	}
	for _, s := range notPublic {
		if ip := parseIPHelper(s); isPublicIP(ip) {
			t.Errorf("isPublicIP(%q) = true, want false", s)
		}
	}
	public := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
	for _, s := range public {
		if ip := parseIPHelper(s); !isPublicIP(ip) {
			t.Errorf("isPublicIP(%q) = false, want true", s)
		}
	}
}

// TestDirect_isPublicIP_IPv6TransitionSSRF is a security-contract regression: an
// IPv6 transition address (NAT64 / 6to4 / Teredo) that EMBEDS a private/loopback
// IPv4 must NOT be treated as public. On a host with a NAT64/6to4 gateway such an
// address routes to an INTERNAL IPv4 target, so screening only the outer IPv6
// (which Go's stdlib predicates report as global-unicast) is an SSRF bypass. The
// embedded v4 must be extracted and re-screened.
func TestDirect_isPublicIP_IPv6TransitionSSRF(t *testing.T) {
	mustBlock := []struct{ addr, why string }{
		{"64:ff9b::7f00:1", "NAT64 well-known prefix embedding 127.0.0.1 (loopback)"},
		{"64:ff9b::a00:1", "NAT64 embedding 10.0.0.1 (RFC1918)"},
		{"64:ff9b::c0a8:1", "NAT64 embedding 192.168.0.1 (RFC1918)"},
		{"64:ff9b::a9fe:a9fe", "NAT64 embedding 169.254.169.254 (cloud metadata)"},
		{"64:ff9b::6440:1", "NAT64 embedding 100.64.0.1 (CGNAT)"},
		{"2002:7f00:1::1", "6to4 embedding 127.0.0.1 (loopback)"},
		{"2002:a00:1::1", "6to4 embedding 10.0.0.1 (RFC1918)"},
		{"2002:a9fe:a9fe::1", "6to4 embedding 169.254.169.254 (cloud metadata)"},
		{"2001:db8::1", "IPv6 documentation range (never a real target)"},
	}
	for _, tc := range mustBlock {
		ip := parseIPHelper(tc.addr)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse", tc.addr)
		}
		if isPublicIP(ip) {
			t.Errorf("SSRF bypass: isPublicIP(%q) = true, want false — %s", tc.addr, tc.why)
		}
	}

	// A NAT64/6to4 address embedding a genuinely PUBLIC v4 stays reachable (we must
	// not over-block legitimate transition traffic to public hosts).
	mustAllow := []struct{ addr, why string }{
		{"64:ff9b::808:808", "NAT64 embedding 8.8.8.8 (public)"},
		{"2002:0808:0808::1", "6to4 embedding 8.8.8.8 (public)"},
	}
	for _, tc := range mustAllow {
		ip := parseIPHelper(tc.addr)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse", tc.addr)
		}
		if !isPublicIP(ip) {
			t.Errorf("over-block: isPublicIP(%q) = false, want true — %s", tc.addr, tc.why)
		}
	}
}
