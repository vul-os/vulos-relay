package server

// directprobe.go — DIRECT-IP: reachability + endpoint-OWNERSHIP verification for
// a box's advertised direct-connect endpoint.
//
// A box may advertise a direct endpoint (a public https:// base URL) alongside
// its relay tunnel so clients can dial it DIRECTLY for near-native latency + full
// bandwidth, falling back to the relay tunnel when direct fails. The relay MUST
// NOT take the box's word for the endpoint: an attacker box could otherwise
// advertise someone else's IP/hostname to (a) hijack that victim's client traffic
// or (b) point the relay's probe at an internal service (SSRF). So before the
// relay surfaces a direct endpoint to any client, verifyDirectEndpoint proves two
// things by GETting {endpoint}{wire.DirectProbePath} over the public internet:
//
//   1. REACHABILITY — the endpoint answers over TLS from the relay's vantage; a
//      firewalled/NAT'd endpoint that does not answer is NOT advertised (the box
//      transparently stays on the relay path).
//   2. OWNERSHIP — the relay sends a fresh 256-bit nonce in the DirectProbeHeader
//      and requires the box to echo it back in the response body. Only the box
//      that actually serves that TLS endpoint sees the nonce, so echoing it proves
//      the advertiser controls the endpoint. A box cannot advertise an endpoint it
//      does not serve: the victim host would not echo our nonce.
//
// SSRF POSTURE (mirrors the agent-side loopback guard): the probe target host is
// screened BEFORE any dial. It must be a public (non-loopback, non-private, non
// link-local, non-CGNAT, non-metadata, non-unspecified) address, and the URL must
// be https on the default port set. The custom dialer re-screens the RESOLVED IP
// at connect time (control), defeating DNS-rebind: a hostname that resolves to an
// internal IP is refused at the socket, not just at parse time. Redirects are not
// followed (a redirect could bounce us to an internal target after the fact).

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

// directProbeTimeout bounds the whole reachability+ownership probe.
const directProbeTimeout = 8 * time.Second

// directProbeMaxBody caps how many bytes of the probe response we read (we only
// need the echoed nonce, which is 64 hex chars).
const directProbeMaxBody = 1 << 10 // 1 KiB

// directEndpointVerifier verifies a box-advertised direct endpoint. It is a small
// interface so tests can substitute an in-memory verifier (the real one performs a
// real internet GET, which unit tests must not do). The default is httpDirectVerifier.
type directEndpointVerifier interface {
	// verify returns the normalized endpoint (scheme://host[:port], no trailing
	// slash) on success, or a non-nil error whose message is a short, non-leaky
	// reason on failure.
	verify(ctx context.Context, endpoint string) (normalized string, err error)
}

// httpDirectVerifier probes over real HTTPS with an SSRF-guarded dialer.
type httpDirectVerifier struct {
	// allowInsecure, when true, permits http:// endpoints and skips the public-IP
	// screen — TEST-ONLY (an httptest server binds 127.0.0.1). Never set in prod.
	allowInsecure bool
	// nonce, when non-empty, is used instead of a random one — TEST-ONLY determinism.
	nonce string
}

// verifyDirectEndpoint validates + probes a box's advertised direct endpoint. On
// success it returns the normalized endpoint to advertise to clients; on any
// failure it returns a non-leaky error. It NEVER returns a partially-trusted
// endpoint: either the endpoint is fully verified (reachable + owned) or it is
// refused and the box stays on the relay path.
func (v *httpDirectVerifier) verify(ctx context.Context, endpoint string) (string, error) {
	norm, host, err := normalizeDirectEndpoint(endpoint, v.allowInsecure)
	if err != nil {
		return "", err
	}
	// Screen the host FORM before any dial (parse-time SSRF guard). The dialer
	// below re-screens the RESOLVED IP at connect (defeats DNS-rebind).
	if !v.allowInsecure {
		if err := screenPublicHost(host); err != nil {
			return "", err
		}
	}

	nonce := v.nonce
	if nonce == "" {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("probe nonce")
		}
		nonce = hex.EncodeToString(b[:])
	}

	probeURL := norm + wire.DirectProbePath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", fmt.Errorf("probe request")
	}
	req.Header.Set(wire.DirectProbeHeader, nonce)

	client := &http.Client{
		Timeout: directProbeTimeout,
		// Never follow redirects: a 30x could bounce the probe to an internal
		// target AFTER the parse-time screen. Treat any redirect as a failure.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirect not allowed")
		},
		Transport: &http.Transport{
			// DialContext re-screens the resolved IP of the ACTUAL connection at
			// connect time — the anti-DNS-rebind control. It resolves the host,
			// screens every candidate IP, and dials only a screened one.
			DialContext:           v.guardedDial,
			TLSHandshakeTimeout:   directProbeTimeout,
			ResponseHeaderTimeout: directProbeTimeout,
			DisableKeepAlives:     true,
			MaxIdleConns:          1,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unreachable")
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, directProbeMaxBody))
	got := strings.TrimSpace(string(body))
	// Ownership proof: constant-time compare of the echoed nonce. Only a box that
	// actually served our probe over TLS saw the nonce, so echoing it proves
	// control of the endpoint.
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return "", fmt.Errorf("ownership proof failed")
	}
	return norm, nil
}

// guardedDial resolves the target host, screens EVERY resolved IP as public
// (unless allowInsecure), and dials the first screened address. If any resolved
// IP is internal the whole dial is refused — a hostname must not resolve to a
// private/loopback/metadata address (DNS-rebind defense at connect time).
func (v *httpDirectVerifier) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("bad addr")
	}
	if v.allowInsecure {
		// TEST-ONLY: dial as-is (httptest binds loopback).
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve failed")
	}
	// Refuse if ANY resolved IP is internal (defense-in-depth: a rebind attacker
	// may return one public + one internal answer; we take no chances).
	for _, ip := range ips {
		if !isPublicIP(ip.IP) {
			return nil, fmt.Errorf("resolves to non-public address")
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// normalizeDirectEndpoint parses + normalizes an advertised endpoint to
// "scheme://host[:port]" (no path/query/fragment, no trailing slash) and returns
// the host portion for screening. It enforces https (unless allowInsecure) and
// rejects any endpoint carrying a path/userinfo (which could smuggle a probe path
// or credentials).
func normalizeDirectEndpoint(endpoint string, allowInsecure bool) (normalized, host string, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", "", fmt.Errorf("empty endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("invalid endpoint")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure {
			return "", "", fmt.Errorf("not https")
		}
	default:
		return "", "", fmt.Errorf("not https")
	}
	if u.User != nil {
		return "", "", fmt.Errorf("userinfo not allowed")
	}
	// A direct endpoint is a BASE URL only. Reject a path/query/fragment so a box
	// cannot advertise "https://victim/some/path" or smuggle anything.
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("endpoint must be a bare origin")
	}
	h := u.Hostname()
	if h == "" {
		return "", "", fmt.Errorf("no host")
	}
	// Rebuild a canonical origin (drops any trailing slash + default-port noise is
	// preserved as given, which is fine for the probe URL).
	normalized = u.Scheme + "://" + u.Host
	return normalized, h, nil
}

// screenPublicHost rejects a host FORM that is (or literally is) a non-public
// address. A bare hostname is allowed here (it is re-screened at resolve time by
// guardedDial); an IP LITERAL must be public. This is the parse-time half of the
// SSRF guard; guardedDial is the connect-time half.
func screenPublicHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("non-public address")
		}
		return nil
	}
	// A hostname literal. Reject obvious internal names outright; the real defense
	// is guardedDial re-screening the resolved IP.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".local") {
		return fmt.Errorf("internal hostname")
	}
	return nil
}

// isPublicIP reports whether ip is a globally-routable public address: NOT
// loopback, private (RFC1918), link-local, CGNAT (RFC6598 100.64/10), the cloud
// metadata IP (169.254.169.254 is link-local so already covered), IPv6 ULA
// (fc00::/7), unspecified, or multicast.
//
// It ALSO screens IPv6 transition mechanisms that embed an IPv4 address, because
// on a host with a NAT64/6to4 gateway an address like 64:ff9b::7f00:1 (the
// well-known NAT64 prefix carrying 127.0.0.1) would otherwise route to an
// INTERNAL IPv4 target — an SSRF bypass that Go's stdlib predicates do not catch
// (To4() returns nil for these, so the v4 checks below never fire). We extract
// the embedded v4 and re-screen it. Teredo (2001::/32), 6to4 (2002::/16) and the
// NAT64 well-known prefix (64:ff9b::/96) are all covered; any other IPv6 that is
// not global-unicast is refused outright.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if ip.IsPrivate() { // RFC1918 v4 + ULA fc00::/7 v6
		return false
	}
	// CGNAT / shared address space 100.64.0.0/10 (RFC6598) — not IsPrivate() in Go.
	if v4 := ip.To4(); v4 != nil {
		return isPublicV4(v4)
	}
	// IPv6 from here on. Anything that is not global-unicast (e.g. reserved,
	// discard-only, documentation) is not a public dial target. Note: fc00::/7 ULA
	// is IsPrivate (handled above) but IsGlobalUnicast returns true for it, so this
	// check comes AFTER the IsPrivate screen, not instead of it.
	if !ip.IsGlobalUnicast() {
		return false
	}
	// IPv6 transition mechanisms that embed an IPv4 address must be re-screened
	// against that embedded v4 — a NAT64/6to4 gateway would otherwise route them to
	// an internal IPv4 host.
	if embedded := embeddedV4(ip); embedded != nil {
		return isPublicV4(embedded)
	}
	// 2001:db8::/32 documentation range (never a real target).
	if len(ip) == net.IPv6len && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}
	return true
}

// isPublicV4 screens a 4-byte IPv4 address for the non-public ranges Go's stdlib
// predicates miss (CGNAT + 0.0.0.0/8). It assumes loopback/private/link-local
// were already screened by the caller's stdlib checks, but re-applies them here so
// it is also safe to call on an IPv4 extracted from an IPv6 transition address.
func isPublicV4(v4 net.IP) bool {
	v4 = v4.To4()
	if v4 == nil {
		return false
	}
	// Re-apply the stdlib predicates: an embedded v4 pulled out of an IPv6
	// transition address never went through them.
	if v4.IsLoopback() || v4.IsUnspecified() || v4.IsPrivate() ||
		v4.IsLinkLocalUnicast() || v4.IsLinkLocalMulticast() || v4.IsMulticast() {
		return false
	}
	// CGNAT / shared address space 100.64.0.0/10 (RFC6598) — not IsPrivate() in Go.
	if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	// 0.0.0.0/8 "this network".
	if v4[0] == 0 {
		return false
	}
	// 192.0.0.0/24 IETF protocol assignments, 192.0.2.0/24 / 198.51.100.0/24 /
	// 203.0.113.0/24 documentation, 198.18.0.0/15 benchmarking, 240.0.0.0/4 reserved.
	switch {
	case v4[0] == 192 && v4[1] == 0 && v4[2] == 0:
		return false
	case v4[0] == 192 && v4[1] == 0 && v4[2] == 2:
		return false
	case v4[0] == 198 && v4[1] == 51 && v4[2] == 100:
		return false
	case v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
		return false
	case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19):
		return false
	case v4[0] >= 240:
		return false
	}
	return true
}

// embeddedV4 extracts the IPv4 address embedded in an IPv6 transition-mechanism
// address, or nil if there is none. It handles the NAT64 well-known prefix
// (64:ff9b::/96), 6to4 (2002::/16 carries the v4 in bytes 2..5) and Teredo
// (2001:0000::/32 carries the client v4, XOR-obfuscated, in the last 4 bytes).
func embeddedV4(ip net.IP) net.IP {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	// NAT64 well-known prefix 64:ff9b::/96 — the low 32 bits are the v4 target.
	if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	}
	// 6to4 2002::/16 — the embedded v4 is bytes 2..5.
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4()
	}
	// Teredo 2001:0000::/32 — the client v4 is the last 4 bytes, XORed with 0xff.
	if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 {
		return net.IPv4(ip[12]^0xff, ip[13]^0xff, ip[14]^0xff, ip[15]^0xff).To4()
	}
	return nil
}
