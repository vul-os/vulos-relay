package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// hopByHopHeaders are stripped in both directions (RFC 7230 §6.1). Connection's
// own listed tokens are additionally stripped below.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Te", "Trailer",
	"Transfer-Encoding", "Upgrade",
}

// handlePublic routes an inbound public request to the right agent session and
// proxies it over a fresh yamux stream.
func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	// Health check convenience.
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "ok agents=%d\n", s.registry.count())
		return
	}

	// DIRECT-IP: direct-endpoint discovery. A client asks the relay whether the
	// tunnel it is about to use has a VERIFIED direct endpoint, so it can attempt a
	// direct dial first and fall back to this relay tunnel on failure (ICE-like).
	// This only ever returns an endpoint the relay itself verified (reachable +
	// ownership-proven) — never the box's unverified claim. It is a read-only
	// lookup: it carries no user data and mutates nothing, so it needs no session
	// auth (the direct endpoint is a public URL by definition; knowing it grants no
	// access — the box's OWN auth stack still gates every request there).
	if r.URL.Path == wireDirectResolvePath {
		s.handleDirectResolve(w, r)
		return
	}

	// SFU-HOST REGISTRY (Vulos Meet SFU Phase 2). These are relay-owned control
	// endpoints, NOT tunnel-proxied paths, so they are matched here before the
	// name route. They are inert by default: resolve returns available=false and
	// register is refused unless EnableSFUHostRegistry is set (handlers enforce).
	switch r.URL.Path {
	case sfuHostRegisterPath:
		s.handleSFUHostRegister(w, r)
		return
	case sfuHostHeartbeatPath:
		s.handleSFUHostHeartbeat(w, r)
		return
	case sfuHostDeregisterPath:
		s.handleSFUHostDeregister(w, r)
		return
	case sfuHostResolvePath:
		s.handleSFUHostResolve(w, r)
		return
	case s2sNotifyPath:
		// CROSS-INSTANCE notify forwarding (MINST-06). A relay-owned control route,
		// NOT a tunnel-proxied path, so it is matched here before the name route. It
		// authenticates the origin box and forwards the bare notification to the
		// target box over the target's existing tunnel (SSRF-safe by construction).
		s.handleS2SNotify(w, r)
		return
	}

	name, trimmedPath, matched := s.route(r)
	if !matched {
		s.metrics.request(outcomeNoTunnel)
		http.Error(w, "no such tunnel", http.StatusNotFound)
		return
	}

	// WAVE34-RELAY-HARDEN: rate-limit inbound public requests. A global bucket
	// caps aggregate load across all tunnels; a per-agent bucket caps any single
	// tunnel. Both return 429 (with Retry-After) when exceeded. These are ON TOP
	// OF the per-agent stream cap below (which bounds concurrency, not rate).
	if !s.globalLimiter.allow() {
		s.metrics.rateLimitReject(limitGlobal)
		s.metrics.request(outcomeRateLimited)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "relay busy (rate limited)", http.StatusTooManyRequests)
		return
	}
	if !s.reqLimiter.allow(name) {
		s.metrics.rateLimitReject(limitPerReq)
		s.metrics.request(outcomeRateLimited)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many requests for this tunnel", http.StatusTooManyRequests)
		return
	}

	sess, ok := s.registry.lookup(name)
	if !ok {
		s.metrics.request(outcomeOffline)
		http.Error(w, "tunnel offline", http.StatusBadGateway)
		return
	}

	// WAVE24-RELAY-BILLING: mid-session entitlement gate (fail OPEN on a transient
	// CP blip — allowContinue keeps a live tunnel up on error). A definitive deny
	// (relay disabled / over quota) returns 402 so the box surfaces "upgrade/over
	// quota" rather than a generic error. Unbilled sessions (accountID "") pass.
	if !s.gate.allowContinue(sess.accountID) {
		// WAVE50: this is the mid-session over-quota/entitlement cut on the request
		// path (the 402). Count it as an over-quota cut + outcome.
		s.metrics.tunnelCut(cutOverQuota)
		s.metrics.request(outcomeOverQuota)
		s.logInfo("request cut: over quota / entitlement denied", logFields{Name: name, Account: sess.accountID, Reason: string(cutOverQuota)})
		http.Error(w, "relay quota exceeded or not permitted for this account", http.StatusPaymentRequired)
		return
	}

	if !sess.acquireStream() {
		s.metrics.request(outcomeBusy)
		http.Error(w, "tunnel busy", http.StatusServiceUnavailable)
		return
	}
	defer sess.releaseStream()

	// WAVE50-RELAY-OBSERVABILITY: track this in-flight stream.
	s.metrics.streamOpened()
	defer s.metrics.streamClosed()

	// Count this request as one metered session for the account.
	s.meter.addSession(sess.accountID)

	// Cap request body size (bounds memory / abuse); streaming still works up to cap.
	// Hold a reference to the counting wrapper so we can distinguish a
	// body-too-large overflow (→ 413) from a genuine gateway fault (→ 502) after the
	// forward write fails (CONSOLIDATION A-1).
	var bodyCounter *countingReadCloser
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)
		// Meter inbound (request) bytes for the account, and always count them into
		// the direction-bucketed proxied-bytes metric (WAVE50).
		acct := ""
		if s.meter.enabled() {
			acct = sess.accountID
		}
		bodyCounter = &countingReadCloser{rc: r.Body, meter: s.meter, account: acct, metrics: s.metrics}
		r.Body = bodyCounter
	}

	// Open a stream into the agent for this one request.
	stream, err := sess.mux.OpenStream()
	if err != nil {
		s.metrics.request(outcomeBadGateway)
		http.Error(w, "tunnel error", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	// Enforce RequestTimeout as a bound on how long the agent may take to accept the
	// forwarded request AND return response headers. Without this a HALF-DEAD agent —
	// one whose yamux keepalive still answers (so the session is not torn down) but
	// which never services this particular stream — would hold the stream slot and
	// the public client's connection open forever; once MaxStreamsPerAgent such
	// streams pile up the whole tunnel bricks (503 to everyone) with no recovery. The
	// deadline bounds time-to-headers only: it is CLEARED before the response body is
	// streamed, so legitimate long-lived responses (SSE, downloads) are unaffected.
	// A configured 0 (or negative) disables it. (Previously RequestTimeout was
	// defined + defaulted but never enforced — a dead knob.)
	if s.cfg.RequestTimeout > 0 {
		_ = stream.SetDeadline(time.Now().Add(s.cfg.RequestTimeout))
	}

	// Build the outbound request as the agent's local app should see it.
	outReq := r.Clone(r.Context())
	outReq.URL.Path = trimmedPath
	outReq.RequestURI = ""
	sanitizeRequestHeaders(outReq, r, s.cfg.TrustProxyHeaders)

	// WebSocket upgrade passthrough: if the client is upgrading, we cannot use the
	// normal buffered response path — we hijack and splice raw bytes.
	if isWebSocketUpgrade(r) {
		s.metrics.request(outcomeUpgrade)
		s.proxyWebSocket(w, outReq, stream, sess.accountID)
		return
	}

	// Write the request to the agent over the stream. If the write fails because
	// the inbound body exceeded MaxRequestBytes, MaxBytesReader surfaces a
	// *http.MaxBytesError; return a clean 413 (with the limit echoed) so the box UI
	// can tell the user "file too big for a single upload" instead of a confusing
	// gateway error. Any other write error is a genuine tunnel/gateway fault (502).
	// (CONSOLIDATION A-1)
	if err := outReq.Write(stream); err != nil {
		// req.Write wraps the body-read failure in an unexported
		// http.requestBodyReadError that does NOT unwrap to *http.MaxBytesError, so
		// we consult the counting wrapper (which saw the read error at the source)
		// rather than errors.As on this err.
		if bodyCounter != nil && bodyCounter.overLimit {
			s.metrics.request(outcomeBadGateway)
			w.Header().Set("Connection", "close")
			http.Error(w, fmt.Sprintf("request body too large (limit %d bytes)", s.cfg.MaxRequestBytes), http.StatusRequestEntityTooLarge)
			return
		}
		s.metrics.request(outcomeBadGateway)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// Read the agent's response and copy it back to the public client.
	br := bufio.NewReader(stream)
	resp, err := http.ReadResponse(br, outReq)
	if err != nil {
		s.metrics.request(outcomeBadGateway)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Response headers are in hand: clear the deadline so the body may stream for as
	// long as it needs (SSE / large downloads must not be cut mid-body).
	_ = stream.SetDeadline(time.Time{})

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	s.metrics.request(outcomeOK)
	// Meter outbound (response) bytes for the account AS THEY STREAM to the client —
	// incrementally, per chunk (see meterReader), NOT only at io.Copy completion — so
	// a long-lived SSE stream or a large download is captured by periodic flushes and
	// by the shutdown drain instead of being lost if the process is killed mid-stream.
	// WAVE50: bytes are always counted in the direction-bucketed proxied-bytes metric,
	// regardless of whether per-account billing is enabled.
	outAcct := ""
	if s.meter.enabled() {
		outAcct = sess.accountID
	}
	_, _ = io.Copy(w, &meterReader{r: resp.Body, meter: s.meter, account: outAcct, metrics: s.metrics, dir: dirOutbound})
}

// route resolves an inbound request to a tunnel name. Subdomain mode is primary;
// path mode (/t/<name>/…) is the fallback when enabled. Returns the name, the path
// to forward to the agent, and whether a route matched.
func (s *Server) route(r *http.Request) (name, path string, ok bool) {
	// Subdomain mode: <name>.<domain>.
	if n := s.nameFromHost(r.Host); n != "" {
		return n, r.URL.Path, true
	}
	// Path mode fallback.
	if s.cfg.EnablePathMode {
		if n, rest, ok := nameFromPath(r.URL.Path); ok {
			return n, rest, true
		}
	}
	return "", "", false
}

// nameFromHost extracts <name> from "<name>.<domain>[:port]". Returns "" if the
// host is exactly the base domain or doesn't match.
func (s *Server) nameFromHost(host string) string {
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	base := strings.ToLower(s.cfg.Domain)
	suffix := "." + base
	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	label := strings.TrimSuffix(host, suffix)
	// Must be a single label (no further dots) — no nested wildcards.
	if label == "" || strings.Contains(label, ".") {
		return ""
	}
	return normalizeName(label)
}

// nameFromPath extracts <name> and the rest-of-path from "/t/<name>/rest".
func nameFromPath(p string) (name, rest string, ok bool) {
	const prefix = "/t/"
	if !strings.HasPrefix(p, prefix) {
		return "", "", false
	}
	tail := p[len(prefix):]
	slash := strings.IndexByte(tail, '/')
	if slash < 0 {
		// "/t/<name>" with no trailing slash -> forward "/".
		n := normalizeName(tail)
		if n == "" {
			return "", "", false
		}
		return n, "/", true
	}
	n := normalizeName(tail[:slash])
	if n == "" {
		return "", "", false
	}
	return n, tail[slash:], true
}

func (s *Server) publicURL(name string) string {
	return fmt.Sprintf("%s://%s.%s", s.cfg.PublicScheme, name, s.cfg.Domain)
}

// sanitizeRequestHeaders strips hop-by-hop headers and sets X-Forwarded-* so the
// agent's local app sees correct client metadata without trusting agent input.
//
// SECURITY (ingress-choke-point spoofing): the relay is the trust boundary. A
// PUBLIC client is untrusted and can send ANY X-Forwarded-For / X-Real-IP /
// X-Forwarded-Proto value. If the relay merely APPENDED to a client-supplied XFF,
// that forged value would be the leftmost entry — exactly what the box's app reads
// as "the real client IP" for IP allowlists, rate-limits, audit logs and geo.
//
// Default posture (trustProxy=false — the relay is DIRECTLY internet-facing, e.g.
// ListenAndServeTLS): OVERWRITE the forwarding headers with the OBSERVED peer.
// Whatever the client sent is discarded; the app sees only the relay's own
// verdict. This is the safe default for the single reachability ingress.
//
// trustProxy=true: the relay runs behind ITS OWN trusted TLS-terminating edge/CDN
// (e.g. Fly's proxy, the fly.toml deployment) which has already validated and set
// XFF. In that ONE topology the incoming XFF is trustworthy, so we append the
// peer (the edge) to preserve the real client chain. Only enable this when a
// trusted proxy actually fronts the relay — enabling it while directly exposed
// re-opens the spoof.
func sanitizeRequestHeaders(out, orig *http.Request, trustProxy bool) {
	stripHopByHop(out.Header)

	clientIP, _, _ := net.SplitHostPort(orig.RemoteAddr)
	if clientIP == "" {
		clientIP = orig.RemoteAddr
	}

	if trustProxy {
		// Trusted upstream edge already set XFF; append the peer (the edge) so the
		// real client chain is preserved.
		if prior := orig.Header.Get("X-Forwarded-For"); prior != "" {
			out.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			out.Header.Set("X-Forwarded-For", clientIP)
		}
	} else {
		// Directly internet-facing: the client is untrusted. OVERWRITE any
		// client-supplied forwarding headers with the observed peer so a forged XFF
		// prefix cannot spoof the source IP the box's app sees. Also drop X-Real-IP
		// (a common alias) so it cannot smuggle a spoofed value past the app.
		out.Header.Set("X-Forwarded-For", clientIP)
		out.Header.Set("X-Real-IP", clientIP)
	}
	out.Header.Set("X-Forwarded-Host", orig.Host)

	scheme := "https"
	switch {
	case orig.TLS != nil:
		// The relay itself terminated TLS — authoritative.
		scheme = "https"
	case trustProxy && orig.Header.Get("X-Forwarded-Proto") != "":
		// Behind a trusted terminating proxy: honor its X-Forwarded-Proto.
		scheme = orig.Header.Get("X-Forwarded-Proto")
	case orig.TLS == nil:
		// Directly plain (no trusted proxy): a client-supplied X-Forwarded-Proto is
		// untrusted and ignored; assume http.
		scheme = "http"
	}
	out.Header.Set("X-Forwarded-Proto", scheme)
}

func copyResponseHeaders(dst, src http.Header) {
	stripHopByHop(src)
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// stripHopByHop removes standard hop-by-hop headers plus any listed in Connection.
func stripHopByHop(h http.Header) {
	for _, tok := range strings.Split(h.Get("Connection"), ",") {
		if t := strings.TrimSpace(tok); t != "" {
			h.Del(t)
		}
	}
	for _, hh := range hopByHopHeaders {
		h.Del(hh)
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, tok := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

// clientIP resolves the per-source key used for the control-plane rate limiters
// (ctrlLimiter: control connects, S2S-notify, SFU-host) and for audit logging.
//
// SECURITY (trusted-edge client-IP resolution — same class as the resolver used
// elsewhere in the suite): the key MUST identify the real caller, not whatever
// hop the relay happens to observe.
//
//   - TrustProxyHeaders=true: the relay runs behind ITS OWN trusted TLS-
//     terminating edge (the fly.toml deployment), so RemoteAddr is the EDGE IP
//     for EVERY connection — keying on it collapses the whole fleet into ONE
//     shared bucket (per-source throttle defeated; a fleet reconnecting after a
//     redeploy false-throttles itself). We therefore key on the LEFT-MOST
//     X-Forwarded-For entry (the real client). This is the SAME header, from the
//     SAME trusted edge, that sanitizeRequestHeaders (proxy.go) already trusts as
//     the client IP for the box's app in this exact mode. Fall back to RemoteAddr
//     when XFF is absent/empty.
//
//   - TrustProxyHeaders=false: the relay is directly internet-facing and the peer
//     is UNTRUSTED — a client could forge XFF to spoof its rate-limit identity, so
//     we key strictly on the observed RemoteAddr and ignore XFF entirely.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		// Left-most XFF entry is the real client (the edge appends the peer; see
		// sanitizeRequestHeaders). Only trusted because a trusted edge fronts us.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); first != "" {
				return first
			}
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
