package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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

	name, trimmedPath, matched := s.route(r)
	if !matched {
		http.Error(w, "no such tunnel", http.StatusNotFound)
		return
	}
	sess, ok := s.registry.lookup(name)
	if !ok {
		http.Error(w, "tunnel offline", http.StatusBadGateway)
		return
	}

	// WAVE24-RELAY-BILLING: mid-session entitlement gate (fail OPEN on a transient
	// CP blip — allowContinue keeps a live tunnel up on error). A definitive deny
	// (relay disabled / over quota) returns 402 so the box surfaces "upgrade/over
	// quota" rather than a generic error. Unbilled sessions (accountID "") pass.
	if !s.gate.allowContinue(sess.accountID) {
		http.Error(w, "relay quota exceeded or not permitted for this account", http.StatusPaymentRequired)
		return
	}

	if !sess.acquireStream() {
		http.Error(w, "tunnel busy", http.StatusServiceUnavailable)
		return
	}
	defer sess.releaseStream()

	// Count this request as one metered session for the account.
	s.meter.addSession(sess.accountID)

	// Cap request body size (bounds memory / abuse); streaming still works up to cap.
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)
		// Meter inbound (request) bytes for the account.
		if s.meter.enabled() && sess.accountID != "" {
			r.Body = &countingReadCloser{rc: r.Body, meter: s.meter, account: sess.accountID}
		}
	}

	// Open a stream into the agent for this one request.
	stream, err := sess.mux.OpenStream()
	if err != nil {
		http.Error(w, "tunnel error", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	// Build the outbound request as the agent's local app should see it.
	outReq := r.Clone(r.Context())
	outReq.URL.Path = trimmedPath
	outReq.RequestURI = ""
	sanitizeRequestHeaders(outReq, r)

	// WebSocket upgrade passthrough: if the client is upgrading, we cannot use the
	// normal buffered response path — we hijack and splice raw bytes.
	if isWebSocketUpgrade(r) {
		s.proxyWebSocket(w, outReq, stream, sess.accountID)
		return
	}

	// Write the request to the agent over the stream.
	if err := outReq.Write(stream); err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// Read the agent's response and copy it back to the public client.
	br := bufio.NewReader(stream)
	resp, err := http.ReadResponse(br, outReq)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	// Meter outbound (response) bytes for the account as they stream to the client.
	if s.meter.enabled() && sess.accountID != "" {
		n, _ := io.Copy(w, resp.Body)
		s.meter.addBytes(sess.accountID, n)
	} else {
		_, _ = io.Copy(w, resp.Body)
	}
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
func sanitizeRequestHeaders(out, orig *http.Request) {
	stripHopByHop(out.Header)

	clientIP, _, _ := net.SplitHostPort(orig.RemoteAddr)
	if clientIP == "" {
		clientIP = orig.RemoteAddr
	}
	// Append to any existing X-Forwarded-For chain.
	if prior := out.Header.Get("X-Forwarded-For"); prior != "" {
		out.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		out.Header.Set("X-Forwarded-For", clientIP)
	}
	out.Header.Set("X-Forwarded-Host", orig.Host)
	scheme := "https"
	if orig.TLS == nil && orig.Header.Get("X-Forwarded-Proto") == "" {
		// Behind a terminating proxy TLS==nil; trust its X-Forwarded-Proto if set,
		// else assume http for a directly-plain listener.
		scheme = "http"
	}
	if xfp := orig.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
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

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
