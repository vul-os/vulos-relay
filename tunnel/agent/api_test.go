package agent

// api_test.go — coverage for the agent's PUBLIC surface + the two config-time
// helpers that gate a connect: validateOptions (which includes the SSRF loopback
// guard applied at configuration time) and controlURL (scheme normalization +
// enforcement). These are the reverse-tunnel connect path's front door and were
// previously exercised only indirectly by the full e2e harness.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestValidateOptions_RequiredFields asserts each mandatory field is enforced.
func TestValidateOptions_RequiredFields(t *testing.T) {
	base := Options{ServerURL: "wss://relay.test", Token: "t", Name: "box1", LocalAddr: "127.0.0.1:8080"}
	if err := validateOptions(base); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(o *Options)
		want   string
	}{
		{"no server", func(o *Options) { o.ServerURL = "  " }, "ServerURL"},
		{"no token", func(o *Options) { o.Token = "" }, "Token"},
		{"no name", func(o *Options) { o.Name = "\t" }, "Name"},
		{"no local", func(o *Options) { o.LocalAddr = "" }, "LocalAddr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.mutate(&o)
			err := validateOptions(o)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err, tc.want)
			}
		})
	}
}

// TestValidateOptions_SSRFLoopbackGuard is the config-time half of the SSRF guard:
// a non-loopback LocalAddr is refused before the agent ever starts (defense in
// depth on top of the per-stream re-check in serveStream).
func TestValidateOptions_SSRFLoopbackGuard(t *testing.T) {
	base := Options{ServerURL: "wss://relay.test", Token: "t", Name: "box1"}
	blocked := []string{
		"10.0.0.5:8080",      // RFC1918
		"192.168.1.1:80",     // RFC1918
		"169.254.169.254:80", // cloud metadata
		"172.16.0.1:8080",    // RFC1918
		"8.8.8.8:443",        // public
		"0.0.0.0:8080",       // unspecified
		"example.com:80",     // arbitrary hostname (never resolved)
		"metadata.google.internal:80",
		"[::]:8080", // unspecified v6
	}
	for _, addr := range blocked {
		o := base
		o.LocalAddr = addr
		if err := validateOptions(o); err == nil {
			t.Fatalf("SSRF guard let non-loopback target %q pass", addr)
		}
	}
	allowed := []string{"127.0.0.1:8080", "localhost:3000", "127.9.9.9:1", "[::1]:8080", "LocalHost:80"}
	for _, addr := range allowed {
		o := base
		o.LocalAddr = addr
		if err := validateOptions(o); err != nil {
			t.Fatalf("loopback target %q wrongly rejected: %v", addr, err)
		}
	}
	// A host with no port must be refused (host:port required).
	o := base
	o.LocalAddr = "127.0.0.1"
	if err := validateOptions(o); err == nil {
		t.Fatal("LocalAddr without port should be refused")
	}
}

// TestControlURL_SchemeNormalizationAndPath asserts https/wss→wss, http/ws→ws,
// base-path preservation + control path appended, query/fragment stripping, and
// rejection of unsupported schemes.
func TestControlURL_SchemeNormalizationAndPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://relay.test", "wss://relay.test" + controlPath},
		{"wss://relay.test", "wss://relay.test" + controlPath},
		{"http://relay.test:8443", "ws://relay.test:8443" + controlPath},
		{"ws://relay.test", "ws://relay.test" + controlPath},
		// A base path in front of the relay is preserved, trailing slash trimmed.
		{"https://relay.test/edge/", "wss://relay.test/edge" + controlPath},
		// Query + fragment are stripped (the control path carries no query).
		{"https://relay.test/?a=1#frag", "wss://relay.test" + controlPath},
	}
	for _, tc := range cases {
		got, err := controlURL(tc.in)
		if err != nil {
			t.Fatalf("controlURL(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("controlURL(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"ftp://relay.test", "tcp://relay.test", "relay.test", "://relay"} {
		if _, err := controlURL(bad); err == nil {
			t.Fatalf("controlURL(%q) should have failed", bad)
		}
	}
}

// TestSnapshot_NeverLeaksToken is a security-contract regression: the observable
// Snapshot / PublicURL surface must never carry the agent's bearer token, even in
// the log lines. A UI reads Snapshot, so a leak there is a token disclosure.
func TestSnapshot_NeverLeaksToken(t *testing.T) {
	const secret = "super-secret-bearer-DO-NOT-LEAK"
	a := New(Options{ServerURL: "wss://relay.test", Token: secret, Name: "box1", LocalAddr: "127.0.0.1:8080"})
	a.appendLog("connecting to %s for %q", a.opts.ServerURL, a.opts.Name)
	a.setStatus(StatusConnected, "https://box1.relay.test", "")
	snap := a.Snapshot()
	if snap.Status != StatusConnected {
		t.Fatalf("status=%q", snap.Status)
	}
	if a.PublicURL() != "https://box1.relay.test" {
		t.Fatalf("PublicURL=%q", a.PublicURL())
	}
	blob := snap.PublicURL + snap.LastError + strings.Join(snap.Log, "\n") + snap.DirectEndpoint + snap.DirectError
	if strings.Contains(blob, secret) {
		t.Fatal("Snapshot leaked the bearer token")
	}
}

// TestLifecycle_StopClearsPublicURL asserts Stop resets the observable state and
// PublicURL returns "" unless connected.
func TestLifecycle_StopClearsPublicURL(t *testing.T) {
	a := New(Options{ServerURL: "wss://relay.test", Token: "t", Name: "box1", LocalAddr: "127.0.0.1:8080"})
	// Not connected yet: PublicURL is empty even if a stale value was recorded.
	a.setStatus(StatusStarting, "https://stale.relay.test", "")
	if got := a.PublicURL(); got != "" {
		t.Fatalf("PublicURL while not connected = %q, want empty", got)
	}
	a.setStatus(StatusConnected, "https://box1.relay.test", "")
	if got := a.PublicURL(); got == "" {
		t.Fatal("PublicURL empty while connected")
	}
	a.Stop()
	if snap := a.Snapshot(); snap.Status != StatusStopped || snap.PublicURL != "" || snap.Connected {
		t.Fatalf("after Stop snapshot=%+v", snap)
	}
}

// TestAppendLog_BoundedToMaxLines asserts the in-memory log ring is capped so a
// long-lived agent cannot grow memory without bound.
func TestAppendLog_BoundedToMaxLines(t *testing.T) {
	a := New(Options{ServerURL: "wss://relay.test", Token: "t", Name: "box1", LocalAddr: "127.0.0.1:8080"})
	for i := 0; i < maxLogLines*3; i++ {
		a.appendLog("line %d", i)
	}
	if got := len(a.Snapshot().Log); got > maxLogLines {
		t.Fatalf("log grew to %d lines, cap is %d", got, maxLogLines)
	}
}

// TestStart_RequiresValidOptions asserts Start fails fast (before any dial) on
// invalid options — e.g. a non-loopback LocalAddr — and is idempotent otherwise.
func TestStart_RequiresValidOptions(t *testing.T) {
	a := New(Options{ServerURL: "wss://relay.test", Token: "t", Name: "box1", LocalAddr: "10.0.0.1:8080"})
	if err := a.Start(context.Background()); err == nil {
		t.Fatal("Start accepted a non-loopback LocalAddr (SSRF guard bypass)")
	}
}

// TestStart_DialHookErrorSurfacesAsErrorStatus drives the async maintain loop with
// an injected dial hook that always fails, and asserts the agent reports an error
// status without any real network — then Stop unwinds the loop cleanly.
func TestStart_DialHookErrorSurfacesAsErrorStatus(t *testing.T) {
	a := New(Options{
		ServerURL:        "wss://relay.test",
		Token:            "t",
		Name:             "box1",
		LocalAddr:        "127.0.0.1:8080",
		MaxBackoff:       10 * time.Millisecond,
		HandshakeTimeout: 50 * time.Millisecond,
	})
	a.dialHook = func(ctx context.Context) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer a.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.Snapshot().Status == StatusError {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("agent never reached error status; snapshot=%+v", a.Snapshot())
}
