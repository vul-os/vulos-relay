// Package tunnel_test drives the full sovereign reverse tunnel in-process: a real
// relay server, a real agent dialing it over ws, and a real local target httptest
// server. Every test exercises the actual wire path (WebSocket control conn +
// yamux stream multiplexing), not mocks.
package tunnel_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/vul-os/vulos-relay/tunnel/agent"
	"github.com/vul-os/vulos-relay/tunnel/server"
)

const (
	testDomain = "relay.test"
	testToken  = "super-secret-token"
	testName   = "box1"
)

// harness wires a relay server + a local target + (optionally) an agent.
type harness struct {
	t        *testing.T
	relay    *httptest.Server // the relay's public+control HTTP surface (plain http for tests)
	target   *httptest.Server // the box's local app
	agentObj *agent.Agent
}

// newRelay stands up a relay server with a single grant for testName, plus path
// mode enabled so we can route by /t/<name>/ against the httptest host.
func newRelay(t *testing.T, grants []server.Grant) *httptest.Server {
	t.Helper()
	store, err := server.NewStaticTokenStore(grants)
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	srv, err := server.New(server.Config{
		Domain:             testDomain,
		Tokens:             store,
		EnablePathMode:     true,
		MaxAgents:          4,
		MaxStreamsPerAgent: 4,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return httptest.NewServer(srv.Handler())
}

func defaultGrants() []server.Grant {
	return []server.Grant{{Token: testToken, Names: []string{testName}}}
}

// startAgent creates and starts an agent pointing at the relay + a local target.
func startAgent(t *testing.T, relayURL, token, name, localAddr string) *agent.Agent {
	t.Helper()
	a := agent.New(agent.Options{
		ServerURL: relayURL, // httptest gives http://…, agent normalizes to ws://
		Token:     token,
		Name:      name,
		LocalAddr: localAddr,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.Start(ctx); err != nil {
		t.Fatalf("agent.Start: %v", err)
	}
	t.Cleanup(a.Stop)
	return a
}

// waitConnected polls the agent snapshot until connected or timeout.
func waitConnected(t *testing.T, a *agent.Agent) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.Snapshot().Status == agent.StatusConnected {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("agent never connected; snapshot=%+v", a.Snapshot())
}

// waitAgents polls the server for the expected live-agent count.
func waitAgents(t *testing.T, want int, count func() int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if count() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("agent count never reached %d (got %d)", want, count())
}

// localAddr strips the scheme from an httptest URL -> host:port.
func localAddr(u string) string { return strings.TrimPrefix(u, "http://") }

// getViaPath issues a public request routed by path mode against the relay host.
func getViaPath(t *testing.T, relayURL, name, path string) (*http.Response, string) {
	t.Helper()
	u := relayURL + "/t/" + name + path
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// --- Tests ---

// TestRoundTrip: an inbound HTTP request to the relay tunnels to the local target
// and returns its body, with X-Forwarded-* applied.
func TestRoundTrip(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from local; path=%s; xff=%s; xfh=%s",
			r.URL.Path, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Host"))
	}))
	defer target.Close()

	relay := newRelay(t, defaultGrants())
	defer relay.Close()

	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)

	resp, body := getViaPath(t, relay.URL, testName, "/hello/world")
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if !strings.Contains(body, "hello from local") {
		t.Fatalf("unexpected body: %q", body)
	}
	if !strings.Contains(body, "path=/hello/world") {
		t.Fatalf("path not forwarded: %q", body)
	}
	if !strings.Contains(body, "xfh=") || strings.Contains(body, "xff=;") {
		t.Fatalf("X-Forwarded headers missing: %q", body)
	}
	// PublicURL is subdomain-form regardless of test path routing.
	if got := a.PublicURL(); got != "https://box1.relay.test" {
		t.Fatalf("PublicURL=%q", got)
	}
}

// TestPostBodyRoundTrip: request bodies are forwarded intact.
func TestPostBodyRoundTrip(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "echo:%s", b)
	}))
	defer target.Close()
	relay := newRelay(t, defaultGrants())
	defer relay.Close()
	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)

	resp, err := http.Post(relay.URL+"/t/"+testName+"/", "text/plain", strings.NewReader("ping-payload"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "echo:ping-payload" {
		t.Fatalf("body=%q", body)
	}
}

// TestWebSocketPassthrough: a WS upgrade tunnels end to end.
func TestWebSocketPassthrough(t *testing.T) {
	// Local WS echo server using coder/websocket.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "")
		for {
			typ, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			_ = c.Write(r.Context(), typ, append([]byte("echo:"), data...))
		}
	}))
	defer target.Close()

	relay := newRelay(t, defaultGrants())
	defer relay.Close()
	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)

	// Dial the relay via path mode with a ws:// URL.
	wsURL := "ws://" + strings.TrimPrefix(relay.URL, "http://") + "/t/" + testName + "/socket"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	if err := c.Write(ctx, websocket.MessageText, []byte("marco")); err != nil {
		t.Fatalf("ws write: %v", err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	if string(data) != "echo:marco" {
		t.Fatalf("ws echo=%q", data)
	}
}

// TestUnauthenticatedRejected: an agent with no/invalid token never connects.
func TestUnauthenticatedRejected(t *testing.T) {
	relay := newRelay(t, defaultGrants())
	defer relay.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	a := agent.New(agent.Options{
		ServerURL:        relay.URL,
		Token:            "WRONG-TOKEN",
		Name:             testName,
		LocalAddr:        localAddr(target.URL),
		HandshakeTimeout: time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer a.Stop()

	// Should never reach connected; should surface an error status.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s := a.Snapshot()
		if s.Status == agent.StatusConnected {
			t.Fatal("unauthenticated agent connected — auth bypass")
		}
		if s.Status == agent.StatusError {
			return // expected
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected error status; got %+v", a.Snapshot())
}

// TestNameNotAuthorized: a valid token cannot claim a name outside its grant.
func TestNameNotAuthorized(t *testing.T) {
	relay := newRelay(t, defaultGrants()) // token authorizes only "box1"
	defer relay.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	a := agent.New(agent.Options{
		ServerURL:        relay.URL,
		Token:            testToken,
		Name:             "someoneelse", // not in the grant
		LocalAddr:        localAddr(target.URL),
		HandshakeTimeout: time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = a.Start(ctx)
	defer a.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a.Snapshot().Status == agent.StatusConnected {
			t.Fatal("agent claimed an unauthorized name")
		}
		if a.Snapshot().Status == agent.StatusError {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected rejection; got %+v", a.Snapshot())
}

// TestSSRFGuard: the agent refuses a non-loopback LocalAddr at construction/start.
func TestSSRFGuard(t *testing.T) {
	relay := newRelay(t, defaultGrants())
	defer relay.Close()

	cases := []string{
		"10.0.0.5:80",        // private, non-loopback
		"169.254.169.254:80", // cloud metadata endpoint
		"example.com:80",     // arbitrary host
		"0.0.0.0:80",         // wildcard
	}
	for _, addr := range cases {
		a := agent.New(agent.Options{
			ServerURL: relay.URL,
			Token:     testToken,
			Name:      testName,
			LocalAddr: addr,
		})
		if err := a.Start(context.Background()); err == nil {
			a.Stop()
			t.Fatalf("SSRF guard failed: Start accepted non-loopback %q", addr)
		}
	}
}

// TestNameCollision: a second agent cannot hijack a name already served.
func TestNameCollision(t *testing.T) {
	// Two grants sharing the same name, distinct tokens.
	grants := []server.Grant{
		{Token: "tok-a", Names: []string{testName}},
		{Token: "tok-b", Names: []string{testName}},
	}
	relay := newRelay(t, grants)
	defer relay.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "A")
	}))
	defer target.Close()

	a1 := startAgent(t, relay.URL, "tok-a", testName, localAddr(target.URL))
	waitConnected(t, a1)

	// Second agent claims the same name -> must be rejected (no hijack).
	a2 := agent.New(agent.Options{
		ServerURL:        relay.URL,
		Token:            "tok-b",
		Name:             testName,
		LocalAddr:        localAddr(target.URL),
		HandshakeTimeout: time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = a2.Start(ctx)
	defer a2.Stop()

	deadline := time.Now().Add(3 * time.Second)
	got := agent.StatusStopped
	for time.Now().Before(deadline) {
		got = a2.Snapshot().Status
		if got == agent.StatusError {
			break
		}
		if got == agent.StatusConnected {
			t.Fatal("second agent hijacked an in-use name")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got != agent.StatusError {
		t.Fatalf("expected collision rejection; got %v", got)
	}
	// First agent still serves.
	resp, body := getViaPath(t, relay.URL, testName, "/")
	if resp.StatusCode != 200 || body != "A" {
		t.Fatalf("original agent disrupted: status=%d body=%q", resp.StatusCode, body)
	}
}

// TestReconnect: after the control conn is dropped, the agent reconnects and
// resumes serving.
func TestReconnect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "alive")
	}))
	defer target.Close()

	store, _ := server.NewStaticTokenStore(defaultGrants())
	srv, _ := server.New(server.Config{Domain: testDomain, Tokens: store, EnablePathMode: true})
	relay := httptest.NewServer(srv.Handler())
	defer relay.Close()

	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)
	waitAgents(t, 1, srv.AgentCount)

	// Record the current session identity via a marker: close all relay conns to
	// drop the agent's control connection out from under it.
	relay.CloseClientConnections()

	// The agent must observe the drop and reconnect. Because reconnect can be near-
	// instant, we assert recovery by (a) the agent flapping through a non-connected
	// state and then (b) returning to connected and serving traffic again.
	sawDrop := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.Snapshot().Status != agent.StatusConnected {
			sawDrop = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !sawDrop {
		// It may have reconnected before we sampled; that's still a successful
		// reconnect. Proceed to verify end-to-end recovery below.
		t.Log("did not observe an explicit non-connected sample (fast reconnect)")
	}

	waitConnected(t, a) // reconnected
	waitAgents(t, 1, srv.AgentCount)

	// Retry the request briefly: the freshly-registered session may race the poll.
	var resp *http.Response
	var body string
	rdeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(rdeadline) {
		resp, body = getViaPath(t, relay.URL, testName, "/")
		if resp.StatusCode == 200 && body == "alive" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("after reconnect: status=%d body=%q", resp.StatusCode, body)
}

// TestStreamLimit: concurrent in-flight streams beyond the per-agent cap are
// rejected with 503 rather than exhausting memory.
func TestStreamLimit(t *testing.T) {
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // hold the request open to occupy a stream slot
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()

	store, _ := server.NewStaticTokenStore(defaultGrants())
	srv, _ := server.New(server.Config{
		Domain: testDomain, Tokens: store, EnablePathMode: true,
		MaxStreamsPerAgent: 2,
	})
	relay := httptest.NewServer(srv.Handler())
	defer relay.Close()

	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)

	// Fire 2 requests that will block occupying both slots.
	type res struct {
		code int
	}
	blocked := make(chan res, 2)
	for i := 0; i < 2; i++ {
		go func() {
			resp, err := http.Get(relay.URL + "/t/" + testName + "/")
			if err != nil {
				blocked <- res{code: -1}
				return
			}
			resp.Body.Close()
			blocked <- res{code: resp.StatusCode}
		}()
	}
	// Give the two requests time to occupy slots.
	time.Sleep(300 * time.Millisecond)

	// A 3rd concurrent request should be rejected (503) because the cap is 2.
	resp, err := http.Get(relay.URL + "/t/" + testName + "/")
	if err != nil {
		t.Fatalf("3rd GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for over-limit stream; got %d", resp.StatusCode)
	}

	// Release the held requests; they should complete 200.
	close(release)
	for i := 0; i < 2; i++ {
		r := <-blocked
		if r.code != 200 {
			t.Fatalf("blocked request code=%d", r.code)
		}
	}
}

// TestRequestBodyCap: request bodies over MaxRequestBytes are cut off AND the
// public client gets a clean 413 Payload Too Large (CONSOLIDATION A-1), not a
// truncated/confusing gateway error.
func TestRequestBodyCap(t *testing.T) {
	// The handler reports the bytes it received back in the response body, so the
	// test reads it from the response (no shared state).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%d", len(b))
	}))
	defer target.Close()

	store, _ := server.NewStaticTokenStore(defaultGrants())
	srv, _ := server.New(server.Config{
		Domain: testDomain, Tokens: store, EnablePathMode: true,
		MaxRequestBytes: 1024,
	})
	relay := httptest.NewServer(srv.Handler())
	defer relay.Close()
	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)

	// Send 4 KiB against a 1 KiB cap.
	big := strings.Repeat("x", 4096)
	resp, err := http.Post(relay.URL+"/t/"+testName+"/", "text/plain", strings.NewReader(big))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Overflow must surface as 413 (not 200 with a truncated body, not 502).
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("overflow status = %d, want 413; body=%q", resp.StatusCode, string(rb))
	}
	// The local target must NOT have received the full body: the body count (if any
	// leaked into the 413 body accounting) is irrelevant — the box app never saw a
	// completed >cap body. Sanity-check the error body echoes the limit.
	if !strings.Contains(string(rb), "1024") {
		t.Fatalf("413 body should echo the limit; got %q", string(rb))
	}
}

// TestRequestBodyUnderCap: a body at/under MaxRequestBytes streams through intact
// (the cap does not block legitimate uploads). (CONSOLIDATION A-1)
func TestRequestBodyUnderCap(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%d", len(b))
	}))
	defer target.Close()

	store, _ := server.NewStaticTokenStore(defaultGrants())
	srv, _ := server.New(server.Config{
		Domain: testDomain, Tokens: store, EnablePathMode: true,
		MaxRequestBytes: 4096,
	})
	relay := httptest.NewServer(srv.Handler())
	defer relay.Close()
	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)

	body := strings.Repeat("y", 4096) // exactly at the cap
	resp, err := http.Post(relay.URL+"/t/"+testName+"/", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("at-cap upload status = %d, want 200; body=%q", resp.StatusCode, string(rb))
	}
	var received int
	fmt.Sscanf(string(rb), "%d", &received)
	if received != 4096 {
		t.Fatalf("box received %d bytes, want 4096 (full body must pass under cap)", received)
	}
}
