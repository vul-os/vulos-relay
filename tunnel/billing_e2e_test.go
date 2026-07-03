// billing_e2e_test.go — WAVE24-RELAY-BILLING end-to-end: a real agent tunnels
// through a real relay whose token is linked to an account; traffic is metered
// and the per-account byte deltas are flushed to a fake CP usage endpoint with a
// valid HMAC. Also exercises the connect-time entitlement deny.
package tunnel_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
	"github.com/vul-os/vulos-relay/tunnel/server"
)

// fakeCPForE2E records usage POSTs (validating the X-Pop-Sig HMAC + report_id
// dedup) and serves entitlements for the service (X-Relay-Auth) path.
type fakeCPForE2E struct {
	secret string
	mu     sync.Mutex
	allow  map[string]bool  // account → relay_allowed
	bytes  map[string]int64 // account → accumulated bytes
	sess   map[string]int   // account → accumulated sessions
	seen   map[string]bool  // report_id → seen
}

func (f *fakeCPForE2E) totals(a string) (int64, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bytes[a], f.sess[a]
}

func (f *fakeCPForE2E) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/relay/entitlement", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Relay-Auth") != f.secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		acct := r.URL.Query().Get("account_id")
		f.mu.Lock()
		allowed := f.allow[acct]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"account_id": acct, "tier": "pro",
			"relay_allowed": allowed, "over_quota": false,
			"byte_cap": int64(1) << 40, "turn_cap": 1000,
		})
	})
	mux.HandleFunc("POST /api/relay/usage", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		mac := hmac.New(sha256.New, []byte(f.secret))
		mac.Write(body)
		if r.Header.Get("X-Pop-Sig") != hex.EncodeToString(mac.Sum(nil)) {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		var env struct {
			ReportID string `json:"report_id"`
			Items    []struct {
				AccountID string `json:"account_id"`
				Bytes     int64  `json:"bytes"`
				Sessions  int    `json:"sessions"`
			} `json:"items"`
		}
		_ = json.Unmarshal(body, &env)
		f.mu.Lock()
		defer f.mu.Unlock()
		if env.ReportID != "" && f.seen[env.ReportID] {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "applied": false})
			return
		}
		f.seen[env.ReportID] = true
		for _, it := range env.Items {
			f.bytes[it.AccountID] += it.Bytes
			f.sess[it.AccountID] += it.Sessions
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "applied": true, "over_quota": []string{}})
	})
	return mux
}

// newBilledRelay stands up a relay wired to a fake CP with a short flush period.
func newBilledRelay(t *testing.T, cp *server.CPClient, grants []server.Grant) *httptest.Server {
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
		CP:                 cp,
		GateTTL:            200 * time.Millisecond,
		MeterFlushPeriod:   150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts
}

func TestBilling_E2E_MeteredFlush(t *testing.T) {
	const secret = "e2e-secret"
	fake := &fakeCPForE2E{
		secret: secret,
		allow:  map[string]bool{"acct-e2e": true},
		bytes:  map[string]int64{},
		sess:   map[string]int{},
		seen:   map[string]bool{},
	}
	cpSrv := httptest.NewServer(fake.handler(t))
	defer cpSrv.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a known-size body so we can assert a byte floor.
		fmt.Fprint(w, strings.Repeat("x", 1000))
	}))
	defer target.Close()

	cp := &server.CPClient{BaseURL: cpSrv.URL, SharedSecret: secret, PoPID: "pop-e2e"}
	relay := newBilledRelay(t, cp, []server.Grant{
		{Token: testToken, Names: []string{testName}, AccountID: "acct-e2e"},
	})

	a := startAgent(t, relay.URL, testToken, testName, localAddr(target.URL))
	waitConnected(t, a)

	// Drive several requests through the tunnel.
	const n = 5
	for i := 0; i < n; i++ {
		resp, body := getViaPath(t, relay.URL, testName, "/")
		if resp.StatusCode != 200 {
			t.Fatalf("req %d: status=%d body=%q", i, resp.StatusCode, body)
		}
	}

	// Wait for at least one flush cycle to land the deltas at the CP.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		b, s := fake.totals("acct-e2e")
		if s >= n && b >= int64(n*1000) {
			return // metered: sessions counted and response bytes flushed
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, s := fake.totals("acct-e2e")
	t.Fatalf("metering did not land: bytes=%d (want >=%d) sessions=%d (want >=%d)",
		b, n*1000, s, n)
}

func TestBilling_E2E_ConnectDeniedWhenNotEntitled(t *testing.T) {
	const secret = "e2e-secret"
	fake := &fakeCPForE2E{
		secret: secret,
		allow:  map[string]bool{"acct-blocked": false}, // relay NOT allowed
		bytes:  map[string]int64{},
		sess:   map[string]int{},
		seen:   map[string]bool{},
	}
	cpSrv := httptest.NewServer(fake.handler(t))
	defer cpSrv.Close()

	cp := &server.CPClient{BaseURL: cpSrv.URL, SharedSecret: secret, PoPID: "pop-e2e"}
	relay := newBilledRelay(t, cp, []server.Grant{
		{Token: testToken, Names: []string{testName}, AccountID: "acct-blocked"},
	})

	// The agent should be refused at register (entitlement denied → never connects).
	a := agent.New(agent.Options{
		ServerURL: relay.URL, Token: testToken, Name: testName, LocalAddr: "127.0.0.1:1",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Start returns without a live connection; poll a moment to confirm it never
	// reaches Connected.
	_ = a.Start(ctx)
	defer a.Stop()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if a.Snapshot().Status == agent.StatusConnected {
			t.Fatal("agent connected despite entitlement denial")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
