package server

// pubcache_mount_test.go — the relay-integration contract for the DMTAP-PUB
// CACHE/PIN role: it is OFF by default (it serves plaintext, so it is explicit
// operator opt-in), it is served on the relay's APEX host when enabled, and it
// NEVER shadows a tunnel subdomain's own well-known paths — a box reached at
// <name>.<domain> may serve the very same role itself.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vul-os/vulos-relay/tunnel/pubcache"
)

func newPubCacheTestServer(t *testing.T, enable bool) *Server {
	t.Helper()
	store, err := NewStaticTokenStore([]Grant{{Token: "tok", Names: []string{"box1"}}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Domain:         "relay.example.com",
		Tokens:         store,
		EnablePubCache: enable,
		PubCache: pubcache.Config{
			// No upstreams: a valid holder that holds nothing. The mount contract
			// is about ROUTING, not about fetching.
			RequestRate: -1, GlobalRate: -1,
		},
		ControlConnRate: -1, PublicReqRate: -1, GlobalReqRate: -1,
		GlobalConnRate: -1, ConnPerAccountRate: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// TestPubCacheDisabledByDefault: the plain reverse-tunnel relay is unchanged,
// and — the point of § 22.6.1 — an operator never finds themselves serving
// readable public plaintext without having asked to.
func TestPubCacheDisabledByDefault(t *testing.T) {
	srv := newPubCacheTestServer(t, false)
	if srv.pubcache != nil {
		t.Fatal("pubcache service built despite EnablePubCache=false")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/.well-known/dmtap-pub/healthz", nil)
	req.Host = "relay.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled pubcache should 404, got %d", resp.StatusCode)
	}
}

// TestPubCacheServedOnApex: with the role enabled, the well-known surface on the
// apex host is answered by the cache service.
func TestPubCacheServedOnApex(t *testing.T) {
	srv := newPubCacheTestServer(t, true)
	if srv.pubcache == nil {
		t.Fatal("pubcache service not built despite EnablePubCache=true")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/.well-known/dmtap-pub/healthz", nil)
	req.Host = "relay.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("apex pubcache healthz should 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected JSON, got %q", ct)
	}
}

// TestPubCacheNotShadowingTunnelSubdomain: a request to <name>.<domain> must NOT
// be captured by the cache — the box owns its own /.well-known/* paths, and may
// well be serving the § 22 surface itself.
func TestPubCacheNotShadowingTunnelSubdomain(t *testing.T) {
	srv := newPubCacheTestServer(t, true)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/.well-known/dmtap-pub/healthz", nil)
	req.Host = "box1.relay.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// box1 is a known name with no live agent ⇒ tunnel-offline 502, NOT the
	// cache's 200. The assertion is that the cache did not answer.
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("pubcache wrongly shadowed a tunnel subdomain's path (got 200)")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected tunnel-offline 502 for box1 subdomain, got %d", resp.StatusCode)
	}
}

// TestPubCacheRejectsBadUpstreamConfig: a misconfigured upstream fails the relay
// at construction rather than silently yielding a role that contacts something
// unintended.
func TestPubCacheRejectsBadUpstreamConfig(t *testing.T) {
	store, err := NewStaticTokenStore([]Grant{{Token: "tok", Names: []string{"box1"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{
		Domain:         "relay.example.com",
		Tokens:         store,
		EnablePubCache: true,
		PubCache:       pubcache.Config{Upstreams: []string{"file:///etc/passwd"}},
	})
	if err == nil {
		t.Fatal("relay accepted a non-http upstream for the pubcache role")
	}
}
