// direct_test.go — DIRECT-IP client negotiation: selection logic + seamless
// fallback. Proves "try direct first, fall back to relay" ordering and that a
// discovery failure NEVER breaks reachability (the relay path always remains).
package direct

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolution_SelectionLogic(t *testing.T) {
	withDirect := Resolution{
		RelayURL:  "https://box1.relay.vulos.dev",
		DirectURL: "https://box1.example.net",
	}
	if !withDirect.HasDirect() {
		t.Fatal("HasDirect should be true when DirectURL is set")
	}
	if withDirect.Preferred() != TransportDirect {
		t.Fatalf("Preferred should be direct when a direct endpoint exists, got %q", withDirect.Preferred())
	}
	if got := withDirect.BaseURL(TransportDirect); got != "https://box1.example.net" {
		t.Fatalf("BaseURL(direct) = %q", got)
	}
	if got := withDirect.BaseURL(TransportRelay); got != "https://box1.relay.vulos.dev" {
		t.Fatalf("BaseURL(relay) = %q", got)
	}
	// ORDER: direct first, then relay (ICE-like).
	order := withDirect.OrderedBaseURLs()
	if len(order) != 2 || order[0] != "https://box1.example.net" || order[1] != "https://box1.relay.vulos.dev" {
		t.Fatalf("OrderedBaseURLs should be [direct, relay], got %v", order)
	}

	relayOnly := Resolution{RelayURL: "https://box1.relay.vulos.dev"}
	if relayOnly.HasDirect() {
		t.Fatal("HasDirect should be false with no DirectURL")
	}
	if relayOnly.Preferred() != TransportRelay {
		t.Fatal("Preferred should be relay when no direct endpoint")
	}
	// Asking for direct on a relay-only box transparently yields the relay URL.
	if got := relayOnly.BaseURL(TransportDirect); got != "https://box1.relay.vulos.dev" {
		t.Fatalf("BaseURL(direct) on relay-only box should fall back to relay, got %q", got)
	}
	if order := relayOnly.OrderedBaseURLs(); len(order) != 1 || order[0] != "https://box1.relay.vulos.dev" {
		t.Fatalf("relay-only OrderedBaseURLs should be [relay], got %v", order)
	}
}

// fakeRelay serves the resolve endpoint with a fixed body.
func fakeRelay(t *testing.T, direct bool, directEP string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/_vulos-direct/resolve", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if direct {
			_, _ = w.Write([]byte(`{"name":"box1","direct":true,"directEndpoint":"` + directEP + `"}`))
		} else {
			_, _ = w.Write([]byte(`{"name":"box1","direct":false}`))
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestResolve_DirectAvailable(t *testing.T) {
	// Use an https direct endpoint; the resolver only trusts https.
	relay := fakeRelay(t, true, "https://box1.example.net")
	rv := &Resolver{}
	res, err := rv.Resolve(context.Background(), relay.URL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !res.HasDirect() || res.DirectURL != "https://box1.example.net" {
		t.Fatalf("expected direct endpoint, got %+v", res)
	}
	if res.RelayURL != relay.URL {
		t.Fatalf("RelayURL should be the relay base, got %q", res.RelayURL)
	}
}

// TestResolve_DirectIsPreferredFirst PINS the ratified trust/cost decision at the
// end-to-end resolve level: when the relay advertises a VERIFIED direct endpoint,
// the client must ATTEMPT DIRECT FIRST (E2E, bypasses the relay = cheaper + more
// private) and use the relay only as fallback. This complements the struct-level
// TestResolution_SelectionLogic by asserting the ordering survives a real Resolve.
func TestResolve_DirectIsPreferredFirst(t *testing.T) {
	relay := fakeRelay(t, true, "https://box1.example.net")
	rv := &Resolver{}
	res, err := rv.Resolve(context.Background(), relay.URL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Direct must be the PREFERRED transport when a verified direct endpoint exists.
	if res.Preferred() != TransportDirect {
		t.Fatalf("direct-first: Preferred must be direct when a direct endpoint is present, got %q", res.Preferred())
	}
	// The ordered attempt list must be [direct, relay] — direct tried first, relay
	// only as fallback. This is the core of the ratified direct-first decision.
	order := res.OrderedBaseURLs()
	if len(order) != 2 {
		t.Fatalf("direct-first: expected 2 ordered URLs [direct, relay], got %v", order)
	}
	if order[0] != "https://box1.example.net" {
		t.Fatalf("direct-first: the FIRST base URL must be the DIRECT endpoint, got %q", order[0])
	}
	if order[1] != res.RelayURL {
		t.Fatalf("direct-first: the SECOND (fallback) base URL must be the relay, got %q", order[1])
	}
}

// TestResolve_RelayOnlyWhenNoDirect PINS the fail-safe half of the decision: with
// NO direct endpoint the client falls back to relay-only ordering — reachability is
// never broken when a box has no public endpoint (NAT'd/CGNAT/opted-out).
func TestResolve_RelayOnlyWhenNoDirect(t *testing.T) {
	relay := fakeRelay(t, false, "")
	rv := &Resolver{}
	res, err := rv.Resolve(context.Background(), relay.URL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Preferred() != TransportRelay {
		t.Fatalf("no-direct: Preferred must be relay, got %q", res.Preferred())
	}
	if order := res.OrderedBaseURLs(); len(order) != 1 || order[0] != res.RelayURL {
		t.Fatalf("no-direct: ordered list must be [relay] only, got %v", order)
	}
}

func TestResolve_RejectsCleartextDirect(t *testing.T) {
	// A relay that (impossibly) returns a cleartext direct endpoint must be ignored
	// by the client — no cleartext fast path. Falls back to relay.
	relay := fakeRelay(t, true, "http://box1.example.net")
	rv := &Resolver{}
	res, _ := rv.Resolve(context.Background(), relay.URL)
	if res.HasDirect() {
		t.Fatalf("client must not accept a cleartext direct endpoint, got %+v", res)
	}
	if res.RelayURL != relay.URL {
		t.Fatal("must still return the relay URL")
	}
}

func TestResolve_NoDirect(t *testing.T) {
	relay := fakeRelay(t, false, "")
	rv := &Resolver{}
	res, err := rv.Resolve(context.Background(), relay.URL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.HasDirect() {
		t.Fatal("should report no direct endpoint")
	}
	if res.Preferred() != TransportRelay {
		t.Fatal("should prefer relay")
	}
}

func TestResolve_DiscoveryFailureIsSeamless(t *testing.T) {
	// The relay is DOWN for discovery. Resolve must STILL return a usable relay URL
	// and a nil error — a failed direct-discovery never breaks reachability.
	relay := fakeRelay(t, true, "https://box1.example.net")
	relay.Close() // now unreachable
	rv := &Resolver{}
	res, err := rv.Resolve(context.Background(), relay.URL)
	if err != nil {
		t.Fatalf("discovery failure must NOT be an error, got %v", err)
	}
	if res.RelayURL != relay.URL {
		t.Fatalf("relay URL must always be returned, got %q", res.RelayURL)
	}
	if res.HasDirect() {
		t.Fatal("no direct endpoint when discovery failed")
	}
	// The client's ordered list is just the relay path — identical to a relay-only
	// client, so behavior is unchanged when direct is unavailable.
	if order := res.OrderedBaseURLs(); len(order) != 1 || order[0] != relay.URL {
		t.Fatalf("fallback ordered list should be [relay], got %v", order)
	}
}

func TestResolve_EmptyBaseIsError(t *testing.T) {
	rv := &Resolver{}
	if _, err := rv.Resolve(context.Background(), ""); err == nil {
		t.Fatal("empty relayBase must error")
	}
}
