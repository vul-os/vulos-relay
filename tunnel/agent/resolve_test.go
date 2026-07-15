package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// resolve_test.go — SMART-AUTOSCALE (agent side): the ROUTING HOOK. The agent must
// dial the PoP a directory assigns (nearest + least-loaded) and fall back to its
// static ServerURL when there is no resolver or the directory is unreachable.

// fakeResolver is a test PoPResolver whose assignment can be switched at runtime
// (a drain flips it to a different PoP).
type fakeResolver struct {
	mu   sync.Mutex
	asg  Assignment
	err  error
	hits int
}

func (r *fakeResolver) set(a Assignment) { r.mu.Lock(); r.asg = a; r.mu.Unlock() }

func (r *fakeResolver) Resolve(_ context.Context, _ string) (Assignment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits++
	return r.asg, r.err
}

// TestResolveEndpoint_NoResolverUsesServerURL: with no directory, the agent dials
// its static ServerURL (self-host / single relay).
func TestResolveEndpoint_NoResolverUsesServerURL(t *testing.T) {
	a := New(Options{ServerURL: "wss://relay.test", Token: "t", Name: "box", LocalAddr: "127.0.0.1:1"})
	if got := a.resolveEndpoint(context.Background()); got != "wss://relay.test" {
		t.Fatalf("resolveEndpoint = %q, want the static ServerURL", got)
	}
	if a.Snapshot().AssignedPoP != "" {
		t.Fatal("no resolver should mean no assigned PoP")
	}
}

// TestResolveEndpoint_UsesDirectory: the resolver's assignment is dialed and
// surfaced in Snapshot.
func TestResolveEndpoint_UsesDirectory(t *testing.T) {
	fr := &fakeResolver{asg: Assignment{Endpoint: "wss://hel1.relay.test", Region: "eu-central", PoPID: "hel1-a"}}
	a := New(Options{ServerURL: "wss://fallback.test", Token: "t", Name: "box", LocalAddr: "127.0.0.1:1", Resolver: fr})
	if got := a.resolveEndpoint(context.Background()); got != "wss://hel1.relay.test" {
		t.Fatalf("resolveEndpoint = %q, want the assigned PoP", got)
	}
	snap := a.Snapshot()
	if snap.AssignedPoP != "hel1-a" || snap.AssignedRegion != "eu-central" {
		t.Fatalf("assignment not surfaced: %+v", snap)
	}
}

// TestResolveEndpoint_FallsBackOnError: a directory error never strands the agent —
// it falls back to the static ServerURL.
func TestResolveEndpoint_FallsBackOnError(t *testing.T) {
	fr := &fakeResolver{err: fmt.Errorf("directory down")}
	a := New(Options{ServerURL: "wss://fallback.test", Token: "t", Name: "box", LocalAddr: "127.0.0.1:1", Resolver: fr})
	if got := a.resolveEndpoint(context.Background()); got != "wss://fallback.test" {
		t.Fatalf("resolveEndpoint = %q, want the fallback ServerURL on resolver error", got)
	}
}

// TestHTTPResolver_ParsesAssignment: the default HTTP resolver hits the directory
// contract (GET /api/relay/assign?name=…, Bearer token) and decodes the assignment.
func TestHTTPResolver_ParsesAssignment(t *testing.T) {
	var gotName, gotRegion, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/relay/assign" {
			http.NotFound(w, r)
			return
		}
		gotName = r.URL.Query().Get("name")
		gotRegion = r.URL.Query().Get("region")
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(Assignment{Endpoint: "wss://jhb.relay.test", Region: "af-south", PoPID: "jhb-1"})
	}))
	defer srv.Close()

	res := newHTTPResolver(srv.URL, "secret-token", "af-south")
	if res == nil {
		t.Fatal("newHTTPResolver returned nil for a non-empty URL")
	}
	asg, err := res.Resolve(context.Background(), "box1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if asg.Endpoint != "wss://jhb.relay.test" || asg.PoPID != "jhb-1" {
		t.Fatalf("assignment = %+v", asg)
	}
	if gotName != "box1" || gotRegion != "af-south" || gotAuth != "Bearer secret-token" {
		t.Fatalf("directory request wrong: name=%q region=%q auth=%q", gotName, gotRegion, gotAuth)
	}
}

// TestHTTPResolver_NilForBlankURL: no directory URL => nil resolver (static dial).
func TestHTTPResolver_NilForBlankURL(t *testing.T) {
	if newHTTPResolver("", "t", "") != nil {
		t.Fatal("expected nil resolver for a blank directory URL")
	}
}
