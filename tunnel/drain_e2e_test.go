package tunnel_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/agent"
	"github.com/vul-os/vulos-relay/tunnel/server"
)

// drain_e2e_test.go — SMART-AUTOSCALE end-to-end: GRACEFUL DRAIN migrates every
// tunnel to a fresh PoP via a proactive reconnect signal, make-before-break, with
// ZERO dropped connectivity, and the drain COMPLETES (source PoP → 0 tunnels).
//
// The whole path is real: two real relay servers (a draining source A and a target
// B), a real agent dialing over ws + yamux, and a real local app. The agent's
// routing hook is driven by a switchable resolver standing in for the CP directory.

// switchResolver is a test PoPResolver whose assignment the test flips (a drain
// makes the CP hand out a DIFFERENT PoP, which is exactly what makes the agent
// migrate). Safe for concurrent use.
type switchResolver struct {
	mu  sync.Mutex
	asg agent.Assignment
}

func (r *switchResolver) set(endpoint, region, pop string) {
	r.mu.Lock()
	r.asg = agent.Assignment{Endpoint: endpoint, Region: region, PoPID: pop}
	r.mu.Unlock()
}

func (r *switchResolver) Resolve(_ context.Context, _ string) (agent.Assignment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.asg, nil
}

// newRelayWithServer stands up a relay and returns BOTH the *server.Server (so a
// test can call Drain()/AgentCount()) and its public httptest surface.
func newRelayWithServer(t *testing.T, grants []server.Grant, domain string) (*server.Server, *httptest.Server) {
	t.Helper()
	store, err := server.NewStaticTokenStore(grants)
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	srv, err := server.New(server.Config{
		Domain:             domain,
		Tokens:             store,
		EnablePathMode:     true,
		MaxAgents:          8,
		MaxStreamsPerAgent: 8,
		RevokeSweepPeriod:  -1,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	t.Cleanup(srv.Close)
	return srv, hs
}

// okThroughRelay reports whether a path-mode request to the given relay for `name`
// returns 200 (i.e. that relay currently holds the tunnel and proxied it).
func okThroughRelay(relayURL, name string) bool {
	resp, err := http.Get(relayURL + "/t/" + name + "/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

// TestGracefulDrain_ZeroDropMigration is the headline test.
func TestGracefulDrain_ZeroDropMigration(t *testing.T) {
	// A local app that always answers 200 — the "box" behind the tunnel.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()

	grants := defaultGrants()
	relayA, hsA := newRelayWithServer(t, grants, testDomain)
	relayB, hsB := newRelayWithServer(t, grants, testDomain)

	// The agent starts assigned to A; the resolver flips to B when A drains.
	res := &switchResolver{}
	res.set(hsA.URL, "eu-central", "pop-A")

	a := agent.New(agent.Options{
		ServerURL: hsA.URL, // fallback; the resolver drives the actual endpoint
		Token:     testToken,
		Name:      testName,
		LocalAddr: localAddr(target.URL),
		Resolver:  res,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("agent.Start: %v", err)
	}
	defer a.Stop()

	waitConnected(t, a)
	waitAgents(t, 1, relayA.AgentCount)
	if !okThroughRelay(hsA.URL, testName) {
		t.Fatal("request via A did not succeed before drain")
	}
	if relayB.AgentCount() != 0 {
		t.Fatalf("B already has %d agents before drain", relayB.AgentCount())
	}

	// A continuous availability probe spanning the migration: each round hits BOTH
	// relays and records whether AT LEAST ONE served the tunnel. Make-before-break
	// means the old (A) tunnel stays up until the new (B) one is live, so there must
	// NEVER be a round where neither serves — that is the "zero drop" invariant.
	var (
		stop       atomic.Bool
		rounds     atomic.Int64
		bothFailed atomic.Int64
		probeWG    sync.WaitGroup
	)
	probeWG.Add(1)
	go func() {
		defer probeWG.Done()
		for !stop.Load() {
			okA := okThroughRelay(hsA.URL, testName)
			okB := okThroughRelay(hsB.URL, testName)
			rounds.Add(1)
			if !okA && !okB {
				bothFailed.Add(1)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// Accrue baseline probe rounds while A alone serves (all must succeed via A).
	time.Sleep(150 * time.Millisecond)

	// The CP has decided to scale A down: it will stop handing out A (flip the
	// directory to B) and then drain A. Make-before-break in-process is near-instant,
	// so the zero-drop guarantee is structural (the old A tunnel is not closed until
	// the new B tunnel is connected), not something the probe has to catch mid-window.
	res.set(hsB.URL, "eu-central", "pop-B")
	signaled := relayA.Drain()
	if signaled != 1 {
		t.Fatalf("Drain signaled %d agents, want 1", signaled)
	}

	// The agent must migrate to B (make-before-break) and A must drain to 0.
	if !waitFor2(8*time.Second, func() bool { return relayB.AgentCount() == 1 }) {
		t.Fatalf("agent never migrated to B (B has %d agents)", relayB.AgentCount())
	}
	if !waitFor2(8*time.Second, func() bool { return relayA.AgentCount() == 0 }) {
		t.Fatalf("A never drained to 0 (A has %d agents)", relayA.AgentCount())
	}

	// Keep probing after the migration (B alone now serves) to accrue post-migration
	// rounds, then stop.
	time.Sleep(150 * time.Millisecond)
	stop.Store(true)
	probeWG.Wait()

	// ZERO DROP: not a single probe round found BOTH relays failing.
	if bothFailed.Load() != 0 {
		t.Fatalf("connectivity dropped during drain: %d/%d probe rounds had NO serving relay",
			bothFailed.Load(), rounds.Load())
	}
	if rounds.Load() < 3 {
		t.Fatalf("availability probe ran too few rounds (%d) to be meaningful", rounds.Load())
	}

	// After migration, B serves and the agent reports its new PoP assignment.
	if !okThroughRelay(hsB.URL, testName) {
		t.Fatal("request via B failed after migration")
	}
	if snap := a.Snapshot(); snap.AssignedPoP != "pop-B" {
		t.Fatalf("agent AssignedPoP = %q, want pop-B after migration", snap.AssignedPoP)
	}

	// Drain is COMPLETE: the CP may now terminate A (0 tunnels).
	if relayA.DrainingTunnels() != 0 {
		t.Fatalf("A still holds %d tunnels after migration", relayA.DrainingTunnels())
	}
}

// TestDrain_RefusesNewTunnels: while draining, A refuses a NEW registration so an
// agent cannot land on a node that is going away.
func TestDrain_RefusesNewTunnels(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()

	relayA, hsA := newRelayWithServer(t, defaultGrants(), testDomain)
	relayA.Drain() // draining before any agent connects

	a := agent.New(agent.Options{
		ServerURL:  hsA.URL,
		Token:      testToken,
		Name:       testName,
		LocalAddr:  localAddr(target.URL),
		MaxBackoff: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatalf("agent.Start: %v", err)
	}
	defer a.Stop()

	// The agent must NOT successfully register on the draining relay.
	if waitFor2(1500*time.Millisecond, func() bool { return relayA.AgentCount() > 0 }) {
		t.Fatalf("draining relay accepted a new tunnel (agents=%d)", relayA.AgentCount())
	}
	if a.Snapshot().Status == agent.StatusConnected {
		t.Fatal("agent reports connected to a draining relay")
	}
}

// waitFor2 polls cond until true or the deadline elapses (local to this file so it
// does not depend on helpers in other test files).
func waitFor2(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}
