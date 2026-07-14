package autoscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestPool_AddRemoveSize(t *testing.T) {
	p := NewPool(nil)
	if p.Size() != 0 {
		t.Fatalf("empty size = %d", p.Size())
	}
	p.Add(Node{ID: "a", Region: "eu"})
	p.Add(Node{ID: "b", Region: "af"})
	p.Add(Node{ID: ""}) // ignored
	if p.Size() != 2 {
		t.Fatalf("size = %d, want 2", p.Size())
	}
	p.Remove("a")
	if p.Size() != 1 {
		t.Fatalf("size after remove = %d, want 1", p.Size())
	}
}

func TestPool_ReAddPreservesLiveState(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "a", Region: "eu", Addr: "https://old"})
	p.Drain("a")
	p.UpdateLoad("a", 0.7)
	p.MarkHealth("a", false)
	// Re-announce with a new addr; drain/load/health must survive.
	p.Add(Node{ID: "a", Region: "eu", Addr: "https://new"})
	m, ok := p.Get("a")
	if !ok {
		t.Fatal("missing after re-add")
	}
	if m.Addr != "https://new" {
		t.Fatalf("addr = %q, want refreshed", m.Addr)
	}
	if !m.Draining {
		t.Fatal("re-add reset the draining flag (must preserve)")
	}
	if m.LoadRatio != 0.7 {
		t.Fatalf("load = %v, want preserved 0.7", m.LoadRatio)
	}
	if m.Healthy {
		t.Fatal("re-add reset health (must preserve)")
	}
}

func TestPool_HealthySizeExcludesDrainingAndUnhealthy(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "a"})
	p.Add(Node{ID: "b"})
	p.Add(Node{ID: "c"})
	p.Drain("b")
	p.MarkHealth("c", false)
	if got := p.HealthySize(); got != 1 {
		t.Fatalf("healthy size = %d, want 1 (only a)", got)
	}
	if got := p.Size(); got != 3 {
		t.Fatalf("total size = %d, want 3 (draining still counts as capacity)", got)
	}
}

func TestPool_NearestPrefersSameRegion(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "eu1", Region: "eu-central"})
	p.Add(Node{ID: "af1", Region: "af-south"})
	p.UpdateLoad("eu1", 0.9) // heavily loaded but same region
	p.UpdateLoad("af1", 0.1)

	n, ok := p.Nearest("af-south")
	if !ok || n.ID != "af1" {
		t.Fatalf("Nearest(af-south) = %v ok=%v, want af1", n.ID, ok)
	}
	// Region match beats load: eu client gets eu1 even though it is more loaded.
	n, ok = p.Nearest("eu-central")
	if !ok || n.ID != "eu1" {
		t.Fatalf("Nearest(eu-central) = %v, want eu1 (region beats load)", n.ID)
	}
}

func TestPool_NearestBreaksTiesByLeastLoad(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "a", Region: "eu"})
	p.Add(Node{ID: "b", Region: "eu"})
	p.UpdateLoad("a", 0.8)
	p.UpdateLoad("b", 0.2)
	n, ok := p.Nearest("eu")
	if !ok || n.ID != "b" {
		t.Fatalf("Nearest = %v, want b (least loaded)", n.ID)
	}
}

func TestPool_NearestSkipsUnhealthyAndDraining(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "a", Region: "eu"})
	p.Add(Node{ID: "b", Region: "eu"})
	p.MarkHealth("a", false) // unhealthy
	p.Drain("b")             // draining
	if _, ok := p.Nearest("eu"); ok {
		t.Fatal("Nearest returned a node when all are unroutable")
	}
	// Recover a → it becomes selectable again.
	p.MarkHealth("a", true)
	n, ok := p.Nearest("eu")
	if !ok || n.ID != "a" {
		t.Fatalf("Nearest after recovery = %v, want a", n.ID)
	}
}

func TestPool_NearestEmptyRegionPicksLeastLoaded(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "a", Region: "eu"})
	p.Add(Node{ID: "b", Region: "af"})
	p.UpdateLoad("a", 0.5)
	p.UpdateLoad("b", 0.1)
	n, ok := p.Nearest("")
	if !ok || n.ID != "b" {
		t.Fatalf("Nearest('') = %v, want b (least loaded globally)", n.ID)
	}
}

func TestPool_DrainCandidateExcludesSelf(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "self"})
	p.Add(Node{ID: "extra"})
	id, ok := p.DrainCandidate("self")
	if !ok || id != "extra" {
		t.Fatalf("DrainCandidate = %v ok=%v, want extra", id, ok)
	}
}

func TestPool_DrainCandidateNoneWhenOnlySelf(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "self"})
	if _, ok := p.DrainCandidate("self"); ok {
		t.Fatal("DrainCandidate found a target when only self exists")
	}
}

func TestPool_DrainCandidatePrefersAlreadyDrainingOrUnhealthy(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "self"})
	p.Add(Node{ID: "healthy"})
	p.Add(Node{ID: "sick"})
	p.UpdateLoad("healthy", 0.1)
	p.UpdateLoad("sick", 0.9)
	p.MarkHealth("sick", false) // already down → reap it first
	id, ok := p.DrainCandidate("self")
	if !ok || id != "sick" {
		t.Fatalf("DrainCandidate = %v, want sick (reap the already-down node)", id)
	}
}

func TestPool_DrainCandidatePrefersLeastLoadedAmongHealthy(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "self"})
	p.Add(Node{ID: "busy"})
	p.Add(Node{ID: "idle"})
	p.UpdateLoad("busy", 0.9)
	p.UpdateLoad("idle", 0.1)
	id, ok := p.DrainCandidate("self")
	if !ok || id != "idle" {
		t.Fatalf("DrainCandidate = %v, want idle (least loaded)", id)
	}
}

func TestPool_MembersSnapshotIsCopy(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "a"})
	ms := p.Members()
	ms[0].Healthy = false // mutate the copy
	m, _ := p.Get("a")
	if !m.Healthy {
		t.Fatal("mutating the Members() snapshot affected the pool")
	}
}

// ---- HealthChecker -----------------------------------------------------------

func TestHealthChecker_FlipsHealthFromProbe(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "a", Addr: "https://a"})
	p.Add(Node{ID: "b", Addr: "https://b"})

	// Fake probe: a healthy, b not.
	probe := func(_ context.Context, url string) bool { return url == "https://a/readyz" }
	hc := NewHealthChecker(p, HealthCheckerConfig{Probe: probe})
	hc.CheckOnce(context.Background())

	ma, _ := p.Get("a")
	mb, _ := p.Get("b")
	if !ma.Healthy {
		t.Fatal("a should be healthy")
	}
	if mb.Healthy {
		t.Fatal("b should be unhealthy after a failed probe")
	}
}

func TestHealthChecker_SkipSelfNotProbed(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "self", Addr: "https://self"})
	var mu sync.Mutex
	probed := map[string]bool{}
	probe := func(_ context.Context, url string) bool {
		mu.Lock()
		probed[url] = true
		mu.Unlock()
		return false
	}
	hc := NewHealthChecker(p, HealthCheckerConfig{Probe: probe, SkipSelf: "self"})
	hc.CheckOnce(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(probed) != 0 {
		t.Fatalf("self was probed: %v", probed)
	}
	// Self health left untouched (still the optimistic default true).
	m, _ := p.Get("self")
	if !m.Healthy {
		t.Fatal("self health should be left untouched")
	}
}

func TestHealthChecker_DefaultHTTPProbe(t *testing.T) {
	// A real httptest server exercises HTTPHealthProbe end-to-end.
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()
	downSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer downSrv.Close()

	p := NewPool(nil)
	p.Add(Node{ID: "up", HealthURL: okSrv.URL + "/readyz"})
	p.Add(Node{ID: "down", HealthURL: downSrv.URL + "/readyz"})
	hc := NewHealthChecker(p, HealthCheckerConfig{Timeout: 2 * time.Second})
	hc.CheckOnce(context.Background())

	if m, _ := p.Get("up"); !m.Healthy {
		t.Fatal("up node should be healthy (200)")
	}
	if m, _ := p.Get("down"); m.Healthy {
		t.Fatal("down node should be unhealthy (503)")
	}
}

func TestHealthChecker_RunStopsOnCancel(t *testing.T) {
	p := NewPool(nil)
	p.Add(Node{ID: "a", Addr: "https://a"})
	hc := NewHealthChecker(p, HealthCheckerConfig{
		Interval: time.Millisecond,
		Probe:    func(context.Context, string) bool { return true },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { hc.Run(ctx); close(done) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HealthChecker.Run did not stop on cancel")
	}
}

func TestHTTPHealthProbe_EmptyURLUnhealthy(t *testing.T) {
	probe := HTTPHealthProbe(time.Second)
	if probe(context.Background(), "") {
		t.Fatal("empty URL should probe unhealthy")
	}
}

func TestPool_ConcurrentAccess(t *testing.T) {
	// Race-detector smoke test: hammer the pool from many goroutines.
	p := NewPool(nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := string(rune('a' + i%5))
			p.Add(Node{ID: id, Region: "eu"})
			p.UpdateLoad(id, float64(i)/100)
			p.MarkHealth(id, i%2 == 0)
			p.Nearest("eu")
			p.DrainCandidate("a")
			p.Members()
			p.Size()
		}(i)
	}
	wg.Wait()
}
