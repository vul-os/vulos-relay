package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/autoscale"
)

// TestLoad_ReflectsLiveState verifies Load() surfaces the registry agent count,
// the in-flight stream gauge, and the cumulative byte total that the autoscaler
// samples.
func TestLoad_ReflectsLiveState(t *testing.T) {
	s := newTestServer(t)

	if ld := s.Load(); ld.Agents != 0 || ld.Streams != 0 || ld.TotalBytes != 0 {
		t.Fatalf("fresh Load = %+v, want zero", ld)
	}

	// Simulate two in-flight streams and some proxied bytes.
	s.metrics.streamOpened()
	s.metrics.streamOpened()
	s.metrics.proxiedBytes(dirInbound, 1000)
	s.metrics.proxiedBytes(dirOutbound, 500)

	ld := s.Load()
	if ld.Streams != 2 {
		t.Fatalf("Streams = %d, want 2", ld.Streams)
	}
	if ld.TotalBytes != 1500 {
		t.Fatalf("TotalBytes = %d, want 1500", ld.TotalBytes)
	}
}

// TestServerImplementsLoadSource is a compile+behavior check that *Server can be
// used directly as an autoscale.LoadSource.
func TestServerImplementsLoadSource(t *testing.T) {
	s := newTestServer(t)
	var src autoscale.LoadSource = s
	if got := src.Load(); got.Agents != 0 {
		t.Fatalf("Load via interface = %+v", got)
	}
}

// TestSaturationSampler_PublishesGauge starts a server with a soft stream capacity
// and a short sample period, drives the stream gauge up, and asserts the
// saturation ratio (and the /metrics gauge) reflect it.
func TestSaturationSampler_PublishesGauge(t *testing.T) {
	store, _ := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	s, err := New(Config{
		Domain:                 "relay.test",
		Tokens:                 store,
		RevokeSweepPeriod:      -1,
		SoftCapacity:           autoscale.Capacity{MaxStreams: 4},
		SaturationSamplePeriod: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)

	// 2 in-flight streams / soft cap 4 = 0.5 saturation.
	s.metrics.streamOpened()
	s.metrics.streamOpened()

	if !waitFor(2*time.Second, func() bool {
		r := s.SaturationRatio()
		return r > 0.49 && r < 0.51
	}) {
		t.Fatalf("saturation did not reach ~0.5 (got %v)", s.SaturationRatio())
	}

	// The /metrics render must carry the gauge.
	var buf bytes.Buffer
	s.metrics.writeTo(&buf)
	if !strings.Contains(buf.String(), "vulos_relay_saturation_ratio 0.5") {
		t.Fatalf("metrics missing saturation gauge 0.5:\n%s", buf.String())
	}
}

// TestSaturationSampler_DisabledWithoutCapacity: no soft capacity => no sampler,
// gauge stays 0 even under load.
func TestSaturationSampler_DisabledWithoutCapacity(t *testing.T) {
	s := newTestServer(t) // no SoftCapacity
	if s.satStop != nil {
		t.Fatal("sampler started despite no soft capacity")
	}
	s.metrics.streamOpened()
	time.Sleep(30 * time.Millisecond)
	if s.SaturationRatio() != 0 {
		t.Fatalf("saturation = %v, want 0 (sampler disabled)", s.SaturationRatio())
	}
}

// TestSaturationSampler_NegativePeriodDisables: a negative period turns the sampler
// off even when a soft capacity is set.
func TestSaturationSampler_NegativePeriodDisables(t *testing.T) {
	store, _ := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	s, err := New(Config{
		Domain:                 "relay.test",
		Tokens:                 store,
		RevokeSweepPeriod:      -1,
		SoftCapacity:           autoscale.Capacity{MaxStreams: 4},
		SaturationSamplePeriod: -1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	if s.satStop != nil {
		t.Fatal("sampler started despite a negative (disabled) period")
	}
}

// TestPoolNode_FallsBackToDomain: PoolNode uses the domain as id when NodeID unset.
func TestPoolNode_FallsBackToDomain(t *testing.T) {
	s := newTestServer(t)
	if n := s.PoolNode(); n.ID != "relay.test" {
		t.Fatalf("PoolNode id = %q, want fallback to domain", n.ID)
	}

	store, _ := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	s2, _ := New(Config{Domain: "relay.test", Tokens: store, RevokeSweepPeriod: -1,
		NodeID: "hel1-a", Region: "eu-central", Provider: "hetzner"})
	t.Cleanup(s2.Close)
	n := s2.PoolNode()
	if n.ID != "hel1-a" || n.Region != "eu-central" || n.Provider != "hetzner" {
		t.Fatalf("PoolNode = %+v, want the configured identity", n)
	}
}

// TestHealthz_ShowsNodeIdentity: /healthz surfaces node id + region when set.
func TestHealthz_ShowsNodeIdentity(t *testing.T) {
	store, _ := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	s, _ := New(Config{Domain: "relay.test", Tokens: store, RevokeSweepPeriod: -1,
		NodeID: "vultr-jhb", Region: "af-south"})
	t.Cleanup(s.Close)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	s.handleHealthz(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "node=vultr-jhb") || !strings.Contains(body, "region=af-south") {
		t.Fatalf("/healthz missing node identity: %q", body)
	}
}

// TestMultiNodeSafe_FailsCleanForNameNotHere proves the relay makes NO single-node
// assumption: a public request for a tunnel name this node does not hold fails
// CLEANLY (a well-defined status, never a panic / crash), which is exactly what a
// pool member must do for a name that lives on (or is misrouted from) a DIFFERENT
// node.
//
//   - a subdomain of the relay domain with no live session here => 502 "offline"
//     (the name is well-formed but simply not registered on this node), and
//   - a host outside the relay domain entirely => 404 "no such tunnel".
//
// Either way the node answers rather than assuming it is the only relay.
func TestMultiNodeSafe_FailsCleanForNameNotHere(t *testing.T) {
	s := newTestServer(t)

	// Case 1: valid subdomain, no session on this node → clean 502 offline.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://elsewhere.relay.test/", nil)
	req.Host = "elsewhere.relay.test"
	req.RemoteAddr = "203.0.113.9:5555"
	s.handlePublic(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("offline-name status = %d, want 502 (name not held on this node)", rec.Code)
	}

	// Case 2: host outside the relay domain → clean 404.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "http://not-our-domain.example/", nil)
	req2.Host = "not-our-domain.example"
	req2.RemoteAddr = "203.0.113.9:5555"
	s.handlePublic(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("foreign-host status = %d, want 404", rec2.Code)
	}
}

// serverFakeProvisioner is a minimal Provisioner for the server↔autoscale
// integration test.
type serverFakeProvisioner struct{ provisioned int }

func (p *serverFakeProvisioner) Provision(_ context.Context) (autoscale.Node, error) {
	p.provisioned++
	return autoscale.Node{ID: "new-node", Region: "eu"}, nil
}
func (p *serverFakeProvisioner) Decommission(_ context.Context, _ string) error { return nil }

// TestAutoscalerDrivenByRealServer wires an autoscale.Autoscaler to the REAL
// *Server as its LoadSource and a fake Provisioner, then drives it past the
// saturation watermark and asserts the pool grew. This exercises the full seam:
// server load → saturation → detector → provisioner → pool.
func TestAutoscalerDrivenByRealServer(t *testing.T) {
	s := newTestServer(t)
	// Drive the stream gauge to full: 5 streams over a soft cap of 4 => >High(0.8).
	for i := 0; i < 5; i++ {
		s.metrics.streamOpened()
	}

	pool := autoscale.NewPool(nil)
	pool.Add(autoscale.Node{ID: "self"})
	prov := &serverFakeProvisioner{}
	as := autoscale.NewAutoscaler(autoscale.AutoscalerConfig{
		Capacity: autoscale.Capacity{MaxStreams: 4},
		Detector: autoscale.DetectorConfig{High: 0.8, Sustain: -1, Cooldown: -1, MaxNodes: 10},
		Interval: time.Hour, // we drive Tick() manually
		SelfID:   "self",
	}, s, pool, prov)

	if act := as.Tick(context.Background()); act != autoscale.ScaleUp {
		t.Fatalf("Tick = %v, want ScaleUp (server reports 5/4 streams)", act)
	}
	// Let the async provision goroutine finish.
	if !waitFor(2*time.Second, func() bool { return pool.Size() == 2 }) {
		t.Fatalf("pool did not grow (size %d); provisioned=%d", pool.Size(), prov.provisioned)
	}
}

// waitFor polls cond until true or the deadline elapses.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}
