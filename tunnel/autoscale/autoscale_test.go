package autoscale

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock for deterministic time-based tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeSource returns whatever Sample it is told to.
type fakeSource struct {
	mu sync.Mutex
	s  Sample
}

func (f *fakeSource) set(s Sample) { f.mu.Lock(); f.s = s; f.mu.Unlock() }
func (f *fakeSource) Load() Sample { f.mu.Lock(); defer f.mu.Unlock(); return f.s }

// fakeProvisioner records calls and can be made to fail.
type fakeProvisioner struct {
	mu           sync.Mutex
	provisions   int
	decommission []string
	nextNode     Node
	provErr      error
	decErr       error
	block        chan struct{} // if non-nil, Provision blocks on it
}

func (f *fakeProvisioner) Provision(ctx context.Context) (Node, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return Node{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.provisions++
	if f.provErr != nil {
		return Node{}, f.provErr
	}
	n := f.nextNode
	if n.ID == "" {
		n = Node{ID: "prov-node", Region: "eu", Addr: "https://x"}
	}
	return n, nil
}

func (f *fakeProvisioner) Decommission(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.decErr != nil {
		return f.decErr
	}
	f.decommission = append(f.decommission, id)
	return nil
}

func (f *fakeProvisioner) counts() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.provisions, append([]string(nil), f.decommission...)
}

// ---- Saturation --------------------------------------------------------------

func TestSaturation_MaxDimensionWins(t *testing.T) {
	cap := Capacity{MaxAgents: 100, MaxStreams: 200, MaxBytesPerSec: 1000}
	// agents 50/100=0.5, streams 20/200=0.1, rate 900/1000=0.9 → 0.9 wins.
	got := Saturation(Sample{Agents: 50, Streams: 20}, 900, cap)
	if got < 0.89 || got > 0.91 {
		t.Fatalf("saturation = %v, want ~0.9", got)
	}
}

func TestSaturation_ZeroCapacityIsZero(t *testing.T) {
	if got := Saturation(Sample{Agents: 9999}, 1<<30, Capacity{}); got != 0 {
		t.Fatalf("no-capacity saturation = %v, want 0", got)
	}
}

func TestSaturation_IgnoresUnsetDimensions(t *testing.T) {
	// Only bytes configured: agents/streams must not contribute.
	cap := Capacity{MaxBytesPerSec: 100}
	if got := Saturation(Sample{Agents: 1_000_000, Streams: 1_000_000}, 50, cap); got != 0.5 {
		t.Fatalf("bytes-only saturation = %v, want 0.5", got)
	}
}

func TestSaturation_CanExceedOne(t *testing.T) {
	if got := Saturation(Sample{Agents: 300}, 0, Capacity{MaxAgents: 100}); got != 3 {
		t.Fatalf("over-cap saturation = %v, want 3", got)
	}
}

// ---- Detector hysteresis -----------------------------------------------------

func TestDetector_ScaleUpNeedsSustain(t *testing.T) {
	clk := newClock()
	d := NewDetector(DetectorConfig{High: 0.8, Low: 0.3, Sustain: time.Minute, Cooldown: time.Minute, MinNodes: 1})

	// First high reading: not sustained yet.
	if a := d.Observe(0.95, 1, clk.now()); a != None {
		t.Fatalf("immediate high => %v, want None", a)
	}
	clk.advance(30 * time.Second)
	if a := d.Observe(0.95, 1, clk.now()); a != None {
		t.Fatalf("30s high => %v, want None (need 60s)", a)
	}
	clk.advance(31 * time.Second) // now 61s of sustained high
	if a := d.Observe(0.95, 1, clk.now()); a != ScaleUp {
		t.Fatalf("61s high => %v, want ScaleUp", a)
	}
}

func TestDetector_SpikeResetsSustain(t *testing.T) {
	clk := newClock()
	d := NewDetector(DetectorConfig{High: 0.8, Low: 0.3, Sustain: time.Minute, Cooldown: time.Minute})
	d.Observe(0.95, 1, clk.now())
	clk.advance(59 * time.Second)
	// Drop into the stable band → resets the above-timer.
	if a := d.Observe(0.5, 1, clk.now()); a != None {
		t.Fatalf("band reading => %v, want None", a)
	}
	clk.advance(2 * time.Second)
	// Back to high, but the sustain clock restarted, so still no action.
	if a := d.Observe(0.95, 1, clk.now()); a != None {
		t.Fatalf("high after reset => %v, want None (sustain restarted)", a)
	}
}

func TestDetector_ScaleUpRespectsMaxNodes(t *testing.T) {
	clk := newClock()
	d := NewDetector(DetectorConfig{High: 0.8, Sustain: -1, Cooldown: -1, MaxNodes: 3})
	// At the ceiling: no scale up even though saturated.
	if a := d.Observe(0.99, 3, clk.now()); a != None {
		t.Fatalf("at MaxNodes => %v, want None", a)
	}
	if a := d.Observe(0.99, 2, clk.now()); a != ScaleUp {
		t.Fatalf("below MaxNodes => %v, want ScaleUp", a)
	}
}

func TestDetector_ScaleDownRespectsMinNodes(t *testing.T) {
	clk := newClock()
	d := NewDetector(DetectorConfig{High: 0.8, Low: 0.3, Sustain: -1, Cooldown: -1, MinNodes: 2})
	// At the floor: no scale down.
	if a := d.Observe(0.05, 2, clk.now()); a != None {
		t.Fatalf("at MinNodes => %v, want None", a)
	}
	if a := d.Observe(0.05, 3, clk.now()); a != ScaleDown {
		t.Fatalf("above MinNodes => %v, want ScaleDown", a)
	}
}

func TestDetector_Cooldown(t *testing.T) {
	clk := newClock()
	d := NewDetector(DetectorConfig{High: 0.8, Sustain: -1, Cooldown: 5 * time.Minute, MaxNodes: 100})
	if a := d.Observe(0.99, 1, clk.now()); a != ScaleUp {
		t.Fatalf("first => %v, want ScaleUp", a)
	}
	clk.advance(time.Minute)
	if a := d.Observe(0.99, 2, clk.now()); a != None {
		t.Fatalf("within cooldown => %v, want None", a)
	}
	clk.advance(5 * time.Minute)
	if a := d.Observe(0.99, 2, clk.now()); a != ScaleUp {
		t.Fatalf("after cooldown => %v, want ScaleUp", a)
	}
}

func TestDetector_StableBandDoesNothing(t *testing.T) {
	clk := newClock()
	d := NewDetector(DetectorConfig{High: 0.8, Low: 0.3, Sustain: -1, Cooldown: -1, MinNodes: 1, MaxNodes: 10})
	for i := 0; i < 10; i++ {
		clk.advance(time.Minute)
		if a := d.Observe(0.5, 5, clk.now()); a != None {
			t.Fatalf("mid-band => %v, want None", a)
		}
	}
}

func TestDetector_LowClampedBelowHigh(t *testing.T) {
	// Low >= High is nonsensical; applyDefaults must fix it so a value is not both.
	d := NewDetector(DetectorConfig{High: 0.5, Low: 0.9})
	cfg := d.Config()
	if cfg.Low >= cfg.High {
		t.Fatalf("Low %v not clamped below High %v", cfg.Low, cfg.High)
	}
}

// ---- Autoscaler end-to-end ---------------------------------------------------

func newAutoscaler(clk *fakeClock, src LoadSource, pool *Pool, prov Provisioner, cap Capacity, det DetectorConfig) *Autoscaler {
	cfg := AutoscalerConfig{
		Capacity: cap,
		Detector: det,
		Interval: time.Second,
		SelfID:   "self",
		now:      clk.now,
	}
	return NewAutoscaler(cfg, src, pool, prov)
}

func TestAutoscaler_RateDerivedFromByteDeltas(t *testing.T) {
	clk := newClock()
	src := &fakeSource{}
	pool := NewPool(clk.now)
	pool.Add(Node{ID: "self"})
	prov := &fakeProvisioner{}
	// Only bandwidth configured: 1000 B/s soft cap; high at 0.8 => 800 B/s.
	a := newAutoscaler(clk, src, pool, prov, Capacity{MaxBytesPerSec: 1000},
		DetectorConfig{High: 0.8, Low: 0.3, Sustain: -1, Cooldown: -1, MinNodes: 1, MaxNodes: 10})

	// First tick: no previous sample → rate 0 → saturation 0.
	src.set(Sample{TotalBytes: 0})
	a.Tick(context.Background())
	if a.Saturation() != 0 {
		t.Fatalf("cold-start saturation = %v, want 0", a.Saturation())
	}

	// Advance 1s and jump 900 bytes → 900 B/s → ratio 0.9 → ScaleUp.
	clk.advance(time.Second)
	src.set(Sample{TotalBytes: 900})
	if act := a.Tick(context.Background()); act != ScaleUp {
		t.Fatalf("tick action = %v, want ScaleUp (rate 900 B/s)", act)
	}
	if a.Saturation() < 0.89 {
		t.Fatalf("saturation = %v, want ~0.9", a.Saturation())
	}
	waitInflight(t, a)
	p, _ := prov.counts()
	if p != 1 {
		t.Fatalf("provisions = %d, want 1", p)
	}
	if pool.Size() != 2 {
		t.Fatalf("pool size = %d, want 2 (self + provisioned)", pool.Size())
	}
}

func TestAutoscaler_CounterResetNoSpuriousScale(t *testing.T) {
	clk := newClock()
	src := &fakeSource{}
	pool := NewPool(clk.now)
	pool.Add(Node{ID: "self"})
	prov := &fakeProvisioner{}
	a := newAutoscaler(clk, src, pool, prov, Capacity{MaxBytesPerSec: 1000},
		DetectorConfig{High: 0.8, Sustain: -1, Cooldown: -1, MaxNodes: 10})

	src.set(Sample{TotalBytes: 1_000_000})
	a.Tick(context.Background())
	clk.advance(time.Second)
	src.set(Sample{TotalBytes: 5}) // counter reset (restart)
	if act := a.Tick(context.Background()); act != None {
		t.Fatalf("counter-reset tick = %v, want None", act)
	}
	if a.Saturation() != 0 {
		t.Fatalf("saturation after reset = %v, want 0", a.Saturation())
	}
}

func TestAutoscaler_ScaleDownDrainsAndDecommissions(t *testing.T) {
	clk := newClock()
	src := &fakeSource{}
	pool := NewPool(clk.now)
	pool.Add(Node{ID: "self"})
	pool.Add(Node{ID: "extra"})
	prov := &fakeProvisioner{}
	a := newAutoscaler(clk, src, pool, prov, Capacity{MaxAgents: 100},
		DetectorConfig{High: 0.8, Low: 0.3, Sustain: -1, Cooldown: -1, MinNodes: 1, MaxNodes: 10})

	src.set(Sample{Agents: 2}) // 2/100 = 0.02 <= Low → ScaleDown (2 nodes > MinNodes 1)
	if act := a.Tick(context.Background()); act != ScaleDown {
		t.Fatalf("tick = %v, want ScaleDown", act)
	}
	waitInflight(t, a)
	_, dec := prov.counts()
	if len(dec) != 1 || dec[0] != "extra" {
		t.Fatalf("decommissioned = %v, want [extra] (never self)", dec)
	}
	if _, ok := pool.Get("extra"); ok {
		t.Fatalf("extra should have been removed from the pool")
	}
	if _, ok := pool.Get("self"); !ok {
		t.Fatalf("self must never be removed")
	}
}

func TestAutoscaler_ScaleDownNeverPicksSelf(t *testing.T) {
	clk := newClock()
	src := &fakeSource{}
	pool := NewPool(clk.now)
	pool.Add(Node{ID: "self"}) // ONLY self
	prov := &fakeProvisioner{}
	a := newAutoscaler(clk, src, pool, prov, Capacity{MaxAgents: 100},
		DetectorConfig{High: 0.8, Low: 0.3, Sustain: -1, Cooldown: -1, MinNodes: 0, MaxNodes: 10})

	src.set(Sample{Agents: 0})
	// Detector may say ScaleDown (0 nodes floor allows it since MinNodes 0 → default 1;
	// but size 1 <= 1 so it won't). Force by adding capacity is unnecessary: verify no
	// decommission of self regardless.
	a.Tick(context.Background())
	waitInflight(t, a)
	_, dec := prov.counts()
	for _, id := range dec {
		if id == "self" {
			t.Fatalf("self was decommissioned: %v", dec)
		}
	}
}

func TestAutoscaler_ProvisionFailureLeavesPoolUnchanged(t *testing.T) {
	clk := newClock()
	src := &fakeSource{}
	pool := NewPool(clk.now)
	pool.Add(Node{ID: "self"})
	prov := &fakeProvisioner{provErr: errors.New("boom")}
	a := newAutoscaler(clk, src, pool, prov, Capacity{MaxAgents: 100},
		DetectorConfig{High: 0.8, Sustain: -1, Cooldown: -1, MaxNodes: 10})

	src.set(Sample{Agents: 99}) // 0.99 → ScaleUp
	a.Tick(context.Background())
	waitInflight(t, a)
	if pool.Size() != 1 {
		t.Fatalf("pool size = %d, want 1 (provision failed)", pool.Size())
	}
}

func TestAutoscaler_DecommissionFailureUndrains(t *testing.T) {
	clk := newClock()
	src := &fakeSource{}
	pool := NewPool(clk.now)
	pool.Add(Node{ID: "self"})
	pool.Add(Node{ID: "extra"})
	prov := &fakeProvisioner{decErr: errors.New("nope")}
	a := newAutoscaler(clk, src, pool, prov, Capacity{MaxAgents: 100},
		DetectorConfig{High: 0.8, Low: 0.3, Sustain: -1, Cooldown: -1, MinNodes: 1, MaxNodes: 10})

	src.set(Sample{Agents: 1})
	a.Tick(context.Background())
	waitInflight(t, a)
	m, ok := pool.Get("extra")
	if !ok {
		t.Fatalf("extra removed despite decommission failure")
	}
	if m.Draining {
		t.Fatalf("extra left draining after a failed decommission (should un-drain)")
	}
}

func TestAutoscaler_OnlyOneScaleOpInFlight(t *testing.T) {
	clk := newClock()
	src := &fakeSource{}
	pool := NewPool(clk.now)
	pool.Add(Node{ID: "self"})
	prov := &fakeProvisioner{block: make(chan struct{})}
	a := newAutoscaler(clk, src, pool, prov, Capacity{MaxAgents: 100},
		DetectorConfig{High: 0.8, Sustain: -1, Cooldown: -1, MaxNodes: 10})

	src.set(Sample{Agents: 99})
	a.Tick(context.Background()) // launches a blocked Provision
	a.Tick(context.Background()) // should NOT launch a second
	// Give the goroutines a moment; then unblock and drain.
	deadline := time.Now().Add(2 * time.Second)
	for a.InflightScaleOps() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := a.InflightScaleOps(); got != 1 {
		close(prov.block)
		t.Fatalf("inflight scale ops = %d, want 1", got)
	}
	close(prov.block)
	waitInflight(t, a)
	p, _ := prov.counts()
	if p != 1 {
		t.Fatalf("provisions = %d, want 1 (second tick skipped)", p)
	}
}

func TestAutoscaler_NilProvisionerJustTracks(t *testing.T) {
	clk := newClock()
	src := &fakeSource{}
	pool := NewPool(clk.now)
	pool.Add(Node{ID: "self"})
	var gotAction Action
	a := newAutoscaler(clk, src, pool, nil, Capacity{MaxAgents: 100},
		DetectorConfig{High: 0.8, Sustain: -1, Cooldown: -1, MaxNodes: 10})
	a.SetActionHook(func(act Action, _ float64) { gotAction = act })

	src.set(Sample{Agents: 99})
	if act := a.Tick(context.Background()); act != ScaleUp {
		t.Fatalf("tick = %v, want ScaleUp", act)
	}
	if gotAction != ScaleUp {
		t.Fatalf("action hook saw %v, want ScaleUp", gotAction)
	}
	// No provisioner: pool unchanged, but saturation is tracked for an external scaler.
	if pool.Size() != 1 {
		t.Fatalf("pool size = %d, want 1 (no in-process provisioning)", pool.Size())
	}
	if a.Saturation() < 0.98 {
		t.Fatalf("saturation = %v, want ~0.99", a.Saturation())
	}
}

func TestAutoscaler_RunStopsOnContextCancel(t *testing.T) {
	clk := newClock()
	src := &fakeSource{}
	src.set(Sample{})
	pool := NewPool(clk.now)
	pool.Add(Node{ID: "self"})
	a := NewAutoscaler(AutoscalerConfig{
		Capacity: Capacity{MaxAgents: 100},
		Interval: time.Millisecond,
		SelfID:   "self",
		now:      clk.now,
	}, src, pool, &fakeProvisioner{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// waitInflight blocks until all scale goroutines have finished (bounded).
func waitInflight(t *testing.T, a *Autoscaler) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for a.InflightScaleOps() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("scale ops did not complete in time")
		}
		time.Sleep(time.Millisecond)
	}
}
