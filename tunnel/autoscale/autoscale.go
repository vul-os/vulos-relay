// Package autoscale is the relay's app-level, provider-agnostic capacity control
// plane. It is the machinery that lets the sovereign Vulos relay run as a
// geo-distributed POOL of nodes (Hetzner primary, Vultr edge/HA — flat-bandwidth
// hosts with NO managed autoscaler) and grow/shrink that pool as load moves.
//
// It has three cleanly separable pieces, each independently testable:
//
//  1. SATURATION DETECTION (Detector): a node samples its own load — live agents,
//     in-flight streams, and recent throughput (bytes/sec) — normalizes it to a
//     0..1 saturation ratio against soft capacity, and applies hysteresis so a
//     brief spike does not thrash the pool. It emits ScaleUp when load stays above
//     a high-watermark for a sustained window, and ScaleDown when it stays below a
//     low-watermark (with more nodes than the floor), separated by a cooldown.
//
//  2. THE PROVISIONER SEAM (Provisioner): a small interface an ORCHESTRATOR
//     implements to actually bring up / tear down a relay node on whatever host it
//     uses. The autoscaler NEVER hardcodes a cloud provider — it only calls
//     Provision / Decommission. Wiring a real Hetzner/Vultr API (or a Fly machine,
//     or a Terraform run) behind this interface is the deploy-side integration.
//
//  3. POOL MEMBERSHIP (Pool): a health-checked set of relay nodes with a
//     nearest-healthy selector, so a router/geo-DNS layer can send a client to the
//     closest LIVE node and a drained node stops receiving traffic. Real geo-DNS /
//     anycast steering is deploy-side; the Pool is the in-process source of truth
//     the autoscaler and any router consult.
//
// The Autoscaler ties them together: it reads a LoadSource each interval, feeds the
// Detector, and on a scale signal drives the Provisioner and updates the Pool. It
// is content-blind and holds no tunnel bytes — it only ever sees aggregate counts.
package autoscale

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Sample is a point-in-time load snapshot of ONE relay node. TotalBytes is a
// cumulative-since-boot counter (monotonic); the Autoscaler derives a bytes/sec
// rate by differencing consecutive samples, so a LoadSource never has to compute a
// rate itself. Agents/Streams are instantaneous gauges.
type Sample struct {
	Agents     int   // live agent (tunnel) sessions registered on this node
	Streams    int   // in-flight proxied streams across all tunnels
	TotalBytes int64 // cumulative bytes proxied since boot (monotonic)
}

// LoadSource yields the current load of the local node. *server.Server implements
// it (see the server package); tests use a fake.
type LoadSource interface {
	Load() Sample
}

// Capacity is a node's SOFT limits — the point at which it is considered "full"
// for scaling purposes (NOT a hard cap; the server keeps its own hard MaxAgents /
// MaxStreamsPerAgent / rate limits independently). A dimension whose limit is 0 is
// IGNORED in the saturation computation, so an operator can scale purely on, say,
// bandwidth by leaving the agent/stream limits at 0.
type Capacity struct {
	MaxAgents      int   // soft cap on concurrent agents
	MaxStreams     int   // soft cap on concurrent in-flight streams
	MaxBytesPerSec int64 // soft cap on throughput (bytes/sec)
}

// zero reports whether no dimension is configured (saturation is undefined / 0).
func (c Capacity) zero() bool {
	return c.MaxAgents <= 0 && c.MaxStreams <= 0 && c.MaxBytesPerSec <= 0
}

// Saturation returns the node's load as a 0..1+ ratio: the MAX utilization across
// every configured dimension (a node is as saturated as its most-stressed
// resource). ratePerSec is the derived throughput. Dimensions with a 0 limit are
// skipped. A node with no configured capacity returns 0 (never scales). The result
// may exceed 1.0 when a dimension is over its soft cap — callers compare against
// watermarks, so an over-1 value simply reads as "very saturated".
func Saturation(s Sample, ratePerSec int64, c Capacity) float64 {
	if c.zero() {
		return 0
	}
	worst := 0.0
	consider := func(v, limit float64) {
		if limit <= 0 {
			return
		}
		if r := v / limit; r > worst {
			worst = r
		}
	}
	consider(float64(s.Agents), float64(c.MaxAgents))
	consider(float64(s.Streams), float64(c.MaxStreams))
	consider(float64(ratePerSec), float64(c.MaxBytesPerSec))
	return worst
}

// Action is what the Detector recommends after observing a saturation ratio.
type Action int

const (
	// None: stay put (load is in the stable band, or a watermark was crossed but
	// the sustain/cooldown/bounds conditions are not yet met).
	None Action = iota
	// ScaleUp: provision another node (load has been saturated long enough).
	ScaleUp
	// ScaleDown: drain + remove a node (load has been low long enough and we are
	// above the node floor).
	ScaleDown
)

func (a Action) String() string {
	switch a {
	case ScaleUp:
		return "scale_up"
	case ScaleDown:
		return "scale_down"
	default:
		return "none"
	}
}

// DetectorConfig tunes the hysteresis of scale decisions. Zero fields take safe
// defaults via applyDefaults so a caller can construct a Detector with just the
// watermarks (or nothing at all).
type DetectorConfig struct {
	// High is the scale-UP watermark (saturation ratio, 0..1). Default 0.80.
	High float64
	// Low is the scale-DOWN watermark. Must be < High or it is clamped below it.
	// Default 0.30.
	Low float64
	// Sustain is how long saturation must stay past a watermark BEFORE the Detector
	// acts — this is the anti-thrash hysteresis (a momentary spike is ignored).
	// 0 => default 60s; a NEGATIVE value => 0 (act immediately, no hysteresis).
	Sustain time.Duration
	// Cooldown is the minimum gap between two scale actions, so the pool is not
	// resized faster than a freshly provisioned node can start absorbing load.
	// 0 => default 3m; a NEGATIVE value => 0 (no cooldown).
	Cooldown time.Duration
	// MinNodes is the pool floor: the Detector never emits ScaleDown at or below it
	// (a pool must always keep serving). Default 1.
	MinNodes int
	// MaxNodes is the pool ceiling: the Detector never emits ScaleUp at or above it.
	// 0 => unbounded (no ceiling).
	MaxNodes int
}

// durationField resolves a configured duration: 0 => the supplied default, a
// negative value => 0 (explicitly disabled). Mirrors server.rateLimitField so the
// "0=default, <0=off" convention is uniform across the relay.
func durationField(v, def time.Duration) time.Duration {
	switch {
	case v < 0:
		return 0
	case v == 0:
		return def
	default:
		return v
	}
}

func (c *DetectorConfig) applyDefaults() {
	if c.High <= 0 {
		c.High = 0.80
	}
	if c.Low <= 0 {
		c.Low = 0.30
	}
	// Low must sit strictly below High or hysteresis collapses (a value could be
	// simultaneously "high" and "low"). Clamp Low under High, leaving a band.
	if c.Low >= c.High {
		c.Low = c.High / 2
	}
	// Duration sentinel (mirrors the server's rateLimitField): 0 => default, a
	// negative value => 0 (explicitly disabled — act with no hysteresis/cooldown).
	c.Sustain = durationField(c.Sustain, 60*time.Second)
	c.Cooldown = durationField(c.Cooldown, 3*time.Minute)
	if c.MinNodes <= 0 {
		c.MinNodes = 1
	}
	// MaxNodes 0 == unbounded (left as-is).
}

// Detector is the standalone saturation state machine. It is NOT safe for
// concurrent Observe calls (the Autoscaler drives it from a single loop); wrap it
// if you need concurrency. Construct with NewDetector.
type Detector struct {
	cfg DetectorConfig

	aboveSince time.Time // when the ratio first went >= High in the current run (zero = not above)
	belowSince time.Time // when the ratio first went <= Low in the current run (zero = not below)
	lastAction time.Time // when the last ScaleUp/ScaleDown fired (for cooldown)
}

// NewDetector builds a Detector with defaults applied.
func NewDetector(cfg DetectorConfig) *Detector {
	cfg.applyDefaults()
	return &Detector{cfg: cfg}
}

// Config returns the effective (defaulted) configuration — handy for tests/logs.
func (d *Detector) Config() DetectorConfig { return d.cfg }

// Observe feeds one saturation reading plus the CURRENT node count and wall clock,
// and returns the recommended Action. It is a pure function of its inputs and the
// Detector's accumulated state (the above/below timers and the last-action time).
//
// Semantics:
//   - ratio >= High, sustained for >= Sustain, cooldown elapsed, nodes < MaxNodes
//     => ScaleUp.
//   - ratio <= Low, sustained for >= Sustain, cooldown elapsed, nodes > MinNodes
//     => ScaleDown.
//   - anything else => None (and the opposing timer is reset so the two watermarks
//     never fight).
func (d *Detector) Observe(ratio float64, nodes int, now time.Time) Action {
	switch {
	case ratio >= d.cfg.High:
		d.belowSince = time.Time{}
		if d.aboveSince.IsZero() {
			d.aboveSince = now
		}
		if now.Sub(d.aboveSince) < d.cfg.Sustain {
			return None
		}
		if !d.cooldownElapsed(now) {
			return None
		}
		if d.cfg.MaxNodes > 0 && nodes >= d.cfg.MaxNodes {
			return None // already at the ceiling
		}
		d.lastAction = now
		d.aboveSince = time.Time{} // require a fresh sustained run before the next up
		return ScaleUp

	case ratio <= d.cfg.Low:
		d.aboveSince = time.Time{}
		if d.belowSince.IsZero() {
			d.belowSince = now
		}
		if now.Sub(d.belowSince) < d.cfg.Sustain {
			return None
		}
		if !d.cooldownElapsed(now) {
			return None
		}
		if nodes <= d.cfg.MinNodes {
			return None // already at the floor
		}
		d.lastAction = now
		d.belowSince = time.Time{}
		return ScaleDown

	default:
		// Stable band between the watermarks: reset both timers so a transient dip or
		// spike does not carry over into a decision.
		d.aboveSince = time.Time{}
		d.belowSince = time.Time{}
		return None
	}
}

// cooldownElapsed reports whether enough time has passed since the last action.
// The first action (lastAction zero) is always allowed.
func (d *Detector) cooldownElapsed(now time.Time) bool {
	if d.lastAction.IsZero() {
		return true
	}
	return now.Sub(d.lastAction) >= d.cfg.Cooldown
}

// Provisioner is the SEAM an orchestrator implements to grow/shrink the pool. The
// autoscaler is deliberately provider-agnostic: it never imports a cloud SDK, it
// only calls these two methods. A real implementation might call the Hetzner Cloud
// API to boot a server, wait for the relay to come up and pass its health check,
// and return the node; Decommission would drain and destroy it.
//
// Both calls are made OFF the sample loop (in their own goroutine) and receive a
// context the Autoscaler cancels on shutdown, so a slow provider API never stalls
// load sampling.
type Provisioner interface {
	// Provision brings up ONE additional relay node and returns it once it is
	// reachable and ready to accept tunnels. It should block until the node is live
	// or ctx is done. An error means "no node was added" (the pool is unchanged).
	Provision(ctx context.Context) (Node, error)
	// Decommission drains and removes the node with the given id. It should return
	// once the node is gone (or ctx is done). The autoscaler only ever asks to
	// decommission a node the Pool reported as a drain candidate — never the node
	// running the autoscaler itself.
	Decommission(ctx context.Context, id string) error
}

// AutoscalerConfig configures the Autoscaler loop.
type AutoscalerConfig struct {
	// Capacity is the soft capacity used to compute this node's saturation ratio.
	Capacity Capacity
	// Detector tunes the scale hysteresis (watermarks / sustain / cooldown / bounds).
	Detector DetectorConfig
	// Interval is the load-sample cadence. Default 15s. The bytes/sec rate is
	// derived across one interval, so a very short interval yields a noisier rate.
	Interval time.Duration
	// SelfID is the Pool id of the node RUNNING this autoscaler. It is never chosen
	// as a scale-down/decommission target (a node must not decommission itself via
	// the autoscaler; graceful self-shutdown is a separate, operator-driven path).
	SelfID string
	// now is an injectable clock for tests; nil => time.Now.
	now func() time.Time
}

func (c *AutoscalerConfig) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = 15 * time.Second
	}
	if c.now == nil {
		c.now = time.Now
	}
	// NOTE: Detector defaults are applied by NewDetector, NOT here. applyDefaults on
	// DetectorConfig is intentionally NOT idempotent (the negative "disabled"
	// sentinel maps to 0, and 0 maps to the default), so it must run exactly once.
}

// Autoscaler wires a LoadSource → Detector → Provisioner + Pool. Run it in a
// goroutine via Run; stop it by cancelling Run's context. Safe for concurrent
// reads of Saturation(); the scale loop itself is single-goroutine.
type Autoscaler struct {
	cfg  AutoscalerConfig
	src  LoadSource
	prov Provisioner
	pool *Pool
	det  *Detector

	// prev holds the previous sample + its timestamp, for rate derivation.
	prevSample Sample
	prevAt     time.Time
	havePrev   bool

	// scaling guards a single in-flight Provision/Decommission so the loop never
	// launches a second scale action while one is still running.
	scaling atomic.Bool

	// saturation is the last computed ratio (x1000, atomic) for observability.
	saturationMilli atomic.Int64

	// hooks for tests/observability; nil-safe.
	onAction func(a Action, ratio float64)

	mu       sync.Mutex
	inflight int // count of scale goroutines still running (for graceful Close/tests)
	wg       sync.WaitGroup
}

// NewAutoscaler builds an Autoscaler. src and pool are required; prov may be nil,
// in which case the autoscaler still tracks saturation + emits actions to onAction
// but performs NO provisioning (useful when an EXTERNAL orchestrator scrapes the
// saturation metric and drives scaling itself — the deploy-side alternative to the
// in-process Provisioner).
func NewAutoscaler(cfg AutoscalerConfig, src LoadSource, pool *Pool, prov Provisioner) *Autoscaler {
	cfg.applyDefaults()
	if pool == nil {
		pool = NewPool(nil)
	}
	return &Autoscaler{
		cfg:  cfg,
		src:  src,
		prov: prov,
		pool: pool,
		det:  NewDetector(cfg.Detector),
	}
}

// SetActionHook registers a callback invoked (synchronously, from the loop) each
// time a scale Action other than None is decided. Intended for metrics/logging.
func (a *Autoscaler) SetActionHook(fn func(Action, float64)) { a.onAction = fn }

// Saturation returns the most recently computed saturation ratio (0..1+).
func (a *Autoscaler) Saturation() float64 {
	return float64(a.saturationMilli.Load()) / 1000.0
}

// Pool returns the pool this autoscaler manages.
func (a *Autoscaler) Pool() *Pool { return a.pool }

// Run drives the sample loop until ctx is cancelled, then waits for any in-flight
// scale goroutine to finish. Call it in a goroutine.
func (a *Autoscaler) Run(ctx context.Context) {
	t := time.NewTicker(a.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.wg.Wait() // let a running Provision/Decommission finish cleanly
			return
		case <-t.C:
			a.tick(ctx)
		}
	}
}

// tick performs one sample→detect→act cycle. It is exported-for-test via Tick.
func (a *Autoscaler) tick(ctx context.Context) Action {
	now := a.cfg.now()
	s := a.src.Load()

	rate := a.deriveRate(s, now)
	ratio := Saturation(s, rate, a.cfg.Capacity)
	a.saturationMilli.Store(int64(ratio * 1000))

	// Also publish this node's own load into the pool so a router sees fresh
	// utilization for the self node (best-effort; harmless if self isn't a member).
	if a.cfg.SelfID != "" {
		a.pool.UpdateLoad(a.cfg.SelfID, ratio)
	}

	action := a.det.Observe(ratio, a.pool.Size(), now)
	if action == None {
		return None
	}
	if a.onAction != nil {
		a.onAction(action, ratio)
	}
	a.dispatch(ctx, action)
	return action
}

// Tick runs exactly one sample→detect→act cycle and returns the decided Action.
// Provided for deterministic tests (drive it with a fake clock via the config).
func (a *Autoscaler) Tick(ctx context.Context) Action { return a.tick(ctx) }

// deriveRate computes bytes/sec from the delta between this sample and the prior
// one. The first sample has no predecessor, so its rate is 0 (no premature scale
// on a cold start). A counter reset (TotalBytes went backwards, e.g. a restart) is
// treated as 0 rather than a huge negative.
func (a *Autoscaler) deriveRate(s Sample, now time.Time) int64 {
	defer func() {
		a.prevSample = s
		a.prevAt = now
		a.havePrev = true
	}()
	if !a.havePrev {
		return 0
	}
	dt := now.Sub(a.prevAt).Seconds()
	if dt <= 0 {
		return 0
	}
	db := s.TotalBytes - a.prevSample.TotalBytes
	if db < 0 {
		return 0 // counter reset (restart) — do not report a spurious spike
	}
	return int64(float64(db) / dt)
}

// dispatch launches the scale action in its own goroutine (bounded to one at a
// time via the scaling flag) so a slow Provisioner never blocks sampling.
func (a *Autoscaler) dispatch(ctx context.Context, action Action) {
	if a.prov == nil {
		return // provisioner-less mode: an external orchestrator acts on the metric
	}
	if !a.scaling.CompareAndSwap(false, true) {
		return // a scale op is already in flight; skip until it completes
	}
	a.wg.Add(1)
	a.mu.Lock()
	a.inflight++
	a.mu.Unlock()
	go func() {
		defer a.wg.Done()
		defer a.scaling.Store(false)
		defer func() {
			a.mu.Lock()
			a.inflight--
			a.mu.Unlock()
		}()
		switch action {
		case ScaleUp:
			a.doProvision(ctx)
		case ScaleDown:
			a.doDecommission(ctx)
		}
	}()
}

func (a *Autoscaler) doProvision(ctx context.Context) {
	node, err := a.prov.Provision(ctx)
	if err != nil {
		return // provisioning failed; the pool is unchanged, we retry on a later tick
	}
	a.pool.Add(node)
}

func (a *Autoscaler) doDecommission(ctx context.Context) {
	// Choose the least-useful drainable node — never self. If the pool has no valid
	// candidate (only self, or everything already draining) there is nothing to do.
	id, ok := a.pool.DrainCandidate(a.cfg.SelfID)
	if !ok {
		return
	}
	// Mark it draining so any router stops sending it new traffic BEFORE we tear it
	// down (graceful: in-flight requests on that node wind down first).
	a.pool.Drain(id)
	if err := a.prov.Decommission(ctx, id); err != nil {
		// Decommission failed — un-drain so the node keeps serving rather than being
		// stranded as a drained-but-alive ghost the router avoids.
		a.pool.Undrain(id)
		return
	}
	a.pool.Remove(id)
}

// InflightScaleOps returns the number of scale goroutines still running (tests).
func (a *Autoscaler) InflightScaleOps() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inflight
}
