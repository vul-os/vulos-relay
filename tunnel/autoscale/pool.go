package autoscale

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// pool.go — health-checked, geo-aware POOL membership for the relay.
//
// The relay runs as N nodes across providers/regions (Hetzner primary, Vultr edge).
// A Pool is the in-process source of truth for "which nodes are live right now and
// how loaded is each", so:
//
//   - the Autoscaler knows how many nodes exist (for its MinNodes/MaxNodes bounds)
//     and which one to drain when scaling down, and
//   - a ROUTER / geo-DNS control layer can ask Nearest(region) for the closest
//     HEALTHY, non-draining node to steer a client to.
//
// Real geo-DNS / anycast steering is a DEPLOY-side concern (the DNS provider or an
// anycast BGP fabric does the actual client routing). The Pool is the health +
// membership model that layer consults; it does not itself terminate client
// traffic. A HealthChecker polls each member's readiness probe and flips its
// Healthy flag, so a wedged node drops out of routing without an operator in the
// loop.

// Node identifies one relay node in the pool. It is small, comparable-by-id, and
// carries just enough for routing + health-checking.
type Node struct {
	// ID is the stable unique node id (e.g. "hel1-a", a Hetzner server id, …).
	ID string
	// Region is a coarse geo/location tag used by Nearest (e.g. "eu-central",
	// "af-south"). Free-form; matching is exact + case-insensitive.
	Region string
	// Provider is an informational tag (e.g. "hetzner", "vultr"). Not used for
	// routing decisions; handy for observability + capacity planning.
	Provider string
	// Addr is the node's reachable base (e.g. "https://hel1.relay.vulos.org"). Used
	// as the default health-probe target and returned to a router.
	Addr string
	// HealthURL, if set, overrides the probe URL (default: Addr + "/readyz").
	HealthURL string
}

// healthURL resolves the effective readiness-probe URL for the node.
func (n Node) healthURL() string {
	if strings.TrimSpace(n.HealthURL) != "" {
		return n.HealthURL
	}
	if strings.TrimSpace(n.Addr) == "" {
		return ""
	}
	return strings.TrimRight(n.Addr, "/") + "/readyz"
}

// Member is a Node plus its live health/routing state inside the Pool.
type Member struct {
	Node
	// Healthy is set by the HealthChecker (or MarkHealth). A member with no health
	// check yet run defaults to Healthy=true when added (optimistic: a freshly
	// provisioned node the orchestrator says is ready should route immediately; the
	// first failed probe flips it off).
	Healthy bool
	// Draining is set when the node is being decommissioned. A draining node is
	// EXCLUDED from Nearest even while still Healthy, so no NEW traffic is steered
	// to it while in-flight requests wind down.
	Draining bool
	// LoadRatio is the node's last-reported saturation (0..1+), used as the
	// tie-breaker in Nearest (prefer the least-loaded healthy node). 0 until known.
	LoadRatio float64
	// LastProbe is when the health state was last updated.
	LastProbe time.Time
}

// routable reports whether the member may receive NEW client traffic.
func (m *Member) routable() bool { return m.Healthy && !m.Draining }

// Pool is a thread-safe, health-checked set of relay nodes. Construct with
// NewPool. A nil clock uses time.Now.
type Pool struct {
	mu      sync.RWMutex
	members map[string]*Member
	now     func() time.Time
}

// NewPool builds an empty Pool. now may be nil (=> time.Now).
func NewPool(now func() time.Time) *Pool {
	if now == nil {
		now = time.Now
	}
	return &Pool{members: make(map[string]*Member), now: now}
}

// Add inserts (or replaces) a node. A re-Add of an existing id refreshes its Node
// fields but PRESERVES its live health/drain/load state (an orchestrator
// re-announcing a node must not silently reset its drain flag). A node with an
// empty ID is ignored.
func (p *Pool) Add(n Node) {
	if strings.TrimSpace(n.ID) == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.members[n.ID]; ok {
		existing.Node = n // refresh addr/region/provider, keep health/drain/load
		return
	}
	p.members[n.ID] = &Member{Node: n, Healthy: true, LastProbe: p.now()}
}

// Remove deletes a node from the pool entirely.
func (p *Pool) Remove(id string) {
	p.mu.Lock()
	delete(p.members, id)
	p.mu.Unlock()
}

// Size returns the number of members (of ANY health/drain state). The Autoscaler
// compares this against MinNodes/MaxNodes — a draining-but-still-present node still
// counts as capacity until it is actually removed.
func (p *Pool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.members)
}

// HealthySize returns the number of routable (healthy, non-draining) members.
func (p *Pool) HealthySize() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, m := range p.members {
		if m.routable() {
			n++
		}
	}
	return n
}

// Members returns a snapshot copy of the current members (stable order by id), for
// observability / a router. Mutating the returned slice does not affect the pool.
func (p *Pool) Members() []Member {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Member, 0, len(p.members))
	for _, m := range p.members {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns a copy of one member.
func (p *Pool) Get(id string) (Member, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	m, ok := p.members[id]
	if !ok {
		return Member{}, false
	}
	return *m, true
}

// MarkHealth sets a member's Healthy flag (the HealthChecker calls this; exposed so
// an orchestrator that already knows a node's state can set it directly).
func (p *Pool) MarkHealth(id string, healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m, ok := p.members[id]; ok {
		m.Healthy = healthy
		m.LastProbe = p.now()
	}
}

// Drain marks a member draining (excluded from Nearest; still counted in Size).
func (p *Pool) Drain(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m, ok := p.members[id]; ok {
		m.Draining = true
	}
}

// Undrain clears the draining flag (used when a Decommission failed and the node
// should keep serving rather than being stranded).
func (p *Pool) Undrain(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m, ok := p.members[id]; ok {
		m.Draining = false
	}
}

// UpdateLoad records a member's latest saturation ratio (routing tie-break).
func (p *Pool) UpdateLoad(id string, ratio float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m, ok := p.members[id]; ok {
		m.LoadRatio = ratio
	}
}

// Nearest returns the best node to steer a client in `region` to: a HEALTHY,
// non-draining member, preferring an exact region match, then breaking ties by the
// LEAST-loaded node (and finally by id for determinism). It returns ok=false when
// no routable member exists at all (the router should then fail the client over to
// any other discovery path). Passing an empty region just picks the least-loaded
// healthy node globally.
//
// NOTE: this is NODE selection (which relay is closest+live), NOT tunnel-name
// resolution. Which node actually HOLDS a given box's tunnel is deploy-side
// affinity (per-name DNS / a directory): a box dials one home node, and a request
// for that name must reach that node. A node that does not hold the name returns a
// clean 404 (see server.handlePublic) — no node assumes it is the only relay.
func (p *Pool) Nearest(region string) (Node, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	region = strings.ToLower(strings.TrimSpace(region))
	var best *Member
	var bestSameRegion bool
	for _, m := range p.members {
		if !m.routable() {
			continue
		}
		sameRegion := region != "" && strings.EqualFold(m.Region, region)
		if best == nil {
			best, bestSameRegion = m, sameRegion
			continue
		}
		// Prefer a same-region node over an out-of-region one.
		if sameRegion != bestSameRegion {
			if sameRegion {
				best, bestSameRegion = m, true
			}
			continue
		}
		// Same region-preference class: pick the least-loaded, id as final tiebreak.
		if m.LoadRatio < best.LoadRatio ||
			(m.LoadRatio == best.LoadRatio && m.ID < best.ID) {
			best = m
		}
	}
	if best == nil {
		return Node{}, false
	}
	return best.Node, true
}

// DrainCandidate picks the node the autoscaler should drain on scale-DOWN, EXCLUDING
// selfID (a node never decommissions the one running the autoscaler). It prefers a
// node that is already draining or unhealthy (finish tearing it down), then the
// LEAST-loaded routable node, then id order. Returns ok=false if the only member is
// self (or the pool is empty).
func (p *Pool) DrainCandidate(selfID string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var best *Member
	better := func(cand, cur *Member) bool {
		if cur == nil {
			return true
		}
		// A not-routable node (already draining/unhealthy) is the best thing to reap.
		cr, curR := cand.routable(), cur.routable()
		if cr != curR {
			return !cr // prefer the non-routable candidate
		}
		if cand.LoadRatio != cur.LoadRatio {
			return cand.LoadRatio < cur.LoadRatio
		}
		return cand.ID < cur.ID
	}
	for _, m := range p.members {
		if m.ID == selfID {
			continue
		}
		if better(m, best) {
			best = m
		}
	}
	if best == nil {
		return "", false
	}
	return best.ID, true
}

// HealthProbe reports whether a node at healthURL is ready. The default
// (HTTPHealthProbe) does an HTTP GET and treats 2xx as healthy; tests inject a fake.
type HealthProbe func(ctx context.Context, healthURL string) bool

// HTTPHealthProbe is the default probe: GET healthURL, healthy iff 2xx within the
// timeout. A node with no health URL is treated as unhealthy (nothing to probe).
func HTTPHealthProbe(timeout time.Duration) HealthProbe {
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context, healthURL string) bool {
		if strings.TrimSpace(healthURL) == "" {
			return false
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode >= 200 && resp.StatusCode < 300
	}
}

// HealthCheckerConfig configures the background pool health checker.
type HealthCheckerConfig struct {
	// Interval is the probe cadence per round (every member is probed each round).
	// Default 15s.
	Interval time.Duration
	// Timeout bounds a single probe. Default 5s. Only used by the default probe.
	Timeout time.Duration
	// Probe overrides the health probe (tests inject a fake). nil => HTTPHealthProbe.
	Probe HealthProbe
	// SkipSelf, if set, is a node id NOT probed over the network (the local node
	// knows its own health directly). Its Healthy flag is left untouched by the
	// checker.
	SkipSelf string
	// now is an injectable clock for tests; nil => time.Now.
	now func() time.Time
}

func (c *HealthCheckerConfig) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = 15 * time.Second
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Probe == nil {
		c.Probe = HTTPHealthProbe(c.Timeout)
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// HealthChecker periodically probes every pool member and updates its Healthy
// flag, so an unreachable/wedged node stops receiving routed traffic without an
// operator. Construct with NewHealthChecker and Run it in a goroutine.
type HealthChecker struct {
	cfg  HealthCheckerConfig
	pool *Pool
}

// NewHealthChecker builds a checker for pool with defaults applied.
func NewHealthChecker(pool *Pool, cfg HealthCheckerConfig) *HealthChecker {
	cfg.applyDefaults()
	return &HealthChecker{cfg: cfg, pool: pool}
}

// Run probes the pool every Interval until ctx is cancelled.
func (h *HealthChecker) Run(ctx context.Context) {
	t := time.NewTicker(h.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.CheckOnce(ctx)
		}
	}
}

// CheckOnce probes every member once and applies the results. Exposed for
// deterministic tests. Probes run concurrently but the whole call blocks until the
// round completes (or ctx is done).
func (h *HealthChecker) CheckOnce(ctx context.Context) {
	members := h.pool.Members()
	var wg sync.WaitGroup
	for _, m := range members {
		if m.ID == h.cfg.SkipSelf {
			continue
		}
		wg.Add(1)
		go func(mem Member) {
			defer wg.Done()
			healthy := h.cfg.Probe(ctx, mem.Node.healthURL())
			h.pool.MarkHealth(mem.ID, healthy)
		}(m)
	}
	wg.Wait()
}
