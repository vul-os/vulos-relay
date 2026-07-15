package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
	"time"
)

// poplink.go — SMART-AUTOSCALE (relay side): PoP REGISTRATION + LOAD HEARTBEAT.
//
// This is the relay half of the CP↔relay autoscaler contract. A managed relay PoP
// announces itself to Vulos Cloud (CP) and then heartbeats its live load, so a
// CP-side autoscaler can (a) hand agents their nearest/least-loaded PoP and (b)
// decide when to provision a new PoP or drain an existing one. The relay reuses the
// EXISTING CP link (CPClient + CP_SHARED_SECRET + the same HMAC X-Pop-Sig scheme
// as usage reports) — no new secret, no new transport.
//
// CP-OPTIONAL: a standalone relay with no CP configured (or with no public endpoint
// advertised) runs exactly as before and does none of this — the heartbeat loop is
// a no-op. This is the self-host contract: pool autoscaling is a managed-relay
// feature, never a requirement.
//
// OFF THE HOT PATH: the load sample is taken once per heartbeat (~12s) from cheap
// aggregate counters already maintained by the data path (registry.count, the
// cumulative byte counter, the saturation gauge). No per-request/per-packet work is
// added — the heartbeat only READS counters a request already bumped.
//
// ── CP↔relay contract (relay → CP) ─────────────────────────────────────────
//
//	POST {cp}/api/relay/pop/register        (once on startup, retried)
//	  headers: X-Pop-Sig: hex(HMAC-SHA256(CP_SHARED_SECRET, body))
//	  body: PoPRegistration{pop_id, region, provider, public_endpoint, capacity{…}}
//	  → 200 (the CP records the PoP as a routable member of its directory)
//
//	POST {cp}/api/relay/pop/heartbeat       (every HeartbeatPeriod)
//	  headers: X-Pop-Sig: hex(HMAC-SHA256(CP_SHARED_SECRET, body))
//	  body: PoPLoad{pop_id, region, active_tunnels, bytes_per_sec, cpu_pct, mem_pct,
//	                saturation, draining}
//	  → 200 (stale PoPs — no heartbeat within a CP-side TTL — are dropped from
//	     routing by the CP; a draining PoP is excluded from NEW assignments)

// PoPCapacity is a PoP's advertised soft capacity, sent once at registration so
// the CP knows this node's headroom for placement/scaling decisions. Mirrors
// autoscale.Capacity (the relay's own saturation model) so the CP prices load
// against the same dimensions.
type PoPCapacity struct {
	MaxAgents      int   `json:"max_agents"`
	MaxStreams     int   `json:"max_streams"`
	MaxBytesPerSec int64 `json:"max_bytes_per_sec"`
}

// PoPRegistration is the one-time announce POSTed to /api/relay/pop/register.
type PoPRegistration struct {
	PoPID    string `json:"pop_id"`
	Region   string `json:"region"`
	Provider string `json:"provider,omitempty"`
	// PublicEndpoint is the agent-facing base URL of this PoP (e.g.
	// "wss://hel1.relay.vulos.org") that the CP hands to an agent as its assigned
	// PoP. It is what makes the PoP addressable in the CP's directory.
	PublicEndpoint string      `json:"public_endpoint"`
	Capacity       PoPCapacity `json:"capacity"`
}

// PoPLoad is the periodic load heartbeat POSTed to /api/relay/pop/heartbeat. It is
// the signal a CP-side autoscaler consumes: active_tunnels + bytes_per_sec +
// saturation drive scale/placement; draining tells the CP to stop assigning new
// tunnels here (and to terminate the machine once active_tunnels hits 0).
type PoPLoad struct {
	PoPID         string  `json:"pop_id"`
	Region        string  `json:"region,omitempty"`
	ActiveTunnels int     `json:"active_tunnels"`
	BytesPerSec   int64   `json:"bytes_per_sec"`
	CPUPct        float64 `json:"cpu_pct"`
	MemPct        float64 `json:"mem_pct"`
	Saturation    float64 `json:"saturation"`
	Draining      bool    `json:"draining"`
}

// RegisterPoP announces this PoP to the CP (idempotent on the CP side — a re-announce
// refreshes the record). HMAC-signed with the shared secret, same scheme as usage.
func (c *CPClient) RegisterPoP(ctx context.Context, reg PoPRegistration) error {
	if c.SharedSecret == "" {
		return fmt.Errorf("cpclient: no shared secret")
	}
	return c.postSigned(ctx, "/api/relay/pop/register", reg)
}

// HeartbeatPoP reports this PoP's current load to the CP. HMAC-signed.
func (c *CPClient) HeartbeatPoP(ctx context.Context, load PoPLoad) error {
	if c.SharedSecret == "" {
		return fmt.Errorf("cpclient: no shared secret")
	}
	return c.postSigned(ctx, "/api/relay/pop/heartbeat", load)
}

// postSigned marshals v, signs the exact body with X-Pop-Sig (the same HMAC scheme
// the CP verifies for usage reports), and POSTs it to the CP path.
func (c *CPClient) postSigned(ctx context.Context, path string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pop-Sig", signBody(c.SharedSecret, body))
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cpclient: %s status %d", path, resp.StatusCode)
	}
	return nil
}

// ── relay-side heartbeat loop ───────────────────────────────────────────────

// SysSampler yields best-effort host CPU% and memory% (0..100) for the load
// heartbeat. It is injectable (tests/operators wire cgroup/proc stats); the default
// reports a runtime-derived memory figure and leaves CPU at 0 (see defaultSysSampler).
type SysSampler func() (cpuPct, memPct float64)

// defaultSysSampler is a dependency-free, cross-platform best-effort sampler. It
// reports the Go runtime's committed memory (MemStats.Sys) as a fraction of an
// optional host memory limit, and 0 for CPU (real per-core CPU% needs platform
// syscalls the relay deliberately does not pull in — an operator injects a proper
// sampler where it matters). The autoscaler's PRIMARY signals are active_tunnels,
// bytes_per_sec and saturation, which are exact; cpu/mem are advisory host gauges.
func defaultSysSampler(memLimitBytes int64) SysSampler {
	return func() (float64, float64) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memPct := 0.0
		if memLimitBytes > 0 {
			memPct = float64(m.Sys) / float64(memLimitBytes) * 100
			if memPct > 100 {
				memPct = 100
			}
		}
		return 0, memPct
	}
}

// popLinkState holds the heartbeat loop's lifecycle handles.
type popLinkState struct {
	stop   chan struct{}
	wg     sync.WaitGroup
	period time.Duration
	sys    SysSampler
}

// heartbeatPeriod resolves the heartbeat cadence: 0 => default 12s, negative =>
// disabled (mirrors the "0=default, <0=off" convention used elsewhere).
func (s *Server) heartbeatPeriod() time.Duration {
	switch {
	case s.cfg.HeartbeatPeriod < 0:
		return 0
	case s.cfg.HeartbeatPeriod == 0:
		return 12 * time.Second
	default:
		return s.cfg.HeartbeatPeriod
	}
}

// startPoPHeartbeat starts the CP registration + load-heartbeat loop. It is a NO-OP
// (the self-host / CP-optional contract) unless BOTH a CP client is configured AND
// a public endpoint is advertised — a PoP the CP cannot route to has nothing to
// register. The loop registers once (retrying briefly), then heartbeats forever.
func (s *Server) startPoPHeartbeat() {
	period := s.heartbeatPeriod()
	if s.cfg.CP == nil || s.cfg.PublicEndpoint == "" || period <= 0 {
		return
	}
	sys := s.cfg.SysSampler
	if sys == nil {
		sys = defaultSysSampler(s.cfg.HostMemLimitBytes)
	}
	s.popLink = &popLinkState{stop: make(chan struct{}), period: period, sys: sys}

	reg := PoPRegistration{
		PoPID:          s.cfg.CP.PoPID,
		Region:         s.cfg.Region,
		Provider:       s.cfg.Provider,
		PublicEndpoint: s.cfg.PublicEndpoint,
		Capacity: PoPCapacity{
			MaxAgents:      s.cfg.SoftCapacity.MaxAgents,
			MaxStreams:     s.cfg.SoftCapacity.MaxStreams,
			MaxBytesPerSec: s.cfg.SoftCapacity.MaxBytesPerSec,
		},
	}

	s.popLink.wg.Add(1)
	go func() {
		defer s.popLink.wg.Done()
		s.runPoPHeartbeat(reg)
	}()
}

// runPoPHeartbeat registers the PoP (with a few quick retries so a transient CP
// blip at boot does not leave the PoP unregistered) and then heartbeats its load
// until stopped. A final heartbeat marked draining is sent on stop so the CP sees
// the PoP leaving even if a graceful drain did not run.
func (s *Server) runPoPHeartbeat(reg PoPRegistration) {
	// Register, retrying briefly on failure.
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := s.cfg.CP.RegisterPoP(ctx, reg)
		cancel()
		if err == nil {
			s.logInfo("PoP registered with CP", logFields{Name: reg.PoPID, Region: reg.Region})
			break
		}
		s.logInfo("PoP registration failed (will retry)", logFields{Name: reg.PoPID, Reason: err.Error()})
		select {
		case <-s.popLink.stop:
			return
		case <-time.After(backoffFor(attempt)):
		}
	}

	var (
		prevBytes int64
		prevAt    time.Time
		havePrev  bool
	)
	beat := func() {
		now := time.Now()
		ld := s.Load()
		var rate int64
		if havePrev {
			if dt := now.Sub(prevAt).Seconds(); dt > 0 {
				if db := ld.TotalBytes - prevBytes; db >= 0 {
					rate = int64(float64(db) / dt)
				}
			}
		}
		prevBytes, prevAt, havePrev = ld.TotalBytes, now, true

		cpu, mem := s.popLink.sys()
		load := PoPLoad{
			PoPID:         reg.PoPID,
			Region:        reg.Region,
			ActiveTunnels: ld.Agents,
			BytesPerSec:   rate,
			CPUPct:        cpu,
			MemPct:        mem,
			Saturation:    s.SaturationRatio(),
			Draining:      s.draining.Load(),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := s.cfg.CP.HeartbeatPoP(ctx, load); err != nil {
			s.logDebug("PoP heartbeat failed", logFields{Name: reg.PoPID, Reason: err.Error()})
		}
		cancel()
	}

	// Seed a baseline immediately so the first tick can derive a byte rate.
	beat()

	t := time.NewTicker(s.popLink.period)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			beat()
		case <-s.popLink.stop:
			// Best-effort farewell heartbeat flagged draining, so the CP drops this
			// PoP from routing promptly on a clean shutdown.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.cfg.CP.HeartbeatPoP(ctx, PoPLoad{
				PoPID: reg.PoPID, Region: reg.Region,
				ActiveTunnels: s.registry.count(), Draining: true,
			})
			cancel()
			return
		}
	}
}

// stopPoPHeartbeat stops the heartbeat loop if running. Idempotent.
func (s *Server) stopPoPHeartbeat() {
	if s.popLink == nil {
		return
	}
	select {
	case <-s.popLink.stop:
		// already closed
	default:
		close(s.popLink.stop)
	}
	s.popLink.wg.Wait()
}

// backoffFor returns a bounded registration retry backoff.
func backoffFor(attempt int) time.Duration {
	d := time.Duration(1<<uint(min(attempt, 4))) * time.Second // 1,2,4,8,16s
	if d > 16*time.Second {
		d = 16 * time.Second
	}
	return d
}
