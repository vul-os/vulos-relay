package server

import (
	"time"

	"github.com/vul-os/vulos-relay/tunnel/autoscale"
)

// load.go — AUTOSCALE-ON-SATURATION: this node's live load surface.
//
// The relay is the core reachability product and runs as a geo-distributed POOL
// (Hetzner primary, Vultr edge) on flat-bandwidth hosts with NO managed
// autoscaler. Scaling is therefore APP-LEVEL: each node measures its own load and
// exposes a saturation signal; an orchestrator (or the in-process
// autoscale.Autoscaler) reads that signal and provisions/drains nodes through the
// provider-agnostic ProvisionerSeam (tunnel/autoscale).
//
// This file gives the server two things:
//
//   - Load(): a point-in-time snapshot (live agents, in-flight streams, cumulative
//     bytes) satisfying autoscale.LoadSource, so the server can be handed straight
//     to an Autoscaler as its source.
//
//   - a background sampler that computes this node's saturation ratio against the
//     configured SoftCapacity and publishes it as the vulos_relay_saturation_ratio
//     gauge, so an EXTERNAL orchestrator scraping /metrics can drive scaling even
//     when it does not run the in-process Autoscaler.

// Load returns this node's current load snapshot. It implements
// autoscale.LoadSource, so *Server can be passed directly to an
// autoscale.NewAutoscaler as the load source for a pool this node participates in.
func (s *Server) Load() autoscale.Sample {
	return autoscale.Sample{
		Agents:     s.registry.count(),
		Streams:    int(nonNeg(s.metrics.activeStreams.get())),
		TotalBytes: s.metrics.totalBytes(),
	}
}

// SoftCapacity returns the node's configured soft capacity (zero when unset).
func (s *Server) SoftCapacity() autoscale.Capacity { return s.cfg.SoftCapacity }

// SaturationRatio returns this node's most-recently-sampled saturation ratio
// (0..1+), the same value published on /metrics. 0 when no soft capacity is
// configured or the sampler has not run yet.
func (s *Server) SaturationRatio() float64 { return s.metrics.saturation() }

// NodeID / Region / Provider expose this node's pool identity (empty on a
// single-node self-host).
func (s *Server) NodeID() string   { return s.cfg.NodeID }
func (s *Server) Region() string   { return s.cfg.Region }
func (s *Server) Provider() string { return s.cfg.Provider }

// PoolNode returns this node as an autoscale.Node, ready to Add to a pool. Addr is
// left empty (the caller knows this node's externally reachable address); ID falls
// back to the domain when NodeID is unset so a node is always identifiable.
func (s *Server) PoolNode() autoscale.Node {
	id := s.cfg.NodeID
	if id == "" {
		id = s.cfg.Domain
	}
	return autoscale.Node{ID: id, Region: s.cfg.Region, Provider: s.cfg.Provider}
}

// saturationSamplePeriod resolves the sampler cadence: a negative period disables
// the sampler; 0 => default 15s.
func (s *Server) saturationSamplePeriod() time.Duration {
	switch {
	case s.cfg.SaturationSamplePeriod < 0:
		return 0
	case s.cfg.SaturationSamplePeriod == 0:
		return 15 * time.Second
	default:
		return s.cfg.SaturationSamplePeriod
	}
}

// startSaturationSampler launches the background saturation sampler. It is a no-op
// when no soft-capacity dimension is configured (saturation is undefined) or the
// period is disabled — so a relay that does not opt into pool scaling is
// byte-for-byte unchanged.
func (s *Server) startSaturationSampler() {
	period := s.saturationSamplePeriod()
	if period <= 0 || s.cfg.SoftCapacity == (autoscale.Capacity{}) {
		return
	}
	s.satStop = make(chan struct{})
	s.satWG.Add(1)
	go func() {
		defer s.satWG.Done()
		t := time.NewTicker(period)
		defer t.Stop()

		var (
			prevBytes int64
			prevAt    time.Time
			havePrev  bool
		)
		sampleOnce := func(now time.Time) {
			ld := s.Load()
			var rate int64
			if havePrev {
				dt := now.Sub(prevAt).Seconds()
				if dt > 0 {
					if db := ld.TotalBytes - prevBytes; db >= 0 {
						rate = int64(float64(db) / dt)
					}
				}
			}
			prevBytes, prevAt, havePrev = ld.TotalBytes, now, true
			s.metrics.setSaturation(autoscale.Saturation(ld, rate, s.cfg.SoftCapacity))
		}
		// Seed a baseline immediately so the first tick can derive a rate.
		sampleOnce(time.Now())

		for {
			select {
			case <-t.C:
				sampleOnce(time.Now())
			case <-s.satStop:
				return
			}
		}
	}()
}

// stopSaturationSampler stops the sampler loop if it is running. Idempotent.
func (s *Server) stopSaturationSampler() {
	if s.satStop == nil {
		return
	}
	select {
	case <-s.satStop:
		// already closed
	default:
		close(s.satStop)
	}
	s.satWG.Wait()
}

var _ autoscale.LoadSource = (*Server)(nil)
