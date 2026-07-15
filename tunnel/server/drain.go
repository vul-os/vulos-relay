package server

import (
	"bufio"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

// drain.go — SMART-AUTOSCALE (relay side): GRACEFUL DRAIN + proactive RECONNECT.
//
// The relay carries STATEFUL, sticky yamux tunnels, so scaling DOWN a PoP must be
// graceful — a hard kill would drop every live tunnel. A CP-side autoscaler drives
// the drain via the authed control endpoint (admin.go): Drain() makes this PoP
//
//	(a) stop accepting NEW tunnels (handleControl refuses registrations, /readyz
//	    flips to draining so a load balancer stops routing here), and
//	(b) send a PROACTIVE CommandReconnect to EVERY connected agent, so each agent
//	    re-resolves its nearest/least-loaded PoP (the CP no longer hands out THIS
//	    one) and migrates make-before-break — no tunnel is dropped.
//
// The CP polls the live draining tunnel count (control /status, or the heartbeat's
// active_tunnels) and terminates the machine once it reaches 0.

// Drain puts the PoP into draining mode and proactively signals every connected
// agent to reconnect elsewhere. It is idempotent (a second Drain just re-broadcasts
// to any stragglers). Returns the number of agents signaled. Flipping readiness to
// draining stops a fronting load balancer / pool health-checker from routing NEW
// public traffic here while in-flight requests wind down.
func (s *Server) Drain() int {
	s.draining.Store(true)
	s.metrics.setReady(false) // /readyz → draining; LB stops routing new traffic here
	s.logInfo("PoP draining: refusing new tunnels, signaling reconnect to all agents", logFields{})
	return s.broadcastReconnect("drain")
}

// Undrain clears draining mode (used if the CP aborts a drain). New tunnels are
// accepted again and readiness is restored.
func (s *Server) Undrain() {
	s.draining.Store(false)
	s.metrics.setReady(true)
	s.logInfo("PoP drain cleared: accepting new tunnels", logFields{})
}

// IsDraining reports whether the PoP is draining.
func (s *Server) IsDraining() bool { return s.draining.Load() }

// DrainingTunnels returns the count of tunnels still connected to this PoP. The CP
// terminates the machine once this reaches 0 during a drain.
func (s *Server) DrainingTunnels() int { return s.registry.count() }

// broadcastReconnect sends a CommandReconnect to every live session, concurrently
// but with a bounded fan-out so a large fleet does not spawn thousands of
// simultaneous goroutines. Off the hot path (only runs on a drain). Returns the
// number of sessions to which the signal was written without error.
func (s *Server) broadcastReconnect(reason string) int {
	sessions := s.registry.snapshot()
	if len(sessions) == 0 {
		return 0
	}

	const maxParallel = 64
	sem := make(chan struct{}, maxParallel)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		signaled int
	)
	for _, sess := range sessions {
		wg.Add(1)
		sem <- struct{}{}
		go func(sess *session) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := s.signalReconnect(sess, reason); err != nil {
				s.logDebug("reconnect signal failed", logFields{Name: sess.name, Reason: err.Error()})
				return
			}
			mu.Lock()
			signaled++
			mu.Unlock()
		}(sess)
	}
	wg.Wait()
	return signaled
}

// signalReconnect opens ONE yamux stream into the agent and writes an
// agent-terminated control request (AgentControlPath + CommandReconnect), then
// reads the tiny ack. The agent handles it itself — nothing is proxied to the box's
// local app. Bounded by a short deadline so a half-dead agent cannot stall the
// drain broadcast. Does NOT consume a per-agent stream slot (a control signal must
// not be starved by the request stream cap); the stream is opened and closed
// immediately.
func (s *Server) signalReconnect(sess *session, reason string) error {
	stream, err := sess.mux.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))

	req, err := http.NewRequest(http.MethodPost, "http://"+sess.name+wire.AgentControlPath, nil)
	if err != nil {
		return err
	}
	req.Header.Set(wire.AgentCommandHeader, wire.CommandReconnect)
	if reason != "" {
		req.Header.Set(wire.AgentReasonHeader, reason)
	}
	req.Header.Set("Connection", "close")
	if err := req.Write(stream); err != nil {
		return err
	}
	// Read (and discard) the agent's small ack so the stream closes cleanly.
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return nil
}
