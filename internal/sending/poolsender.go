// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"context"
	"log"
)

// PoolSender is a Sender that selects a warmed source IP from a Pool (honouring
// ramp caps from a RampScheduler) for each outbound message, then delegates to
// an inner Sender (typically *SMTPSender) with the chosen SourceBinding.
//
// This is the wiring that makes the warm-IP pool, the ramp scheduler, and (via
// the Pool's Quarantine hook fed by a BlocklistMonitor) the blocklist
// quarantine actually take effect on the send path.
//
// PoolSender is safe for concurrent use (Pool and RampScheduler are).
type PoolSender struct {
	// Pool supplies SourceBindings. Required.
	Pool *Pool

	// Ramp, if non-nil, enforces per-IP warm-up daily caps: an IP whose CapFor
	// is exhausted is skipped, and each dispatched message is Recorded against
	// the ramp counter.
	Ramp *RampScheduler

	// Inner is the underlying Sender that performs delivery. Required.
	Inner Sender

	// SegmentFor maps an account ID to the pool SegmentName hint used for
	// selection. If nil, the empty hint ("best available") is used.
	SegmentFor func(accountID string) SegmentName

	// Logger is used for operational messages. If nil, the standard logger.
	Logger *log.Logger
}

func (p *PoolSender) logger() *log.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return log.Default()
}

// Send selects a source binding and delegates to the inner Sender.
func (p *PoolSender) Send(ctx context.Context, msg Message) (SendResult, error) {
	hint := SegmentName("")
	if p.SegmentFor != nil {
		hint = p.SegmentFor(msg.AccountID)
	}

	binding, err := p.Pool.Select(SegmentName(msg.AccountID), hint)
	if err != nil {
		// No IP available (all quarantined or none configured) — defer so the
		// message is retried rather than dropped or sent from an arbitrary IP.
		p.logger().Printf("sending: pool selection failed for account %s: %v — deferring", msg.AccountID, err)
		return SendResult{State: StateDeferred, Message: "no available source IP: " + err.Error()}, nil
	}

	// Enforce the warm-up ramp cap for the selected IP.
	if p.Ramp != nil && binding.LocalIP != nil {
		if p.Ramp.CapFor(binding.LocalIP) <= 0 {
			p.logger().Printf("sending: ramp cap exhausted for IP %s (account %s) — deferring", binding.LocalIP, msg.AccountID)
			return SendResult{State: StateDeferred, Message: "ramp daily cap reached for source IP"}, nil
		}
	}

	msg.Binding = &binding
	result, sendErr := p.Inner.Send(ctx, msg)

	// Record the dispatch against the ramp counter for delivered/deferred
	// attempts (a 5xx bounce still consumed a connection attempt, so count it
	// too — the cap protects the receiving side from volume, regardless of
	// outcome).
	if p.Ramp != nil && binding.LocalIP != nil {
		p.Ramp.Record(binding.LocalIP)
	}

	return result, sendErr
}

var _ Sender = (*PoolSender)(nil)
