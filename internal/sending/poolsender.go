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

	// Trust classifies the sending account into a trust tier, which is mapped
	// to the pool SegmentName hint used for selection. This is the warm-IP
	// trust-gating: an untrusted/new account is confined to the cold/ramp
	// segments and never rides a warm "established" IP. If nil, the sender
	// fails closed to the coldest tier (TrustNew) so an unclassified account is
	// never promoted to warm IPs.
	Trust TrustSource

	// SegmentFor is a legacy override that maps an account ID directly to a
	// SegmentName hint. When set it takes precedence over Trust. Prefer Trust;
	// this field is retained so a tenant-aware deployment can inject a fully
	// custom mapping. If both are nil the sender fails closed to the cold tier.
	SegmentFor func(accountID string) SegmentName

	// Observer, if non-nil, is notified of per-send pool events (segment
	// selected, defers) so the metrics layer can export them without this
	// package importing the obs/prometheus stack.
	Observer PoolObserver

	// Logger is used for operational messages. If nil, the standard logger.
	Logger *log.Logger
}

// PoolObserver receives per-send notifications from a PoolSender so an external
// metrics layer can record them. All methods must be safe for concurrent use
// and must not block. A nil PoolObserver disables observation.
type PoolObserver interface {
	// SegmentSelected reports that account was selected onto the given pool
	// segment with the given source IP (ip may be empty if unknown).
	SegmentSelected(accountID string, segment SegmentName, ip string)
	// SendDeferred reports that a send was deferred at the pool layer for the
	// given reason ("no_available_ip" or "ramp_cap").
	SendDeferred(reason string)
	// RampStep reports the current ramp step index for the selected IP.
	RampStep(ip string, step int)
}

func (p *PoolSender) logger() *log.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return log.Default()
}

// segmentHint resolves the pool segment for an account from the trust source
// (or the legacy SegmentFor override). It fails closed to the coldest tier so
// an unclassified account is never selected onto a warm IP.
func (p *PoolSender) segmentHint(accountID string) SegmentName {
	if p.SegmentFor != nil {
		return p.SegmentFor(accountID)
	}
	return SegmentForTrust(p.Trust, accountID) // nil Trust → TrustNew → SegmentNew
}

// Send selects a source binding and delegates to the inner Sender.
func (p *PoolSender) Send(ctx context.Context, msg Message) (SendResult, error) {
	hint := p.segmentHint(msg.AccountID)

	binding, err := p.Pool.Select(SegmentName(msg.AccountID), hint)
	if err != nil {
		// No IP available — either the pool is empty/all quarantined, or this
		// account's trust tier is gated off the only (warm) IPs available. Defer
		// so the message is retried rather than dropped or sent from a warm IP
		// the sender has not earned.
		p.logger().Printf("sending: pool selection failed for account %s (segment hint %q): %v — deferring", msg.AccountID, hint, err)
		if p.Observer != nil {
			p.Observer.SendDeferred("no_available_ip")
		}
		return SendResult{State: StateDeferred, Message: "no available source IP: " + err.Error()}, nil
	}

	ipStr := ""
	if binding.LocalIP != nil {
		ipStr = binding.LocalIP.String()
	}
	if p.Observer != nil {
		p.Observer.SegmentSelected(msg.AccountID, hint, ipStr)
	}

	// Enforce the warm-up ramp cap for the selected IP.
	if p.Ramp != nil && binding.LocalIP != nil {
		if p.Observer != nil {
			p.Observer.RampStep(ipStr, p.Ramp.Step(binding.LocalIP))
		}
		if p.Ramp.CapFor(binding.LocalIP) <= 0 {
			p.logger().Printf("sending: ramp cap exhausted for IP %s (account %s) — deferring", binding.LocalIP, msg.AccountID)
			if p.Observer != nil {
				p.Observer.SendDeferred("ramp_cap")
			}
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
