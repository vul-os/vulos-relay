// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package main

import (
	"github.com/vul-os/vulos-relay/internal/obs"
	"github.com/vul-os/vulos-relay/internal/peering"
	"github.com/vul-os/vulos-relay/internal/relay"
	"github.com/vul-os/vulos-relay/internal/reputation"
	"github.com/vul-os/vulos-relay/internal/sending"
	"github.com/vul-os/vulos-relay/internal/suppression"
)

// metricsObserver bridges each package's observation hooks (sending.PoolObserver,
// sending.SMTPObserver, relay.SubmitObserver, suppression.Observer) to the
// obs/prometheus metrics, so those packages never import the metrics stack. It
// is a stateless adapter; all methods are safe for concurrent use (the
// underlying prometheus collectors are).
type metricsObserver struct{}

var _ sending.PoolObserver = metricsObserver{}
var _ sending.SMTPObserver = metricsObserver{}
var _ relay.SubmitObserver = metricsObserver{}
var _ suppression.Observer = metricsObserver{}
var _ reputation.QuarantineObserver = metricsObserver{}
var _ peering.PeerObserver = metricsObserver{}

// ── PoolObserver ──────────────────────────────────────────────────────────────

func (metricsObserver) SegmentSelected(_ string, segment sending.SegmentName, _ string) {
	obs.PoolSegmentSelections.WithLabelValues(string(segment)).Inc()
}

func (metricsObserver) SendDeferred(reason string) {
	obs.PoolDeferrals.WithLabelValues(reason).Inc()
}

func (metricsObserver) RampStep(ip string, step int) {
	obs.RampStep.WithLabelValues(ip).Set(float64(step))
}

// ── SMTPObserver ──────────────────────────────────────────────────────────────

func (metricsObserver) MTASTSEnforced(_ string) {
	obs.MTASTSEvents.WithLabelValues("enforced").Inc()
}

func (metricsObserver) MTASTSDeferred(_ string, _ string) {
	obs.MTASTSEvents.WithLabelValues("deferred").Inc()
}

func (metricsObserver) DKIMSigned() {
	obs.DKIMSignCount.Inc()
}

// ── relay.SubmitObserver ──────────────────────────────────────────────────────

func (metricsObserver) Submission(ip, outcome string) {
	obs.SubmitPerIP.WithLabelValues(ip, outcome).Inc()
}

// ── suppression.Observer ──────────────────────────────────────────────────────

// Suppressed fires when an address is ADDED to the list (from a DSN/ARF report).
func (metricsObserver) Suppressed(reason suppression.Reason) {
	obs.SuppressionAdds.WithLabelValues(string(reason)).Inc()
}

// Hit fires when a send is BLOCKED because the recipient is suppressed.
func (metricsObserver) Hit(reason suppression.Reason) {
	obs.SuppressionHits.WithLabelValues(string(reason)).Inc()
}

// ── reputation.QuarantineObserver ─────────────────────────────────────────────

func (metricsObserver) Quarantined(source string) {
	obs.QuarantineEvents.WithLabelValues(source).Inc()
}

// ── peering.PeerObserver ──────────────────────────────────────────────────────

func (metricsObserver) PeerDelivered() {
	obs.PeeringEvents.WithLabelValues("deliver").Inc()
}

func (metricsObserver) PeerRejected(_ string) {
	obs.PeeringEvents.WithLabelValues("reject").Inc()
}
