// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package obs_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vul-os/vulos-relay/internal/obs"
)

// TestSecurityMetricsExported verifies the new security/deliverability
// counters and gauges are registered and surfaced via the /metrics handler.
func TestSecurityMetricsExported(t *testing.T) {
	obs.Init()

	// Touch each new metric so it has a non-empty series exported.
	obs.QuarantineEvents.WithLabelValues("spamhaus").Inc()
	obs.RampStep.WithLabelValues("203.0.113.5").Set(2)
	obs.SubmitPerIP.WithLabelValues("198.51.100.7", "rate_limited").Inc()
	obs.SuppressionHits.WithLabelValues("hard_bounce").Inc()
	obs.SuppressionAdds.WithLabelValues("complaint").Inc()
	obs.DKIMSignCount.Inc()
	obs.PeeringEvents.WithLabelValues("deliver").Inc()
	obs.PeeringEvents.WithLabelValues("reject").Inc()
	obs.MTASTSEvents.WithLabelValues("deferred").Inc()
	obs.PoolSegmentSelections.WithLabelValues("untrusted").Inc()
	obs.PoolDeferrals.WithLabelValues("ramp_cap").Inc()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	obs.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("/metrics status: want 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	wantSeries := []string{
		"vulos_relay_quarantine_events_total",
		"vulos_relay_ramp_step",
		"vulos_relay_submit_total",
		"vulos_relay_suppression_hits_total",
		"vulos_relay_suppression_adds_total",
		"vulos_relay_dkim_sign_total",
		"vulos_relay_peering_events_total",
		"vulos_relay_mtasts_events_total",
		"vulos_relay_pool_segment_selections_total",
		"vulos_relay_pool_deferrals_total",
	}
	for _, name := range wantSeries {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics output missing series %q", name)
		}
	}
	// Spot-check a couple of label values are present.
	if !strings.Contains(body, `source="spamhaus"`) {
		t.Error("quarantine_events missing source label value")
	}
	if !strings.Contains(body, `outcome="rate_limited"`) {
		t.Error("submit_total missing outcome=rate_limited label")
	}
}
