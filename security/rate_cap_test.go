// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vul-os/vulos-relay/internal/relay"
)

// ─── Attack class 4: per-IP rate cap ─────────────────────────────────────────
//
// The submission gate enforces a per-IP request cap BEFORE authentication so an
// unauthenticated flood from one source cannot exhaust the relay or the auth
// path. The cap is keyed on the connection RemoteAddr and must NOT trust the
// spoofable X-Forwarded-For header.

func postFrom(t *testing.T, h http.Handler, remoteAddr string, xff string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(submitBody()))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// ATTACK: flood the submission endpoint from a single source IP. EXPECT: once
// the per-IP cap is exceeded, requests get 429 BEFORE the auth path even runs.
func TestRateCap_FloodFromOneIP_Gets429(t *testing.T) {
	r := newSubmitRig(t, 3) // cap = 3 / window
	const attacker = "198.51.100.66:40000"

	// First 3 requests pass the limiter (then get 401 from the auth gate).
	for i := 0; i < 3; i++ {
		if code := postFrom(t, r.handler, attacker, ""); code == http.StatusTooManyRequests {
			t.Fatalf("request %d hit cap too early (429)", i+1)
		}
	}
	// The 4th must be rate-limited.
	if code := postFrom(t, r.handler, attacker, ""); code != http.StatusTooManyRequests {
		t.Fatalf("VULN: flood from one IP not capped, 4th request got %d (want 429)", code)
	}
}

// ATTACK: a different source IP must not be penalised by the first IP's flood
// (the cap is per-IP, not global). EXPECT: the second IP is served normally.
func TestRateCap_DifferentIP_Unaffected(t *testing.T) {
	r := newSubmitRig(t, 3)
	const attacker = "198.51.100.66:40000"
	for i := 0; i < 5; i++ {
		_ = postFrom(t, r.handler, attacker, "") // exhaust attacker's window
	}
	// A legitimate, different IP must still be served (not 429).
	if code := postFrom(t, r.handler, "203.0.113.10:51000", ""); code == http.StatusTooManyRequests {
		t.Fatal("VULN: an innocent IP was rate-limited by another IP's flood")
	}
}

// ATTACK: rotate a spoofed X-Forwarded-For header on every request from the
// SAME connection, trying to evade the per-IP cap by appearing to be many
// clients. EXPECT: the cap still triggers — XFF is NOT trusted; the real
// RemoteAddr is what counts.
func TestRateCap_XForwardedForSpoof_DoesNotBypass(t *testing.T) {
	r := newSubmitRig(t, 3)
	const realConn = "198.51.100.99:40000"

	// Burn the window with rotating, spoofed XFF values from one real connection.
	spoofs := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	hit429 := false
	for _, s := range spoofs {
		if code := postFrom(t, r.handler, realConn, s); code == http.StatusTooManyRequests {
			hit429 = true
		}
	}
	if !hit429 {
		t.Fatal("VULN: rotating X-Forwarded-For bypassed the per-IP cap (XFF is trusted)")
	}
}

// ATTACK: confirm the cap runs BEFORE auth — a flood of unauthenticated
// requests should be cheaply turned away with 429, never reaching the
// (more expensive) authenticator. We assert the 429 outcome class directly.
func TestRateCap_EnforcedBeforeAuth(t *testing.T) {
	r := newSubmitRig(t, 1) // cap = 1
	const attacker = "198.51.100.77:40000"

	// First request consumes the single slot (gets 401 — auth ran).
	if code := postFrom(t, r.handler, attacker, ""); code == http.StatusTooManyRequests {
		t.Fatal("first request should not be 429 with cap=1")
	}
	// Second request: limiter rejects with 429 (the auth gate is not consulted).
	if code := postFrom(t, r.handler, attacker, ""); code != http.StatusTooManyRequests {
		t.Fatalf("VULN: rate cap not enforced before auth, got %d (want 429)", code)
	}
	_ = relay.NewMemAccountRegistry // keep relay import meaningful
}
