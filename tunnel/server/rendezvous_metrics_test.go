package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/internal/keyauth"
)

// rendezvous_metrics_test.go — relay-side ground truth for the RENDEZVOUS role.
//
// Before this, only the tunnel role was instrumented: an operator running a
// rendezvous node could not tell announces from resolves, a dead signalling path
// from an idle one, or a rate-limit wall from a client bug. A real end-to-end P2P
// debugging session had no relay-side numbers to check at all.

// TestRendezvousMetrics_AbsentWhenRoleDisabled: a tunnel-only relay's exposition
// is unchanged — no rendezvous series at all, so a scraper can distinguish "role
// off" from "role on, zero traffic".
func TestRendezvousMetrics_AbsentWhenRoleDisabled(t *testing.T) {
	srv := newRendezvousTestServer(t, false)
	h := srv.adminHandler("")
	r := doReq(h, "GET", "/metrics", "127.0.0.1:5555", "")
	if r.Code != http.StatusOK {
		t.Fatalf("/metrics = %d, want 200", r.Code)
	}
	if strings.Contains(r.Body.String(), "vulos_relay_rendezvous_") {
		t.Fatalf("rendezvous series emitted on a tunnel-only relay:\n%s", r.Body.String())
	}
}

// TestRendezvousMetrics_PresentWhenRoleEnabled: with the role on, every counter is
// pre-registered at zero so a dashboard has a stable series set from the first
// scrape.
func TestRendezvousMetrics_PresentWhenRoleEnabled(t *testing.T) {
	srv := newRendezvousTestServer(t, true)
	h := srv.adminHandler("")
	r := doReq(h, "GET", "/metrics", "127.0.0.1:5555", "")
	if r.Code != http.StatusOK {
		t.Fatalf("/metrics = %d, want 200", r.Code)
	}
	out := r.Body.String()
	for _, want := range []string{
		"vulos_relay_rendezvous_live_presence 0",
		"vulos_relay_rendezvous_announces_total 0",
		"vulos_relay_rendezvous_announce_rejects_total 0",
		"vulos_relay_rendezvous_resolves_total 0",
		"vulos_relay_rendezvous_signal_deposits_total 0",
		"vulos_relay_rendezvous_signal_pickups_total 0",
		"vulos_relay_rendezvous_mailbox_deposits_total 0",
		"vulos_relay_rendezvous_mailbox_pickups_total 0",
		"vulos_relay_rendezvous_auth_failures_total 0",
		"vulos_relay_rendezvous_rate_limited_total 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestRendezvousMetrics_CountRealTraffic drives real signed traffic through the
// relay's public handler and asserts the counters move. This is the assertion that
// actually matters: the numbers must reflect what the node did, not just exist.
func TestRendezvousMetrics_CountRealTraffic(t *testing.T) {
	srv := newRendezvousTestServer(t, true)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	key := base64.RawURLEncoding.EncodeToString(pub)

	// A signed announce (accepted) …
	if code := postAnnounce(t, ts.URL, key, priv, time.Now()); code != http.StatusOK {
		t.Fatalf("announce = %d, want 200", code)
	}
	// … a resolve read …
	resolveOnce(t, ts.URL, key)
	// … and an announce with a corrupted signature (rejected).
	if code := postAnnounceBadSig(t, ts.URL, key); code == http.StatusOK {
		t.Fatal("announce with a bad signature was accepted")
	}

	h := srv.adminHandler("")
	r := doReq(h, "GET", "/metrics", "127.0.0.1:5555", "")
	out := r.Body.String()

	for _, want := range []string{
		"vulos_relay_rendezvous_announces_total 1",
		"vulos_relay_rendezvous_resolves_total 1",
		"vulos_relay_rendezvous_live_presence 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The rejected announce must be counted somewhere (reject and/or auth-failure),
	// never silently dropped — a node refusing everything has to be visible.
	if strings.Contains(out, "vulos_relay_rendezvous_announce_rejects_total 0") &&
		strings.Contains(out, "vulos_relay_rendezvous_auth_failures_total 0") {
		t.Errorf("a bad-signature announce moved no reject/auth counter:\n%s", out)
	}
}

// ── signing helpers (mirror tunnel/rendezvous's canonical message) ───────────

// canonicalAnnounce rebuilds the domain-separated, length-prefixed signing message
// for an announce, using the SAME keyauth primitive the service verifies with.
// Field order mirrors rendezvous.announceSigningMessage: key, ts, ttl, nonce, meta,
// then endpoints.
func canonicalAnnounce(key string, endpoints []string, ts int64, nonce string) []byte {
	fields := append([]string{key, strconv.FormatInt(ts, 10), "0", nonce, ""}, endpoints...)
	return keyauth.CanonicalMessage("vulos-rdv/announce/1", fields...)
}

var rdvNonce int

func postAnnounce(t *testing.T, base, key string, priv ed25519.PrivateKey, now time.Time) int {
	t.Helper()
	rdvNonce++
	nonce := fmt.Sprintf("n%d", rdvNonce)
	eps := []string{}
	ts := now.Unix()
	sig := ed25519.Sign(priv, canonicalAnnounce(key, eps, ts, nonce))
	body, _ := json.Marshal(map[string]any{
		"key": key, "endpoints": eps, "ts": ts, "nonce": nonce,
		"sig": base64.RawURLEncoding.EncodeToString(sig),
	})
	req, _ := http.NewRequest("POST", base+"/rendezvous/announce", bytes.NewReader(body))
	req.Host = "relay.example.com"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func postAnnounceBadSig(t *testing.T, base, key string) int {
	t.Helper()
	rdvNonce++
	body, _ := json.Marshal(map[string]any{
		"key": key, "endpoints": []string{}, "ts": time.Now().Unix(),
		"nonce": fmt.Sprintf("n%d", rdvNonce),
		"sig":   base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	})
	req, _ := http.NewRequest("POST", base+"/rendezvous/announce", bytes.NewReader(body))
	req.Host = "relay.example.com"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func resolveOnce(t *testing.T, base, key string) {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/rendezvous/resolve/"+key, nil)
	req.Host = "relay.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
