package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/autoscale"
)

// poplink_test.go — SMART-AUTOSCALE (relay side): PoP registration + load
// heartbeat. These pin the CP↔relay autoscaler contract a CP-side autoscaler
// consumes: the payload shapes, the HMAC signature, and the CP-OPTIONAL rule that
// a relay with no CP (or no public endpoint) never runs any of it.

// fakePoPCP captures PoP registrations + heartbeats and verifies the X-Pop-Sig HMAC.
type fakePoPCP struct {
	secret string

	mu         sync.Mutex
	registered []PoPRegistration
	heartbeats []PoPLoad
	badSig     int
}

func newFakePoPCP(secret string) *fakePoPCP { return &fakePoPCP{secret: secret} }

func (f *fakePoPCP) verify(body []byte, sig string) bool {
	mac := hmac.New(sha256.New, []byte(f.secret))
	mac.Write(body)
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig))
}

func (f *fakePoPCP) server(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/relay/pop/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if !f.verify(body, r.Header.Get("X-Pop-Sig")) {
			f.mu.Lock()
			f.badSig++
			f.mu.Unlock()
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		var reg PoPRegistration
		_ = json.Unmarshal(body, &reg)
		f.mu.Lock()
		f.registered = append(f.registered, reg)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /api/relay/pop/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if !f.verify(body, r.Header.Get("X-Pop-Sig")) {
			f.mu.Lock()
			f.badSig++
			f.mu.Unlock()
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		var ld PoPLoad
		_ = json.Unmarshal(body, &ld)
		f.mu.Lock()
		f.heartbeats = append(f.heartbeats, ld)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakePoPCP) regs() []PoPRegistration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]PoPRegistration(nil), f.registered...)
}

func (f *fakePoPCP) beats() []PoPLoad {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]PoPLoad(nil), f.heartbeats...)
}

// TestCPClient_RegisterAndHeartbeat_HMAC verifies the two new CP calls sign the
// exact body with X-Pop-Sig and carry the contract's fields.
func TestCPClient_RegisterAndHeartbeat_HMAC(t *testing.T) {
	fake := newFakePoPCP("popsecret")
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "popsecret", PoPID: "hel1-a", Region: "eu-central"}

	reg := PoPRegistration{
		PoPID: "hel1-a", Region: "eu-central", Provider: "hetzner",
		PublicEndpoint: "wss://hel1.relay.test",
		Capacity:       PoPCapacity{MaxAgents: 500, MaxStreams: 2000, MaxBytesPerSec: 1 << 30},
	}
	if err := cp.RegisterPoP(context.Background(), reg); err != nil {
		t.Fatalf("RegisterPoP: %v", err)
	}
	load := PoPLoad{
		PoPID: "hel1-a", Region: "eu-central",
		ActiveTunnels: 7, BytesPerSec: 12345, CPUPct: 4, MemPct: 20, Saturation: 0.35,
	}
	if err := cp.HeartbeatPoP(context.Background(), load); err != nil {
		t.Fatalf("HeartbeatPoP: %v", err)
	}

	if fake.badSig != 0 {
		t.Fatalf("HMAC verification failed on %d requests", fake.badSig)
	}
	regs := fake.regs()
	if len(regs) != 1 || regs[0].PublicEndpoint != "wss://hel1.relay.test" ||
		regs[0].Region != "eu-central" || regs[0].Capacity.MaxAgents != 500 {
		t.Fatalf("registration not recorded as expected: %+v", regs)
	}
	beats := fake.beats()
	if len(beats) != 1 || beats[0].ActiveTunnels != 7 || beats[0].BytesPerSec != 12345 ||
		beats[0].Region != "eu-central" {
		t.Fatalf("heartbeat not recorded as expected: %+v", beats)
	}
}

// TestCPClient_RegisterPoP_RejectsTamperedBody proves the CP rejects a body whose
// signature does not match (a wrong shared secret).
func TestCPClient_PoP_BadSecretRejected(t *testing.T) {
	fake := newFakePoPCP("right")
	srv := fake.server(t)
	cp := &CPClient{BaseURL: srv.URL, SharedSecret: "wrong", PoPID: "p"}
	if err := cp.RegisterPoP(context.Background(), PoPRegistration{PoPID: "p"}); err == nil {
		t.Fatal("expected registration with wrong secret to be rejected")
	}
	if fake.badSig == 0 {
		t.Fatal("CP did not observe a bad signature")
	}
}

// TestPoPHeartbeat_NoOpWithoutCP: a self-host relay (no CP) never starts the
// heartbeat loop — the CP-optional contract.
func TestPoPHeartbeat_NoOpWithoutCP(t *testing.T) {
	s := newTestServer(t) // no CP
	if s.popLink != nil {
		t.Fatal("heartbeat loop started on a CP-less relay")
	}
}

// TestPoPHeartbeat_NoOpWithoutPublicEndpoint: a relay WITH a CP but no advertised
// public endpoint is not a routable PoP, so it does not register/heartbeat.
func TestPoPHeartbeat_NoOpWithoutPublicEndpoint(t *testing.T) {
	store, _ := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	s, err := New(Config{
		Domain:            "relay.test",
		Tokens:            store,
		RevokeSweepPeriod: -1,
		CP:                &CPClient{BaseURL: "http://cp.invalid", SharedSecret: "s", PoPID: "p"},
		// PublicEndpoint intentionally empty.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	if s.popLink != nil {
		t.Fatal("heartbeat loop started without a public endpoint")
	}
}

// TestPoPHeartbeat_RegistersAndBeats: a fully-configured PoP registers once and then
// heartbeats its live load (active_tunnels reflects the registry), off the hot path.
func TestPoPHeartbeat_RegistersAndBeats(t *testing.T) {
	fake := newFakePoPCP("popsecret")
	cpSrv := fake.server(t)
	store, _ := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	s, err := New(Config{
		Domain:            "relay.test",
		Tokens:            store,
		RevokeSweepPeriod: -1,
		Region:            "af-south",
		Provider:          "vultr",
		CP:                &CPClient{BaseURL: cpSrv.URL, SharedSecret: "popsecret", PoPID: "jhb-1", Region: "af-south"},
		PublicEndpoint:    "wss://jhb.relay.test",
		HeartbeatPeriod:   10 * time.Millisecond,
		SoftCapacity:      autoscale.Capacity{MaxAgents: 100},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)

	if !waitFor(2*time.Second, func() bool { return len(fake.regs()) >= 1 }) {
		t.Fatal("PoP never registered with the CP")
	}
	reg := fake.regs()[0]
	if reg.PoPID != "jhb-1" || reg.PublicEndpoint != "wss://jhb.relay.test" || reg.Region != "af-south" {
		t.Fatalf("registration fields wrong: %+v", reg)
	}
	if reg.Capacity.MaxAgents != 100 {
		t.Fatalf("registration capacity not carried: %+v", reg.Capacity)
	}
	if !waitFor(2*time.Second, func() bool { return len(fake.beats()) >= 2 }) {
		t.Fatal("PoP did not heartbeat repeatedly")
	}
	for _, b := range fake.beats() {
		if b.PoPID != "jhb-1" || b.Region != "af-south" {
			t.Fatalf("heartbeat identity wrong: %+v", b)
		}
	}
	if fake.badSig != 0 {
		t.Fatalf("some heartbeat/registration failed HMAC (%d)", fake.badSig)
	}
}

// TestPoPHeartbeat_SendsDrainingFlag: a draining PoP reports draining=true so the CP
// stops assigning new tunnels to it.
func TestPoPHeartbeat_SendsDrainingFlag(t *testing.T) {
	fake := newFakePoPCP("popsecret")
	cpSrv := fake.server(t)
	store, _ := NewStaticTokenStore([]Grant{{Token: "t", Names: []string{"box1"}}})
	s, err := New(Config{
		Domain:            "relay.test",
		Tokens:            store,
		RevokeSweepPeriod: -1,
		CP:                &CPClient{BaseURL: cpSrv.URL, SharedSecret: "popsecret", PoPID: "p", Region: "eu"},
		PublicEndpoint:    "wss://p.relay.test",
		HeartbeatPeriod:   10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)

	// Wait for the loop to be beating, then drain and assert a draining heartbeat.
	if !waitFor(2*time.Second, func() bool { return len(fake.beats()) >= 1 }) {
		t.Fatal("no heartbeat before drain")
	}
	s.Drain()
	if !waitFor(2*time.Second, func() bool {
		for _, b := range fake.beats() {
			if b.Draining {
				return true
			}
		}
		return false
	}) {
		t.Fatal("no draining heartbeat observed after Drain()")
	}
}
