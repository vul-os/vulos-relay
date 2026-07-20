package server

import (
	"testing"

	"github.com/vul-os/vulos-relay/tunnel/agent"
)

// TestDirectProbe_BudgetDefaults asserts the probe-reflection budget defaults: an
// unset rate/burst resolves to 1/s, burst 5; a negative value disables the limiter.
func TestDirectProbe_BudgetDefaults(t *testing.T) {
	var zero Config
	zero.applyDefaults()
	if zero.DirectProbeRate != 1 || zero.DirectProbeBurst != 5 {
		t.Fatalf("default probe budget = %v/%v, want 1/5", zero.DirectProbeRate, zero.DirectProbeBurst)
	}
	off := Config{DirectProbeRate: -1}
	off.applyDefaults()
	if off.DirectProbeRate != 0 {
		t.Fatalf("negative DirectProbeRate should disable (→0), got %v", off.DirectProbeRate)
	}
}

// TestDirectProbe_BudgetExhausted drives the per-account/per-name probe budget guard
// directly: a burst of probes for one key is allowed up to the burst, then refused,
// while a DIFFERENT key is unaffected (per-key isolation). This is the guard control.go
// consults before making the relay emit an outbound verification GET, so a box cannot
// re-register in a loop to reflect GETs off the relay.
func TestDirectProbe_BudgetExhausted(t *testing.T) {
	store, _ := NewStaticTokenStore([]Grant{{Token: "tok", Names: []string{"box1"}}})
	s, err := New(Config{
		Domain: "relay.test", Tokens: store,
		DirectProbeBurst:  2,
		DirectProbeRate:   0.001, // effectively no refill during the test
		RevokeSweepPeriod: -1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)

	// Account "acct-1": first burst(=2) probes allowed, the third refused.
	// Two separate draws against acct-1's budget; burst is 2.
	first, second := s.allowDirectProbe("acct-1", "box1"), s.allowDirectProbe("acct-1", "box1")
	if !first || !second {
		t.Fatal("first two probes within burst must be allowed")
	}
	if s.allowDirectProbe("acct-1", "box1") {
		t.Fatal("third probe past burst must be refused (probe budget not enforced)")
	}
	// A different account is isolated — its own burst is intact.
	if !s.allowDirectProbe("acct-2", "box1") {
		t.Fatal("a different account's probe budget must be independent")
	}
	// Unbilled (empty account) is keyed by name and also bounded.
	unbilled1, unbilled2 := s.allowDirectProbe("", "boxA"), s.allowDirectProbe("", "boxA")
	if !unbilled1 || !unbilled2 {
		t.Fatal("unbilled probes within burst must be allowed")
	}
	if s.allowDirectProbe("", "boxA") {
		t.Fatal("unbilled probe past burst must be refused")
	}
}

// TestDirectProbe_BudgetSkipsProbeAtRegister is the integration guard: when the
// budget for a box's key is already spent, a fresh register does NOT run the verifier
// (no reflected outbound GET) and reports directErr="probe rate limited", while the
// tunnel still comes up on the relay path.
func TestDirectProbe_BudgetSkipsProbeAtRegister(t *testing.T) {
	sv := &stubVerifier{accept: true}
	// Burst 1, negligible refill: exactly one probe is affordable per key.
	ws, base, s := liveRelay(t, Config{
		directVerifier:   sv,
		DirectProbeBurst: 1,
		DirectProbeRate:  0.001,
	})

	// Pre-spend the single probe token for this box's key. The static grant carries no
	// account, so the key is name-based ("name:box1"); consume it before the box dials.
	if !s.allowDirectProbe("", "box1") {
		t.Fatal("pre-spend probe token should be allowed once")
	}

	a, stop := bringUpBox(t, ws, "https://box1.example.net")
	defer stop()

	snap := a.Snapshot()
	if snap.Status != agent.StatusConnected {
		t.Fatalf("box must still connect on the relay path, got %v", snap.Status)
	}
	if snap.DirectVerified {
		t.Fatal("direct must NOT be verified when the probe budget was exhausted")
	}
	if snap.DirectError != "probe rate limited" {
		t.Fatalf("expected directErr=%q, got %q", "probe rate limited", snap.DirectError)
	}
	if sv.calls.Load() != 0 {
		t.Fatalf("verifier must NOT run when the probe budget is spent, ran %d", sv.calls.Load())
	}
	// And the client discovery reports no direct endpoint.
	if got := resolveDirect(t, base); got.Direct {
		t.Fatalf("resolve must report direct=false when the probe was skipped, got %+v", got)
	}
}
