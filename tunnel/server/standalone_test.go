package server

// standalone_test.go — the SELF-HOST / no-CP contract. A relay run without any
// Vulos Cloud link (no -cp-url/-cp-shared-secret) must still fully function:
// tokens authorize, tunnels route, and NOTHING is metered or gated against a CP.
// These tests pin that contract at the unit level so a future change to the
// billing seam cannot silently make a CP mandatory. The end-to-end no-CP routing
// path is additionally proven by the tunnel_test harness, whose relays carry no CP.

import (
	"testing"
	"time"
)

// TestSelfHost_GateInertWithoutCP: with no CP the entitlement gate is disabled and
// admits every account at connect AND mid-session, never reports a revoke, and its
// over-quota push is a safe no-op. This is the "metering/gating is OPTIONAL" half of
// the self-host contract — a relay with no account link must never refuse a tunnel.
func TestSelfHost_GateInertWithoutCP(t *testing.T) {
	g := newEntitlementGate(nil, 0)
	if g.enabled() {
		t.Fatal("gate with nil CP reports enabled")
	}
	for _, acct := range []string{"", "acct-123", "anything"} {
		if !g.allowConnect(acct) {
			t.Fatalf("self-host gate refused connect for %q", acct)
		}
		if !g.allowContinue(acct) {
			t.Fatalf("self-host gate refused continue for %q", acct)
		}
		if g.definitivelyRevoked(acct) {
			t.Fatalf("self-host gate reported %q revoked", acct)
		}
	}
	// markOverQuota must be a safe no-op (no CP, no cache to poison, no panic).
	g.markOverQuota("acct-123")
	if !g.allowConnect("acct-123") {
		t.Fatal("markOverQuota on a self-host gate wrongly cut an account")
	}
}

// TestSelfHost_MeterInertWithoutCP: with no CP the meter is disabled — its flush
// loop and final drain are no-ops, and the cheap in-memory accounting calls stay
// safe (a relay still counts bytes for its own metrics, it just never ships them).
func TestSelfHost_MeterInertWithoutCP(t *testing.T) {
	m := newMeter(nil, time.Hour)
	if m.enabled() {
		t.Fatal("meter with nil CP reports enabled")
	}
	// The data-path accounting calls must be safe even though nothing is flushed.
	m.addBytes("acct", 4096)
	m.addSession("acct")
	// run() must not start a goroutine that touches a nil CP; flushOnce/stopAndFlush
	// must no-op. If any of these dereferenced the nil CP this would panic.
	m.run()
	m.flushOnce()
	m.stopAndFlush()
}

// TestSelfHost_ServerConstructsAndServesWithoutCP: server.New with a static token
// store and no CP builds a usable relay whose public handler is non-nil, and it is
// safe to Close (which flushes the — disabled — meter). Fails closed only on the
// genuine misconfigurations (missing domain / token store), never on "no CP".
func TestSelfHost_ServerConstructsAndServesWithoutCP(t *testing.T) {
	store, err := NewStaticTokenStore([]Grant{{Token: "secret", Names: []string{"box1"}}})
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	srv, err := New(Config{Domain: "relay.test", Tokens: store}) // no CP
	if err != nil {
		t.Fatalf("self-host server.New: %v", err)
	}
	if srv.Handler() == nil {
		t.Fatal("self-host server has a nil public handler")
	}
	if srv.gate.enabled() || srv.meter.enabled() {
		t.Fatal("self-host server has an enabled gate/meter without a CP")
	}
	srv.Close()
}

// TestSelfHost_NewFailsClosedOnMissingEssentials confirms the constructor still
// refuses to run OPEN — a missing domain or token store is an error even though CP
// is optional. "No CP" is fine; "no token store" is never fine.
func TestSelfHost_NewFailsClosedOnMissingEssentials(t *testing.T) {
	if _, err := New(Config{Domain: "relay.test"}); err == nil {
		t.Fatal("New without a TokenStore must fail closed (refusing to run open)")
	}
	store, _ := NewStaticTokenStore([]Grant{{Token: "s", Names: []string{"n"}}})
	if _, err := New(Config{Tokens: store}); err == nil {
		t.Fatal("New without a Domain must fail")
	}
}
