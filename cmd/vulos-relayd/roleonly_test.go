package main

import (
	"errors"
	"os"
	"testing"

	"github.com/vul-os/vulos-relay/tunnel/server"
)

// roleonly_test.go — a node serving ONLY the rendezvous (and/or pubcache) role
// must start with no agent grants.
//
// It previously refused to boot without them, so anyone running a pure rendezvous
// node had to invent a dummy token authorizing a box that did not exist — a
// startup gate with nothing behind it, and a worse security posture than no grant
// at all. The fix must NOT weaken the tunnel relay's fail-closed stance: with no
// grants the tunnel surface must authorize NOBODY.

func TestLoadGrants_NoSourceIsIdentifiableError(t *testing.T) {
	t.Setenv("VULOS_RELAY_TOKENS", "")
	_, err := loadGrants("")
	if !errors.Is(err, errNoGrants) {
		t.Fatalf("loadGrants with no source: err = %v, want errNoGrants (the role-only branch keys on it)", err)
	}
}

func TestLoadGrants_StillReadsConfiguredSources(t *testing.T) {
	t.Setenv("VULOS_RELAY_TOKENS", `[{"token":"SECRET","names":["box1"]}]`)
	grants, err := loadGrants("")
	if err != nil {
		t.Fatalf("env grants: %v", err)
	}
	if len(grants) != 1 || grants[0].Names[0] != "box1" {
		t.Fatalf("env grants not parsed: %+v", grants)
	}

	f, err := os.CreateTemp(t.TempDir(), "grants*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`[{"token":"S2","names":["box2"]}]`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	g2, err := loadGrants(f.Name())
	if err != nil {
		t.Fatalf("file grants: %v", err)
	}
	if len(g2) != 1 || g2[0].Names[0] != "box2" {
		t.Fatalf("file grants not parsed: %+v", g2)
	}
}

func TestRolesWithoutTunnel(t *testing.T) {
	cases := []struct {
		rdv, pub, want bool
	}{
		{false, false, false}, // plain tunnel relay: no grants is still fatal
		{true, false, true},   // pure rendezvous node
		{false, true, true},   // pure pubcache node
		{true, true, true},
	}
	for _, c := range cases {
		if got := rolesWithoutTunnel(c.rdv, c.pub); got != c.want {
			t.Errorf("rolesWithoutTunnel(%v,%v) = %v, want %v", c.rdv, c.pub, got, c.want)
		}
	}
}

func TestEnabledRoleNames(t *testing.T) {
	for _, c := range []struct {
		rdv, pub bool
		want     string
	}{
		{true, false, "rendezvous"},
		{false, true, "pubcache"},
		{true, true, "rendezvous+pubcache"},
		{false, false, "none"},
	} {
		if got := enabledRoleNames(c.rdv, c.pub); got != c.want {
			t.Errorf("enabledRoleNames(%v,%v) = %q, want %q", c.rdv, c.pub, got, c.want)
		}
	}
}

// TestEmptyGrantStore_StartsButAuthorizesNobody is the load-bearing assertion:
// role-only mode is "no tunnels", never "open tunnels".
func TestEmptyGrantStore_StartsButAuthorizesNobody(t *testing.T) {
	store := server.NewDenyAllTokenStore()

	srv, err := server.New(server.Config{
		Domain:           "relay.example.com",
		Tokens:           store,
		EnableRendezvous: true,
	})
	if err != nil {
		t.Fatalf("rendezvous-only relay refused to start with no grants: %v", err)
	}
	defer srv.Close()

	// Nothing is authorized — not a made-up token, not an empty one.
	for _, tok := range []string{"", "anything", "dummy-token-operators-used-to-invent"} {
		if _, err := store.Authorize(tok, "box1"); err == nil {
			t.Fatalf("empty grant store authorized token %q — role-only mode must authorize nobody", tok)
		}
	}
}

// TestStaticStoreStillRefusesEmptyGrants guards the OTHER half of the change: the
// role-only path must not have weakened the plain tunnel relay. A static grant set
// that parses to nothing is still a hard failure — an operator whose grants file
// silently produced zero entries must not end up with a relay that started anyway.
func TestStaticStoreStillRefusesEmptyGrants(t *testing.T) {
	if _, err := server.NewStaticTokenStore(nil); err == nil {
		t.Fatal("static token store accepted an empty grant set — the fail-closed guard was weakened")
	}
	if _, err := server.NewStaticTokenStore([]server.Grant{}); err == nil {
		t.Fatal("static token store accepted a zero-length grant slice")
	}
}
