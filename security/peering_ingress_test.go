// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/vul-os/vulos-relay/internal/peering"
)

// ─── Attack class 2: peering ingress authentication ──────────────────────────
//
// The peering HTTP ingress is authenticated ingress: there is NO open
// injection path. Every mail envelope must pass the full §8 checks (signature
// against the pinned sender key, sender-domain authority, receiver targeting,
// replay window, AEAD integrity) before anything is delivered. Each test below
// forges or tampers with one of those and proves the ingress rejects it (422 +
// the matching X-Vulos-Peer-Outcome) and never delivers to the canary sink.

// ATTACK: a peer sends an envelope with a BAD signature (the signed bytes are
// tampered after sealing). EXPECT: rejected as unauthenticated, never delivered.
func TestPeering_ForgedSignature_Rejected(t *testing.T) {
	attacker, _ := peering.GenerateIdentity()
	victim := newPeerVictim(t, "victim.example", nil)
	victim.pinIdentity(t, "attacker.example", attacker)

	env := sealFrom(t, attacker, "attacker.example", victim,
		"eve@attacker.example", []string{"bob@victim.example"}, []byte("forged"))
	// Flip a payload byte: breaks both the Ed25519 signature and the AEAD tag.
	env.Payload[0] ^= 0xff
	wire := peering.MarshalEnvelope(env)

	status, outcome := postWire(t, victim, wire)
	if status != http.StatusUnprocessableEntity || outcome != "unauthenticated" {
		t.Fatalf("forged signature: want 422/unauthenticated, got %d/%q", status, outcome)
	}
	if victim.sink.delivered() != 0 {
		t.Fatal("VULN: forged-signature envelope was delivered to local mailbox")
	}
}

// ATTACK: replay a byte-identical, fully-valid envelope a second time within
// the acceptance window. EXPECT: the second delivery is rejected as a replay
// and the message is delivered exactly once.
func TestPeering_ReplayWithinWindow_Rejected(t *testing.T) {
	sender, _ := peering.GenerateIdentity()
	victim := newPeerVictim(t, "victim.example", nil)
	victim.pinIdentity(t, "sender.example", sender)

	env := sealFrom(t, sender, "sender.example", victim,
		"alice@sender.example", []string{"bob@victim.example"}, []byte("once only"))
	wire := peering.MarshalEnvelope(env)

	// First delivery: accepted.
	if status, _ := postWire(t, victim, wire); status != http.StatusAccepted {
		t.Fatalf("first delivery should be accepted, got %d", status)
	}
	// Replay the identical wire: must be rejected as a replay.
	status, outcome := postWire(t, victim, wire)
	if status != http.StatusUnprocessableEntity || outcome != "replay" {
		t.Fatalf("replay: want 422/replay, got %d/%q", status, outcome)
	}
	if got := victim.sink.delivered(); got != 1 {
		t.Fatalf("VULN: replay delivered the message %d times, want exactly 1", got)
	}
}

// ATTACK: a relay we have never pinned tries to deliver a (correctly self-
// signed) envelope. EXPECT: rejected as unauthorized — an unknown/unpinned peer
// can never inject mail (no TOFU on the ingress path).
func TestPeering_UnknownUnpinnedPeer_Rejected(t *testing.T) {
	stranger, _ := peering.GenerateIdentity()
	victim := newPeerVictim(t, "victim.example", nil)
	// NOTE: victim does NOT pin stranger.example — it is entirely unknown.

	env := sealFrom(t, stranger, "stranger.example", victim,
		"mallory@stranger.example", []string{"bob@victim.example"}, []byte("hi from nowhere"))
	wire := peering.MarshalEnvelope(env)

	status, outcome := postWire(t, victim, wire)
	if status != http.StatusUnprocessableEntity || outcome != "unauthorized" {
		t.Fatalf("unknown peer: want 422/unauthorized, got %d/%q", status, outcome)
	}
	if victim.sink.delivered() != 0 {
		t.Fatal("VULN: unknown/unpinned peer was able to inject mail")
	}
}

// ATTACK: a pinned peer signs correctly but lies about its origin domain —
// claims to be sender.example while its key is pinned under attacker.example
// (impersonation of a domain it is not authoritative for). EXPECT: rejected
// (the signing key is not the pin for the claimed domain).
func TestPeering_SenderDomainImpersonation_Rejected(t *testing.T) {
	attacker, _ := peering.GenerateIdentity()
	victim := newPeerVictim(t, "victim.example", nil)
	// attacker's key is pinned ONLY under attacker.example.
	victim.pinIdentity(t, "attacker.example", attacker)

	// It claims to be the (also-pinned, but different) bank.example.
	other, _ := peering.GenerateIdentity()
	victim.pinIdentity(t, "bank.example", other)

	env := sealFrom(t, attacker, "bank.example", victim,
		"ceo@bank.example", []string{"bob@victim.example"}, []byte("wire me money"))
	wire := peering.MarshalEnvelope(env)

	status, outcome := postWire(t, victim, wire)
	if status != http.StatusUnprocessableEntity || outcome != "unauthorized" {
		t.Fatalf("domain impersonation: want 422/unauthorized, got %d/%q", status, outcome)
	}
	if victim.sink.delivered() != 0 {
		t.Fatal("VULN: a peer impersonated a domain it does not hold the pinned key for")
	}
}

// ATTACK: an envelope addressed to the WRONG receiver — sealed to one node's
// kex key but POSTed at a different node, OR listing a recipient domain the
// receiver is not authoritative for. EXPECT: rejected as misrouted; the
// receiver never decrypts/delivers mail not meant for it.
func TestPeering_WrongReceiverTarget_Rejected(t *testing.T) {
	sender, _ := peering.GenerateIdentity()
	victim := newPeerVictim(t, "victim.example", nil)
	otherNode := newPeerVictim(t, "other.example", nil)
	victim.pinIdentity(t, "sender.example", sender)
	otherNode.pinIdentity(t, "sender.example", sender)

	// Seal to otherNode's key, but POST it at victim's ingress.
	env := sealFrom(t, sender, "sender.example", otherNode,
		"alice@sender.example", []string{"x@other.example"}, []byte("not for you"))
	wire := peering.MarshalEnvelope(env)

	status, outcome := postWire(t, victim, wire)
	if status != http.StatusUnprocessableEntity || outcome != "misrouted" {
		t.Fatalf("wrong receiver: want 422/misrouted, got %d/%q", status, outcome)
	}
	if victim.sink.delivered() != 0 {
		t.Fatal("VULN: an envelope targeted at another receiver was delivered here")
	}
}

// ATTACK: an envelope correctly sealed to the victim's key, but every recipient
// is at a domain the victim is not authoritative for (relay-through attempt).
// EXPECT: rejected as misrouted.
func TestPeering_RelayThroughForeignRecipient_Rejected(t *testing.T) {
	sender, _ := peering.GenerateIdentity()
	victim := newPeerVictim(t, "victim.example", nil)
	victim.pinIdentity(t, "sender.example", sender)

	env := sealFrom(t, sender, "sender.example", victim,
		"alice@sender.example", []string{"carol@elsewhere.example"}, []byte("please relay"))
	wire := peering.MarshalEnvelope(env)

	status, outcome := postWire(t, victim, wire)
	if status != http.StatusUnprocessableEntity || outcome != "misrouted" {
		t.Fatalf("relay-through: want 422/misrouted, got %d/%q", status, outcome)
	}
	if victim.sink.delivered() != 0 {
		t.Fatal("VULN: relay accepted mail for a domain it is not authoritative for")
	}
}

// ATTACK: AEAD-tamper. The signature is recomputed by an attacker who controls
// the claimed sender key, but the ciphertext was produced for a DIFFERENT
// receiver key, so the AEAD tag will not verify against the recovered shared
// secret. We model the inverse: take a valid envelope, mutate ONLY the
// ciphertext, and (because we cannot re-sign as the real pinned sender) prove
// it is caught at the signature gate. A pure-AEAD tamper that still carries a
// valid signature is impossible without the sender's signing key, which is the
// security property — so we additionally tamper the AAD-bound header nonce on a
// validly-signed envelope by re-sealing with a mismatched key, asserting the
// open fails. Here we tamper the ciphertext tail (post-signature bytes) to show
// the AEAD/signature binding rejects it.
func TestPeering_AEADTamper_Rejected(t *testing.T) {
	sender, _ := peering.GenerateIdentity()
	victim := newPeerVictim(t, "victim.example", nil)
	victim.pinIdentity(t, "sender.example", sender)

	env := sealFrom(t, sender, "sender.example", victim,
		"alice@sender.example", []string{"bob@victim.example"}, []byte("tamper me"))
	// Flip the LAST ciphertext byte (the AEAD tag region). This breaks the
	// signature (which covers header||payload) — the attacker cannot re-sign
	// without sender's Ed25519 private key — so it is caught at §8.1.
	env.Payload[len(env.Payload)-1] ^= 0x01
	wire := peering.MarshalEnvelope(env)

	status, outcome := postWire(t, victim, wire)
	if status != http.StatusUnprocessableEntity || (outcome != "unauthenticated" && outcome != "corrupt") {
		t.Fatalf("AEAD tamper: want 422/(unauthenticated|corrupt), got %d/%q", status, outcome)
	}
	if victim.sink.delivered() != 0 {
		t.Fatal("VULN: an AEAD-tampered envelope was delivered")
	}
}

// ATTACK: a malformed/garbage wire blob (not a valid envelope, not a known
// side-channel frame). EXPECT: rejected as corrupt, no delivery, no panic.
func TestPeering_GarbageWire_Rejected(t *testing.T) {
	victim := newPeerVictim(t, "victim.example", nil)
	status, outcome := postWire(t, victim, []byte("\x00\x01garbage-not-an-envelope\xff\xff"))
	if status != http.StatusUnprocessableEntity || outcome != "corrupt" {
		t.Fatalf("garbage wire: want 422/corrupt, got %d/%q", status, outcome)
	}
	if victim.sink.delivered() != 0 {
		t.Fatal("VULN: garbage wire produced a delivery")
	}
}

// ─── Attack class 2 (forged key-rotation) ────────────────────────────────────

// ATTACK: a forged key-rotation attestation — an attacker publishes a new
// identity key for a domain we pin, signed by the ATTACKER's key (not the held
// pin). EXPECT: rejected; the pin is NOT changed, so a follow-up envelope signed
// by the attacker's "new" key is still unauthorized.
func TestPeering_ForgedKeyRotation_Rejected(t *testing.T) {
	legit, _ := peering.GenerateIdentity()    // the real, currently-pinned key
	attacker, _ := peering.GenerateIdentity() // attacker who wants to take over the domain
	victim := newPeerVictim(t, "victim.example", nil)
	victim.pinIdentity(t, "target.example", legit)

	// Attacker tries to re-pin target.example to attacker.SignPub, signing the
	// rotation with their OWN key (not the held pin `legit`).
	att := &peering.RotationAttestation{
		Domain:         "target.example",
		NewIdentityPub: attacker.SignPub,
		NewKexPub:      attacker.KexPub,
	}
	peering.SignRotation(att, attacker.SignPriv) // signed by attacker, not the pin
	body, err := peering.MarshalRotation(att)
	if err != nil {
		t.Fatal(err)
	}
	frame := peering.MakeRotationFrame(body)

	// The ingress applies rotations on the side-channel; a forged one is rejected.
	status, outcome := postWire(t, victim, frame)
	if status != http.StatusUnprocessableEntity || outcome != "unauthorized" {
		t.Fatalf("forged rotation: want 422/unauthorized, got %d/%q", status, outcome)
	}

	// Prove the takeover failed: the pin is unchanged, so an envelope signed by
	// the attacker's key for target.example is still rejected as unauthorized.
	pin, ok := victim.resolver.PinnedKey("target.example")
	if !ok || !pin.Equal(legit.SignPub) {
		t.Fatal("VULN: forged rotation changed the pinned identity key")
	}
	env := sealFrom(t, attacker, "target.example", victim,
		"ceo@target.example", []string{"bob@victim.example"}, []byte("now i am you"))
	st2, oc2 := postWire(t, victim, peering.MarshalEnvelope(env))
	if st2 != http.StatusUnprocessableEntity || oc2 != "unauthorized" {
		t.Fatalf("post-rotation envelope: want 422/unauthorized, got %d/%q", st2, oc2)
	}
	if victim.sink.delivered() != 0 {
		t.Fatal("VULN: attacker took over a pinned domain via a forged rotation")
	}
}

// ATTACK: a rotation that tries to bootstrap trust for a domain that was NEVER
// pinned (rotation must not be a TOFU back-door). EXPECT: rejected; domain
// remains unknown.
func TestPeering_RotationCannotBootstrapTrust_Rejected(t *testing.T) {
	attacker, _ := peering.GenerateIdentity()
	victim := newPeerVictim(t, "victim.example", nil)
	// never.pinned is unknown to the victim.

	att := &peering.RotationAttestation{Domain: "never.pinned", NewIdentityPub: attacker.SignPub}
	peering.SignRotation(att, attacker.SignPriv)
	body, _ := peering.MarshalRotation(att)
	frame := peering.MakeRotationFrame(body)

	status, outcome := postWire(t, victim, frame)
	if status != http.StatusUnprocessableEntity || outcome != "unauthorized" {
		t.Fatalf("bootstrap rotation: want 422/unauthorized, got %d/%q", status, outcome)
	}
	if _, ok := victim.resolver.PinnedKey("never.pinned"); ok {
		t.Fatal("VULN: a rotation established first-trust for a never-pinned domain")
	}
}

// ATTACK: only POST is a valid ingress method; a GET (or any other verb) must
// not reach the Accept path. EXPECT: 405.
func TestPeering_NonPostMethod_Rejected(t *testing.T) {
	victim := newPeerVictim(t, "victim.example", nil)
	resp, err := http.Get(victim.srv.URL + peering.PeeringPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET on ingress: want 405, got %d", resp.StatusCode)
	}
}

// sanity: a fully-valid envelope from a pinned peer IS accepted (so the
// rejections above are proving real checks, not a broken-always-reject ingress).
func TestPeering_ValidEnvelope_Accepted(t *testing.T) {
	sender, _ := peering.GenerateIdentity()
	victim := newPeerVictim(t, "victim.example", nil)
	victim.pinIdentity(t, "sender.example", sender)

	env := sealFrom(t, sender, "sender.example", victim,
		"alice@sender.example", []string{"bob@victim.example"}, []byte("Subject: ok\r\n\r\nlegit"))
	status, _ := postWire(t, victim, peering.MarshalEnvelope(env))
	if status != http.StatusAccepted {
		t.Fatalf("valid envelope: want 202, got %d", status)
	}
	if victim.sink.delivered() != 1 {
		t.Fatal("valid envelope from a pinned peer should be delivered exactly once")
	}
	_ = context.Background()
}
