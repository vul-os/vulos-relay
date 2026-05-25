// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"
	"crypto/ed25519"
	"testing"
)

// TestRotationReKeysPinnedPeer: a rotation signed by the outgoing (pinned) key
// is verified and the resolver re-pins to the new key (spec §3.2).
func TestRotationReKeysPinnedPeer(t *testing.T) {
	res := NewStaticResolver()
	oldID, _ := GenerateIdentity()
	newID, _ := GenerateIdentity()

	if err := res.Add(&PeerDescriptor{
		Domains: []string{"p.example"}, IdentityPub: oldID.SignPub, KexPub: oldID.KexPub,
		Versions: []string{ProtoV1}, Suites: []string{SuiteV1}, Endpoint: "ep-old",
	}); err != nil {
		t.Fatal(err)
	}

	att := &RotationAttestation{
		Domain:         "p.example",
		NewIdentityPub: newID.SignPub,
		NewKexPub:      newID.KexPub,
		Endpoint:       "ep-new",
		NotBefore:      0,
	}
	SignRotation(att, oldID.SignPriv) // signed by OUTGOING key

	if err := res.ApplyRotation(att); err != nil {
		t.Fatalf("ApplyRotation: %v", err)
	}

	// The pin must now be the new key.
	pin, ok := res.PinnedKey("p.example")
	if !ok || !pin.Equal(newID.SignPub) {
		t.Fatalf("pin not rotated to new key")
	}
	// Descriptor refreshed (kex + endpoint).
	desc, err := res.Resolve(context.Background(), "p.example")
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.PublicKey(desc.IdentityPub).Equal(newID.SignPub) {
		t.Fatal("descriptor identity not rotated")
	}
	if desc.Endpoint != "ep-new" {
		t.Fatalf("endpoint = %q, want ep-new", desc.Endpoint)
	}
}

// TestRotationUnsignedRejected: a rotation NOT signed by the outgoing key MUST
// be rejected (spec §3.2 — unsigned key changes are never silently accepted).
func TestRotationUnsignedRejected(t *testing.T) {
	res := NewStaticResolver()
	oldID, _ := GenerateIdentity()
	newID, _ := GenerateIdentity()
	attacker, _ := GenerateIdentity()

	_ = res.Add(&PeerDescriptor{
		Domains: []string{"p.example"}, IdentityPub: oldID.SignPub, KexPub: oldID.KexPub,
		Versions: []string{ProtoV1}, Suites: []string{SuiteV1}, Endpoint: "ep-old",
	})

	// Attestation signed by an ATTACKER key, not the pinned outgoing key.
	att := &RotationAttestation{
		Domain: "p.example", NewIdentityPub: newID.SignPub, NewKexPub: newID.KexPub,
	}
	SignRotation(att, attacker.SignPriv)

	if err := res.ApplyRotation(att); err == nil {
		t.Fatal("expected rotation signed by non-pinned key to be rejected")
	}
	// Pin must be unchanged.
	pin, _ := res.PinnedKey("p.example")
	if !pin.Equal(oldID.SignPub) {
		t.Fatal("pin must not change on a rejected rotation")
	}
}

// TestRotationSpoofedOutgoingFieldRejected: an attacker self-asserts a fake
// OutgoingIdentityPub and signs with their own key. Verification must fail
// because the field does not match the resolver's real pin.
func TestRotationSpoofedOutgoingFieldRejected(t *testing.T) {
	res := NewStaticResolver()
	oldID, _ := GenerateIdentity()
	newID, _ := GenerateIdentity()
	attacker, _ := GenerateIdentity()

	_ = res.Add(&PeerDescriptor{
		Domains: []string{"p.example"}, IdentityPub: oldID.SignPub, KexPub: oldID.KexPub,
		Versions: []string{ProtoV1}, Suites: []string{SuiteV1}, Endpoint: "ep",
	})

	att := &RotationAttestation{Domain: "p.example", NewIdentityPub: newID.SignPub}
	// SignRotation sets OutgoingIdentityPub = attacker pub; that will not match
	// the pin (oldID), so VerifyRotation rejects on the chain check.
	SignRotation(att, attacker.SignPriv)
	if err := res.ApplyRotation(att); err == nil {
		t.Fatal("rotation chaining to a non-pinned outgoing key must be rejected")
	}
}

// TestRotationUnpinnedDomainRejected: rotation cannot bootstrap trust for a
// domain that was never pinned.
func TestRotationUnpinnedDomainRejected(t *testing.T) {
	res := NewStaticResolver()
	id, _ := GenerateIdentity()
	att := &RotationAttestation{Domain: "never.seen", NewIdentityPub: id.SignPub}
	SignRotation(att, id.SignPriv)
	if err := res.ApplyRotation(att); err == nil {
		t.Fatal("rotation for an unpinned domain must be rejected")
	}
}

// TestRotationFrameRoundTrip checks the frame wrapping used to carry a rotation
// attestation over the existing transport.
func TestRotationFrameRoundTrip(t *testing.T) {
	id, _ := GenerateIdentity()
	att := &RotationAttestation{Domain: "p.example", NewIdentityPub: id.SignPub, NewKexPub: id.KexPub}
	SignRotation(att, id.SignPriv)
	b, err := MarshalRotation(att)
	if err != nil {
		t.Fatal(err)
	}
	frame := MakeRotationFrame(b)
	if !IsRotationFrame(frame) {
		t.Fatal("MakeRotationFrame output not recognised as a rotation frame")
	}
	// Must not be confused with a mail envelope or reputation frame.
	if IsReputationFrame(frame) {
		t.Fatal("rotation frame misidentified as reputation frame")
	}
	payload, err := ParseRotationFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalRotation(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != "p.example" {
		t.Fatalf("domain = %q", got.Domain)
	}
}

// TestRotationViaIngress: a rotation attestation delivered over the real HTTP
// ingress is verified and re-pins the receiver's resolver.
func TestRotationViaIngress(t *testing.T) {
	b := newPeerNode(t, "b.example")
	oldID, _ := GenerateIdentity()
	newID, _ := GenerateIdentity()

	// b pins a.example to oldID.
	if err := b.resolver.Add(&PeerDescriptor{
		Domains: []string{"a.example"}, IdentityPub: oldID.SignPub, KexPub: oldID.KexPub,
		Versions: []string{ProtoV1}, Suites: []string{SuiteV1}, Endpoint: "ep-a",
	}); err != nil {
		t.Fatal(err)
	}

	att := &RotationAttestation{
		Domain: "a.example", NewIdentityPub: newID.SignPub, NewKexPub: newID.KexPub,
	}
	SignRotation(att, oldID.SignPriv)
	body, _ := MarshalRotation(att)
	frame := MakeRotationFrame(body)

	if err := NewHTTPTransport().Deliver(context.Background(), b.srv.URL+PeeringPath, frame); err != nil {
		t.Fatalf("deliver rotation frame: %v", err)
	}
	pin, ok := b.resolver.PinnedKey("a.example")
	if !ok || !pin.Equal(newID.SignPub) {
		t.Fatal("ingress did not apply the rotation")
	}
}
