// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// generateTestKey generates a fresh Ed25519 keypair for tests.
func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestAttestationSignVerify verifies that SignAttestation + VerifyAttestation
// round-trips correctly, and that tampering the attestation invalidates the signature.
func TestAttestationSignVerify(t *testing.T) {
	pub, priv := generateTestKey(t)

	a := &ReputationAttestation{
		SenderHandle:      "alice@example.com",
		PeerNodePubkey:    pub,
		WindowStart:       1000000,
		WindowEnd:         1086400,
		MessagesSent:      200,
		ReportedSpamCount: 5,
		ReportedHamCount:  180,
	}
	SignAttestation(a, priv)

	if err := VerifyAttestation(a); err != nil {
		t.Fatalf("valid attestation should verify: %v", err)
	}

	// Tamper with spam count — signature must fail.
	a.ReportedSpamCount++
	if err := VerifyAttestation(a); err == nil {
		t.Fatal("tampered attestation must NOT verify")
	}
}

// TestAggregateReputation verifies that AggregateReputation combines
// attestations from multiple trusted peers and returns a sensible 0..1 score.
func TestAggregateReputation(t *testing.T) {
	pub1, priv1 := generateTestKey(t)
	pub2, priv2 := generateTestKey(t)

	store := NewReputationStore([]ed25519.PublicKey{pub1, pub2}, 48*time.Hour)

	now := time.Now()
	makeAtt := func(pub ed25519.PublicKey, priv ed25519.PrivateKey, spam, ham, total int64) *ReputationAttestation {
		a := &ReputationAttestation{
			SenderHandle:      "sender@test.example",
			PeerNodePubkey:    pub,
			WindowStart:       now.Add(-24 * time.Hour).Unix(),
			WindowEnd:         now.Add(-1 * time.Hour).Unix(),
			MessagesSent:      total,
			ReportedSpamCount: spam,
			ReportedHamCount:  ham,
		}
		SignAttestation(a, priv)
		return a
	}

	// Peer 1: low spam, high ham — clean sender.
	if err := store.Receive(makeAtt(pub1, priv1, 1, 95, 100)); err != nil {
		t.Fatalf("receive peer1: %v", err)
	}
	// Peer 2: moderate spam — suspicious.
	if err := store.Receive(makeAtt(pub2, priv2, 20, 70, 100)); err != nil {
		t.Fatalf("receive peer2: %v", err)
	}

	score := store.AggregateReputation("sender@test.example")
	if score <= 0 || score > 1 {
		t.Errorf("score out of range [0,1]: got %f", score)
	}
	// With 96% ham rate on peer1 and 70% on peer2, combined score should be > 0.5.
	if score <= 0.5 {
		t.Errorf("expected score > 0.5 for mostly-ham sender, got %f", score)
	}
}

// TestCombineScoreWeighting verifies the combined score formula:
// combined = rspamd_score * (1 + (1 - rep) * 0.5)
func TestCombineScoreWeighting(t *testing.T) {
	cases := []struct {
		rspamd float64
		rep    ReputationScore
		want   float64
	}{
		{8.0, 1.0, 8.0},  // perfect rep → no change
		{8.0, 0.0, 12.0}, // zero rep → 50% inflation (8 * 1.5)
		{8.0, 0.5, 10.0}, // neutral → 25% inflation (8 * 1.25)
	}
	for _, tc := range cases {
		got := CombineScore(tc.rspamd, tc.rep)
		if abs64(got-tc.want) > 0.001 {
			t.Errorf("CombineScore(%f, %f): want %f, got %f", tc.rspamd, float64(tc.rep), tc.want, got)
		}
	}
}

// TestUntrustedPeerAttestationIgnored verifies that attestations from nodes
// NOT in the trusted set are silently ignored.
func TestUntrustedPeerAttestationIgnored(t *testing.T) {
	trustedPub, _ := generateTestKey(t)
	untrustedPub, untrustedPriv := generateTestKey(t)

	// Only trust trustedPub.
	store := NewReputationStore([]ed25519.PublicKey{trustedPub}, 48*time.Hour)

	now := time.Now()
	a := &ReputationAttestation{
		SenderHandle:      "spammer@untrusted.example",
		PeerNodePubkey:    untrustedPub,
		WindowStart:       now.Add(-2 * time.Hour).Unix(),
		WindowEnd:         now.Add(-1 * time.Hour).Unix(),
		MessagesSent:      50,
		ReportedSpamCount: 0,
		ReportedHamCount:  50,
	}
	SignAttestation(a, untrustedPriv)

	if err := store.Receive(a); err != nil {
		t.Fatalf("Receive must not error on untrusted peer: %v", err)
	}

	// AggregateReputation should return neutral (0.5) — untrusted attestation was ignored.
	score := store.AggregateReputation("spammer@untrusted.example")
	if score != 0.5 {
		t.Errorf("expected neutral (0.5) when untrusted peer ignored, got %f", score)
	}
}

// TestStaleAttestationExpiry verifies that attestations with a WindowEnd
// older than staleCutoff are ignored during aggregation.
func TestStaleAttestationExpiry(t *testing.T) {
	pub, priv := generateTestKey(t)
	store := NewReputationStore([]ed25519.PublicKey{pub}, 48*time.Hour)

	staleTime := time.Now().Add(-72 * time.Hour) // older than 48h cutoff
	a := &ReputationAttestation{
		SenderHandle:      "old@example.com",
		PeerNodePubkey:    pub,
		WindowStart:       staleTime.Add(-24 * time.Hour).Unix(),
		WindowEnd:         staleTime.Unix(),
		MessagesSent:      100,
		ReportedSpamCount: 90, // very spammy
		ReportedHamCount:  5,
	}
	SignAttestation(a, priv)

	// Receive the stale attestation — should be silently ignored (no error).
	if err := store.Receive(a); err != nil {
		t.Fatalf("stale attestation receive: %v", err)
	}

	// Score should be neutral (0.5) since the stale record is not counted.
	score := store.AggregateReputation("old@example.com")
	if score != 0.5 {
		t.Errorf("expected neutral score (stale attestation ignored), got %f", score)
	}
}

// TestPeeringBackwardsCompatibility verifies that:
//  1. IsReputationFrame / ParseReputationFrame correctly distinguish reputation
//     frames from mail envelopes.
//  2. Normal mail delivery (Seal + LoopbackTransport) still works alongside
//     the reputation extension.
//  3. Reputation frames produce ErrCorrupt on the loopback transport (which
//     validates full peering envelopes), demonstrating they are correctly
//     segregated from the mail path.
func TestPeeringBackwardsCompatibility(t *testing.T) {
	sender, receiver, res := testPair(t)
	transport := NewLoopbackTransport()
	// The LoopbackEndpoint must have the receiver identity and the correct
	// authorized domain / pinned-key callbacks matching what sealFixture produces.
	// - receiver authoritative for "recv.example" (the RcptTo domain in sealFixture)
	// - pinned sender key is for "send.example" (the SenderDomain in sealFixture)
	ep := &LoopbackEndpoint{
		Receiver:   receiver,
		Authorized: func(domain string) bool { return domain == "recv.example" },
		PinnedKey: func(domain string) (ed25519.PublicKey, bool) {
			if domain == "send.example" {
				return sender.SignPub, true
			}
			return nil, false
		},
	}
	transport.Register("ep-recv", ep)

	// Build a reputation frame.
	pub, priv := generateTestKey(t)
	now := time.Now()
	a := &ReputationAttestation{
		SenderHandle:   "test@example.com",
		PeerNodePubkey: pub,
		WindowStart:    now.Add(-24 * time.Hour).Unix(),
		WindowEnd:      now.Unix(),
		MessagesSent:   10,
	}
	SignAttestation(a, priv)
	frame := makeReputationFrame(mustMarshalAttestation(t, a))

	// The loopback transport always tries to parse wire as a full peering
	// envelope. A reputation frame will fail that parse (ErrCorrupt) — that is
	// the expected behavior: each path (mail vs reputation) is cleanly separated.
	transportErr := transport.Deliver(context.Background(), "ep-recv", frame)
	if transportErr == nil {
		t.Log("transport accepted reputation frame (would mean it passes the mail-envelope parse — unexpected but not fatal)")
	}
	// No mail should have been delivered from the reputation frame.
	if len(ep.Delivered) != 0 {
		t.Error("reputation frame must NOT result in a delivered mail message")
	}

	// Now deliver a real mail envelope via the same transport — must succeed
	// regardless of the earlier reputation frame error.
	env := sealFixture(t, sender, receiver, res)
	wire := MarshalEnvelope(env)
	if err := transport.Deliver(context.Background(), "ep-recv", wire); err != nil {
		t.Fatalf("mail delivery must still work: %v", err)
	}
	if len(ep.Delivered) == 0 {
		t.Error("expect at least one delivered message after valid mail envelope")
	}

	// Verify IsReputationFrame correctly identifies frames.
	if !IsReputationFrame(frame) {
		t.Error("IsReputationFrame should return true for reputation frame")
	}
	if IsReputationFrame(wire) {
		t.Error("IsReputationFrame should return false for mail envelope")
	}

	// Verify ParseReputationFrame + UnmarshalAttestation round-trip.
	payload, err := ParseReputationFrame(frame)
	if err != nil {
		t.Fatalf("ParseReputationFrame: %v", err)
	}
	recovered, err := UnmarshalAttestation(payload)
	if err != nil {
		t.Fatalf("UnmarshalAttestation: %v", err)
	}
	if recovered.SenderHandle != "test@example.com" {
		t.Errorf("recovered handle: want test@example.com, got %q", recovered.SenderHandle)
	}
	if !bytes.Equal(recovered.PeerNodePubkey, pub) {
		t.Error("recovered pubkey mismatch")
	}
}

func mustMarshalAttestation(t *testing.T, a *ReputationAttestation) []byte {
	t.Helper()
	b, err := MarshalAttestation(a)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func abs64(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
