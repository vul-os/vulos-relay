// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// RotationAttestation is a signed key-rotation record (spec/PEERING.md §3.2).
//
// A peer rotates its long-term identity key by publishing the NEW key signed by
// the OUTGOING (currently pinned) key. A sender that holds the old pin verifies
// the signature against the old key and re-pins to the new key. This lets keys
// rotate without a fresh trust-on-first-use and without ever silently accepting
// an unsigned key change: a rotation that does not verify against the pinned
// outgoing key is rejected (treated as a resolution failure).
//
// The attestation is a payload-level message carried over the existing
// transport (like the reputation side-channel); it does NOT change the
// VULOS-PEER/1 envelope wire format.
type RotationAttestation struct {
	// Domain is the mail domain whose identity key is rotating.
	Domain string `json:"domain"`
	// NewIdentityPub is the incoming Ed25519 identity public key (32 bytes).
	NewIdentityPub ed25519.PublicKey `json:"new_identity_pub"`
	// NewKexPub is the incoming X25519 key-agreement public key (32 bytes). May
	// be empty to keep the existing kex key.
	NewKexPub []byte `json:"new_kex_pub,omitempty"`
	// Endpoint optionally updates the carrier endpoint for the domain.
	Endpoint string `json:"endpoint,omitempty"`
	// NotBefore is the Unix-seconds time from which the new key is valid. It is
	// covered by the signature so it cannot be back-dated by a carrier.
	NotBefore int64 `json:"not_before"`
	// OutgoingIdentityPub is the outgoing (currently pinned) key. It is included
	// so a verifier can sanity-check which pin the rotation chains FROM; the
	// authoritative check still verifies the signature against the resolver's
	// own pinned key, never against this self-asserted field.
	OutgoingIdentityPub ed25519.PublicKey `json:"outgoing_identity_pub"`
	// Signature is the Ed25519 signature by the OUTGOING key over the canonical
	// body (all fields except Signature).
	Signature []byte `json:"signature"`
}

// rotationCanonical returns the deterministic signed-over byte representation of
// the attestation (every field except Signature), length-prefixed big-endian to
// match the §6 codec style so two independent implementations sign identically.
func rotationCanonical(a *RotationAttestation) []byte {
	var b []byte
	putU32Str := func(s string) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		b = append(b, l[:]...)
		b = append(b, s...)
	}
	putU32Bytes := func(p []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		b = append(b, l[:]...)
		b = append(b, p...)
	}
	putI64 := func(v int64) {
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], uint64(v))
		b = append(b, x[:]...)
	}
	// Bind a domain-separation label so a rotation signature can never be
	// confused with a mail-envelope or reputation signature.
	putU32Str("VULOS-PEER/1 rotation")
	putU32Str(a.Domain)
	putU32Bytes(a.NewIdentityPub)
	putU32Bytes(a.NewKexPub)
	putU32Str(a.Endpoint)
	putI64(a.NotBefore)
	putU32Bytes(a.OutgoingIdentityPub)
	return b
}

// SignRotation signs the attestation with the OUTGOING identity private key,
// setting OutgoingIdentityPub and Signature in place.
func SignRotation(a *RotationAttestation, outgoing ed25519.PrivateKey) {
	a.OutgoingIdentityPub = outgoing.Public().(ed25519.PublicKey)
	a.Signature = ed25519.Sign(outgoing, rotationCanonical(a))
}

// VerifyRotation verifies a rotation attestation against the pinned outgoing
// key the verifier currently holds. It MUST be the caller's own pinned key, not
// the self-asserted OutgoingIdentityPub field. Returns nil iff the signature
// verifies and the embedded outgoing key matches the pin.
func VerifyRotation(a *RotationAttestation, pinnedOutgoing ed25519.PublicKey) error {
	if a == nil {
		return fmt.Errorf("peering: nil rotation attestation")
	}
	if len(a.NewIdentityPub) != ed25519PubLen {
		return fmt.Errorf("peering: rotation new identity key length %d", len(a.NewIdentityPub))
	}
	if len(a.NewKexPub) != 0 && len(a.NewKexPub) != x25519PubLen {
		return fmt.Errorf("peering: rotation new kex key length %d", len(a.NewKexPub))
	}
	if len(a.Signature) != sigLen {
		return fmt.Errorf("peering: rotation signature length %d", len(a.Signature))
	}
	if len(pinnedOutgoing) != ed25519PubLen {
		return fmt.Errorf("peering: no pinned outgoing key to verify rotation")
	}
	// The self-asserted outgoing key must equal the pin we hold; otherwise the
	// attestation is chaining from a key we never trusted.
	if !pinnedOutgoing.Equal(a.OutgoingIdentityPub) {
		return fmt.Errorf("peering: rotation does not chain to pinned key for %q", a.Domain)
	}
	if !ed25519.Verify(pinnedOutgoing, rotationCanonical(a), a.Signature) {
		return fmt.Errorf("peering: rotation signature does not verify for %q", a.Domain)
	}
	return nil
}

// rotationMagic is the 8-byte magic prefix identifying a rotation frame on the
// wire. It is distinct from the reputation magic and from any envelope start.
const rotationMagic = "VLSROT1\x00"

// MarshalRotation serialises a rotation attestation to JSON.
func MarshalRotation(a *RotationAttestation) ([]byte, error) { return json.Marshal(a) }

// UnmarshalRotation deserialises a rotation attestation from JSON.
func UnmarshalRotation(b []byte) (*RotationAttestation, error) {
	var a RotationAttestation
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("peering: unmarshal rotation: %w", err)
	}
	return &a, nil
}

// MakeRotationFrame wraps a marshaled rotation attestation with the rotation
// magic + length so a receiver can distinguish it from a mail envelope or a
// reputation frame before parsing.
func MakeRotationFrame(payload []byte) []byte {
	frame := make([]byte, len(rotationMagic)+4+len(payload))
	copy(frame, rotationMagic)
	binary.BigEndian.PutUint32(frame[len(rotationMagic):], uint32(len(payload)))
	copy(frame[len(rotationMagic)+4:], payload)
	return frame
}

// IsRotationFrame reports whether wire begins with the rotation magic.
func IsRotationFrame(wire []byte) bool {
	return len(wire) >= len(rotationMagic) && string(wire[:len(rotationMagic)]) == rotationMagic
}

// ParseRotationFrame extracts the JSON payload from a rotation frame.
func ParseRotationFrame(wire []byte) ([]byte, error) {
	if !IsRotationFrame(wire) {
		return nil, fmt.Errorf("peering: not a rotation frame")
	}
	off := len(rotationMagic)
	if len(wire) < off+4 {
		return nil, fmt.Errorf("peering: rotation frame too short")
	}
	plen := binary.BigEndian.Uint32(wire[off:])
	off += 4
	if uint32(len(wire)-off) < plen {
		return nil, fmt.Errorf("peering: rotation frame payload truncated")
	}
	return wire[off : off+int(plen)], nil
}
