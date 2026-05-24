// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// Protocol and suite identifiers, per spec/PEERING.md and spec/VERSIONS.md.
const (
	// ProtoV1 is the wire identifier of the current peering protocol version.
	ProtoV1 = "VULOS-PEER/1"

	// SuiteV1 is the only cipher suite defined for VULOS-PEER/1.
	SuiteV1 = "X25519-AESGCM-ED25519"
)

// Wire field sizes (bytes).
const (
	ed25519PubLen = ed25519.PublicKeySize // 32
	x25519PubLen  = 32                    // X25519 public key
	nonceLen      = 12                    // AES-GCM 96-bit nonce
	sigLen        = ed25519.SignatureSize // 64
)

// Identity is a peer's long-term key material. A peer holds two keypairs: an
// Ed25519 keypair for identity/signing and an X25519 keypair for key agreement
// (see spec/PEERING.md §5). The private halves are present only on the owning
// node; resolved descriptors of remote peers carry the public halves.
type Identity struct {
	// SignPub is the Ed25519 identity public key.
	SignPub ed25519.PublicKey
	// SignPriv is the Ed25519 identity private key. Nil for remote peers.
	SignPriv ed25519.PrivateKey

	// KexPub is the X25519 key-agreement public key (raw 32 bytes).
	KexPub []byte
	// KexPriv is the X25519 key-agreement private key. Nil for remote peers.
	KexPriv *ecdh.PrivateKey
}

// GenerateIdentity creates a fresh peer identity (both keypairs). Use it to
// stand up a node; persist the result via the caller's key store.
func GenerateIdentity() (*Identity, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("peering: generate ed25519: %w", err)
	}
	kexPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("peering: generate x25519: %w", err)
	}
	return &Identity{
		SignPub:  signPub,
		SignPriv: signPriv,
		KexPub:   kexPriv.PublicKey().Bytes(),
		KexPriv:  kexPriv,
	}, nil
}

// PeerDescriptor describes a remote peer as resolved from a registry or DNS
// (spec/PEERING.md §3). It carries only public material.
type PeerDescriptor struct {
	// Domains are the mail domains this peer is authoritative for.
	Domains []string
	// IdentityPub is the peer's Ed25519 identity public key.
	IdentityPub ed25519.PublicKey
	// KexPub is the peer's X25519 key-agreement public key (raw 32 bytes).
	KexPub []byte
	// Versions are the VULOS-PEER/<N> protocol versions the peer supports.
	Versions []string
	// Suites are the cipher suites the peer supports.
	Suites []string
	// Endpoint is the carrier address (opaque to this package).
	Endpoint string
}

// supports reports whether the descriptor advertises the given protocol
// version and suite.
func (d *PeerDescriptor) supports(proto, suite string) bool {
	return contains(d.Versions, proto) && contains(d.Suites, suite)
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// Sentinel errors for resolution and handoff.
var (
	// ErrNotPeer indicates the recipient domain is not a known Vulos peer;
	// the caller should fall back to SMTP.
	ErrNotPeer = errors.New("peering: recipient is not a vulos peer")

	// ErrNoCommonVersion indicates no protocol version / suite is supported by
	// both sender and receiver.
	ErrNoCommonVersion = errors.New("peering: no common protocol version or suite")

	// ErrReplay indicates an envelope was rejected as a replay.
	ErrReplay = errors.New("peering: replayed envelope rejected")

	// ErrUnauthenticated indicates the sender signature did not verify.
	ErrUnauthenticated = errors.New("peering: sender signature verification failed")

	// ErrUnauthorized indicates the sender is not authoritative for the claimed
	// origin domain.
	ErrUnauthorized = errors.New("peering: sender not authorized for origin domain")

	// ErrMisrouted indicates the envelope was not targeted at this receiver.
	ErrMisrouted = errors.New("peering: envelope misrouted to wrong receiver")

	// ErrUnsupported indicates the proto/suite is not implemented by the receiver.
	ErrUnsupported = errors.New("peering: unsupported protocol version or suite")

	// ErrCorrupt indicates the envelope failed to parse or decrypt.
	ErrCorrupt = errors.New("peering: corrupt envelope")
)
