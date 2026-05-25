// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
)

// Resolver maps a recipient domain to a PeerDescriptor (spec/PEERING.md §3).
// It returns ErrNotPeer when the domain is not a known Vulos peer, in which
// case the caller falls back to SMTP. Implementations must be safe for
// concurrent use.
type Resolver interface {
	// Resolve returns the descriptor for the peer authoritative for domain,
	// or ErrNotPeer if the domain is not a peer.
	Resolve(ctx context.Context, domain string) (*PeerDescriptor, error)
}

// StaticResolver is the reference Resolver over an in-memory registry. It is
// the authoritative, fastest source (spec §3.1 source 1) and is what the Vulos
// control plane uses to wire tenants together. Independent operators can use
// the DNS path; this package ships the static one for self-hosting and tests.
type StaticResolver struct {
	mu sync.RWMutex
	// byDomain maps a lowercased domain to its descriptor.
	byDomain map[string]*PeerDescriptor
	// pinned tracks the first-seen identity key per domain (spec §3.2 TOFU).
	pinned map[string]ed25519.PublicKey
}

// NewStaticResolver creates an empty StaticResolver.
func NewStaticResolver() *StaticResolver {
	return &StaticResolver{
		byDomain: make(map[string]*PeerDescriptor),
		pinned:   make(map[string]ed25519.PublicKey),
	}
}

// Add registers (or replaces) a peer descriptor. It enforces key pinning
// (spec §3.2): once a domain's identity key is seen, a later Add with a
// different key is rejected unless it matches the pin. The control-plane /
// registry path is trusted, so Add is the authoritative pin source.
func (r *StaticResolver) Add(d *PeerDescriptor) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, dom := range d.Domains {
		dom = strings.ToLower(dom)
		if pin, ok := r.pinned[dom]; ok && !pin.Equal(d.IdentityPub) {
			return fmt.Errorf("peering: identity key for %q does not match pin", dom)
		}
	}
	for _, dom := range d.Domains {
		dom = strings.ToLower(dom)
		r.byDomain[dom] = d
		r.pinned[dom] = d.IdentityPub
	}
	return nil
}

// Resolve implements Resolver.
func (r *StaticResolver) Resolve(_ context.Context, domain string) (*PeerDescriptor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.byDomain[strings.ToLower(domain)]
	if !ok {
		return nil, ErrNotPeer
	}
	return d, nil
}

// PinnedKey returns the pinned Ed25519 identity key for domain, or ok=false if
// the domain has never been seen. This is the lookup the receiver-side Open
// checks (spec §8.2) consume to bind an inbound envelope to an authoritative
// origin peer. A descriptor learned over an untrusted channel (DNS, beacon) is
// trusted only up to this pinned key.
func (r *StaticResolver) PinnedKey(domain string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.pinned[strings.ToLower(domain)]
	if !ok {
		return nil, false
	}
	return k, true
}

// ApplyRotation verifies and applies a key-rotation attestation (spec §3.2).
//
// Rotation is the ONLY way a domain's pinned identity key may change: the
// receiver publishes a new identity key signed by the OUTGOING (currently
// pinned) key. A sender that holds the old pin verifies the chain and re-pins.
// An unsigned or wrongly-signed key change is treated as a resolution failure
// and never silently accepted (spec §3.2). The descriptor's KexPub and other
// fields are updated to those carried in the attestation so the new identity is
// usable immediately.
func (r *StaticResolver) ApplyRotation(att *RotationAttestation) error {
	if att == nil {
		return fmt.Errorf("peering: nil rotation attestation")
	}
	dom := strings.ToLower(att.Domain)
	r.mu.Lock()
	defer r.mu.Unlock()

	cur, ok := r.pinned[dom]
	if !ok {
		// No prior pin: rotation cannot establish first trust (that is what the
		// authoritative Add path is for). Refuse rather than TOFU off a rotation.
		return fmt.Errorf("peering: rotation for unpinned domain %q rejected", att.Domain)
	}
	// The attestation MUST be signed by the OUTGOING (currently pinned) key and
	// MUST chain to it; if it already matches the pin it is a no-op replay.
	if err := VerifyRotation(att, cur); err != nil {
		return err
	}
	if cur.Equal(att.NewIdentityPub) {
		return nil // idempotent: new key already pinned
	}

	// Re-pin and refresh the descriptor for this domain.
	r.pinned[dom] = att.NewIdentityPub
	d := r.byDomain[dom]
	if d == nil {
		d = &PeerDescriptor{Domains: []string{dom}}
	}
	d.IdentityPub = att.NewIdentityPub
	if len(att.NewKexPub) == x25519PubLen {
		d.KexPub = att.NewKexPub
	}
	if att.Endpoint != "" {
		d.Endpoint = att.Endpoint
	}
	r.byDomain[dom] = d
	return nil
}

// DomainOf returns the lowercased domain part of an RFC 5321 address.
func DomainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

// b64 is the base64url encoding used for keys in DNS/registry text contexts
// (spec §3.1). Exposed as a helper for descriptor (de)serialization.
var b64 = base64.RawURLEncoding

// EncodeKey renders a raw key as base64url, for descriptor text contexts.
func EncodeKey(key []byte) string { return b64.EncodeToString(key) }

// DecodeKey parses a base64url-encoded key.
func DecodeKey(s string) ([]byte, error) { return b64.DecodeString(s) }
