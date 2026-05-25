// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"encoding/json"
	"fmt"
	"os"
)

// PeerEntry is one operator-registered peer in a peers config file (spec §3.1
// source 1 — the local peer registry). Keys are base64url-encoded raw keys
// (spec §3.1), matching the DNS/registry text form.
type PeerEntry struct {
	// Domains are the mail domains this peer is authoritative for.
	Domains []string `json:"domains"`
	// IdentityPub is the peer's Ed25519 identity public key, base64url (raw,
	// 32 bytes decoded). This is the trust anchor; it is pinned on load.
	IdentityPub string `json:"identity_pub"`
	// KexPub is the peer's X25519 key-agreement public key, base64url (raw,
	// 32 bytes decoded).
	KexPub string `json:"kex_pub"`
	// Endpoint is the carrier address: a peering ingress URL
	// (https://peer.example/peering/v1/deliver) or a bare host[:port].
	Endpoint string `json:"endpoint"`
	// Versions are the VULOS-PEER/<N> versions the peer supports. Defaults to
	// [VULOS-PEER/1] when omitted.
	Versions []string `json:"versions,omitempty"`
	// Suites are the cipher suites the peer supports. Defaults to
	// [X25519-AESGCM-ED25519] when omitted.
	Suites []string `json:"suites,omitempty"`
}

// PeersFile is the on-disk format of RELAY_PEER_CONFIG.
type PeersFile struct {
	Peers []PeerEntry `json:"peers"`
}

// LoadPeersFile reads a peers config file and registers every entry into r,
// enforcing key pinning (spec §3.2) on the way in. It is the production path
// that lets an operator wire peers without the control plane (the StaticResolver
// is the spec §3.1 source-1 registry). It returns the number of peers loaded.
func LoadPeersFile(r *StaticResolver, path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("peering: read peers config %q: %w", path, err)
	}
	var pf PeersFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return 0, fmt.Errorf("peering: parse peers config %q: %w", path, err)
	}
	n := 0
	for i, e := range pf.Peers {
		desc, err := e.descriptor()
		if err != nil {
			return n, fmt.Errorf("peering: peers config %q entry %d: %w", path, i, err)
		}
		if err := r.Add(desc); err != nil {
			return n, fmt.Errorf("peering: peers config %q entry %d: %w", path, i, err)
		}
		n++
	}
	return n, nil
}

// descriptor decodes a PeerEntry into a PeerDescriptor, validating key lengths
// and applying suite/version defaults.
func (e PeerEntry) descriptor() (*PeerDescriptor, error) {
	if len(e.Domains) == 0 {
		return nil, fmt.Errorf("entry has no domains")
	}
	idPub, err := DecodeKey(e.IdentityPub)
	if err != nil {
		return nil, fmt.Errorf("decode identity_pub: %w", err)
	}
	if len(idPub) != ed25519PubLen {
		return nil, fmt.Errorf("identity_pub length %d, want %d", len(idPub), ed25519PubLen)
	}
	kexPub, err := DecodeKey(e.KexPub)
	if err != nil {
		return nil, fmt.Errorf("decode kex_pub: %w", err)
	}
	if len(kexPub) != x25519PubLen {
		return nil, fmt.Errorf("kex_pub length %d, want %d", len(kexPub), x25519PubLen)
	}
	if e.Endpoint == "" {
		return nil, fmt.Errorf("entry has no endpoint")
	}
	versions := e.Versions
	if len(versions) == 0 {
		versions = []string{ProtoV1}
	}
	suites := e.Suites
	if len(suites) == 0 {
		suites = []string{SuiteV1}
	}
	return &PeerDescriptor{
		Domains:     e.Domains,
		IdentityPub: idPub,
		KexPub:      kexPub,
		Versions:    versions,
		Suites:      suites,
		Endpoint:    e.Endpoint,
	}, nil
}
