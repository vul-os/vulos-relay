// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadPeersFile loads an operator peer table and confirms the resolver can
// resolve a configured domain and pins its key, while an unconfigured domain
// is not a peer (SMTP fallback).
func TestLoadPeersFile(t *testing.T) {
	id, _ := GenerateIdentity()
	pf := PeersFile{Peers: []PeerEntry{{
		Domains:     []string{"peer.example", "alias.example"},
		IdentityPub: EncodeKey(id.SignPub),
		KexPub:      EncodeKey(id.KexPub),
		Endpoint:    "https://peer.example/peering/v1/deliver",
		// versions/suites omitted → defaults applied.
	}}}
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	raw, _ := json.Marshal(pf)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewStaticResolver()
	n, err := LoadPeersFile(r, path)
	if err != nil {
		t.Fatalf("LoadPeersFile: %v", err)
	}
	if n != 1 {
		t.Fatalf("loaded %d peers, want 1", n)
	}

	desc, err := r.Resolve(context.Background(), "peer.example")
	if err != nil {
		t.Fatalf("resolve configured peer: %v", err)
	}
	if !desc.supports(ProtoV1, SuiteV1) {
		t.Fatal("default versions/suites not applied")
	}
	if desc.Endpoint != "https://peer.example/peering/v1/deliver" {
		t.Fatalf("endpoint = %q", desc.Endpoint)
	}
	if pin, ok := r.PinnedKey("alias.example"); !ok || !pin.Equal(id.SignPub) {
		t.Fatal("alias domain not pinned")
	}

	// Unconfigured domain is not a peer.
	if _, err := r.Resolve(context.Background(), "stranger.example"); err != ErrNotPeer {
		t.Fatalf("unconfigured domain should be ErrNotPeer, got %v", err)
	}
}

// TestLoadPeersFileBadKey rejects an entry with a wrong-length key rather than
// silently registering a broken peer.
func TestLoadPeersFileBadKey(t *testing.T) {
	pf := PeersFile{Peers: []PeerEntry{{
		Domains:     []string{"peer.example"},
		IdentityPub: EncodeKey([]byte("too-short")),
		KexPub:      EncodeKey(make([]byte, x25519PubLen)),
		Endpoint:    "https://peer.example",
	}}}
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	raw, _ := json.Marshal(pf)
	_ = os.WriteFile(path, raw, 0o600)

	r := NewStaticResolver()
	if _, err := LoadPeersFile(r, path); err == nil {
		t.Fatal("expected error for bad identity key length")
	}
}

// TestLoadPeersFileMissing returns an error for a missing file.
func TestLoadPeersFileMissing(t *testing.T) {
	r := NewStaticResolver()
	if _, err := LoadPeersFile(r, filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing peers file")
	}
}
