package pubcache

import (
	"encoding/hex"
	"testing"

	"github.com/zeebo/blake3"
)

// interop_test.go — the primitive half of the CROSS-LANGUAGE INTEROP LOCK.
//
// The tree-and-proof half already exists: TestChunkProofInteropVector in
// proof_test.go pins the 5-chunk "a".."e" vector (root + every proof body). The
// IDENTICAL constants are now asserted in the JS reference client
// (client/src/__tests__/chunkProof.test.js), exactly as canonical_test.go and
// rendezvous.test.js do for the rendezvous canonical signing message. Those
// constants ARE the interop contract: if the Go node and the browser verifier
// diverge by a single byte — a different DS tag, a leaf taken over chunk bytes
// instead of the chunk address, an interior node that picked up a multihash
// prefix, a path ordered top-down, or an odd-node promotion that re-hashes
// instead of promoting — one of the two suites fails.
//
// This file adds the layer beneath that: the HASH ITSELF.

// TestBLAKE3KnownAnswer pins BLAKE3's output against fixed vectors.
//
// The browser verifier uses @noble/hashes' BLAKE3; this node uses zeebo/blake3.
// The tree vector would catch a divergence between them, but only as a confusing
// whole-tree mismatch. These three known-answer vectors — asserted identically
// in the JS suite — localise the failure to the primitive, so a dependency bump
// on either side that changed BLAKE3's output says so plainly instead of looking
// like a Merkle bug.
//
// The third vector is the DS tag's own preimage: it is the one input whose
// hashing this package actually depends on, and pinning it means a typo in the
// tag on either side is caught here rather than three layers up.
func TestBLAKE3KnownAnswer(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
		{"abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"},
		{"DMTAP-PUB-v0/manifest", "2cb5f9a18d18cee51f625aa0f285da550f033606024ec0f7df46e682fa8149f5"},
	}
	for _, c := range cases {
		sum := blake3.Sum256([]byte(c.in))
		if got := hex.EncodeToString(sum[:]); got != c.want {
			t.Fatalf("BLAKE3(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestNChunksIsStructuralNotAuthenticating pins an honest LIMITATION rather
// than a guarantee, and the JS suite asserts the identical numbers.
//
// VerifyChunkProof takes nChunks from the caller, and nChunks is not itself
// authenticated by anything in the proof. What it actually does is fix the
// tree's WIDTH, which determines at which levels the promotion rule skips a path
// element — and several widths can imply the SAME consumption pattern. For chunk
// 0 of the vector tree, n = 5, 6, 7 and 8 all consume the same three elements in
// the same order and therefore fold identically.
//
// This is not a forgery vector: the fold must still reproduce the TRUSTED root,
// so a wrong nChunks cannot smuggle a bad chunk past a correct root. It is the
// reason the doc comment insists nChunks come from the manifest header the
// caller already trusts and never from the proof response — and it is asserted
// here so the property is a tested fact rather than a claim in prose.
func TestNChunksIsStructuralNotAuthenticating(t *testing.T) {
	data := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")}
	chunks := chunkAddrs(data)
	root := ManifestRoot(chunks)

	accepted := func(i int) []int {
		path, err := ChunkProof(chunks, i)
		if err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}
		var out []int
		for n := 1; n <= 40; n++ {
			if VerifyChunkProof(root, n, i, data[i], path) == nil {
				out = append(out, n)
			}
		}
		return out
	}

	if got := accepted(0); len(got) != 4 || got[0] != 5 || got[3] != 8 {
		t.Fatalf("chunk 0 accepted widths %v, want [5 6 7 8]", got)
	}
	// Chunk 4 is the promoted odd node, so its 1-element path pins the width
	// exactly — promotion is what makes the tree size observable at all.
	if got := accepted(4); len(got) != 1 || got[0] != 5 {
		t.Fatalf("chunk 4 accepted widths %v, want [5]", got)
	}
}

// TestInteropPromotionShape asserts in plain terms the property the hex vector
// encodes, so a reader does not have to decode CBOR to see why n=5 was chosen:
// chunk 4 is the promoted odd node and therefore carries a SHORTER path than its
// siblings. A verifier that ignored the promotion rule would demand three
// elements here and reject a valid proof — which is exactly the bug a browser
// reimplementation is most likely to ship.
func TestInteropPromotionShape(t *testing.T) {
	chunks := chunkAddrs([][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")})
	for i, wantLen := range []int{3, 3, 3, 3, 1} {
		path, err := ChunkProof(chunks, i)
		if err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}
		if len(path) != wantLen {
			t.Fatalf("i=%d: path length %d, want %d", i, len(path), wantLen)
		}
	}
}
