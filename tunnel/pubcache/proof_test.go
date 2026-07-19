package pubcache

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// proof_test.go — the FEEDS.md § 5.3 chunk-tree range proofs.
//
// Two things are under test and they are different in kind:
//
//  1. the TREE, where the only interesting question is whether the audit path
//     this package emits folds back to the same root the manifest verifier
//     computes, for every shape a chunk list can take (the odd-node promotion
//     cases are where a Merkle implementation actually goes wrong); and
//  2. the VERIFIER, where the interesting question is the inverse — that every
//     way of lying about a chunk is REJECTED. A proof checker that only ever
//     gets tested on valid proofs is not tested at all, so most of what follows
//     is adversarial.

// chunkData builds n distinct chunk payloads.
func chunkData(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("chunk-%d", i))
	}
	return out
}

// chunkAddrs is the manifest chunk list for those payloads.
func chunkAddrs(data [][]byte) []Addr {
	out := make([]Addr, len(data))
	for i, c := range data {
		out[i] = HashBytes(c)
	}
	return out
}

// ---------------------------------------------------------------------------
// tree shape
// ---------------------------------------------------------------------------

// TestProofFoldMatchesManifestRoot is the load-bearing structural test.
//
// § 3.2 specifies the tree by the RFC 6962 SPLIT rule (recurse on the largest
// power of two below n), which is what merkleRoot() implements with an explicit
// stack. The proof path is generated the other way round, LEVEL BY LEVEL with
// odd-node promotion. Those are only interchangeable if they are the same tree,
// and "they are the same tree" is exactly the kind of claim that is true for the
// powers of two a developer tests by hand and false at n=11. So it is asserted
// here for every n up to a few hundred, which covers every promotion pattern
// that can occur.
func TestProofFoldMatchesManifestRoot(t *testing.T) {
	for n := 1; n <= 300; n++ {
		chunks := chunkAddrs(chunkData(n))
		want := ManifestRoot(chunks)

		// Fold level by level with promotion — vidmesh's rule.
		level := make([][32]byte, n)
		for i, h := range chunks {
			level[i] = merkleLeaf(h)
		}
		for len(level) > 1 {
			level = reduceLevel(level)
		}
		var got Addr
		got[0] = HashPrefixBLAKE3_256
		copy(got[1:], level[0][:])

		if got != want {
			t.Fatalf("n=%d: level-by-level promotion roots to %s, RFC 6962 split rule roots to %s", n, got, want)
		}
	}
}

// TestChunkProofVerifiesEveryChunkOfEverySize walks every index of every tree
// size in the range where promotion patterns repeat. If any single chunk of any
// single shape failed to prove, verified seek would be silently unreliable
// exactly where the feature is meant to be used.
func TestChunkProofVerifiesEveryChunkOfEverySize(t *testing.T) {
	for n := 1; n <= 64; n++ {
		data := chunkData(n)
		chunks := chunkAddrs(data)
		root := ManifestRoot(chunks)
		for i := 0; i < n; i++ {
			path, err := ChunkProof(chunks, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: ChunkProof: %v", n, i, err)
			}
			if err := VerifyChunkProof(root, n, i, data[i], path); err != nil {
				t.Fatalf("n=%d i=%d: valid proof rejected: %v", n, i, err)
			}
		}
	}
}

// TestChunkProofIsLogarithmic pins the whole point of the endpoint: the path is
// O(log n), so verifying one chunk of a huge blob never costs the chunk list.
func TestChunkProofIsLogarithmic(t *testing.T) {
	const n = 4096
	chunks := chunkAddrs(chunkData(n))
	path, err := ChunkProof(chunks, 1234)
	if err != nil {
		t.Fatalf("ChunkProof: %v", err)
	}
	if len(path) != 12 { // log2(4096)
		t.Fatalf("path length %d, want 12 for a %d-leaf tree", len(path), n)
	}
	// The saving is the entire reason § 5.3 exists: 12 hashes instead of 4096.
	if got, full := len(path)*digestLen, n*addrLen; got*20 > full {
		t.Fatalf("proof is %d bytes against a %d-byte chunk list — not the intended saving", got, full)
	}
}

// TestOddNodePromotionPathLengths nails the promotion rule with hand-computed
// expectations rather than a round-trip, because a round-trip test passes just
// as happily against a self-consistently WRONG tree. A promoted node contributes
// NO path element at the level where it has no sibling.
func TestOddNodePromotionPathLengths(t *testing.T) {
	cases := []struct {
		n, index, wantLen int
		why               string
	}{
		{1, 0, 0, "a single chunk is the root; nothing to prove against"},
		{2, 0, 1, "one sibling"},
		{3, 0, 2, "paired at level 0, then against the promoted l2"},
		{3, 2, 1, "l2 is promoted past level 0 and only pairs at the top"},
		{4, 3, 2, "a perfect tree: one sibling per level"},
		{5, 4, 1, "l4 is promoted through two levels, pairing only at the root"},
		{5, 0, 3, "the deep side of a 5-leaf tree"},
		{7, 6, 2, "l6 promoted once, then pairs twice"},
	}
	for _, tc := range cases {
		data := chunkData(tc.n)
		chunks := chunkAddrs(data)
		path, err := ChunkProof(chunks, tc.index)
		if err != nil {
			t.Fatalf("n=%d i=%d: %v", tc.n, tc.index, err)
		}
		if len(path) != tc.wantLen {
			t.Errorf("n=%d i=%d: path length %d, want %d (%s)", tc.n, tc.index, len(path), tc.wantLen, tc.why)
		}
		if err := VerifyChunkProof(ManifestRoot(chunks), tc.n, tc.index, data[tc.index], path); err != nil {
			t.Errorf("n=%d i=%d: %v", tc.n, tc.index, err)
		}
	}
}

// ---------------------------------------------------------------------------
// the verifier says no
// ---------------------------------------------------------------------------

// TestVerifyChunkProofRejectsWrongIndex: the same chunk and the same path, but
// claimed at a different position. Position is part of what a proof asserts —
// otherwise a holder could serve chunk 9 when asked for chunk 3 and a streaming
// client would decode the wrong part of the video against a valid-looking proof.
func TestVerifyChunkProofRejectsWrongIndex(t *testing.T) {
	data := chunkData(8)
	chunks := chunkAddrs(data)
	root := ManifestRoot(chunks)
	path, err := ChunkProof(chunks, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []int{0, 2, 4, 7} {
		if err := VerifyChunkProof(root, 8, wrong, data[3], path); err == nil {
			t.Errorf("chunk 3's proof verified when claimed at index %d", wrong)
		}
	}
}

// TestVerifyChunkProofRejectsTamperedChunk: the bytes are the thing being
// proved, so a single flipped bit must fail. This is the poisoned-holder case.
func TestVerifyChunkProofRejectsTamperedChunk(t *testing.T) {
	data := chunkData(9)
	chunks := chunkAddrs(data)
	root := ManifestRoot(chunks)
	const idx = 5
	path, err := ChunkProof(chunks, idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChunkProof(root, 9, idx, data[idx], path); err != nil {
		t.Fatalf("baseline proof should verify: %v", err)
	}

	tampered := append([]byte(nil), data[idx]...)
	tampered[0] ^= 0x01
	if err := VerifyChunkProof(root, 9, idx, tampered, path); err == nil {
		t.Fatal("a one-bit change to the chunk still verified")
	} else if !errors.Is(err, ErrProofInvalid) {
		t.Errorf("tampered chunk gave %v, want ErrProofInvalid", err)
	}

	// Truncation and extension are the other two ways bytes go wrong.
	if err := VerifyChunkProof(root, 9, idx, data[idx][:len(data[idx])-1], path); err == nil {
		t.Error("a truncated chunk verified")
	}
	if err := VerifyChunkProof(root, 9, idx, append(append([]byte(nil), data[idx]...), 'x'), path); err == nil {
		t.Error("an extended chunk verified")
	}
}

// TestVerifyChunkProofRejectsTamperedPath mutates each element of the path in
// turn: no single sibling may be substitutable.
func TestVerifyChunkProofRejectsTamperedPath(t *testing.T) {
	data := chunkData(11)
	chunks := chunkAddrs(data)
	root := ManifestRoot(chunks)
	const idx = 6
	path, err := ChunkProof(chunks, idx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range path {
		bad := append([][32]byte(nil), path...)
		bad[i][0] ^= 0xff
		if err := VerifyChunkProof(root, 11, idx, data[idx], bad); err == nil {
			t.Errorf("proof verified with sibling %d corrupted", i)
		}
	}
}

// TestVerifyChunkProofRejectsSwappedPathOrder: left/right order is fixed by the
// node's index parity, so reordering siblings must fail even though the multiset
// of hashes is unchanged.
func TestVerifyChunkProofRejectsSwappedPathOrder(t *testing.T) {
	data := chunkData(8)
	chunks := chunkAddrs(data)
	root := ManifestRoot(chunks)
	const idx = 1
	path, err := ChunkProof(chunks, idx)
	if err != nil {
		t.Fatal(err)
	}
	if len(path) < 2 {
		t.Fatalf("need a path of at least 2, got %d", len(path))
	}
	swapped := append([][32]byte(nil), path...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if err := VerifyChunkProof(root, 8, idx, data[idx], swapped); err == nil {
		t.Fatal("a reordered path verified")
	}
}

// TestVerifyChunkProofRejectsWrongLengthPath: a path that is too short cannot be
// padded by the verifier, and one that is too long must not be silently ignored
// — trailing elements would be unverified material riding along inside a
// response that looks proven.
func TestVerifyChunkProofRejectsWrongLengthPath(t *testing.T) {
	data := chunkData(5)
	chunks := chunkAddrs(data)
	root := ManifestRoot(chunks)
	const idx = 0
	path, err := ChunkProof(chunks, idx)
	if err != nil {
		t.Fatal(err)
	}
	if len(path) == 0 {
		t.Fatal("expected a non-empty path")
	}

	if err := VerifyChunkProof(root, 5, idx, data[idx], path[:len(path)-1]); err == nil {
		t.Error("a truncated path verified")
	}
	if err := VerifyChunkProof(root, 5, idx, data[idx], append(append([][32]byte(nil), path...), [32]byte{0x42})); err == nil {
		t.Error("an over-long path verified")
	}
	// An absurdly long path is refused before any hashing work is done.
	huge := make([][32]byte, maxProofPath+1)
	if err := VerifyChunkProof(root, 5, idx, data[idx], huge); err == nil {
		t.Error("an unbounded path was accepted")
	}
}

// TestVerifyChunkProofRejectsWrongRootOrSize: the root and the chunk count are
// the caller's trusted inputs. Supplying either wrongly must fail rather than
// quietly verify against whatever was passed.
func TestVerifyChunkProofRejectsWrongRootOrSize(t *testing.T) {
	data := chunkData(6)
	chunks := chunkAddrs(data)
	root := ManifestRoot(chunks)
	const idx = 2
	path, err := ChunkProof(chunks, idx)
	if err != nil {
		t.Fatal(err)
	}

	other := ManifestRoot(chunkAddrs(chunkData(7)))
	if err := VerifyChunkProof(other, 6, idx, data[idx], path); err == nil {
		t.Error("proof verified against an unrelated root")
	}
	// A chunk count that changes the FOLD SHAPE for this index makes the
	// recomputed root diverge.
	for _, n := range []int{12, 20, 40} {
		if err := VerifyChunkProof(root, n, idx, data[idx], path); err == nil {
			t.Errorf("proof verified with chunk count %d instead of 6", n)
		}
	}
}

// TestChunkCountIsShapeNotAuthentication records a real and slightly
// counter-intuitive property, so nobody later mistakes nChunks for a second
// authenticator and builds on a guarantee it does not provide.
//
// nChunks exists ONLY to tell the verifier where odd-node promotion happens. If
// two different counts imply the SAME fold shape for the index in question
// (n=5 and n=6 do, at index 2), then a proof valid under one is valid under the
// other — and correctly so: the fold is identical, so it reproduces the same
// root, and the root is what authenticates. The security of the scheme rests on
// the ROOT, which the caller takes from the signed announce; the count is
// structural metadata, not a secret and not a claim.
func TestChunkCountIsShapeNotAuthentication(t *testing.T) {
	data := chunkData(6)
	chunks := chunkAddrs(data)
	root := ManifestRoot(chunks)
	const idx = 2
	path, err := ChunkProof(chunks, idx)
	if err != nil {
		t.Fatal(err)
	}
	// n=5 folds identically at index 2, so the same path verifies. This is
	// sound: it proves the chunk is at index 2 of the tree rooted at `root`.
	if err := VerifyChunkProof(root, 5, idx, data[idx], path); err != nil {
		t.Fatalf("n=5 and n=6 fold identically at index 2, so this must verify: %v", err)
	}
	// What must NEVER happen is a chunk verifying under a root it is not in.
	for n := 1; n <= 64; n++ {
		unrelated := ManifestRoot(chunkAddrs(chunkData(n)))
		if unrelated == root {
			continue
		}
		if err := VerifyChunkProof(unrelated, 6, idx, data[idx], path); err == nil {
			t.Fatalf("chunk verified against the unrelated root of a %d-chunk blob", n)
		}
	}
}

// TestChunkProofOutOfRangeIsACleanError: an index past the end is a caller
// error with a distinguishable type, not a panic and not a bogus path.
func TestChunkProofOutOfRangeIsACleanError(t *testing.T) {
	chunks := chunkAddrs(chunkData(4))
	for _, idx := range []int{4, 5, 1000, -1} {
		path, err := ChunkProof(chunks, idx)
		if err == nil {
			t.Errorf("index %d produced a path of %d instead of an error", idx, len(path))
			continue
		}
		if !errors.Is(err, ErrProofRange) {
			t.Errorf("index %d gave %v, want ErrProofRange", idx, err)
		}
	}
	if _, err := ChunkProof(nil, 0); !errors.Is(err, ErrProofRange) {
		t.Errorf("empty chunk list gave %v, want ErrProofRange", err)
	}

	// The verifier applies the same bound independently, since it never sees
	// the chunk list.
	root := ManifestRoot(chunks)
	if err := VerifyChunkProof(root, 4, 4, []byte("x"), nil); !errors.Is(err, ErrProofRange) {
		t.Errorf("verifier out-of-range gave %v, want ErrProofRange", err)
	}
	if err := VerifyChunkProof(root, 0, 0, []byte("x"), nil); !errors.Is(err, ErrProofRange) {
		t.Errorf("verifier empty-tree gave %v, want ErrProofRange", err)
	}
}

// ---------------------------------------------------------------------------
// encoding
// ---------------------------------------------------------------------------

// TestChunkProofEncodingIsCanonicalCBOR checks the § 5.3 wire shape byte for
// byte on the head structure. The body is content-addressed by (id, i), so two
// encodings of one proof would be two cache entries for one fact.
func TestChunkProofEncodingIsCanonicalCBOR(t *testing.T) {
	chunks := chunkAddrs(chunkData(5))
	path, err := ChunkProof(chunks, 2)
	if err != nil {
		t.Fatal(err)
	}
	enc := EncodeChunkProof(2, path)

	if enc[0] != 0x82 {
		t.Fatalf("body does not start with array(2): 0x%02x", enc[0])
	}
	if enc[1] != 0x02 { // uint 2, minimal head
		t.Fatalf("index is not a minimal uint head: 0x%02x", enc[1])
	}
	if want := byte(0x80 | len(path)); enc[2] != want {
		t.Fatalf("path array head 0x%02x, want 0x%02x", enc[2], want)
	}
	// Each element is a definite-length 32-byte string: 0x58 0x20 ‖ digest.
	off := 3
	for i := range path {
		if enc[off] != 0x58 || enc[off+1] != 0x20 {
			t.Fatalf("element %d head is 0x%02x 0x%02x, want 0x58 0x20", i, enc[off], enc[off+1])
		}
		if !bytes.Equal(enc[off+2:off+34], path[i][:]) {
			t.Fatalf("element %d payload does not match the path", i)
		}
		off += 34
	}
	if off != len(enc) {
		t.Fatalf("%d trailing bytes", len(enc)-off)
	}

	// A large index must still use a minimal head.
	if got := EncodeChunkProof(300, nil); !bytes.Equal(got, []byte{0x82, 0x19, 0x01, 0x2c, 0x80}) {
		t.Fatalf("index 300 encoded as %s", hex.EncodeToString(got))
	}
}

// TestChunkProofEncodingRoundTrips over many shapes, and the decoded proof must
// still verify — the encoder and the verifier have to agree about the same fact.
func TestChunkProofEncodingRoundTrips(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 11, 64, 1000} {
		data := chunkData(n)
		chunks := chunkAddrs(data)
		root := ManifestRoot(chunks)
		for _, idx := range []int{0, n / 2, n - 1} {
			path, err := ChunkProof(chunks, idx)
			if err != nil {
				t.Fatal(err)
			}
			gotIdx, gotPath, err := DecodeChunkProof(EncodeChunkProof(idx, path))
			if err != nil {
				t.Fatalf("n=%d i=%d: decode: %v", n, idx, err)
			}
			if gotIdx != idx {
				t.Fatalf("n=%d: index round-tripped as %d", n, gotIdx)
			}
			if err := VerifyChunkProof(root, n, gotIdx, data[idx], gotPath); err != nil {
				t.Fatalf("n=%d i=%d: decoded proof does not verify: %v", n, idx, err)
			}
		}
	}
}

// TestDecodeChunkProofRejectsMalformed keeps the decoder strict. A proof is a
// security statement, so anything ambiguous is refused rather than interpreted.
func TestDecodeChunkProofRejectsMalformed(t *testing.T) {
	valid := EncodeChunkProof(1, [][32]byte{{0x01}, {0x02}})
	cases := []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"not an array", []byte{0xa0}},
		{"wrong arity", []byte{0x83, 0x00, 0x80, 0x00}},
		{"index is a byte string", []byte{0x82, 0x41, 0x00, 0x80}},
		{"non-minimal index", []byte{0x82, 0x18, 0x01, 0x80}},
		{"indefinite-length path", []byte{0x82, 0x00, 0x9f, 0xff}},
		{"path element too short", []byte{0x82, 0x00, 0x81, 0x41, 0xaa}},
		{"path element is a text string", append([]byte{0x82, 0x00, 0x81, 0x78, 0x20}, make([]byte, 32)...)},
		{"truncated payload", valid[:len(valid)-4]},
		{"trailing bytes", append(append([]byte(nil), valid...), 0x00)},
		{"unbounded path", []byte{0x82, 0x00, 0x19, 0xff, 0xff}},
	}
	for _, tc := range cases {
		if _, _, err := DecodeChunkProof(tc.body); err == nil {
			t.Errorf("%s: decoded without error", tc.name)
		}
	}
}

// ---------------------------------------------------------------------------
// the HTTP surface
// ---------------------------------------------------------------------------

// proofFixture stocks an upstream with a manifest and its chunks and returns the
// pieces a client would hold: the trusted root, the chunk count, and the bytes.
func proofFixture(t *testing.T, up *fakeUpstream, n int) (Addr, [][]byte) {
	t.Helper()
	data := chunkData(n)
	id, body := buildManifest(t, data...)
	up.put("/manifest/"+id.String(), body)
	for _, c := range data {
		up.put("/chunk/"+HashBytes(c).String(), c)
	}
	return id, data
}

func proofURL(svc *Service, id Addr, idx int) string {
	return svc.Prefix() + "/manifest/" + id.String() + "/proof?chunk=" + strconv.Itoa(idx)
}

// getProof issues the read and returns the response with its body already
// drained, since every proof assertion needs both.
func getProof(t *testing.T, svc *Service, url string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	resp := get(t, svc, url, hdr)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading proof body: %v", err)
	}
	return resp, body
}

// TestServeChunkProofIsOffByDefault: § 5.3 is advertised BY PRESENCE, so an
// operator who has not opted in answers the ordinary "not served here" 404 and
// clients fall back to whole-manifest verification.
func TestServeChunkProofIsOffByDefault(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, nil)
	id, _ := proofFixture(t, up, 5)

	resp, _ := getProof(t, svc, proofURL(svc, id, 2), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404 when the proof endpoint is not enabled", resp.StatusCode)
	}
	if up.hits.Load() != 0 {
		t.Errorf("a disabled endpoint made %d upstream requests", up.hits.Load())
	}
}

// TestServeChunkProofEndToEnd is the feature working as advertised: a client
// that holds only the trusted root fetches ONE chunk and ONE proof — never the
// manifest — and verifies the chunk locally. That is verified seek.
func TestServeChunkProofEndToEnd(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, func(c *Config) { c.ServeProofs = true })
	const n = 37
	id, data := proofFixture(t, up, n)

	for _, idx := range []int{0, 1, 18, 35, 36} {
		resp, body := getProof(t, svc, proofURL(svc, id, idx), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("chunk %d: status %d, want 200", idx, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/cbor" {
			t.Errorf("chunk %d: content-type %q", idx, ct)
		}
		gotIdx, path, err := DecodeChunkProof(body)
		if err != nil {
			t.Fatalf("chunk %d: decode: %v", idx, err)
		}
		if gotIdx != idx {
			t.Fatalf("asked for chunk %d, proof says %d", idx, gotIdx)
		}
		// The client verifies against the root it already trusts from the
		// signed announce, plus the chunk bytes it fetched separately.
		if err := VerifyChunkProof(id, n, idx, data[idx], path); err != nil {
			t.Fatalf("chunk %d: served proof does not verify: %v", idx, err)
		}
	}
}

// TestServeChunkProofCacheHeaders: the response is immutable and
// content-addressed by (id, i), so it gets the same CDN-frontable posture as the
// other content-addressed reads, with an ETag naming both coordinates.
func TestServeChunkProofCacheHeaders(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, func(c *Config) { c.ServeProofs = true })
	id, _ := proofFixture(t, up, 6)

	resp, _ := getProof(t, svc, proofURL(svc, id, 3), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control %q is not immutable", cc)
	}
	etag := resp.Header.Get("ETag")
	if want := `"` + id.String() + `.3"`; etag != want {
		t.Fatalf("ETag %q, want %q", etag, want)
	}
	// A different chunk of the same manifest is a different resource.
	other, _ := getProof(t, svc, proofURL(svc, id, 4), nil)
	if other.Header.Get("ETag") == etag {
		t.Error("two chunks of one manifest share an ETag")
	}

	rev, _ := getProof(t, svc, proofURL(svc, id, 3), map[string]string{"If-None-Match": etag})
	if rev.StatusCode != http.StatusNotModified {
		t.Fatalf("revalidation gave %d, want 304", rev.StatusCode)
	}
}

// TestServeChunkProofRefusesBadRequests: everything that is not a well-formed
// request for an in-range chunk collapses to the same 404, because a holder's
// refusal is never a statement about what exists.
func TestServeChunkProofRefusesBadRequests(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, func(c *Config) { c.ServeProofs = true })
	id, _ := proofFixture(t, up, 4)

	base := svc.Prefix() + "/manifest/" + id.String() + "/proof"
	cases := []struct {
		name, url string
	}{
		{"index past the end", base + "?chunk=4"},
		{"far past the end", base + "?chunk=99999"},
		{"missing parameter", base},
		{"empty parameter", base + "?chunk="},
		{"negative", base + "?chunk=-1"},
		{"not a number", base + "?chunk=two"},
		{"non-canonical index", base + "?chunk=03"},
		{"hex", base + "?chunk=0x2"},
		{"unknown manifest", svc.Prefix() + "/manifest/" + ManifestRoot(chunkAddrs(chunkData(9))).String() + "/proof?chunk=0"},
		{"malformed address", svc.Prefix() + "/manifest/not-an-address/proof?chunk=0"},
	}
	for _, tc := range cases {
		resp, _ := getProof(t, svc, tc.url, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", tc.name, resp.StatusCode)
		}
	}
}

// TestServeChunkProofNeverBuildsOverAnUnverifiedManifest is the security
// property of the endpoint. A poisoned upstream that serves manifest bytes not
// matching the requested address must not get a proof built over its chunk list
// — the verification gate runs first, so the only paths this node can emit are
// paths over lists it has proved.
func TestServeChunkProofNeverBuildsOverAnUnverifiedManifest(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, func(c *Config) { c.ServeProofs = true })

	// The address of one manifest, the bytes of another.
	honest, _ := buildManifest(t, chunkData(5)...)
	_, evil := buildManifest(t, chunkData(6)...)
	up.put("/manifest/"+honest.String(), evil)

	resp, _ := getProof(t, svc, proofURL(svc, honest, 1), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404 — a proof was built over unverified manifest bytes", resp.StatusCode)
	}
}

// TestServeChunkProofUsesTheCache: a proof over an already-held manifest costs
// no upstream traffic, which is what makes per-chunk proofs affordable for a
// client seeking around a large video.
func TestServeChunkProofUsesTheCache(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, func(c *Config) { c.ServeProofs = true })
	id, _ := proofFixture(t, up, 16)

	if resp, _ := getProof(t, svc, proofURL(svc, id, 0), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("first proof: status %d", resp.StatusCode)
	}
	after := up.hits.Load()
	for i := 1; i < 16; i++ {
		if resp, _ := getProof(t, svc, proofURL(svc, id, i), nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("proof %d: status %d", i, resp.StatusCode)
		}
	}
	if up.hits.Load() != after {
		t.Errorf("15 further proofs made %d extra upstream requests, want 0", up.hits.Load()-after)
	}
}

// TestChunkProofInteropVector pins a deterministic end-to-end vector so another
// implementation (or a future refactor of this one) can be checked against a
// fixed answer rather than against itself. It covers a 5-chunk tree, which
// exercises odd-node promotion at two levels.
func TestChunkProofInteropVector(t *testing.T) {
	data := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")}
	chunks := chunkAddrs(data)
	root := ManifestRoot(chunks)

	if got := root.String(); got != interopRootB64 {
		t.Fatalf("root %s, want %s — the tree or the DS tag changed", got, interopRootB64)
	}
	for idx, wantHex := range interopProofHex {
		path, err := ChunkProof(chunks, idx)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(EncodeChunkProof(idx, path)); got != wantHex {
			t.Errorf("chunk %d proof\n got %s\nwant %s", idx, got, wantHex)
		}
		if err := VerifyChunkProof(root, len(data), idx, data[idx], path); err != nil {
			t.Errorf("chunk %d: %v", idx, err)
		}
	}
}

// The interop vector itself: a 5-chunk blob over the payloads "a".."e", chunked
// one byte each. Five leaves is the smallest tree that promotes an odd node at
// TWO levels, so it pins the promotion rule and not just the happy path — note
// chunk 4's proof carries a single sibling where chunks 0-3 carry three.
//
// These bytes are the § 5.3 response verbatim. Another implementation of the
// endpoint should reproduce them exactly; if it reproduces the root but not the
// paths, its tree shape differs, and if it reproduces neither, its DS tag or
// leaf rule differs (see the vidmesh parity note in docs/PUBCACHE.md).
//
// CROSS-LANGUAGE INTEROP LOCK: the JS reference verifier asserts these SAME
// constants in client/src/__tests__/chunkProof.test.js, so a one-byte
// divergence between the Go node and the browser fails one side. If you ever
// intentionally change the tree or the proof encoding, regenerate BOTH copies
// together.
const interopRootB64 = "HqmS4uJD2JJOZjmeF-YZikRhImZOgGvZHe6IwCOpRyT_"

var interopProofHex = map[int]string{
	0: "8200835820609ad16ca3186fc12dd32ce1d49ed57dd879c802246de385a20f7dbee2f894395820c97979256dd9f06e0dc6be9fabf2baef2acd2118939563d18bfa79661dc36dce58201365330142a154c52d28959cc1db9166d7b10c2591a9acc25d959ec7e1b8d242",
	1: "8201835820208e131bd1411e9d8c1d8417b9e9f370e2118a32b37535c77357c6d152348ac75820c97979256dd9f06e0dc6be9fabf2baef2acd2118939563d18bfa79661dc36dce58201365330142a154c52d28959cc1db9166d7b10c2591a9acc25d959ec7e1b8d242",
	2: "82028358208cc8a6db6f14fc57eacea4131385777a244b1f6feaeae1fed47ee8ef6e0982cf5820abd36c78c5c484698bf962a24adc9293467661696e0897a500df261d2b1664f258201365330142a154c52d28959cc1db9166d7b10c2591a9acc25d959ec7e1b8d242",
	3: "820383582093ce26dbcfb499cfd2b7ddfda025f4377f02bf62416d7f4799ea467720edaddd5820abd36c78c5c484698bf962a24adc9293467661696e0897a500df261d2b1664f258201365330142a154c52d28959cc1db9166d7b10c2591a9acc25d959ec7e1b8d242",
	4: "82048158205fa8b1b087f0c5dec0dc650c299f1779e735fd3b317e85793bbedac488a5183f",
}
