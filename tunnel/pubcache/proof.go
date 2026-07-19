package pubcache

import (
	"errors"
	"fmt"
)

// proof.go — chunk-tree RANGE PROOFS (substrate/FEEDS.md § 5.3), the OPTIONAL
// inclusion-proof endpoint over the § 22.2.2 DS-tagged Merkle tree.
//
// The gap it closes: today a fetcher verifies a chunk by holding the WHOLE
// PubManifest — it has every h_i, so it can check any chunk byte-for-byte. That
// is fine for small blobs and wasteful for large media, where verifying one
// 1 MiB chunk in the middle of a multi-gigabyte video means first pulling a
// chunk-hash list with thousands of entries. The tree already commits to every
// leaf, so an O(log n) audit path is enough: fetch chunk i, fetch its path, fold,
// compare against the PubManifest.id the reader ALREADY TRUSTS from the signed
// announce. That is verified seek, and verified resume, without the manifest.
//
// This adds NO new trust. The endpoint is a convenience exactly like every other
// § 22 read: a lying holder cannot forge a path to a root it does not control
// without a BLAKE3 collision, and a fetcher that does not get one falls back to
// whole-manifest verification (§ 5.3, § 5.1). It allocates no new object, no new
// signing preimage, and no new § 21 error code — it only serves a proof the tree
// already commits to.
//
// TREE SHAPE. § 3.2 specifies the RFC 6962 split rule ("split at the largest
// power of two < n"); the audit path here is computed level-by-level, pairing
// left to right and PROMOTING a level's unpaired final node unchanged. Those two
// constructions are the same tree — merkle_test.go asserts it against
// merkleRoot() for every n up to a few hundred rather than leaving it as a
// claim — and the level form is the one that yields a path and a verifier
// directly. vidmesh's Rust chunk tree uses the same promotion rule, so the
// SHAPE is shared; the HASHES are not (see the note on parity below).

// Errors specific to the § 5.3 proof surface. They are separate from the
// addressing errors because a proof failure is a statement about a PATH, not
// about an object's address.
var (
	// ErrProofRange is a chunk index that does not exist in the tree.
	ErrProofRange = errors.New("pubcache: chunk index out of range")
	// ErrProofInvalid is the load-bearing one: the folded path does not
	// reproduce the trusted root, or the path is not the right length for the
	// tree it claims to be in. Either way the chunk is NOT proven and MUST NOT
	// be used.
	ErrProofInvalid = errors.New("pubcache: chunk proof does not verify")
)

// maxProofPath bounds a decoded path. A 32-level tree is 2^32 chunks — at the
// § 16.4 reference 1 MiB chunk that is 4 PiB, so this cannot bind a real blob
// while still refusing an attacker-chosen unbounded array.
const maxProofPath = 40

// reduceLevel combines one level of the chunk tree into the next: pair nodes
// left to right, and promote a level's unpaired final node UNCHANGED.
//
// The promotion rule is the subtle part and it is why the verifier needs the
// chunk COUNT: whether a node has a sibling at a given level is a fact about the
// tree's width, not about the node, so a verifier that does not know n cannot
// know whether to consume a path element at that level.
func reduceLevel(level [][32]byte) [][32]byte {
	next := make([][32]byte, 0, (len(level)+1)/2)
	i := 0
	for ; i+1 < len(level); i += 2 {
		next = append(next, merkleNode(level[i], level[i+1]))
	}
	if i < len(level) {
		next = append(next, level[i]) // promoted, not re-hashed
	}
	return next
}

// ChunkProof returns the RFC 6962 audit path for leaf `index` under the tree of
// § 3.2: the sibling hashes on the path from that leaf to the root, ordered
// BOTTOM-UP. A level at which the node is the promoted last one contributes NO
// element — the verifier reconstructs that from the chunk count.
//
// chunks is the manifest's ordered plaintext chunk-address list; the returned
// hashes are bare 32-byte tree nodes, NOT 33-byte content addresses (the
// multihash prefix belongs to the root when it becomes PubManifest.id, and to
// the leaves' inputs h_i — never to an interior node).
func ChunkProof(chunks []Addr, index int) ([][32]byte, error) {
	n := len(chunks)
	if n == 0 {
		return nil, fmt.Errorf("%w: empty chunk list", ErrProofRange)
	}
	if index < 0 || index >= n {
		return nil, fmt.Errorf("%w: chunk %d of %d", ErrProofRange, index, n)
	}
	level := make([][32]byte, n)
	for i, h := range chunks {
		level[i] = merkleLeaf(h)
	}
	path := make([][32]byte, 0, 32)
	cur := index
	for len(level) > 1 {
		if sib := cur ^ 1; sib < len(level) {
			path = append(path, level[sib])
		}
		cur /= 2
		level = reduceLevel(level)
	}
	return path, nil
}

// VerifyChunkProof is the CLIENT-SIDE half, and the half that makes the
// endpoint mean anything: it proves that `chunk` really is chunk `index` of the
// blob whose manifest root is `root`, using only the audit path — never the
// manifest's chunk list.
//
// The caller supplies `root` and `nChunks` from something it ALREADY TRUSTS (the
// signed PubAnnounce and the manifest header it commits to). It must never take
// either from the same response that carried the proof, which would be asking
// the server to grade its own work. See the FEEDS.md § 5.3 note in
// docs/PUBCACHE.md: the spec's response encoding carries the index and the path
// but NOT the tree size, so nChunks is necessarily out-of-band.
//
// Returns nil ONLY if the chunk is proven. Every other outcome — wrong index,
// tampered bytes, tampered or mis-sized path, wrong root — is an error, and the
// chunk MUST be discarded (rotate to another holder, ERR_PUB_CHUNK_HASH_MISMATCH
// posture, § 5.2).
func VerifyChunkProof(root Addr, nChunks, index int, chunk []byte, path [][32]byte) error {
	if nChunks <= 0 {
		return fmt.Errorf("%w: empty tree", ErrProofRange)
	}
	if index < 0 || index >= nChunks {
		return fmt.Errorf("%w: chunk %d of %d", ErrProofRange, index, nChunks)
	}
	if len(path) > maxProofPath {
		return fmt.Errorf("%w: path of %d exceeds the %d-level bound", ErrProofInvalid, len(path), maxProofPath)
	}
	// The leaf is taken over the chunk's ADDRESS h_i = 0x1e ‖ BLAKE3-256(bytes),
	// not over the bytes directly (§ 3.2), so tampered bytes change h_i and the
	// fold diverges immediately.
	node := merkleLeaf(HashBytes(chunk))

	cur, levelLen, used := index, nChunks, 0
	for levelLen > 1 {
		if sib := cur ^ 1; sib < levelLen {
			if used >= len(path) {
				return fmt.Errorf("%w: path too short at level %d", ErrProofInvalid, used)
			}
			s := path[used]
			used++
			// Order is fixed by the node's own index parity, never by anything
			// the server says — a swapped pair is a different node.
			if cur%2 == 0 {
				node = merkleNode(node, s)
			} else {
				node = merkleNode(s, node)
			}
		}
		cur /= 2
		levelLen = (levelLen + 1) / 2
	}
	// A path with anything left over is not the path for this tree; accepting it
	// would let a server pad a proof with unverified material.
	if used != len(path) {
		return fmt.Errorf("%w: path has %d unused elements", ErrProofInvalid, len(path)-used)
	}

	var got Addr
	got[0] = HashPrefixBLAKE3_256
	copy(got[1:], node[:])
	if got != root {
		return fmt.Errorf("%w: folds to %s, want root %s", ErrProofInvalid, got, root)
	}
	return nil
}

// EncodeChunkProof renders the § 5.3 response body: the canonically-encoded
// CBOR array `[chunk_index, [sibling hashes…]]`.
//
// Deterministic per § 18.1.2 — minimal-length heads, definite lengths, no tags —
// so the body is a pure function of (id, i) and the endpoint is genuinely
// content-addressed and CDN-frontable like the other immutable reads.
func EncodeChunkProof(index int, path [][32]byte) []byte {
	out := make([]byte, 0, 8+len(path)*34)
	out = append(out, 0x82) // array(2)
	out = appendCBORUint(out, cborMajorUint, uint64(index))
	out = appendCBORUint(out, cborMajorArray, uint64(len(path)))
	for _, h := range path {
		out = appendCBORUint(out, cborMajorByteStr, uint64(len(h)))
		out = append(out, h[:]...)
	}
	return out
}

// DecodeChunkProof parses a § 5.3 response body into its index and path. It is
// the strict counterpart of the encoder — non-minimal integers, indefinite
// lengths, wrong-width hashes, and trailing bytes are all rejected — because a
// proof that two byte strings could both mean is not a proof.
func DecodeChunkProof(b []byte) (index int, path [][32]byte, err error) {
	major, arg, n, err := readHead(b)
	if err != nil {
		return 0, nil, err
	}
	if major != cborMajorArray || arg != 2 {
		return 0, nil, fmt.Errorf("%w: proof is not a 2-element cbor array", ErrMalformedObject)
	}
	off := n

	iMajor, idx, in, err := readHead(b[off:])
	if err != nil {
		return 0, nil, err
	}
	if iMajor != cborMajorUint {
		return 0, nil, fmt.Errorf("%w: proof index is not an unsigned integer", ErrMalformedObject)
	}
	if idx > uint64(maxCBORItems) {
		return 0, nil, fmt.Errorf("%w: proof index out of bounds", ErrMalformedObject)
	}
	off += in

	pMajor, count, pn, err := readHead(b[off:])
	if err != nil {
		return 0, nil, err
	}
	if pMajor != cborMajorArray {
		return 0, nil, fmt.Errorf("%w: proof path is not a cbor array", ErrMalformedObject)
	}
	if count > maxProofPath {
		return 0, nil, fmt.Errorf("%w: proof path of %d exceeds the %d-level bound", ErrMalformedObject, count, maxProofPath)
	}
	off += pn

	path = make([][32]byte, 0, count)
	for i := uint64(0); i < count; i++ {
		eMajor, eLen, en, err := readHead(b[off:])
		if err != nil {
			return 0, nil, err
		}
		if eMajor != cborMajorByteStr || eLen != digestLen {
			return 0, nil, fmt.Errorf("%w: proof element is not a %d-byte hash", ErrMalformedObject, digestLen)
		}
		off += en
		if uint64(len(b)-off) < eLen {
			return 0, nil, fmt.Errorf("%w: truncated proof path", ErrMalformedObject)
		}
		var h [32]byte
		copy(h[:], b[off:off+int(eLen)])
		path = append(path, h)
		off += int(eLen)
	}
	if off != len(b) {
		return 0, nil, fmt.Errorf("%w: %d trailing bytes after proof", ErrMalformedObject, len(b)-off)
	}
	return int(idx), path, nil
}

// appendCBORUint appends a minimal-length CBOR head for the given major type.
func appendCBORUint(b []byte, major byte, v uint64) []byte {
	m := major << 5
	switch {
	case v < 24:
		return append(b, m|byte(v))
	case v <= 0xff:
		return append(b, m|24, byte(v))
	case v <= 0xffff:
		return append(b, m|25, byte(v>>8), byte(v))
	case v <= 0xffffffff:
		return append(b, m|26, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, m|27,
			byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
