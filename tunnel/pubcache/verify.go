package pubcache

import "fmt"

// verify.go — THE MANDATORY GATE.
//
// Nothing enters this cache, and nothing leaves it, without passing Verify. That
// is the invariant the whole role rests on: a poisoned upstream MUST NOT become
// a poisoned cache. Because every § 22 read endpoint served here is
// content-addressed, "is this object authentic?" reduces entirely to "do these
// bytes hash to the address they were requested by?" — a question this node can
// answer alone, offline, with no key material, no DNS, and no trust in whoever
// handed it the bytes (§ 22.5.1: *a server is a convenience, not a trust root*).
//
// Verification runs BEFORE store and is re-run on the way out is unnecessary —
// bytes in the store are immutable and already proved — so the cost is paid once
// per object, on the miss path.
//
// Deliberately NOT handled here: `feed/{pub}/head`. A FeedHead is MUTABLE and
// is authenticated by an Ed25519 signature chaining through a DeviceCert, not by
// a content address, so this node cannot prove it correct with hashing alone.
// Rather than cache an object it cannot verify, this implementation takes
// § 22.5.1's other permitted path and does not cache feed heads at all — see
// service.go. Fail closed, always: an object this node cannot verify is an
// object it does not serve.

// Kind names the § 22.5.1 read endpoint an object was fetched from. Each kind
// has its own self-addressing rule.
type Kind int

const (
	// KindAnnounce is `/announce/{id}` — a PubAnnounce (§ 22.3), addressed by
	// the § 18.9.4 anchor rule over its complete deterministic encoding.
	KindAnnounce Kind = iota
	// KindManifest is `/manifest/{id}` — a PubManifest (§ 22.2.1), addressed by
	// the DS-tagged Merkle root over its chunk list, NOT by a hash of its own
	// bytes.
	KindManifest
	// KindChunk is `/chunk/{h}` — raw plaintext chunk bytes (§ 22.2.2).
	KindChunk
)

func (k Kind) String() string {
	switch k {
	case KindAnnounce:
		return "announce"
	case KindManifest:
		return "manifest"
	case KindChunk:
		return "chunk"
	}
	return "unknown"
}

// Verify proves that body is the object named by want, under the addressing
// rule for kind. A nil return is the ONLY licence to store or serve the bytes.
func Verify(kind Kind, want Addr, body []byte) error {
	switch kind {
	case KindAnnounce, KindChunk:
		// § 22.3.3 step 2 / § 22.2.2 step 1: the address is the anchor hash of
		// the bytes themselves. A mismatch is 0x0905 (announce) / 0x090A (chunk).
		if got := HashBytes(body); got != want {
			return fmt.Errorf("%w: %s hashes to %s, requested as %s", ErrAddrMismatch, kind, got, want)
		}
		return nil
	case KindManifest:
		_, err := verifiedManifestChunks(want, body)
		return err
	}
	return fmt.Errorf("%w: unknown object kind", ErrMalformedObject)
}

// PubManifest field keys (§ 22.2.1).
const (
	manifestKeyID        = 1
	manifestKeySize      = 2
	manifestKeyChunkSz   = 3
	manifestKeyChunks    = 4
	manifestKeyForbidden = 5 // the key-5 trap: FORBIDDEN by construction
	manifestKeySuite     = 6
	// Keys >= 64 are reserved for extension and MAY be ignored in an unsigned
	// object (§ 18.1.2). A PubManifest carries no signature — its integrity
	// comes from the Merkle root — so unknown high keys are tolerated while
	// unknown LOW keys are rejected fail-closed.
	manifestKeyExtensionFloor = 64
)

// verifiedManifestChunks checks a PubManifest against the address it was
// fetched by (§ 22.2.1, § 22.2.3) and, on success, returns its ordered
// plaintext chunk list.
//
// It returns the chunk list because the § 5.3 proof endpoint needs exactly that
// and needs it to have been PROVED first: a path is only meaningful over a chunk
// list that has already been shown to root to the requested address. Returning
// it from the verifier rather than re-parsing elsewhere makes it impossible to
// build a proof over an unverified list.
//
// Three independent checks, all of which must pass:
//  1. the key-5 trap — a manifest carrying a key field is a leaked sealed
//     manifest or a malformation, never a valid public one (0x0902);
//  2. the recomputed DS-tagged Merkle root over `chunks` equals the requested
//     address (0x0909; a sealed manifest fed here fails this by construction,
//     which is 0x0903);
//  3. the manifest's own `id` field agrees with that address, so a cache never
//     stores an object that disagrees with itself.
func verifiedManifestChunks(want Addr, body []byte) ([]Addr, error) {
	entries, err := parseUintKeyedMap(body)
	if err != nil {
		return nil, err
	}
	var (
		selfID    Addr
		haveID    bool
		chunks    []Addr
		haveChunk bool
		haveSize  bool
		haveCsz   bool
		haveSuite bool
	)
	for _, e := range entries {
		switch e.key {
		case manifestKeyForbidden:
			// § 22.2.1: reject on sight. The sealed manifest forbids key 5 lest
			// it LEAK; the public manifest forbids it because none EXISTS.
			return nil, ErrManifestKeyPresent
		case manifestKeyID:
			major, l, n, err := readHead(e.val)
			if err != nil {
				return nil, err
			}
			if major != cborMajorByteStr || l != addrLen || len(e.val) != n+addrLen {
				return nil, fmt.Errorf("%w: PubManifest.id is not a %d-byte address", ErrMalformedObject, addrLen)
			}
			copy(selfID[:], e.val[n:])
			haveID = true
		case manifestKeyChunks:
			if chunks, err = parseAddrArray(e.val); err != nil {
				return nil, err
			}
			haveChunk = true
		case manifestKeySize:
			haveSize = true
		case manifestKeyChunkSz:
			haveCsz = true
		case manifestKeySuite:
			haveSuite = true
		default:
			if e.key < manifestKeyExtensionFloor {
				return nil, fmt.Errorf("%w: unknown PubManifest key %d", ErrMalformedObject, e.key)
			}
		}
	}
	if !haveID || !haveChunk || !haveSize || !haveCsz || !haveSuite {
		return nil, fmt.Errorf("%w: PubManifest missing a required field", ErrMalformedObject)
	}
	if root := ManifestRoot(chunks); root != want {
		return nil, fmt.Errorf("%w: manifest chunk list roots to %s, requested as %s", ErrAddrMismatch, root, want)
	}
	if selfID != want {
		return nil, fmt.Errorf("%w: PubManifest.id %s disagrees with fetch address %s", ErrAddrMismatch, selfID, want)
	}
	return chunks, nil
}
