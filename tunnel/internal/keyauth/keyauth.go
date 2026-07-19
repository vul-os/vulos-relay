// Package keyauth is the shared key-addressed request-authentication primitive
// used by every signed write surface in this relay: the rendezvous role's
// announce/deposit/poll/ack, and the cache/pin role's pin/unpin.
//
// It exists so those surfaces cannot drift apart. The security of a signed
// write rests entirely on two things being identical between signer and
// verifier — the canonical byte string a signature covers, and the freshness /
// replay window — and re-implementing either per role is exactly how one of
// them ends up subtly weaker than the other. There is one implementation here,
// and every role calls it.
//
// The discipline, in full:
//
//   - Identity is an Ed25519 public key, encoded as unpadded base64url
//     everywhere: URL path segments, JSON fields, and inside the signed message.
//     One encoding, so an implementer never has to guess.
//   - A signature covers a DOMAIN-SEPARATED, LENGTH-PREFIXED canonical message
//     (CanonicalMessage). Length-prefixing means no delimiter can be forged
//     across field boundaries; the domain tag means a signature minted for one
//     request type can never be replayed as another.
//   - Every signed write carries a unix timestamp and a random nonce, checked by
//     Guard: the timestamp must be within ±skew (bounding how long a captured
//     request stays replayable) and the (key, nonce) pair must be unseen inside
//     that window.
//
// Everything fails closed. A malformed key, a malformed signature, a stale
// timestamp, or a reused nonce is a refusal, never a degraded acceptance.
package keyauth

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// B64 is the unpadded base64url codec used for every binary field on the wire.
var B64 = base64.RawURLEncoding

// PubKeyLen is the Ed25519 public-key length in bytes.
const PubKeyLen = ed25519.PublicKeySize // 32

// SigLen is the Ed25519 signature length in bytes.
const SigLen = ed25519.SignatureSize // 64

// The refusal set. They are deliberately coarse: a caller distinguishing
// "wrong key" from "bad signature" in a response would be handing an attacker
// an oracle, so the HTTP surfaces collapse these to one status each.
var (
	ErrBadKey   = errors.New("invalid key")
	ErrBadSig   = errors.New("invalid signature encoding")
	ErrSigFail  = errors.New("signature verification failed")
	ErrBadNonce = errors.New("invalid nonce")
)

// DecodeKey parses a base64url-encoded Ed25519 public key of the exact expected
// length. It fails closed on any malformed or wrong-length input rather than
// returning a truncated/padded key.
func DecodeKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrBadKey
	}
	raw, err := B64.DecodeString(s)
	if err != nil || len(raw) != PubKeyLen {
		return nil, ErrBadKey
	}
	return ed25519.PublicKey(raw), nil
}

// NormalizeKey validates a key string and returns its canonical encoding (the
// re-encoded form), so a stored/compared key is always in one form regardless of
// any incidental input variation. Returns "" on invalid input.
func NormalizeKey(s string) string {
	pk, err := DecodeKey(s)
	if err != nil {
		return ""
	}
	return B64.EncodeToString(pk)
}

// DecodeSig parses a base64url Ed25519 signature of the exact expected length.
func DecodeSig(s string) ([]byte, error) {
	raw, err := B64.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != SigLen {
		return nil, ErrBadSig
	}
	return raw, nil
}

// CanonicalMessage builds the unambiguous byte string that a signature covers.
// It length-prefixes every segment (a 4-byte big-endian length followed by the
// segment's UTF-8 bytes), starting with a domain-separation tag.
//
// A reimplementer reproduces this exactly: for the domain tag and then each
// field in order, write uint32be(len(utf8(s))) followed by utf8(s). All binary
// fields (keys, nonces, addresses, payloads) are passed as their base64url
// string form and numbers as their base-10 decimal string, so every segment is
// plain text.
func CanonicalMessage(domain string, fields ...string) []byte {
	total := 4 + len(domain)
	for _, f := range fields {
		total += 4 + len(f)
	}
	buf := make([]byte, 0, total)
	var lp [4]byte
	appendSeg := func(s string) {
		binary.BigEndian.PutUint32(lp[:], uint32(len(s)))
		buf = append(buf, lp[:]...)
		buf = append(buf, s...)
	}
	appendSeg(domain)
	for _, f := range fields {
		appendSeg(f)
	}
	return buf
}

// VerifySig checks an Ed25519 signature (base64url) over the canonical message
// for the given key. It fails closed on any decode error or verification
// failure. The key argument is the already-decoded public key of the purported
// signer.
func VerifySig(pub ed25519.PublicKey, sigB64 string, msg []byte) error {
	sig, err := DecodeSig(sigB64)
	if err != nil {
		return err
	}
	if len(pub) != PubKeyLen {
		return ErrBadKey
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrSigFail
	}
	return nil
}

// KeyEqual is a constant-time equality check for two canonical key strings.
// Both are already-normalized base64url strings of equal length in the common
// case; subtle.ConstantTimeCompare tolerates differing lengths (returns 0)
// safely.
func KeyEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
