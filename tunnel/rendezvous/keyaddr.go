// Package rendezvous is the reference implementation of the open "rendezvous"
// infrastructure role: the key-addressed announce / resolve / signal / mailbox
// substrate that lets peers discover each other and exchange WebRTC signaling
// (and short-lived opaque blobs) through ANY conforming node — a self-hosted
// relayd or a Vulos-run one — with no Vulos OS required.
//
// It is deliberately standalone: it imports nothing from the OS repo and depends
// only on the Go standard library. The wire protocol it speaks is documented in
// docs/RENDEZVOUS.md so any implementer can build a compatible node or client.
//
// ── The role in one paragraph ───────────────────────────────────────────────
//
// Every participant is identified by an Ed25519 public key. A node ANNOUNCEs its
// presence (endpoints + TTL) under its key with a signed request; anyone RESOLVEs
// a key to its current presence with an unauthenticated read. Two peers negotiate
// a direct WebRTC connection by SIGNALing — depositing content-opaque offer /
// answer / ICE blobs addressed to each other's key, picked up by the holder of the
// matching private key. When a peer is offline, a short-TTL content-blind MAILBOX
// buffers opaque encrypted blobs addressed to its key until it comes back.
//
// ── Content-blind by construction ───────────────────────────────────────────
//
// The rendezvous node NEVER inspects, decrypts, or dials application payloads. It
// stores opaque bytes keyed by public key, gates writes with signatures, and hands
// them to the holder of the private key. It makes NO outbound connection on behalf
// of a request (announced endpoints are stored and echoed, never dialed), so it has
// no SSRF surface of its own.
package rendezvous

import (
	"crypto/ed25519"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/internal/keyauth"
)

// keyaddr.go — key addressing and signed-request verification.
//
// The primitives live in tunnel/internal/keyauth and are SHARED with the
// cache/pin role's signed writes. They are aliased rather than reimplemented on
// purpose: the canonical signing message and the replay window are the two
// things that must be byte-identical between every signer and every verifier in
// this binary, so there is exactly one implementation of each and both roles
// call it. The local names below are kept so this package continues to read as
// self-describing.
//
// Only the symbols this package actually uses are aliased. Mirroring every
// keyauth export would make this file a second copy of that API's surface, and
// an alias with no caller tells a reader the role uses something it does not.

// keyB64 is the canonical URL-addressing of an Ed25519 public key: the 32 raw
// key bytes in unpadded base64url. It is the single key encoding used
// everywhere in the protocol — in URL path segments, in JSON fields, and inside
// the signed canonical message — so an implementer never has to guess an
// encoding.

// b64 is the unpadded base64url codec used for every binary field on the wire.
var b64 = keyauth.B64

// sigLen is the Ed25519 signature length in bytes.
const sigLen = keyauth.SigLen

// decodeKey parses a base64url-encoded Ed25519 public key of the exact expected
// length, failing closed on any malformed or wrong-length input.
func decodeKey(s string) (ed25519.PublicKey, error) { return keyauth.DecodeKey(s) }

// normalizeKey validates a key string and returns its canonical encoding.
func normalizeKey(s string) string { return keyauth.NormalizeKey(s) }

// canonicalMessage builds the domain-separated, length-prefixed byte string a
// signature covers (keyauth.CanonicalMessage). Documented in
// docs/RENDEZVOUS.md and reproduced byte-for-byte by the JS client.
func canonicalMessage(domain string, fields ...string) []byte {
	return keyauth.CanonicalMessage(domain, fields...)
}

// verifySig checks an Ed25519 signature over the canonical message, fail-closed.
func verifySig(pub ed25519.PublicKey, sigB64 string, msg []byte) error {
	return keyauth.VerifySig(pub, sigB64, msg)
}

// replayGuard is the shared freshness/replay guard (keyauth.Guard).
type replayGuard = keyauth.Guard

// newReplayGuard builds a guard. skew<=0 => defaultClockSkew; maxKeys<=0 => 100k.
func newReplayGuard(skew time.Duration, maxKeys int) *replayGuard {
	return keyauth.NewGuard(skew, maxKeys)
}
