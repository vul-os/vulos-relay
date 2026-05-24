// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Header is the cleartext, signed envelope header (spec/PEERING.md §4.1).
type Header struct {
	Proto             string   // field 1
	Suite             string   // field 2
	SenderDomain      string   // field 3
	SenderIdentityPub []byte   // field 4 (32)
	ReceiverKexPub    []byte   // field 5 (32)
	EphemeralPub      []byte   // field 6 (32)
	Nonce             []byte   // field 7 (12)
	Timestamp         int64    // field 8
	MailFrom          string   // field 9
	RcptTo            []string // field 10
}

// Envelope is the parsed on-wire unit: header, encrypted payload, signature
// (spec §4).
type Envelope struct {
	Header    Header
	Payload   []byte // AEAD ciphertext+tag of the raw RFC 822 message
	Signature []byte // Ed25519 over canonical(header) || payload
}

// SealParams are the inputs to Seal.
type SealParams struct {
	Sender       *Identity
	SenderDomain string
	Receiver     *PeerDescriptor
	MailFrom     string
	RcptTo       []string
	RawRFC822    []byte
	Proto        string // negotiated; e.g. ProtoV1
	Suite        string // negotiated; e.g. SuiteV1
	// Now, if non-nil, overrides the envelope timestamp (tests).
	Now func() time.Time
}

// Seal builds an encrypted, signed envelope for the receiver per spec §4–§6.
func Seal(p SealParams) (*Envelope, error) {
	if p.Proto != ProtoV1 || p.Suite != SuiteV1 {
		return nil, ErrUnsupported
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}

	// Ephemeral X25519 keypair for forward secrecy (spec §5.1).
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("peering: ephemeral key: %w", err)
	}
	recvKex, err := ecdh.X25519().NewPublicKey(p.Receiver.KexPub)
	if err != nil {
		return nil, fmt.Errorf("peering: receiver kex key: %w", err)
	}
	ss, err := eph.ECDH(recvKex)
	if err != nil {
		return nil, fmt.Errorf("peering: ecdh: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("peering: nonce: %w", err)
	}

	hdr := Header{
		Proto:             p.Proto,
		Suite:             p.Suite,
		SenderDomain:      p.SenderDomain,
		SenderIdentityPub: p.Sender.SignPub,
		ReceiverKexPub:    p.Receiver.KexPub,
		EphemeralPub:      eph.PublicKey().Bytes(),
		Nonce:             nonce,
		Timestamp:         now().UTC().Unix(),
		MailFrom:          p.MailFrom,
		RcptTo:            p.RcptTo,
	}

	hdrBytes := marshalHeader(hdr)

	// Derive key (spec §5.2) and seal payload with header as AAD (spec §5.3).
	key := deriveKey(ss, nonce, p.Sender.SignPub, p.Receiver.KexPub)
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	payload := aead.Seal(nil, nonce, p.RawRFC822, hdrBytes)

	// Sign canonical(header) || payload (spec §5.4).
	sig := ed25519.Sign(p.Sender.SignPriv, append(append([]byte{}, hdrBytes...), payload...))

	return &Envelope{Header: hdr, Payload: payload, Signature: sig}, nil
}

// OpenParams are the inputs to Open.
type OpenParams struct {
	// Receiver is this node's identity (holds the X25519 private key).
	Receiver *Identity
	// AuthorizedDomain reports whether this receiver is authoritative for a
	// recipient domain (spec §8 check 3).
	AuthorizedDomain func(domain string) bool
	// PinnedSenderKey returns the pinned Ed25519 identity key for the claimed
	// sender domain (spec §8 check 2), or ok=false if the domain is unknown.
	PinnedSenderKey func(domain string) (ed25519.PublicKey, bool)
}

// Open verifies and decrypts an envelope, performing all spec §8 receiver-side
// abuse-prevention checks plus §7 replay protection (the latter via the
// supplied ReplayGuard). On success it returns the recovered raw RFC 822
// message. Any failure returns a sentinel error and no plaintext.
func Open(env *Envelope, p OpenParams, guard *ReplayGuard) ([]byte, error) {
	h := env.Header

	// §9 / §3: only known proto+suite.
	if h.Proto != ProtoV1 || h.Suite != SuiteV1 {
		return nil, ErrUnsupported
	}
	if len(h.SenderIdentityPub) != ed25519PubLen || len(h.ReceiverKexPub) != x25519PubLen ||
		len(h.EphemeralPub) != x25519PubLen || len(h.Nonce) != nonceLen ||
		len(env.Signature) != sigLen {
		return nil, ErrCorrupt
	}

	hdrBytes := marshalHeader(h)

	// §8.1 sender authentication: signature over canonical(header) || payload.
	signed := append(append([]byte{}, hdrBytes...), env.Payload...)
	if !ed25519.Verify(h.SenderIdentityPub, signed, env.Signature) {
		return nil, ErrUnauthenticated
	}

	// §8.2 sender-domain authority: signing key must be the pinned key for the
	// claimed origin domain, and MAIL FROM domain must equal SenderDomain.
	pinned, ok := p.PinnedSenderKey(h.SenderDomain)
	if !ok || !bytesEqual(pinned, h.SenderIdentityPub) {
		return nil, ErrUnauthorized
	}
	if DomainOf(h.MailFrom) != normalize(h.SenderDomain) {
		return nil, ErrUnauthorized
	}

	// §8.3 receiver targeting: key must be ours, every recipient domain ours.
	if !bytesEqual(h.ReceiverKexPub, p.Receiver.KexPub) {
		return nil, ErrMisrouted
	}
	if len(h.RcptTo) == 0 {
		return nil, ErrMisrouted
	}
	for _, rcpt := range h.RcptTo {
		if !p.AuthorizedDomain(DomainOf(rcpt)) {
			return nil, ErrMisrouted
		}
	}

	// §7 replay window (timestamp + nonce dedup), keyed by sender identity.
	if guard != nil {
		if err := guard.Check(h.SenderIdentityPub, h.Nonce, time.Unix(h.Timestamp, 0)); err != nil {
			return nil, err
		}
	}

	// §8.5 decryption integrity. Recompute ss from our static key + ephemeral.
	ephPub, err := ecdh.X25519().NewPublicKey(h.EphemeralPub)
	if err != nil {
		return nil, ErrCorrupt
	}
	ss, err := p.Receiver.KexPriv.ECDH(ephPub)
	if err != nil {
		return nil, ErrCorrupt
	}
	key := deriveKey(ss, h.Nonce, h.SenderIdentityPub, h.ReceiverKexPub)
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, h.Nonce, env.Payload, hdrBytes)
	if err != nil {
		return nil, ErrCorrupt
	}
	return plain, nil
}

// deriveKey computes the 32-byte AEAD key via HKDF-SHA-256 (spec §5.2).
func deriveKey(ss, nonce, senderID, recvKex []byte) []byte {
	info := append([]byte(ProtoV1+" "+SuiteV1), senderID...)
	info = append(info, recvKex...)
	return hkdfSHA256(ss, nonce, info, 32)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("peering: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("peering: gcm: %w", err)
	}
	return aead, nil
}

// hkdfSHA256 is a minimal HKDF-SHA-256 (RFC 5869) using only crypto/hmac +
// crypto/sha256 — no external dependency.
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	// Extract.
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)

	// Expand.
	var out, t []byte
	for i := byte(1); len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// --- canonical serialization (spec §6) ---

// marshalHeader renders the header in its single canonical encoding.
func marshalHeader(h Header) []byte {
	var b []byte
	b = putStr(b, h.Proto)
	b = putStr(b, h.Suite)
	b = putStr(b, h.SenderDomain)
	b = putBytes(b, h.SenderIdentityPub)
	b = putBytes(b, h.ReceiverKexPub)
	b = putBytes(b, h.EphemeralPub)
	b = putBytes(b, h.Nonce)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(h.Timestamp))
	b = append(b, ts[:]...)
	b = putStr(b, h.MailFrom)
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(h.RcptTo)))
	b = append(b, cnt[:]...)
	for _, r := range h.RcptTo {
		b = putStr(b, r)
	}
	return b
}

func putStr(b []byte, s string) []byte { return putBytes(b, []byte(s)) }
func putBytes(b []byte, p []byte) []byte {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(p)))
	b = append(b, l[:]...)
	return append(b, p...)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func normalize(s string) string { return DomainOf("x@" + s) }
