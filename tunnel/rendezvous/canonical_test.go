package rendezvous

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// canonical_test.go — pins the canonical signing-message encoding with a fixed
// vector. The IDENTICAL vector is asserted in the JS reference client
// (client/src/__tests__/rendezvous.test.js), so this constant is the cross-language
// interop contract: if either implementation's canonicalMessage diverges by a
// single byte, one of the two tests fails.
//
// If you ever intentionally change the wire encoding, regenerate BOTH constants
// together and bump the domain-tag version.

const canonicalVectorHex = "0000001476756c6f732d7264762f616e6e6f756e63652f31" +
	"00000004414141410000000a313730303030303030300000000333303000000008" +
	"6e6f6e6365313233000000066d6574612d78000000077773733a2f2f6100000009" +
	"68747470733a2f2f62"

func TestCanonicalVector(t *testing.T) {
	m := canonicalMessage("vulos-rdv/announce/1", "AAAA", "1700000000", "300", "nonce123", "meta-x", "wss://a", "https://b")
	got := hex.EncodeToString(m)
	if got != canonicalVectorHex {
		t.Fatalf("canonical vector drift:\n got=%s\nwant=%s", got, canonicalVectorHex)
	}
}

// TestSignVerifyRoundTrip confirms the verify path accepts a signature produced
// over the canonical message and rejects a tamper.
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg := canonicalMessage("vulos-rdv/announce/1", "x", "1", "0", "n", "")
	sig := b64.EncodeToString(ed25519.Sign(priv, msg))
	if err := verifySig(pub, sig, msg); err != nil {
		t.Fatalf("valid sig rejected: %v", err)
	}
	// Tamper one canonical field.
	bad := canonicalMessage("vulos-rdv/announce/1", "x", "2", "0", "n", "")
	if err := verifySig(pub, sig, bad); err == nil {
		t.Fatal("tampered message accepted")
	}
}

func TestDecodeKeyRejectsWrongLength(t *testing.T) {
	if _, err := decodeKey(b64.EncodeToString([]byte("too-short"))); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := decodeKey("!!!not-base64!!!"); err == nil {
		t.Fatal("non-base64 key accepted")
	}
}
