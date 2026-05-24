// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// newTestSigner builds a DKIMSigner backed by a freshly-rotated 1024-bit key
// (small for test speed) and returns the signer plus the public key for
// verification.
func newTestSigner(t *testing.T, domain string) (*DKIMSigner, *rsa.PublicKey, DKIMKey) {
	t.Helper()
	store := NewMemKeyStore()
	rotator, err := NewDKIMRotator(domain, store, DKIMRotatorConfig{KeyBits: 1024, PropagationGrace: 0})
	if err != nil {
		t.Fatalf("NewDKIMRotator: %v", err)
	}
	key, err := rotator.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	signer, err := NewDKIMSigner(DKIMSignerConfig{Domain: domain, Provider: rotator})
	if err != nil {
		t.Fatalf("NewDKIMSigner: %v", err)
	}
	pub := pubKeyFromDNS(t, key.PublicKeyDNS)
	return signer, pub, key
}

// pubKeyFromDNS decodes the base64 SubjectPublicKeyInfo from a DKIM DNS record.
func pubKeyFromDNS(t *testing.T, b64 string) *rsa.PublicKey {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode pub DNS: %v", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("not RSA public key")
	}
	return pub
}

// parseDKIMTags parses a DKIM-Signature header value into its tag map.
func parseDKIMTags(value string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(part[:eq])
		v := strings.TrimSpace(part[eq+1:])
		tags[k] = v
	}
	return tags
}

// extractDKIMHeader returns the DKIM-Signature header value and the rest of the
// message (header block + body) with the DKIM-Signature header removed.
func extractDKIMHeader(t *testing.T, signed []byte) (value string, original []byte) {
	t.Helper()
	const prefix = "DKIM-Signature: "
	s := string(signed)
	if !strings.HasPrefix(s, prefix) {
		t.Fatalf("signed message does not start with DKIM-Signature header; got:\n%q", s[:min(120, len(s))])
	}
	end := strings.Index(s, "\r\n")
	if end < 0 {
		t.Fatal("no CRLF after DKIM-Signature header")
	}
	value = strings.TrimPrefix(s[:end], prefix)
	original = signed[end+2:]
	return value, original
}

// verifyDKIM re-derives the signed data per RFC 6376 relaxed/relaxed and checks
// the body hash + RSA signature against pub. It returns nil on success.
func verifyDKIM(value string, original []byte, pub *rsa.PublicKey) error {
	tags := parseDKIMTags(value)

	// 1. Verify the body hash.
	_, body := splitMessage(original)
	canonBody := canonicalizeBodyRelaxed(body)
	gotBH := sha256.Sum256(canonBody)
	wantBH, err := base64.StdEncoding.DecodeString(tags["bh"])
	if err != nil {
		return errf("decode bh: %v", err)
	}
	if !bytes.Equal(gotBH[:], wantBH) {
		return errf("body hash mismatch")
	}

	// 2. Reconstruct the signed header set in h= order.
	headerBlock, _ := splitMessage(original)
	headers := parseHeaders(headerBlock)
	var toSign bytes.Buffer
	for _, name := range strings.Split(tags["h"], ":") {
		name = strings.TrimSpace(name)
		// Find last matching header.
		for i := len(headers) - 1; i >= 0; i-- {
			if headers[i].name == "" {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(headers[i].name), name) {
				toSign.WriteString(canonicalizeHeaderRelaxed(headers[i].name, headers[i].value))
				headers[i].name = ""
				break
			}
		}
	}

	// 3. Append the DKIM-Signature header with b= emptied, relaxed, no trailing CRLF.
	bIdx := strings.Index(value, " b=")
	if bIdx < 0 {
		bIdx = strings.Index(value, "b=")
	}
	emptied := value[:bIdx] + " b="
	if !strings.HasPrefix(value[bIdx:], " b=") {
		emptied = value[:bIdx] + "b="
	}
	dkimHeader := canonicalizeHeaderRelaxed("DKIM-Signature", emptied)
	dkimHeader = strings.TrimSuffix(dkimHeader, "\r\n")
	toSign.WriteString(dkimHeader)

	// 4. Verify the RSA signature.
	sig, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil {
		return errf("decode b: %v", err)
	}
	hashed := sha256.Sum256(toSign.Bytes())
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig); err != nil {
		return errf("RSA verify: %v", err)
	}
	return nil
}

func errf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

// TestDKIMSignerHeaderPresentAndVerifiable proves the audit P0 fix: outbound
// mail carries a DKIM-Signature header that verifies against the rotator's
// public key.
func TestDKIMSignerHeaderPresentAndVerifiable(t *testing.T) {
	signer, pub, key := newTestSigner(t, "example.com")

	raw := []byte("From: alice@example.com\r\n" +
		"To: bob@example.org\r\n" +
		"Subject: Hello\r\n" +
		"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
		"Message-ID: <abc@example.com>\r\n" +
		"\r\n" +
		"This is the body.\r\nLine two.\r\n")

	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	value, original := extractDKIMHeader(t, signed)

	tags := parseDKIMTags(value)
	if tags["v"] != "1" {
		t.Errorf("v tag = %q, want 1", tags["v"])
	}
	if tags["a"] != "rsa-sha256" {
		t.Errorf("a tag = %q, want rsa-sha256", tags["a"])
	}
	if tags["d"] != "example.com" {
		t.Errorf("d tag = %q, want example.com", tags["d"])
	}
	if tags["s"] != key.Selector {
		t.Errorf("s tag = %q, want %q", tags["s"], key.Selector)
	}
	if !strings.Contains(tags["h"], "from") {
		t.Errorf("h tag = %q, must include from", tags["h"])
	}
	if tags["b"] == "" || tags["bh"] == "" {
		t.Errorf("b/bh tags must be present: b=%q bh=%q", tags["b"], tags["bh"])
	}

	// The original message must be unmodified after the header.
	if !bytes.Equal(original, raw) {
		t.Errorf("signer must not mutate the original message body")
	}

	if err := verifyDKIM(value, original, pub); err != nil {
		t.Fatalf("DKIM signature did not verify: %v", err)
	}
}

// TestDKIMSignerNoKey verifies that Sign returns ErrNoSigningKey when the
// provider has no key (so callers can choose how to handle it rather than
// emitting an invalid signature).
func TestDKIMSignerNoKey(t *testing.T) {
	store := NewMemKeyStore()
	rotator, err := NewDKIMRotator("example.com", store, DKIMRotatorConfig{KeyBits: 1024})
	if err != nil {
		t.Fatalf("NewDKIMRotator: %v", err)
	}
	signer, err := NewDKIMSigner(DKIMSignerConfig{Domain: "example.com", Provider: rotator})
	if err != nil {
		t.Fatalf("NewDKIMSigner: %v", err)
	}
	if _, err := signer.Sign([]byte("From: a@example.com\r\n\r\nbody\r\n")); err != ErrNoSigningKey {
		t.Fatalf("want ErrNoSigningKey, got %v", err)
	}
}

// TestDKIMSignerTamperDetected verifies that altering the body after signing
// causes verification to fail (the signature actually binds the content).
func TestDKIMSignerTamperDetected(t *testing.T) {
	signer, pub, _ := newTestSigner(t, "example.com")
	raw := []byte("From: a@example.com\r\nSubject: x\r\n\r\noriginal body\r\n")
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	value, original := extractDKIMHeader(t, signed)

	// Tamper with the body.
	tampered := bytes.Replace(original, []byte("original body"), []byte("tampered body!"), 1)
	if err := verifyDKIM(value, tampered, pub); err == nil {
		t.Fatal("expected verification to FAIL on tampered body, but it passed")
	}
}
