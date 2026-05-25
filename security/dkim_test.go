// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

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

	"github.com/vul-os/vulos-relay/internal/sending"
)

// ─── Attack class 8: DKIM signing integrity ──────────────────────────────────
//
// Outbound mail must carry a DKIM-Signature that a receiver can verify against
// the published public key (so receivers can authenticate us and we build a
// reputation). The security property: the signature binds the body — tampering
// with the message after signing MUST break verification. These tests do a full
// sign→verify roundtrip against the rotator's real published key, then mount
// body/header tamper attacks and prove verification fails.
//
// The verifier here is an INDEPENDENT, self-contained relaxed/relaxed RSA-SHA256
// implementation (not the signer's own helpers), so a passing roundtrip proves
// real interoperable DKIM, not a signer-marks-its-own-homework artefact.

func newPublishedSigner(t *testing.T, domain string) (*sending.DKIMSigner, *rsa.PublicKey) {
	t.Helper()
	store := sending.NewMemKeyStore()
	rotator, err := sending.NewDKIMRotator(domain, store, sending.DKIMRotatorConfig{KeyBits: 1024, PropagationGrace: 0})
	if err != nil {
		t.Fatalf("rotator: %v", err)
	}
	key, err := rotator.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	signer, err := sending.NewDKIMSigner(sending.DKIMSignerConfig{Domain: domain, Provider: rotator})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	// Recover the public key exactly as a receiver would from the DNS TXT record.
	der, err := base64.StdEncoding.DecodeString(key.PublicKeyDNS)
	if err != nil {
		t.Fatalf("decode pub DNS: %v", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		t.Fatal("published key is not RSA")
	}
	return signer, pub
}

// ATTACK/PROOF: a freshly signed message verifies against the published key.
func TestDKIM_SignVerifyRoundtrip(t *testing.T) {
	signer, pub := newPublishedSigner(t, "tenant.example")
	raw := []byte("From: alice@tenant.example\r\n" +
		"To: bob@elsewhere.example\r\n" +
		"Subject: Roundtrip\r\n" +
		"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
		"Message-ID: <r1@tenant.example>\r\n" +
		"\r\n" +
		"verifiable body\r\nsecond line\r\n")
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	value, original := splitSignedDKIM(t, signed)
	if err := verifyDKIMIndependent(value, original, pub); err != nil {
		t.Fatalf("VULN: legitimately-signed message failed independent DKIM verification: %v", err)
	}
}

// ATTACK: a network/relay attacker tampers with the BODY after signing.
// EXPECT: verification fails (the signature binds the body hash).
func TestDKIM_TamperedBody_FailsVerification(t *testing.T) {
	signer, pub := newPublishedSigner(t, "tenant.example")
	raw := []byte("From: alice@tenant.example\r\nSubject: x\r\n\r\nlegit transfer $10\r\n")
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	value, original := splitSignedDKIM(t, signed)

	tampered := bytes.Replace(original, []byte("$10"), []byte("$10000"), 1)
	if err := verifyDKIMIndependent(value, tampered, pub); err == nil {
		t.Fatal("VULN: DKIM verified a body that was tampered after signing")
	}
}

// ATTACK: tamper a SIGNED header (Subject is in the default h= set). EXPECT:
// verification fails.
func TestDKIM_TamperedSignedHeader_FailsVerification(t *testing.T) {
	signer, pub := newPublishedSigner(t, "tenant.example")
	raw := []byte("From: alice@tenant.example\r\nSubject: Invoice\r\n\r\nbody\r\n")
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	value, original := splitSignedDKIM(t, signed)

	tampered := bytes.Replace(original, []byte("Subject: Invoice"), []byte("Subject: URGENT"), 1)
	if err := verifyDKIMIndependent(value, tampered, pub); err == nil {
		t.Fatal("VULN: DKIM verified after a signed header (Subject) was altered")
	}
}

// ATTACK: substitute a DIFFERENT signing key's signature (forge as us). EXPECT:
// verification against OUR published key fails.
func TestDKIM_WrongKeySignature_FailsVerification(t *testing.T) {
	signer, _ := newPublishedSigner(t, "tenant.example")
	_, attackerPub := newPublishedSigner(t, "tenant.example") // different keypair

	raw := []byte("From: alice@tenant.example\r\nSubject: x\r\n\r\nbody\r\n")
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	value, original := splitSignedDKIM(t, signed)

	// Verifying our real signature against an unrelated public key must fail.
	if err := verifyDKIMIndependent(value, original, attackerPub); err == nil {
		t.Fatal("VULN: a signature verified against an unrelated public key")
	}
}

// ─── independent DKIM verifier (relaxed/relaxed, rsa-sha256) ──────────────────

// splitSignedDKIM separates the prepended DKIM-Signature header value from the
// rest of the message (the original, signer must prepend and not mutate).
func splitSignedDKIM(t *testing.T, signed []byte) (value string, original []byte) {
	t.Helper()
	const prefix = "DKIM-Signature: "
	s := string(signed)
	if !strings.HasPrefix(s, prefix) {
		t.Fatalf("signed message lacks a leading DKIM-Signature header")
	}
	end := strings.Index(s, "\r\n")
	if end < 0 {
		t.Fatal("no CRLF after DKIM-Signature header")
	}
	return strings.TrimPrefix(s[:end], prefix), signed[end+2:]
}

func dkimTagMap(value string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if eq := strings.IndexByte(part, '='); eq > 0 {
			m[strings.TrimSpace(part[:eq])] = strings.TrimSpace(part[eq+1:])
		}
	}
	return m
}

func verifyDKIMIndependent(value string, original []byte, pub *rsa.PublicKey) error {
	tags := dkimTagMap(value)

	// 1. Body hash (relaxed body canonicalization).
	_, body := splitMsg(original)
	gotBH := sha256.Sum256(canonBodyRelaxed(body))
	wantBH, err := base64.StdEncoding.DecodeString(tags["bh"])
	if err != nil {
		return errf("decode bh: %v", err)
	}
	if !bytes.Equal(gotBH[:], wantBH) {
		return errf("body hash mismatch")
	}

	// 2. Reconstruct signed headers in h= order (relaxed header canonicalization).
	headerBlock, _ := splitMsg(original)
	headers := parseHdrs(headerBlock)
	var toSign bytes.Buffer
	for _, name := range strings.Split(tags["h"], ":") {
		name = strings.TrimSpace(name)
		for i := len(headers) - 1; i >= 0; i-- {
			if headers[i].name == "" {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(headers[i].name), name) {
				toSign.WriteString(canonHdrRelaxed(headers[i].name, headers[i].value))
				headers[i].name = ""
				break
			}
		}
	}

	// 3. Append the DKIM-Signature header with b= emptied, relaxed, no trailing CRLF.
	bIdx := strings.Index(value, " b=")
	emptied := value[:bIdx] + " b="
	if bIdx < 0 {
		bIdx = strings.Index(value, "b=")
		emptied = value[:bIdx] + "b="
	}
	toSign.WriteString(strings.TrimSuffix(canonHdrRelaxed("DKIM-Signature", emptied), "\r\n"))

	// 4. RSA verify.
	sig, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil {
		return errf("decode b: %v", err)
	}
	hashed := sha256.Sum256(toSign.Bytes())
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig)
}

type hdrField struct{ name, value string }

func splitMsg(raw []byte) (header, body []byte) {
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[:idx], raw[idx+4:]
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[:idx], raw[idx+2:]
	}
	return raw, nil
}

func parseHdrs(block []byte) []hdrField {
	text := strings.ReplaceAll(string(block), "\r\n", "\n")
	var out []hdrField
	var cur *hdrField
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if cur != nil {
				cur.value += "\n" + line
			}
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		out = append(out, hdrField{name: line[:colon], value: line[colon+1:]})
		cur = &out[len(out)-1]
	}
	return out
}

func canonHdrRelaxed(name, value string) string {
	return strings.ToLower(strings.TrimSpace(name)) + ":" + strings.TrimSpace(collapseWSP(value)) + "\r\n"
}

func collapseWSP(s string) string {
	var sb strings.Builder
	inWSP := false
	for _, r := range s {
		switch r {
		case ' ', '\t', '\r', '\n':
			inWSP = true
		default:
			if inWSP {
				sb.WriteByte(' ')
				inWSP = false
			}
			sb.WriteRune(r)
		}
	}
	if inWSP {
		sb.WriteByte(' ')
	}
	return sb.String()
}

func canonBodyRelaxed(body []byte) []byte {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	canon := make([]string, 0, len(lines))
	for _, line := range lines {
		var sb strings.Builder
		inWSP := false
		for _, r := range line {
			if r == ' ' || r == '\t' {
				inWSP = true
				continue
			}
			if inWSP {
				sb.WriteByte(' ')
				inWSP = false
			}
			sb.WriteRune(r)
		}
		canon = append(canon, sb.String())
	}
	for len(canon) > 0 && canon[len(canon)-1] == "" {
		canon = canon[:len(canon)-1]
	}
	if len(canon) == 0 {
		return []byte("\r\n")
	}
	var out bytes.Buffer
	for _, line := range canon {
		out.WriteString(line)
		out.WriteString("\r\n")
	}
	return out.Bytes()
}

func errf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
