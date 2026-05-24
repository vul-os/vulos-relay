// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrNoSigningKey is returned by a DKIMSigner when no signing key is available
// (e.g. the rotator has not yet generated a key).
var ErrNoSigningKey = errors.New("dkim: no signing key available")

// KeyProvider supplies the current DKIM signing key for a domain.  *DKIMRotator
// satisfies this interface via its CurrentKey method, so the rotator can be
// wired directly into a DKIMSigner.
type KeyProvider interface {
	// CurrentKey returns the key that outbound mail should currently be signed
	// with.  It returns ErrKeyNotFound when no key exists.
	CurrentKey() (DKIMKey, error)
}

// DKIMSignerConfig configures a DKIMSigner.
type DKIMSignerConfig struct {
	// Domain is the signing domain (the d= tag).  Required.
	Domain string

	// Provider supplies the current signing key.  Required.  Usually a
	// *DKIMRotator.
	Provider KeyProvider

	// HeadersToSign is the ordered list of header field names included in the
	// signature (the h= tag).  If empty, a sensible default set is used.
	HeadersToSign []string

	// Now overrides the clock (tests only).
	Now func() time.Time
}

// defaultSignedHeaders is the default set of headers covered by the DKIM
// signature.  From is mandatory per RFC 6376 §5.4.
var defaultSignedHeaders = []string{
	"From", "To", "Cc", "Subject", "Date", "Message-ID",
	"MIME-Version", "Content-Type", "Reply-To",
}

// DKIMSigner produces RFC 6376 DKIM-Signature headers using relaxed/relaxed
// canonicalization and rsa-sha256.  It is safe for concurrent use (the
// underlying KeyProvider must be concurrency-safe; *DKIMRotator is).
type DKIMSigner struct {
	cfg DKIMSignerConfig
}

// NewDKIMSigner constructs a DKIMSigner.  It returns an error if Domain or
// Provider are unset.
func NewDKIMSigner(cfg DKIMSignerConfig) (*DKIMSigner, error) {
	if cfg.Domain == "" {
		return nil, errors.New("dkim: signer requires a Domain")
	}
	if cfg.Provider == nil {
		return nil, errors.New("dkim: signer requires a KeyProvider")
	}
	if len(cfg.HeadersToSign) == 0 {
		cfg.HeadersToSign = defaultSignedHeaders
	}
	return &DKIMSigner{cfg: cfg}, nil
}

func (s *DKIMSigner) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

// Sign returns a copy of raw with a DKIM-Signature header prepended.  The
// original message bytes are not mutated.  If no signing key is available it
// returns ErrNoSigningKey; callers may choose to send unsigned in that case
// (logging a warning) or to defer.
func (s *DKIMSigner) Sign(raw []byte) ([]byte, error) {
	key, err := s.cfg.Provider.CurrentKey()
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, ErrNoSigningKey
		}
		return nil, fmt.Errorf("dkim: load signing key: %w", err)
	}

	priv, err := parseRSAPrivateKey(key.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("dkim: parse signing key: %w", err)
	}

	headerBlock, body := splitMessage(raw)
	headers := parseHeaders(headerBlock)

	// Body hash (bh=): relaxed body canonicalization, SHA-256.
	canonBody := canonicalizeBodyRelaxed(body)
	bodyHash := sha256.Sum256(canonBody)
	bh := base64.StdEncoding.EncodeToString(bodyHash[:])

	// Determine which configured headers are actually present, preserving the
	// configured order; the h= tag must list exactly what we sign.
	signedHeaderNames, signedHeaderLines := selectHeaders(headers, s.cfg.HeadersToSign)

	t := s.now().UTC().Unix()

	// Build the DKIM-Signature header value with an empty b= tag for signing.
	dkimValue := buildDKIMValue(dkimTags{
		domain:    s.cfg.Domain,
		selector:  key.Selector,
		headers:   signedHeaderNames,
		bodyHash:  bh,
		timestamp: t,
	})

	// The DKIM-Signature header itself is included in the hash with its b= value
	// empty (RFC 6376 §3.7).  Canonicalize it relaxed, with no trailing CRLF.
	dkimHeaderForSig := canonicalizeHeaderRelaxed("DKIM-Signature", dkimValue)
	dkimHeaderForSig = strings.TrimSuffix(dkimHeaderForSig, "\r\n")

	// Assemble the data-to-sign: signed headers (relaxed) in h= order, then the
	// DKIM-Signature header (relaxed, b= empty, no trailing CRLF).
	var toSign bytes.Buffer
	for _, line := range signedHeaderLines {
		toSign.WriteString(line)
	}
	toSign.WriteString(dkimHeaderForSig)

	hashed := sha256.Sum256(toSign.Bytes())
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("dkim: sign: %w", err)
	}
	b := base64.StdEncoding.EncodeToString(sig)

	// Final header value carries the b= signature.
	finalValue := dkimValue + b
	finalHeader := "DKIM-Signature: " + finalValue + "\r\n"

	// Prepend the DKIM-Signature header to the original (unmodified) message.
	out := make([]byte, 0, len(finalHeader)+len(raw))
	out = append(out, []byte(finalHeader)...)
	out = append(out, raw...)
	return out, nil
}

// dkimTags carries the values used to assemble the DKIM-Signature header.
type dkimTags struct {
	domain    string
	selector  string
	headers   []string
	bodyHash  string
	timestamp int64
}

// buildDKIMValue assembles the DKIM-Signature header value up to (but not
// including) the b= signature value.  The returned string ends with "b=" so the
// signature can be appended directly.
func buildDKIMValue(t dkimTags) string {
	var sb strings.Builder
	sb.WriteString("v=1; a=rsa-sha256; c=relaxed/relaxed;")
	sb.WriteString(" d=")
	sb.WriteString(t.domain)
	sb.WriteString("; s=")
	sb.WriteString(t.selector)
	sb.WriteString(";")
	sb.WriteString(fmt.Sprintf(" t=%d;", t.timestamp))
	sb.WriteString(" h=")
	sb.WriteString(strings.Join(t.headers, ":"))
	sb.WriteString(";")
	sb.WriteString(" bh=")
	sb.WriteString(t.bodyHash)
	sb.WriteString(";")
	sb.WriteString(" b=")
	return sb.String()
}

// splitMessage splits raw into the header block (without the blank-line
// separator) and the body.  It tolerates both CRLF and LF line endings on
// input.
func splitMessage(raw []byte) (header, body []byte) {
	// Find the header/body separator: CRLFCRLF or LFLF.
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[:idx], raw[idx+4:]
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[:idx], raw[idx+2:]
	}
	// No body.
	return raw, nil
}

// parsedHeader is one unfolded header field.
type parsedHeader struct {
	name  string // original-case field name
	value string // field value with folding preserved (may contain CRLF)
}

// parseHeaders parses a header block into ordered fields, handling continuation
// (folded) lines.  Input may use CRLF or LF; output values retain their raw
// inter-line content for canonicalization.
func parseHeaders(block []byte) []parsedHeader {
	// Normalize to LF for splitting, but reconstruct CRLF awareness is not
	// needed because relaxed canonicalization unfolds whitespace anyway.
	text := strings.ReplaceAll(string(block), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	var headers []parsedHeader
	var cur *parsedHeader
	for _, line := range lines {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Continuation of the previous header.
			if cur != nil {
				cur.value += "\n" + line
			}
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		headers = append(headers, parsedHeader{
			name:  line[:colon],
			value: line[colon+1:],
		})
		cur = &headers[len(headers)-1]
	}
	return headers
}

// selectHeaders returns the lower-cased h= list and the relaxed-canonicalized
// header lines (in h= order) for the configured names that are present.  When a
// header name appears multiple times, the last instance is signed and removed
// from the pool so a second occurrence in h= would bind the earlier one
// (RFC 6376 §5.4 / §3.5 h= semantics).
func selectHeaders(headers []parsedHeader, want []string) (names []string, lines []string) {
	// Track remaining instances per lower-cased name; consume from the end.
	for _, w := range want {
		lw := strings.ToLower(strings.TrimSpace(w))
		// Find the last not-yet-consumed header with this name.
		idx := -1
		for i := len(headers) - 1; i >= 0; i-- {
			if headers[i].name == "" {
				continue
			}
			if strings.ToLower(strings.TrimSpace(headers[i].name)) == lw {
				idx = i
				break
			}
		}
		if idx < 0 {
			continue // header not present; skip it
		}
		names = append(names, lw)
		lines = append(lines, canonicalizeHeaderRelaxed(headers[idx].name, headers[idx].value))
		// Consume this instance so a duplicate name signs the next-earlier one.
		headers[idx].name = ""
	}
	return names, lines
}

// canonicalizeHeaderRelaxed applies RFC 6376 §3.4.2 relaxed header
// canonicalization to a single header field and returns the line terminated
// with CRLF.
func canonicalizeHeaderRelaxed(name, value string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	// Unfold: replace CRLF/LF + WSP runs, collapse all WSP runs to a single SP.
	v := unfoldAndCollapseWSP(value)
	v = strings.TrimSpace(v)
	return n + ":" + v + "\r\n"
}

// unfoldAndCollapseWSP unfolds continuation lines and collapses every run of
// whitespace (including the CRLF that precedes folded lines) into a single
// space, per relaxed canonicalization.
func unfoldAndCollapseWSP(s string) string {
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
		// Trailing whitespace collapses to one space; TrimSpace by caller removes it.
		sb.WriteByte(' ')
	}
	return sb.String()
}

// canonicalizeBodyRelaxed applies RFC 6376 §3.4.4 relaxed body canonicalization:
//   - reduce WSP runs within a line to a single SP
//   - strip trailing WSP on each line
//   - normalize line endings to CRLF
//   - remove trailing empty lines
//   - ensure the body ends with a single CRLF (an empty body becomes a single CRLF)
func canonicalizeBodyRelaxed(body []byte) []byte {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	canon := make([]string, 0, len(lines))
	for _, line := range lines {
		// Collapse internal WSP runs to one space.
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
		// Trailing WSP stripped by not flushing a pending inWSP.
		canon = append(canon, sb.String())
	}

	// Remove trailing empty lines.
	for len(canon) > 0 && canon[len(canon)-1] == "" {
		canon = canon[:len(canon)-1]
	}

	if len(canon) == 0 {
		// Empty body → single CRLF per RFC 6376 §3.4.3/§3.4.4.
		return []byte("\r\n")
	}

	var out bytes.Buffer
	for _, line := range canon {
		out.WriteString(line)
		out.WriteString("\r\n")
	}
	return out.Bytes()
}

// parseRSAPrivateKey parses a PKCS#1 (or PKCS#8) RSA private key from PEM.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rsaKey, nil
}

// sortedTagKeys is a small helper used by tests/diagnostics to enumerate the
// tags of a DKIM-Signature value deterministically.
func sortedTagKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var _ = sortedTagKeys
