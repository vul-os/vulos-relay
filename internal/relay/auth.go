// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Open-relay prevention gate (RELAY-16).
//
// The relay MUST NEVER forward mail for an unauthenticated or unknown sender
// (TASKS.md frozen invariant). This file implements the SubmitAuthenticator
// interface and its two reference implementations, and defines Credentials and
// the sentinel errors used throughout the submission path.
package relay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ─── Sentinel errors ──────────────────────────────────────────────────────────

// ErrUnauthenticated is returned when the supplied credentials do not match
// any known account or fail the cryptographic check.  The relay MUST refuse
// the submission and return this error to the caller.
var ErrUnauthenticated = errors.New("relay: unauthenticated submission refused")

// ErrReplayDetected is returned when a SharedSecretAuth credential is
// replayed (the nonce/ID+timestamp was already seen within the replay window).
var ErrReplayDetected = errors.New("relay: credential replay detected")

// ErrCredentialExpired is returned when the credential timestamp is outside
// the accepted window (too old or too far in the future).
var ErrCredentialExpired = errors.New("relay: credential expired or clock skew too large")

// ErrInvalidSignature is returned when the HMAC or TLS signature does not
// verify, regardless of whether the account exists.
var ErrInvalidSignature = errors.New("relay: invalid credential signature")

// ─── Credentials ──────────────────────────────────────────────────────────────

// Credentials carries one set of submission credentials.  Exactly one of
// HMACToken or TLSState should be non-nil; mixed auth is not supported.
type Credentials struct {
	// HMACToken carries a shared-secret HMAC credential for HTTP/SMTP
	// submission over a secure channel.
	HMACToken *HMACToken

	// TLSState carries the TLS connection state for mutual-TLS submission.
	// The peer-certificate chain is used to identify the account.
	TLSState *tls.ConnectionState
}

// HMACToken is a time-bound HMAC-SHA256 credential.
//
// The HMAC is computed as:
//
//	HMAC-SHA256(key=account_secret, message=account_id + ":" + message_id + ":" + ts)
//
// where ts is the Unix timestamp in seconds (decimal string).  The relay
// verifies both the signature and that ts is within ±AllowedSkew of now.
type HMACToken struct {
	// AccountID is the account claiming this credential.
	AccountID string

	// MessageID is the queue/submission message ID bound to this credential.
	MessageID string

	// Timestamp is the Unix second at which the credential was minted.
	Timestamp int64

	// Signature is the lower-case hex-encoded HMAC-SHA256 digest.
	Signature string
}

// ─── SubmitAuthenticator interface ────────────────────────────────────────────

// SubmitAuthenticator is the open-relay prevention gate.  It MUST be the
// first call in the submission path — before reputation policy, routing, or
// sending.  Every message must be bound to a known, authenticated account;
// any failure MUST abort the submission.
//
// The gate is mandatory.  There is no configuration knob to disable it.
type SubmitAuthenticator interface {
	// Authenticate verifies creds and returns the canonical account_id that the
	// caller is allowed to submit as.
	//
	// Errors:
	//   ErrUnauthenticated  — account unknown or missing credentials
	//   ErrInvalidSignature — HMAC/cert mismatch
	//   ErrReplayDetected   — credential already used (replay)
	//   ErrCredentialExpired — timestamp outside the accepted window
	Authenticate(ctx context.Context, creds Credentials) (accountID string, err error)
}

// ─── AccountRegistry ──────────────────────────────────────────────────────────

// AccountRecord holds the per-account configuration needed by the
// authenticators.
type AccountRecord struct {
	// AccountID is the stable account identifier.
	AccountID string

	// SharedSecret is the raw HMAC key (arbitrary bytes).  Required for
	// SharedSecretAuth.
	SharedSecret []byte

	// AuthorizedDomains lists the sender domains this account may use.
	AuthorizedDomains []string

	// TLSSubjectCN is the expected TLS client-certificate SubjectCN for mTLS
	// auth.  Required for MutualTLSAuth.
	TLSSubjectCN string
}

// AccountRegistry maps account identifiers to their records.  Implementations
// must be safe for concurrent use.
type AccountRegistry interface {
	// Lookup returns the AccountRecord for id, or (nil, nil) if the account is
	// unknown.
	Lookup(ctx context.Context, id string) (*AccountRecord, error)

	// LookupByCN returns the AccountRecord whose TLSSubjectCN matches cn, or
	// (nil, nil) if no account has that CN.
	LookupByCN(ctx context.Context, cn string) (*AccountRecord, error)
}

// ─── MemAccountRegistry ───────────────────────────────────────────────────────

// MemAccountRegistry is an in-memory AccountRegistry for tests and standalone
// use.  Use NewMemAccountRegistry + Register to populate it.
type MemAccountRegistry struct {
	mu   sync.RWMutex
	byID map[string]*AccountRecord
	byCN map[string]*AccountRecord
}

// NewMemAccountRegistry creates an empty MemAccountRegistry.
func NewMemAccountRegistry() *MemAccountRegistry {
	return &MemAccountRegistry{
		byID: make(map[string]*AccountRecord),
		byCN: make(map[string]*AccountRecord),
	}
}

// Register adds or replaces an account record.
func (r *MemAccountRegistry) Register(rec AccountRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := rec // copy to avoid aliasing
	r.byID[rec.AccountID] = &cp
	if rec.TLSSubjectCN != "" {
		r.byCN[rec.TLSSubjectCN] = &cp
	}
}

// Lookup implements AccountRegistry.
func (r *MemAccountRegistry) Lookup(_ context.Context, id string) (*AccountRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return rec, nil
}

// LookupByCN implements AccountRegistry.
func (r *MemAccountRegistry) LookupByCN(_ context.Context, cn string) (*AccountRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.byCN[cn]
	if !ok {
		return nil, nil
	}
	return rec, nil
}

// ─── SharedSecretAuth ─────────────────────────────────────────────────────────

// SharedSecretAuth authenticates submissions using a per-account HMAC-SHA256
// token.  It provides replay protection via a time-bounded nonce cache keyed on
// (account_id, message_id).
//
// The HMAC cover is: HMAC-SHA256(key=account_secret, msg=account_id+":"+message_id+":"+ts)
type SharedSecretAuth struct {
	// Registry is the source of truth for account secrets.
	Registry AccountRegistry

	// AllowedSkew is the maximum clock skew accepted for token timestamps.
	// If zero, defaults to 5 minutes.
	AllowedSkew time.Duration

	// now is used by tests to override time.Now.
	now func() time.Time

	mu sync.Mutex
	// seen tracks (account_id + ":" + message_id + ":" + ts) nonces that have
	// been consumed within the replay window.
	seen map[string]time.Time
}

// NewSharedSecretAuth creates a SharedSecretAuth backed by registry.
func NewSharedSecretAuth(registry AccountRegistry) *SharedSecretAuth {
	return &SharedSecretAuth{
		Registry: registry,
		seen:     make(map[string]time.Time),
	}
}

// SetClock replaces the clock function used to determine "now".  It is
// intended for tests only; production code should leave the clock at the
// default (time.Now).
func (a *SharedSecretAuth) SetClock(fn func() time.Time) {
	a.now = fn
}

func (a *SharedSecretAuth) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a *SharedSecretAuth) skew() time.Duration {
	if a.AllowedSkew > 0 {
		return a.AllowedSkew
	}
	return 5 * time.Minute
}

// Authenticate implements SubmitAuthenticator.
func (a *SharedSecretAuth) Authenticate(ctx context.Context, creds Credentials) (string, error) {
	tok := creds.HMACToken
	if tok == nil {
		return "", fmt.Errorf("%w: no HMAC token provided", ErrUnauthenticated)
	}

	// 1. Look up the account.
	rec, err := a.Registry.Lookup(ctx, tok.AccountID)
	if err != nil {
		return "", fmt.Errorf("%w: registry error: %v", ErrUnauthenticated, err)
	}
	if rec == nil {
		// Unknown account — return a generic error to avoid oracle behavior.
		return "", fmt.Errorf("%w: account not found", ErrUnauthenticated)
	}

	// 2. Validate timestamp.
	now := a.clock()
	ts := time.Unix(tok.Timestamp, 0)
	delta := now.Sub(ts)
	if delta < 0 {
		delta = -delta
	}
	if delta > a.skew() {
		return "", fmt.Errorf("%w: token ts=%d now=%d delta=%s",
			ErrCredentialExpired, tok.Timestamp, now.Unix(), delta)
	}

	// 3. Verify HMAC.
	expected := computeHMAC(rec.SharedSecret, tok.AccountID, tok.MessageID, tok.Timestamp)
	sigBytes, hexErr := hex.DecodeString(tok.Signature)
	if hexErr != nil || !hmac.Equal(sigBytes, expected) {
		return "", fmt.Errorf("%w: account %q", ErrInvalidSignature, tok.AccountID)
	}

	// 4. Replay check.
	nonce := fmt.Sprintf("%s:%s:%d", tok.AccountID, tok.MessageID, tok.Timestamp)
	a.mu.Lock()
	a.evictExpiredLocked(now)
	if _, seen := a.seen[nonce]; seen {
		a.mu.Unlock()
		return "", fmt.Errorf("%w: nonce %q", ErrReplayDetected, nonce)
	}
	a.seen[nonce] = now.Add(a.skew() * 2) // expire nonce after 2× skew window
	a.mu.Unlock()

	return rec.AccountID, nil
}

// evictExpiredLocked removes nonces whose expiry has passed.  Must be called
// with a.mu held.
func (a *SharedSecretAuth) evictExpiredLocked(now time.Time) {
	for k, exp := range a.seen {
		if now.After(exp) {
			delete(a.seen, k)
		}
	}
}

// computeHMAC returns the raw HMAC-SHA256 digest for the given fields.
func computeHMAC(secret []byte, accountID, messageID string, ts int64) []byte {
	msg := fmt.Sprintf("%s:%s:%d", accountID, messageID, ts)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

// ComputeHMACToken is a helper for callers (e.g. test fixtures, SDK) to mint
// a valid HMACToken.  secret is the account's shared secret.
func ComputeHMACToken(secret []byte, accountID, messageID string, ts int64) HMACToken {
	raw := computeHMAC(secret, accountID, messageID, ts)
	return HMACToken{
		AccountID: accountID,
		MessageID: messageID,
		Timestamp: ts,
		Signature: hex.EncodeToString(raw),
	}
}

// ─── MutualTLSAuth ────────────────────────────────────────────────────────────

// MutualTLSAuth authenticates submissions via TLS client certificates.  The
// SubjectCN of the first peer certificate is used to look up the account.
// Account lookup is by TLSSubjectCN (see AccountRecord.TLSSubjectCN).
type MutualTLSAuth struct {
	// Registry is the source of truth for TLS-CN → account mappings.
	Registry AccountRegistry
}

// NewMutualTLSAuth creates a MutualTLSAuth backed by registry.
func NewMutualTLSAuth(registry AccountRegistry) *MutualTLSAuth {
	return &MutualTLSAuth{Registry: registry}
}

// Authenticate implements SubmitAuthenticator.
func (a *MutualTLSAuth) Authenticate(ctx context.Context, creds Credentials) (string, error) {
	if creds.TLSState == nil {
		return "", fmt.Errorf("%w: no TLS connection state provided", ErrUnauthenticated)
	}

	// Require at least one verified peer certificate.
	chains := creds.TLSState.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", fmt.Errorf("%w: no verified TLS client certificate", ErrUnauthenticated)
	}

	leaf := chains[0][0]
	cn := subjectCN(leaf)
	if cn == "" {
		return "", fmt.Errorf("%w: client certificate has no SubjectCN", ErrUnauthenticated)
	}

	rec, err := a.Registry.LookupByCN(ctx, cn)
	if err != nil {
		return "", fmt.Errorf("%w: registry error: %v", ErrUnauthenticated, err)
	}
	if rec == nil {
		return "", fmt.Errorf("%w: no account for TLS CN %q", ErrUnauthenticated, cn)
	}

	return rec.AccountID, nil
}

// subjectCN extracts the Common Name from an x509.Certificate's Subject.
func subjectCN(cert *x509.Certificate) string {
	return strings.TrimSpace(cert.Subject.CommonName)
}

// ─── ConstantTimeEqual helper ─────────────────────────────────────────────────

// safeEqual returns true only when a and b are identical, using a
// constant-time comparison to prevent timing oracles.
func safeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// keep safeEqual reachable from tests via the package; suppress unused warning.
var _ = safeEqual
