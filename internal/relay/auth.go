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

	// MaxNonces is a hard safety cap on the number of retained nonces.  When the
	// cache exceeds this size the oldest time-bucket is dropped early.  Zero
	// uses defaultMaxNonces.
	MaxNonces int

	mu sync.Mutex
	// seen indexes consumed nonces for fast membership test.  The value is the
	// expiry-bucket second the nonce lives in, so it can be removed from buckets
	// when evicted.
	seen map[string]int64
	// buckets groups nonces by their expiry second.  Eviction walks only the
	// buckets whose second has passed (amortized O(1) per call) instead of
	// scanning the entire nonce set on every authentication.
	buckets map[int64]map[string]struct{}
	// minBucket is the lowest bucket second present, so eviction starts there
	// rather than iterating all buckets.
	minBucket int64
}

// defaultMaxNonces bounds the replay cache so a flood of distinct nonces cannot
// grow memory without limit within the skew window.
const defaultMaxNonces = 1 << 20 // ~1M entries

// NewSharedSecretAuth creates a SharedSecretAuth backed by registry.
func NewSharedSecretAuth(registry AccountRegistry) *SharedSecretAuth {
	return &SharedSecretAuth{
		Registry: registry,
		seen:     make(map[string]int64),
		buckets:  make(map[int64]map[string]struct{}),
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
	// Expire the nonce after 2× the skew window (the widest interval over which
	// the same nonce could be re-presented and still pass the timestamp check).
	expiry := now.Add(a.skew() * 2).Unix()
	a.insertNonceLocked(nonce, expiry)
	a.mu.Unlock()

	return rec.AccountID, nil
}

func (a *SharedSecretAuth) maxNonces() int {
	if a.MaxNonces > 0 {
		return a.MaxNonces
	}
	return defaultMaxNonces
}

// insertNonceLocked records nonce in both the index and its expiry bucket.
// Must be called with a.mu held.
func (a *SharedSecretAuth) insertNonceLocked(nonce string, bucket int64) {
	a.seen[nonce] = bucket
	b := a.buckets[bucket]
	if b == nil {
		b = make(map[string]struct{})
		a.buckets[bucket] = b
		if a.minBucket == 0 || bucket < a.minBucket {
			a.minBucket = bucket
		}
	}
	b[nonce] = struct{}{}

	// Hard safety cap: if the cache is over-full, drop whole oldest buckets
	// until back under the limit.  This bounds memory even under a flood of
	// distinct nonces within the skew window.  Recompute minBucket after each
	// drop so we always target a live bucket and the loop makes progress.
	for len(a.seen) > a.maxNonces() && len(a.buckets) > 0 {
		a.recomputeMinBucketLocked()
		a.dropBucketLocked(a.minBucket)
	}
	if len(a.buckets) == 0 {
		a.minBucket = 0
	}
}

// evictExpiredLocked removes nonces whose expiry bucket has passed.  Because
// nonces are grouped by expiry second, eviction walks only the handful of
// elapsed bucket-seconds rather than scanning the entire nonce set — amortized
// O(1) per authentication.  Must be called with a.mu held.
func (a *SharedSecretAuth) evictExpiredLocked(now time.Time) {
	if len(a.buckets) == 0 {
		a.minBucket = 0
		return
	}
	cutoff := now.Unix()
	// Walk forward from the lowest known bucket second, dropping any bucket
	// whose second is at or before the cutoff.  Bucket seconds are sparse but
	// monotonically increasing, so advancing minBucket bounds future work.
	//
	// Cap the number of empty-second probes so a long idle gap cannot turn one
	// call into a multi-thousand-iteration scan: once we exceed maxProbe misses
	// we recompute the true minimum directly from the bucket map.
	const maxProbe = 8
	misses := 0
	for a.minBucket > 0 && a.minBucket <= cutoff {
		if _, ok := a.buckets[a.minBucket]; ok {
			a.dropBucketLocked(a.minBucket)
			misses = 0
		} else {
			misses++
		}
		a.minBucket++
		if len(a.buckets) == 0 {
			a.minBucket = 0
			return
		}
		if misses > maxProbe {
			a.recomputeMinBucketLocked()
			misses = 0
		}
	}
}

// recomputeMinBucketLocked finds the lowest live bucket second.  Used to skip
// over long runs of empty seconds after an idle period.  Must be called with
// a.mu held.
func (a *SharedSecretAuth) recomputeMinBucketLocked() {
	min := int64(0)
	for sec := range a.buckets {
		if min == 0 || sec < min {
			min = sec
		}
	}
	a.minBucket = min
}

// dropBucketLocked removes an entire expiry bucket and all its nonces.  It does
// not adjust minBucket; callers manage that.  Must be called with a.mu held.
func (a *SharedSecretAuth) dropBucketLocked(bucket int64) {
	b, ok := a.buckets[bucket]
	if !ok {
		return
	}
	for nonce := range b {
		delete(a.seen, nonce)
	}
	delete(a.buckets, bucket)
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
