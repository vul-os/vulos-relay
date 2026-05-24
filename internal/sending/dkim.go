// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"
)

// KeyStore is the pluggable persistence layer for DKIM key material.
// Vulos injects its own implementation; this package ships a filesystem
// reference implementation (FSKeyStore).
type KeyStore interface {
	// Save persists a DKIMKey by selector name.
	Save(key DKIMKey) error

	// Load retrieves a DKIMKey by selector name.  Returns ErrKeyNotFound if
	// the selector does not exist.
	Load(selector string) (DKIMKey, error)

	// List returns all stored selectors.
	List() ([]string, error)

	// Delete removes the key with the given selector.
	Delete(selector string) error
}

// ErrKeyNotFound is returned by KeyStore.Load when the selector is not found.
var ErrKeyNotFound = errors.New("dkim: key not found")

// DKIMKey holds one DKIM signing key with its metadata.
type DKIMKey struct {
	// Selector is the DNS selector label (e.g. "s20240601a").
	Selector string

	// Domain is the signing domain.
	Domain string

	// PrivateKeyPEM is the RSA private key in PKCS#1 PEM format.
	PrivateKeyPEM []byte

	// PublicKeyDNS is the base64-encoded public key for the DNS TXT record.
	PublicKeyDNS string

	// DNSTXTRecord is the full DNS TXT record value that must be published at
	// <selector>._domainkey.<domain>.
	DNSTXTRecord string

	// CreatedAt is when the key was generated.
	CreatedAt time.Time

	// ActiveAt is when the key became (or will become) the primary signing key.
	// A key is not activated until its propagation grace period has elapsed.
	ActiveAt time.Time

	// RetireAt is when the key will be removed from the key store.  In-flight
	// messages signed with this key can still verify until RetireAt.
	RetireAt time.Time

	// Retired marks the key as no longer used for signing; it is kept for
	// verification grace until RetireAt.
	Retired bool
}

// DKIMRotatorConfig holds configuration for the DKIM key rotator.
type DKIMRotatorConfig struct {
	// RotationInterval is how often a new key is generated.  Default: 30 days.
	RotationInterval time.Duration

	// PropagationGrace is the time to wait after generating a key before
	// switching to it as the active signing key.  This allows DNS propagation.
	// Default: 48 hours.
	PropagationGrace time.Duration

	// RetentionWindow is how long a retired key is kept so that in-flight
	// mail signed with the old key can still be verified.  Default: 7 days.
	RetentionWindow time.Duration

	// KeyBits is the RSA key size.  Default: 2048.
	KeyBits int
}

func (c *DKIMRotatorConfig) rotationInterval() time.Duration {
	if c.RotationInterval <= 0 {
		return 30 * 24 * time.Hour
	}
	return c.RotationInterval
}

func (c *DKIMRotatorConfig) propagationGrace() time.Duration {
	if c.PropagationGrace <= 0 {
		return 48 * time.Hour
	}
	return c.PropagationGrace
}

func (c *DKIMRotatorConfig) retentionWindow() time.Duration {
	if c.RetentionWindow <= 0 {
		return 7 * 24 * time.Hour
	}
	return c.RetentionWindow
}

func (c *DKIMRotatorConfig) keyBits() int {
	if c.KeyBits <= 0 {
		return 2048
	}
	return c.KeyBits
}

// DKIMRotator manages DKIM signing keys per domain with overlapping validity
// so that signing never lapses during a rotation.
//
// On each Rotate call:
//  1. A new RSA key + selector are generated.
//  2. The DNS TXT record that must be published is returned to the caller.
//  3. After PropagationGrace elapses, the new key becomes the active signing key.
//  4. The old key is retired but retained for RetentionWindow.
//
// CurrentKey returns the key that outbound SMTP should use.
// PendingDNSRecords returns the TXT records that must currently exist in DNS.
//
// DKIMRotator is safe for concurrent use.
type DKIMRotator struct {
	mu     sync.Mutex
	domain string
	store  KeyStore
	cfg    DKIMRotatorConfig
	keys   []DKIMKey // ordered by CreatedAt ascending
}

// NewDKIMRotator creates a DKIMRotator for domain using the given KeyStore.
func NewDKIMRotator(domain string, store KeyStore, cfg DKIMRotatorConfig) (*DKIMRotator, error) {
	r := &DKIMRotator{domain: domain, store: store, cfg: cfg}
	if err := r.loadAll(); err != nil {
		return nil, fmt.Errorf("dkim: load existing keys: %w", err)
	}
	return r, nil
}

// loadAll hydrates r.keys from the KeyStore.
func (r *DKIMRotator) loadAll() error {
	selectors, err := r.store.List()
	if err != nil {
		return err
	}
	for _, sel := range selectors {
		k, err := r.store.Load(sel)
		if err != nil {
			continue
		}
		if k.Domain == r.domain {
			r.keys = append(r.keys, k)
		}
	}
	return nil
}

// Rotate generates a new DKIM key for the domain.  It returns the new DKIMKey
// (including the DNSTXTRecord that must be published) without immediately
// activating it.  A subsequent call to CurrentKey (after PropagationGrace) will
// return the new key once it is active.
//
// Rotate also purges keys whose RetireAt has passed.
func (r *DKIMRotator) Rotate() (DKIMKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Purge expired retired keys.
	r.purgeExpired(now)

	// Generate new RSA key.
	privKey, err := rsa.GenerateKey(rand.Reader, r.cfg.keyBits())
	if err != nil {
		return DKIMKey{}, fmt.Errorf("generate key: %w", err)
	}

	selector := generateSelector(now)
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return DKIMKey{}, fmt.Errorf("marshal public key: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)
	dnsTXT := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubB64)

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	key := DKIMKey{
		Selector:      selector,
		Domain:        r.domain,
		PrivateKeyPEM: privPEM,
		PublicKeyDNS:  pubB64,
		DNSTXTRecord:  dnsTXT,
		CreatedAt:     now,
		ActiveAt:      now.Add(r.cfg.propagationGrace()),
		RetireAt:      now.Add(r.cfg.rotationInterval() + r.cfg.propagationGrace() + r.cfg.retentionWindow()),
	}

	if err := r.store.Save(key); err != nil {
		return DKIMKey{}, fmt.Errorf("save key: %w", err)
	}
	r.keys = append(r.keys, key)

	return key, nil
}

// CurrentKey returns the signing key that should be used for outbound mail.
// It returns the most recently activated key (ActiveAt <= now, not Retired).
// If no key is active yet (e.g. during initial propagation grace), it returns
// the most recently created key regardless of ActiveAt to avoid a signing gap.
func (r *DKIMRotator) CurrentKey() (DKIMKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Find the newest active (non-retired) key.
	var best *DKIMKey
	for i := range r.keys {
		k := &r.keys[i]
		if k.Retired {
			continue
		}
		if k.ActiveAt.After(now) {
			// In propagation grace — skip unless it's the only key.
			if best == nil {
				best = k
			}
			continue
		}
		// Key is active.
		if best == nil || k.ActiveAt.After(best.ActiveAt) {
			best = k
		}
	}

	if best == nil {
		return DKIMKey{}, ErrKeyNotFound
	}
	return *best, nil
}

// PendingDNSRecords returns the set of DNS TXT records that should currently
// exist in DNS for this domain.  This includes the active key and any keys
// still within their retention window.
func (r *DKIMRotator) PendingDNSRecords() []DNSTXTRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	var out []DNSTXTRecord
	for _, k := range r.keys {
		if now.After(k.RetireAt) {
			continue
		}
		out = append(out, DNSTXTRecord{
			Name:  fmt.Sprintf("%s._domainkey.%s", k.Selector, k.Domain),
			Value: k.DNSTXTRecord,
		})
	}
	return out
}

// DNSTXTRecord is a DNS TXT record that must be published for DKIM to work.
type DNSTXTRecord struct {
	// Name is the DNS record name (e.g. "s1._domainkey.example.com").
	Name string
	// Value is the TXT record value.
	Value string
}

// RetireSelector marks the key with the given selector as retired.  It is no
// longer used for signing but is kept for verification until RetireAt.
func (r *DKIMRotator) RetireSelector(selector string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range r.keys {
		if r.keys[i].Selector == selector {
			r.keys[i].Retired = true
			k := r.keys[i]
			return r.store.Save(k)
		}
	}
	return fmt.Errorf("%w: %s", ErrKeyNotFound, selector)
}

// purgeExpired removes keys whose RetireAt has passed from memory and the store.
// Must be called with r.mu held.
func (r *DKIMRotator) purgeExpired(now time.Time) {
	var remaining []DKIMKey
	for _, k := range r.keys {
		if k.Retired && now.After(k.RetireAt) {
			_ = r.store.Delete(k.Selector) // best-effort
			continue
		}
		remaining = append(remaining, k)
	}
	r.keys = remaining
}

// generateSelector returns a timestamp-based DKIM selector.
func generateSelector(t time.Time) string {
	return fmt.Sprintf("s%d", t.UTC().UnixNano())
}

// ---- FSKeyStore: filesystem reference implementation ------------------------

// MemKeyStore is an in-memory KeyStore suitable for tests and simple
// self-hosted deployments that do not require persistence across restarts.
type MemKeyStore struct {
	mu   sync.Mutex
	keys map[string]DKIMKey
}

// NewMemKeyStore creates an empty MemKeyStore.
func NewMemKeyStore() *MemKeyStore {
	return &MemKeyStore{keys: make(map[string]DKIMKey)}
}

// Save implements KeyStore.
func (s *MemKeyStore) Save(key DKIMKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.Selector] = key
	return nil
}

// Load implements KeyStore.
func (s *MemKeyStore) Load(selector string) (DKIMKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[selector]
	if !ok {
		return DKIMKey{}, ErrKeyNotFound
	}
	return k, nil
}

// List implements KeyStore.
func (s *MemKeyStore) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.keys))
	for sel := range s.keys {
		out = append(out, sel)
	}
	return out, nil
}

// Delete implements KeyStore.
func (s *MemKeyStore) Delete(selector string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, selector)
	return nil
}

var _ KeyStore = (*MemKeyStore)(nil)
