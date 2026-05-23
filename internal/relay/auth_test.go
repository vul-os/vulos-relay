// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package relay_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/relay"
)

// ─── SharedSecretAuth tests ───────────────────────────────────────────────────

const testAccountID = "test-account-1"
const testMessageID = "msg-001"

var testSecret = []byte("super-secret-key-for-tests")

func makeRegistry() *relay.MemAccountRegistry {
	reg := relay.NewMemAccountRegistry()
	reg.Register(relay.AccountRecord{
		AccountID:         testAccountID,
		SharedSecret:      testSecret,
		AuthorizedDomains: []string{"example.com"},
	})
	return reg
}

func makeValidToken(ts int64) relay.Credentials {
	tok := relay.ComputeHMACToken(testSecret, testAccountID, testMessageID, ts)
	return relay.Credentials{HMACToken: &tok}
}

// TestSharedSecretAuth_AuthenticatedSubmitSucceeds — open-relay gate proof (1/3)
// Verifies that a well-formed, signed credential for a known account succeeds.
func TestSharedSecretAuth_AuthenticatedSubmitSucceeds(t *testing.T) {
	auth := relay.NewSharedSecretAuth(makeRegistry())
	now := time.Unix(1_700_000_000, 0)
	auth.SetClock(func() time.Time { return now })

	creds := makeValidToken(now.Unix())
	accountID, err := auth.Authenticate(context.Background(), creds)
	if err != nil {
		t.Fatalf("expected authenticated submit to succeed, got: %v", err)
	}
	if accountID != testAccountID {
		t.Errorf("expected accountID %q, got %q", testAccountID, accountID)
	}
}

// TestSharedSecretAuth_UnauthenticatedSubmitRefused — open-relay gate proof (2/3)
// Verifies that a submission with no credentials is refused with ErrUnauthenticated.
func TestSharedSecretAuth_UnauthenticatedSubmitRefused(t *testing.T) {
	auth := relay.NewSharedSecretAuth(makeRegistry())

	creds := relay.Credentials{} // no token, no TLS
	_, err := auth.Authenticate(context.Background(), creds)
	if !errors.Is(err, relay.ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated for missing credentials, got: %v", err)
	}
}

// TestSharedSecretAuth_UnknownAccountRefused — open-relay gate proof (3/3)
// Verifies that a token for an unknown account is refused.
func TestSharedSecretAuth_UnknownAccountRefused(t *testing.T) {
	auth := relay.NewSharedSecretAuth(makeRegistry())
	now := time.Unix(1_700_000_000, 0)
	auth.SetClock(func() time.Time { return now })

	// Mint a token for an account that does not exist in the registry.
	tok := relay.ComputeHMACToken(testSecret, "unknown-account", testMessageID, now.Unix())
	creds := relay.Credentials{HMACToken: &tok}

	_, err := auth.Authenticate(context.Background(), creds)
	if !errors.Is(err, relay.ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated for unknown account, got: %v", err)
	}
}

// TestSharedSecretAuth_WrongSignatureRefused
func TestSharedSecretAuth_WrongSignatureRefused(t *testing.T) {
	auth := relay.NewSharedSecretAuth(makeRegistry())
	now := time.Unix(1_700_000_000, 0)
	auth.SetClock(func() time.Time { return now })

	tok := relay.HMACToken{
		AccountID: testAccountID,
		MessageID: testMessageID,
		Timestamp: now.Unix(),
		Signature: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	}
	_, err := auth.Authenticate(context.Background(), relay.Credentials{HMACToken: &tok})
	if !errors.Is(err, relay.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for wrong HMAC, got: %v", err)
	}
}

// TestSharedSecretAuth_ExpiredTokenRefused
func TestSharedSecretAuth_ExpiredTokenRefused(t *testing.T) {
	auth := relay.NewSharedSecretAuth(makeRegistry())
	now := time.Unix(1_700_000_000, 0)
	auth.SetClock(func() time.Time { return now })

	// Token minted 10 minutes ago — outside default 5-min skew window.
	oldTS := now.Add(-10 * time.Minute).Unix()
	tok := relay.ComputeHMACToken(testSecret, testAccountID, testMessageID, oldTS)
	_, err := auth.Authenticate(context.Background(), relay.Credentials{HMACToken: &tok})
	if !errors.Is(err, relay.ErrCredentialExpired) {
		t.Errorf("expected ErrCredentialExpired for old token, got: %v", err)
	}
}

// TestSharedSecretAuth_ReplayRefused
func TestSharedSecretAuth_ReplayRefused(t *testing.T) {
	auth := relay.NewSharedSecretAuth(makeRegistry())
	now := time.Unix(1_700_000_000, 0)
	auth.SetClock(func() time.Time { return now })

	creds := makeValidToken(now.Unix())

	// First use must succeed.
	if _, err := auth.Authenticate(context.Background(), creds); err != nil {
		t.Fatalf("first authenticate failed unexpectedly: %v", err)
	}
	// Second use with the same credential must be rejected as a replay.
	_, err := auth.Authenticate(context.Background(), creds)
	if !errors.Is(err, relay.ErrReplayDetected) {
		t.Errorf("expected ErrReplayDetected on replay, got: %v", err)
	}
}

// TestSharedSecretAuth_FutureTimestampRefused
func TestSharedSecretAuth_FutureTimestampRefused(t *testing.T) {
	auth := relay.NewSharedSecretAuth(makeRegistry())
	now := time.Unix(1_700_000_000, 0)
	auth.SetClock(func() time.Time { return now })

	// Token minted 10 minutes in the future — outside default skew window.
	futureTS := now.Add(10 * time.Minute).Unix()
	tok := relay.ComputeHMACToken(testSecret, testAccountID, testMessageID, futureTS)
	_, err := auth.Authenticate(context.Background(), relay.Credentials{HMACToken: &tok})
	if !errors.Is(err, relay.ErrCredentialExpired) {
		t.Errorf("expected ErrCredentialExpired for future token, got: %v", err)
	}
}

// ─── MutualTLSAuth tests ──────────────────────────────────────────────────────

const testTLSCN = "relay-node-1.example.com"

func makeRegistryWithTLS() *relay.MemAccountRegistry {
	reg := relay.NewMemAccountRegistry()
	reg.Register(relay.AccountRecord{
		AccountID:         testAccountID,
		TLSSubjectCN:      testTLSCN,
		AuthorizedDomains: []string{"example.com"},
	})
	return reg
}

// selfSignedCert generates an ECDSA self-signed TLS cert with the given CN.
func selfSignedCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func makeTLSCreds(t *testing.T, cn string) relay.Credentials {
	t.Helper()
	cert := selfSignedCert(t, cn)
	return relay.Credentials{
		TLSState: &tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		},
	}
}

// TestMutualTLSAuth_ValidCertSucceeds
func TestMutualTLSAuth_ValidCertSucceeds(t *testing.T) {
	auth := relay.NewMutualTLSAuth(makeRegistryWithTLS())
	creds := makeTLSCreds(t, testTLSCN)
	accountID, err := auth.Authenticate(context.Background(), creds)
	if err != nil {
		t.Fatalf("expected mTLS auth to succeed, got: %v", err)
	}
	if accountID != testAccountID {
		t.Errorf("expected accountID %q, got %q", testAccountID, accountID)
	}
}

// TestMutualTLSAuth_NoCertRefused
func TestMutualTLSAuth_NoCertRefused(t *testing.T) {
	auth := relay.NewMutualTLSAuth(makeRegistryWithTLS())
	creds := relay.Credentials{TLSState: &tls.ConnectionState{}} // no VerifiedChains
	_, err := auth.Authenticate(context.Background(), creds)
	if !errors.Is(err, relay.ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated for missing cert, got: %v", err)
	}
}

// TestMutualTLSAuth_NoTLSStateRefused
func TestMutualTLSAuth_NoTLSStateRefused(t *testing.T) {
	auth := relay.NewMutualTLSAuth(makeRegistryWithTLS())
	creds := relay.Credentials{} // no TLS state at all
	_, err := auth.Authenticate(context.Background(), creds)
	if !errors.Is(err, relay.ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated for nil TLSState, got: %v", err)
	}
}

// TestMutualTLSAuth_UnknownCNRefused
func TestMutualTLSAuth_UnknownCNRefused(t *testing.T) {
	auth := relay.NewMutualTLSAuth(makeRegistryWithTLS())
	creds := makeTLSCreds(t, "unknown-node.example.com")
	_, err := auth.Authenticate(context.Background(), creds)
	if !errors.Is(err, relay.ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated for unknown CN, got: %v", err)
	}
}
