// tlsconfig_test.go — the self-terminating TLS posture. When the relay terminates
// TLS itself (ListenAndServeTLS with -cert/-key) and the operator supplied no
// tls.Config, it must apply an explicit hardened floor (TLS 1.2 minimum + ALPN)
// rather than inheriting Go-version-dependent stdlib defaults. An operator-
// supplied cfg.TLSConfig must be honored verbatim (pass-through, untouched).
package server

import (
	"crypto/tls"
	"testing"
)

func TestHardenedTLSConfig_FloorAndALPN(t *testing.T) {
	c := hardenedTLSConfig()
	if c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want tls.VersionTLS12 (%#x)", c.MinVersion, tls.VersionTLS12)
	}
	want := []string{"h2", "http/1.1"}
	if len(c.NextProtos) != len(want) {
		t.Fatalf("NextProtos = %v, want %v", c.NextProtos, want)
	}
	for i, p := range want {
		if c.NextProtos[i] != p {
			t.Fatalf("NextProtos[%d] = %q, want %q", i, c.NextProtos[i], p)
		}
	}
}

func TestTLSConfigForSelfTerminate_DefaultsWhenUnset(t *testing.T) {
	s := &Server{cfg: Config{}} // no operator TLSConfig
	got := s.tlsConfigForSelfTerminate()
	if got == nil {
		t.Fatal("expected a hardened default config, got nil")
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want tls.VersionTLS12", got.MinVersion)
	}
}

func TestTLSConfigForSelfTerminate_HonorsOperatorConfig(t *testing.T) {
	// An operator-supplied config must pass through UNMODIFIED (same pointer, its
	// own MinVersion preserved) — we never override cfg.TLSConfig.
	op := &tls.Config{MinVersion: tls.VersionTLS13}
	s := &Server{cfg: Config{TLSConfig: op}}
	got := s.tlsConfigForSelfTerminate()
	if got != op {
		t.Fatal("operator-supplied TLSConfig must be returned verbatim (same pointer)")
	}
	if got.MinVersion != tls.VersionTLS13 {
		t.Fatalf("operator MinVersion = %#x, want it preserved (TLS 1.3)", got.MinVersion)
	}
}
