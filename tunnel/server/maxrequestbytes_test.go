package server

import "testing"

// TestMaxRequestBytesDefault asserts the CONSOLIDATION A-1 default: an unset
// (0) MaxRequestBytes resolves to 256 MiB, and a non-zero value is honored
// verbatim (0 must keep meaning "apply default", never "unbounded").
func TestMaxRequestBytesDefault(t *testing.T) {
	const want = 256 << 20 // 256 MiB

	var zero Config
	zero.applyDefaults()
	if zero.MaxRequestBytes != want {
		t.Fatalf("default MaxRequestBytes = %d, want %d (256 MiB)", zero.MaxRequestBytes, want)
	}

	custom := Config{MaxRequestBytes: 5 << 20}
	custom.applyDefaults()
	if custom.MaxRequestBytes != 5<<20 {
		t.Fatalf("explicit MaxRequestBytes overwritten: got %d, want %d", custom.MaxRequestBytes, 5<<20)
	}
}
