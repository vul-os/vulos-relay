package server

import (
	"bytes"
	"io"
	"testing"
)

// bufpool_test.go — EFFICIENCY: prove the forwarding copy path reuses a pooled
// buffer and does NOT allocate a fresh scratch buffer per transfer (which io.Copy
// does — one 32 KiB allocation per call). The relay is bandwidth-bound, so zero
// per-request buffer allocation on the hot path is a real COGS lever.

// discardWriter is a bare io.Writer (no ReaderFrom) so io.CopyBuffer is forced to
// USE the scratch buffer rather than delegate to a fast-path — this is what a yamux
// stream / hijacked conn looks like on the real forwarding path.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// byteReader is a bare io.Reader (no WriterTo) over a payload, likewise forcing the
// buffered copy path.
type byteReader struct{ r *bytes.Reader }

func (b *byteReader) Read(p []byte) (int, error) { return b.r.Read(p) }

// TestPooledCopy_CopiesAllBytes: pooledCopy must move every byte (correctness).
func TestPooledCopy_CopiesAllBytes(t *testing.T) {
	payload := bytes.Repeat([]byte("vulos-relay"), 100_000) // ~1.1 MiB
	var dst bytes.Buffer
	n, err := pooledCopy(&dst, &byteReader{r: bytes.NewReader(payload)})
	if err != nil {
		t.Fatalf("pooledCopy: %v", err)
	}
	if n != int64(len(payload)) || !bytes.Equal(dst.Bytes(), payload) {
		t.Fatalf("pooledCopy moved %d bytes / mismatch", n)
	}
}

// BenchmarkPooledCopy reports allocations for a forwarding copy. The pooled buffer
// makes this allocation-free per call (buffers come from the sync.Pool), versus
// io.Copy which allocates a 32 KiB buffer every call. Run:
//
//	go test ./tunnel/server -run x -bench PooledCopy -benchmem
func BenchmarkPooledCopy(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 256<<10) // 256 KiB per transfer
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pooledCopy(discardWriter{}, &byteReader{r: bytes.NewReader(payload)})
	}
}

// BenchmarkIoCopy is the baseline (io.Copy) for comparison — it allocates a fresh
// 32 KiB scratch buffer per call, which pooledCopy eliminates.
func BenchmarkIoCopy(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 256<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = io.Copy(discardWriter{}, &byteReader{r: bytes.NewReader(payload)})
	}
}
