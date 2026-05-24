package relay_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vul-os/vulos-relay/internal/relay"
)

// TestBucketHealthChecker_Reachable verifies that a 200 from the bucket
// endpoint is reported as reachable=true.
func TestBucketHealthChecker_Reachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method = %q, want HEAD", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	chk := &relay.BucketHealthChecker{
		BucketURL: srv.URL,
		Client:    srv.Client(),
	}
	bh, err := chk.Check(context.Background())
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if !bh.Configured {
		t.Error("expected Configured=true")
	}
	if !bh.Reachable {
		t.Errorf("expected Reachable=true, got false (status=%d error=%q)", bh.StatusCode, bh.Error)
	}
}

// TestBucketHealthChecker_Unreachable verifies that a 503 is reported as
// reachable=false with a non-empty error string.
func TestBucketHealthChecker_Unreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	chk := &relay.BucketHealthChecker{
		BucketURL: srv.URL,
		Client:    srv.Client(),
	}
	bh, err := chk.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bh.Configured {
		t.Error("expected Configured=true")
	}
	if bh.Reachable {
		t.Error("expected Reachable=false for 503")
	}
	if bh.Error == "" {
		t.Error("expected non-empty Error string for 503")
	}
}

// TestBucketHealthChecker_NotConfigured verifies neutral signal when BucketURL
// is empty (standalone relay without shared bucket).
func TestBucketHealthChecker_NotConfigured(t *testing.T) {
	chk := &relay.BucketHealthChecker{BucketURL: ""}
	bh, err := chk.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bh.Configured {
		t.Error("expected Configured=false for empty BucketURL")
	}
	if bh.Reachable {
		t.Error("expected Reachable=false for empty BucketURL")
	}
}

// TestBuildSignal_BothHealthy verifies Overall=true when relay and bucket are
// both healthy.
func TestBuildSignal_BothHealthy(t *testing.T) {
	bh := relay.BucketHealth{Configured: true, Reachable: true}
	sig := relay.BuildSignal(true, bh)
	if !sig.Overall {
		t.Error("expected Overall=true when relay and bucket are healthy")
	}
	if !sig.RelayOK {
		t.Error("expected RelayOK=true")
	}
	if !sig.Bucket.Reachable {
		t.Error("expected Bucket.Reachable=true")
	}
}

// TestBuildSignal_BucketDown verifies Overall=false when bucket is down.
func TestBuildSignal_BucketDown(t *testing.T) {
	bh := relay.BucketHealth{Configured: true, Reachable: false, Error: "503"}
	sig := relay.BuildSignal(true, bh)
	if sig.Overall {
		t.Error("expected Overall=false when bucket is down")
	}
	if !sig.RelayOK {
		t.Error("expected RelayOK=true")
	}
}

// TestBuildSignal_RelayDown verifies Overall=false when the relay itself is
// unhealthy regardless of bucket state.
func TestBuildSignal_RelayDown(t *testing.T) {
	bh := relay.BucketHealth{Configured: true, Reachable: true}
	sig := relay.BuildSignal(false, bh)
	if sig.Overall {
		t.Error("expected Overall=false when relay is unhealthy")
	}
}

// TestBuildSignal_StandaloneMode verifies that when the bucket is not
// configured, Overall is determined solely by RelayOK.
func TestBuildSignal_StandaloneMode(t *testing.T) {
	bh := relay.BucketHealth{Configured: false, Reachable: false}
	sig := relay.BuildSignal(true, bh)
	if !sig.Overall {
		t.Error("expected Overall=true in standalone mode when relay is healthy")
	}
}
