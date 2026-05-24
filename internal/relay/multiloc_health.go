// multiloc_health.go — bucket-reachability in the relay's health signal.
//
// Task: RELAY-STORE-01
//
// The Vulos relay includes bucket-reachability in its own health signal so
// that load balancers and the CP's multi-location router can detect when a
// relay instance can no longer reach the shared object store bucket.
//
// BucketHealthChecker.Check(ctx) performs an HTTP HEAD request against the
// configured bucket endpoint. The result is embedded in HealthSignal.
//
// Integration: wire BucketHealthChecker into the relay's existing health-check
// path by calling BucketHealthChecker.Check inside your /healthz or relay
// health goroutine.  The implementation is intentionally stateless so it can
// be composed with any existing relay health infrastructure.
package relay

import (
	"context"
	"fmt"
	"net/http"
)

// ─────────────────────────────────────────────────────────────────────────────
// BucketHealthChecker
// ─────────────────────────────────────────────────────────────────────────────

// BucketHealthChecker checks whether the shared object-store bucket used by
// the multi-location central-bucket model is reachable from this relay
// instance.
//
// It is safe for concurrent use.
type BucketHealthChecker struct {
	// BucketURL is the bucket endpoint to probe, e.g.
	// "https://<bucket>.fly.storage.tigris.dev/" for Tigris or
	// "http://minio:9000/<bucket>/" for BYO MinIO.
	BucketURL string

	// Client is the HTTP client used for the HEAD probe. If nil,
	// http.DefaultClient is used. Override in tests to avoid real network I/O.
	Client *http.Client
}

// Check issues a HEAD request to BucketURL and returns a BucketHealth report.
//
// A non-nil error indicates a programming or configuration problem (e.g. the
// URL is invalid).  A network-level failure is reported as Reachable=false
// with a nil error so callers can distinguish "bucket down" from "bug".
func (c *BucketHealthChecker) Check(ctx context.Context) (BucketHealth, error) {
	if c.BucketURL == "" {
		// No bucket configured — emit a neutral signal.
		return BucketHealth{Configured: false, Reachable: false}, nil
	}

	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.BucketURL, nil)
	if err != nil {
		return BucketHealth{}, fmt.Errorf("relay/multiloc_health: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Network error → bucket not reachable.
		return BucketHealth{Configured: true, Reachable: false, Error: err.Error()}, nil
	}
	defer resp.Body.Close()

	reachable := resp.StatusCode >= 200 && resp.StatusCode < 300
	bh := BucketHealth{
		Configured: true,
		Reachable:  reachable,
		StatusCode: resp.StatusCode,
	}
	if !reachable {
		bh.Error = fmt.Sprintf("bucket returned HTTP %d", resp.StatusCode)
	}
	return bh, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// BucketHealth
// ─────────────────────────────────────────────────────────────────────────────

// BucketHealth is the result of a single bucket reachability probe.
type BucketHealth struct {
	// Configured is true when a BucketURL was provided.  When false the relay
	// is operating without a shared bucket (standalone mode).
	Configured bool

	// Reachable is true when the bucket returned a 2xx response.
	Reachable bool

	// StatusCode is the HTTP status code from the bucket probe. 0 when
	// Configured is false or a network error occurred.
	StatusCode int

	// Error is a human-readable description of the failure when Reachable is
	// false and Configured is true. Empty on success.
	Error string
}

// ─────────────────────────────────────────────────────────────────────────────
// RelayHealthSignal
// ─────────────────────────────────────────────────────────────────────────────

// RelayHealthSignal is the composite health report produced by the relay.  It
// combines the relay's core health with the bucket-reachability check so that
// the CP multi-location router can make informed routing decisions.
type RelayHealthSignal struct {
	// RelayOK is true when the relay's own internal health checks pass
	// (queue depth, auth service reachable, etc.).
	RelayOK bool

	// Bucket holds the result of the shared-bucket reachability probe.
	Bucket BucketHealth

	// Overall is true when both RelayOK and Bucket.Reachable are true (or the
	// bucket is not configured, in which case bucket health is ignored).
	Overall bool
}

// BuildSignal computes the composite health signal given the relay's own
// health status and the result from BucketHealthChecker.Check.
func BuildSignal(relayOK bool, bucket BucketHealth) RelayHealthSignal {
	overall := relayOK
	if bucket.Configured {
		overall = overall && bucket.Reachable
	}
	return RelayHealthSignal{
		RelayOK: relayOK,
		Bucket:  bucket,
		Overall: overall,
	}
}
