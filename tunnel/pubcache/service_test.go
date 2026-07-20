package pubcache

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// service_test.go — the HTTP surface contract: cacheability headers, the
// verification gate on the miss path, the never-cached feed passthrough, rate
// limits, bounded fan-out, and the SSRF-free upstream story.

// fakeUpstream is a stand-in § 22.5.1 gateway. It counts requests so tests can
// assert that a hit does NOT touch it and that a herd is coalesced.
type fakeUpstream struct {
	mu      sync.Mutex
	objects map[string][]byte // path -> body
	hits    atomic.Int64
	delay   time.Duration
	status  int
}

func newFakeUpstream() *fakeUpstream {
	return &fakeUpstream{objects: map[string][]byte{}}
}

func (u *fakeUpstream) put(path string, body []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.objects[path] = body
}

func (u *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.hits.Add(1)
	if u.delay > 0 {
		time.Sleep(u.delay)
	}
	if u.status != 0 {
		http.Error(w, "upstream says no", u.status)
		return
	}
	key := r.URL.Path
	if r.URL.RawQuery != "" {
		key += "?" + r.URL.RawQuery
	}
	u.mu.Lock()
	body, ok := u.objects[key]
	u.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	_, _ = w.Write(body)
}

func newTestService(t *testing.T, up *fakeUpstream, mutate func(*Config)) *Service {
	t.Helper()
	ts := httptest.NewServer(up)
	t.Cleanup(ts.Close)
	cfg := Config{
		Upstreams: []string{ts.URL},
		// Limiters off unless a test turns them on, so timing never flakes.
		RequestRate: -1, GlobalRate: -1,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return svc
}

func get(t *testing.T, svc *Service, path string, hdr map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "192.0.2.10:1234"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)
	return rec.Result()
}

func chunkPath(a Addr) string { return defaultPrefix + "/chunk/" + a.String() }

// ---------------------------------------------------------------------------
// disabled by default
// ---------------------------------------------------------------------------

// TestNoUpstreamsServesNothing: the zero config is a valid holder that simply
// holds nothing — every read is the § 22.6.2 "not served here" 404, never a
// broken endpoint and never an accidental open proxy.
func TestNoUpstreamsServesNothing(t *testing.T) {
	svc, err := New(Config{RequestRate: -1, GlobalRate: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	resp := get(t, svc, chunkPath(HashBytes([]byte("anything"))), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 from an empty holder, got %d", resp.StatusCode)
	}
}

// TestFeedPassthroughDisabledByDefault: the one endpoint this node cannot verify
// is off unless the operator opts in separately.
func TestFeedPassthroughDisabledByDefault(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, nil)
	pub := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	resp := get(t, svc, defaultPrefix+"/feed/"+pub+"/head", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("feed passthrough should be off by default, got %d", resp.StatusCode)
	}
	if up.hits.Load() != 0 {
		t.Fatal("disabled feed passthrough still contacted an upstream")
	}
}

// ---------------------------------------------------------------------------
// miss, hit, headers
// ---------------------------------------------------------------------------

func TestChunkMissThenHitServesImmutableHeaders(t *testing.T) {
	body := []byte("a public plaintext chunk")
	addr := HashBytes(body)
	up := newFakeUpstream()
	up.put("/chunk/"+addr.String(), body)
	svc := newTestService(t, up, nil)

	// MISS — reads through, verifies, stores.
	resp := get(t, svc, chunkPath(addr), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("miss should 200, got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(body) {
		t.Fatalf("body = %q, want %q", got, body)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") || !strings.Contains(cc, "public") {
		t.Fatalf("content-addressed object must be public+immutable, got %q", cc)
	}
	if et := resp.Header.Get("ETag"); et != `"`+addr.String()+`"` {
		t.Fatalf("ETag must equal the content address, got %q", et)
	}
	if up.hits.Load() != 1 {
		t.Fatalf("expected exactly 1 upstream fetch, got %d", up.hits.Load())
	}

	// HIT — served from the store, upstream untouched.
	resp = get(t, svc, chunkPath(addr), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hit should 200, got %d", resp.StatusCode)
	}
	if up.hits.Load() != 1 {
		t.Fatalf("cache hit still contacted the upstream (%d fetches)", up.hits.Load())
	}
	if st := svc.store.stats(); st.Hits != 1 || st.Stores != 1 {
		t.Fatalf("unexpected store stats: %+v", st)
	}
}

func TestConditionalGetReturnsNotModified(t *testing.T) {
	body := []byte("etag me")
	addr := HashBytes(body)
	up := newFakeUpstream()
	up.put("/chunk/"+addr.String(), body)
	svc := newTestService(t, up, nil)

	get(t, svc, chunkPath(addr), nil) // warm
	resp := get(t, svc, chunkPath(addr), map[string]string{"If-None-Match": `"` + addr.String() + `"`})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("matching ETag should 304, got %d", resp.StatusCode)
	}
}

func TestAnnounceAndManifestEndpoints(t *testing.T) {
	announce := []byte("a signed announce, opaque to this cache")
	aAddr := HashBytes(announce)
	mAddr, manifest := buildManifest(t, []byte("c0"), []byte("c1"), []byte("c2"))

	up := newFakeUpstream()
	up.put("/announce/"+aAddr.String(), announce)
	up.put("/manifest/"+mAddr.String(), manifest)
	svc := newTestService(t, up, nil)

	for _, tc := range []struct{ path, ctype string }{
		{defaultPrefix + "/announce/" + aAddr.String(), "application/cbor"},
		{defaultPrefix + "/manifest/" + mAddr.String(), "application/cbor"},
	} {
		resp := get(t, svc, tc.path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: got %d", tc.path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != tc.ctype {
			t.Fatalf("%s: content-type %q, want %q", tc.path, ct, tc.ctype)
		}
	}
}

// ---------------------------------------------------------------------------
// the gate, at the HTTP layer
// ---------------------------------------------------------------------------

// TestPoisonedUpstreamIsNeitherServedNorCached is the headline test: an upstream
// that answers a valid address with the WRONG bytes gets nothing past this node.
// The client is refused (404 → rotate to another holder), and — critically — the
// poison is not retained, so the next request re-tries upstream rather than being
// served a lie from local memory.
func TestPoisonedUpstreamIsNeitherServedNorCached(t *testing.T) {
	honest := []byte("the object the address names")
	addr := HashBytes(honest)
	up := newFakeUpstream()
	up.put("/chunk/"+addr.String(), []byte("POISON: not what the address names"))
	svc := newTestService(t, up, nil)

	resp := get(t, svc, chunkPath(addr), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("poisoned object must not be served, got %d", resp.StatusCode)
	}
	if st := svc.store.stats(); st.Stores != 0 || st.Objects != 0 {
		t.Fatalf("poisoned object was cached: %+v", st)
	}

	// The upstream repents; the node must not still be holding the poison.
	up.put("/chunk/"+addr.String(), honest)
	resp = get(t, svc, chunkPath(addr), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("honest object should be served after upstream is fixed, got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(honest) {
		t.Fatalf("served %q, want %q", got, honest)
	}
}

// TestPoisonedManifestIsRejected: the same gate, via the Merkle-root rule rather
// than a flat hash.
func TestPoisonedManifestIsRejected(t *testing.T) {
	mAddr, _ := buildManifest(t, []byte("real"))
	_, other := buildManifest(t, []byte("substituted"))
	up := newFakeUpstream()
	up.put("/manifest/"+mAddr.String(), other) // a valid manifest — of a DIFFERENT object
	svc := newTestService(t, up, nil)

	resp := get(t, svc, defaultPrefix+"/manifest/"+mAddr.String(), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("substituted manifest must not be served, got %d", resp.StatusCode)
	}
	if st := svc.store.stats(); st.Stores != 0 {
		t.Fatalf("substituted manifest was cached: %+v", st)
	}
}

func TestMalformedAddressNeverReachesUpstream(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, nil)
	for _, bad := range []string{
		"not-base64!!",
		"../../etc/passwd",
		strings.Repeat("A", 200),
		base64.RawURLEncoding.EncodeToString(make([]byte, 33)), // wrong prefix (0x00)
	} {
		resp := get(t, svc, defaultPrefix+"/chunk/"+bad, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%q: expected 404, got %d", bad, resp.StatusCode)
		}
	}
	if up.hits.Load() != 0 {
		t.Fatalf("a malformed address caused %d upstream fetches", up.hits.Load())
	}
}

// TestOversizeUpstreamObjectRefused: the per-object cap is enforced against the
// upstream, so a hostile gateway cannot stream unbounded bytes into this node.
func TestOversizeUpstreamObjectRefused(t *testing.T) {
	big := make([]byte, 4096)
	addr := HashBytes(big)
	up := newFakeUpstream()
	up.put("/chunk/"+addr.String(), big)
	svc := newTestService(t, up, func(c *Config) { c.MaxObjectBytes = 1024 })

	resp := get(t, svc, chunkPath(addr), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("oversize object should be refused, got %d", resp.StatusCode)
	}
}

func TestUpstreamErrorIsNotServed(t *testing.T) {
	up := newFakeUpstream()
	up.status = http.StatusInternalServerError
	svc := newTestService(t, up, nil)
	resp := get(t, svc, chunkPath(HashBytes([]byte("x"))), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("upstream failure should surface as not-served 404, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// bounded fan-out
// ---------------------------------------------------------------------------

// TestConcurrentMissesCoalesceToOneUpstreamFetch: a thundering herd for one cold
// object must not be amplified onto the swarm.
func TestConcurrentMissesCoalesceToOneUpstreamFetch(t *testing.T) {
	body := []byte("cold object")
	addr := HashBytes(body)
	up := newFakeUpstream()
	up.delay = 50 * time.Millisecond
	up.put("/chunk/"+addr.String(), body)
	svc := newTestService(t, up, nil)

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := get(t, svc, chunkPath(addr), nil)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("concurrent miss got %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	if n := up.hits.Load(); n > 2 {
		t.Fatalf("herd of 24 caused %d upstream fetches; single-flight is not coalescing", n)
	}
}

func TestEvictionUnderCacheCap(t *testing.T) {
	up := newFakeUpstream()
	bodies := make([]Addr, 8)
	for i := range bodies {
		b := []byte(fmt.Sprintf("object-%02d-payload", i))
		a := HashBytes(b)
		bodies[i] = a
		up.put("/chunk/"+a.String(), b)
	}
	// Cap fits roughly three objects.
	svc := newTestService(t, up, func(c *Config) { c.MaxCacheBytes = 60 })
	for _, a := range bodies {
		if resp := get(t, svc, chunkPath(a), nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("fetch failed: %d", resp.StatusCode)
		}
	}
	st := svc.store.stats()
	if st.Bytes > 60 {
		t.Fatalf("cache exceeded its byte cap: %+v", st)
	}
	if st.Evictions == 0 {
		t.Fatalf("expected evictions under a tight cap: %+v", st)
	}
	// An evicted object is still SERVABLE — it is just re-fetched. Eviction is
	// this node ceasing to hold, never a claim the object does not exist.
	if resp := get(t, svc, chunkPath(bodies[0]), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("evicted object should be re-fetched on demand, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// TTL / revalidation
// ---------------------------------------------------------------------------

// TestTTLExpiryRevalidatesUpstream: past the TTL the node goes back to the
// upstream instead of serving from memory forever.
func TestTTLExpiryRevalidatesUpstream(t *testing.T) {
	body := []byte("ttl object")
	addr := HashBytes(body)
	up := newFakeUpstream()
	up.put("/chunk/"+addr.String(), body)
	clk := newFakeClock()
	svc := newTestService(t, up, func(c *Config) {
		c.TTL = 10 * time.Minute
		c.now = clk.now
	})

	get(t, svc, chunkPath(addr), nil)
	if up.hits.Load() != 1 {
		t.Fatalf("expected 1 upstream fetch, got %d", up.hits.Load())
	}
	clk.advance(5 * time.Minute)
	get(t, svc, chunkPath(addr), nil)
	if up.hits.Load() != 1 {
		t.Fatalf("in-TTL read went upstream (%d fetches)", up.hits.Load())
	}
	clk.advance(11 * time.Minute)
	get(t, svc, chunkPath(addr), nil)
	if up.hits.Load() != 2 {
		t.Fatalf("expired entry was not revalidated upstream (%d fetches)", up.hits.Load())
	}
}

// ---------------------------------------------------------------------------
// feed passthrough (mutable, never cached)
// ---------------------------------------------------------------------------

func TestFeedHeadIsProxiedButNeverCached(t *testing.T) {
	pub := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	up := newFakeUpstream()
	up.put("/feed/"+pub+"/head", []byte("head-v1"))
	svc := newTestService(t, up, func(c *Config) { c.ServeFeeds = true })

	resp := get(t, svc, defaultPrefix+"/feed/"+pub+"/head", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("feed head should proxy, got %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "must-revalidate") {
		t.Fatalf("mutable feed head must carry must-revalidate, got %q", cc)
	}

	// A NEW head must be seen immediately: nothing about the previous one is held.
	up.put("/feed/"+pub+"/head", []byte("head-v2"))
	resp = get(t, svc, defaultPrefix+"/feed/"+pub+"/head", nil)
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "head-v2" {
		t.Fatalf("stale feed head served from cache: %q", got)
	}
	if st := svc.store.stats(); st.Stores != 0 || st.Objects != 0 {
		t.Fatalf("an unverifiable feed object was stored: %+v", st)
	}
}

func TestFeedRangeIsBoundedAndValidated(t *testing.T) {
	pub := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	up := newFakeUpstream()
	up.put("/feed/"+pub+"/range?from=0&to=9", []byte("entries"))
	svc := newTestService(t, up, func(c *Config) { c.ServeFeeds = true; c.MaxFeedRange = 10 })

	if resp := get(t, svc, defaultPrefix+"/feed/"+pub+"/range?from=0&to=9", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("valid range should proxy, got %d", resp.StatusCode)
	}
	for _, q := range []string{
		"?from=0&to=10000", // over the span cap
		"?from=9&to=0",     // inverted
		"?from=abc&to=1",   // not a number
		"",                 // unbounded
	} {
		if resp := get(t, svc, defaultPrefix+"/feed/"+pub+"/range"+q, nil); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("range%q should be refused, got %d", q, resp.StatusCode)
		}
	}
}

// TestFeedKeyMustBeACanonicalKey: the {pub} component is validated before it is
// ever interpolated into an upstream path.
func TestFeedKeyMustBeACanonicalKey(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, func(c *Config) { c.ServeFeeds = true })
	for _, bad := range []string{"../../admin", "short", strings.Repeat("A", 200), "a!b!c"} {
		resp := get(t, svc, defaultPrefix+"/feed/"+bad+"/head", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%q: expected 404, got %d", bad, resp.StatusCode)
		}
	}
	if up.hits.Load() != 0 {
		t.Fatalf("an invalid feed key reached an upstream (%d fetches)", up.hits.Load())
	}
}

// ---------------------------------------------------------------------------
// rate limits, methods, SSRF
// ---------------------------------------------------------------------------

func TestRateLimitRejectsBurst(t *testing.T) {
	body := []byte("rate limited object")
	addr := HashBytes(body)
	up := newFakeUpstream()
	up.put("/chunk/"+addr.String(), body)
	svc := newTestService(t, up, func(c *Config) {
		c.RequestRate, c.RequestBurst = 0.0001, 3
		c.GlobalRate = -1
	})

	var limited int
	for i := 0; i < 10; i++ {
		if resp := get(t, svc, chunkPath(addr), nil); resp.StatusCode == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("per-address rate limit never fired")
	}
}

func TestGlobalRateLimitRejectsBurst(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, func(c *Config) {
		c.RequestRate = -1
		c.GlobalRate, c.GlobalBurst = 0.0001, 2
	})
	addr := HashBytes([]byte("x"))
	var limited int
	for i := 0; i < 10; i++ {
		if resp := get(t, svc, chunkPath(addr), nil); resp.StatusCode == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("global rate limit never fired")
	}
}

// TestHealthzIsNotRateLimited keeps liveness answerable while the role is under
// load — an operator must always be able to see what their node is doing.
func TestHealthzIsNotRateLimited(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, func(c *Config) { c.RequestRate, c.RequestBurst = 0.0001, 1 })
	for i := 0; i < 5; i++ {
		resp := get(t, svc, defaultPrefix+"/healthz", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("healthz got %d", resp.StatusCode)
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		if out["role"] != "dmtap-pub-cache" {
			t.Fatalf("unexpected healthz payload: %v", out)
		}
	}
}

// TestWriteMethodsRejected: the role has NO write surface — a cache is filled by
// reads through it, never by anyone pushing objects into it.
func TestWriteMethodsRejected(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, nil)
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		req := httptest.NewRequest(m, chunkPath(HashBytes([]byte("x"))), strings.NewReader("payload"))
		req.RemoteAddr = "192.0.2.10:1234"
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s should be 405, got %d", m, rec.Code)
		}
	}
}

// TestUpstreamsAreConfigOnly documents the SSRF posture structurally: bad
// upstream configurations are refused at construction, and there is no request
// input that can add one.
func TestUpstreamsAreConfigOnly(t *testing.T) {
	for _, bad := range []string{
		"file:///etc/passwd",
		"gopher://internal:70/",
		"https://user:pass@gw.example.com",
		"https://gw.example.com/?a=b",
		"https:///nohost",
	} {
		if _, err := New(Config{Upstreams: []string{bad}}); err == nil {
			t.Fatalf("upstream %q should have been rejected at construction", bad)
		}
	}
	if _, err := New(Config{Upstreams: []string{"https://gw.example.com/dmtap"}}); err != nil {
		t.Fatalf("a valid upstream was rejected: %v", err)
	}
}

// TestUpstreamRedirectsNotFollowed: a redirect is exactly how an allowlist gets
// talked out of its allowlist, so it must fail rather than be chased.
func TestUpstreamRedirectsNotFollowed(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret from a host the operator never listed"))
	}))
	defer elsewhere.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer redirector.Close()

	svc, err := New(Config{Upstreams: []string{redirector.URL}, RequestRate: -1, GlobalRate: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	resp := get(t, svc, chunkPath(HashBytes([]byte("x"))), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a redirected upstream must not be followed, got %d", resp.StatusCode)
	}
}

func TestUnknownPathsAreNotServed(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, nil)
	for _, p := range []string{
		defaultPrefix,
		defaultPrefix + "/",
		defaultPrefix + "/chunk",
		defaultPrefix + "/chunk/a/b",
		defaultPrefix + "/blob/" + HashBytes([]byte("x")).String(),
	} {
		if resp := get(t, svc, p, nil); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s should 404, got %d", p, resp.StatusCode)
		}
	}
}
