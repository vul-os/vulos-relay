package pubcache

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// service.go — the § 22.5.1 read surface, served as a read-through cache in
// front of operator-configured upstream gateways.
//
// Endpoint map (PathPrefix defaults to "/.well-known/dmtap-pub"):
//
//	GET {p}/announce/{id}            PubAnnounce   cached, immutable  (verified)
//	GET {p}/manifest/{id}            PubManifest   cached, immutable  (verified)
//	GET {p}/chunk/{h}                chunk bytes   cached, immutable  (verified)
//	GET {p}/feed/{pub}/head          FeedHead      NEVER cached, must-revalidate
//	GET {p}/feed/{pub}/range?from=&to=  [FeedEntry] NEVER cached, must-revalidate
//	GET {p}/healthz                  liveness + cache counters
//
// THE CACHEABILITY SPLIT IS A SECURITY BOUNDARY, not a performance tweak. The
// three content-addressed endpoints are immutable and self-verifying, so this
// node can PROVE a response correct before storing it and serves them with
// `Cache-Control: public, immutable` and a strong ETag equal to the content
// address (§ 22.5.1). A FeedHead is mutable and authenticated by a SIGNATURE
// chaining through a DeviceCert — something a cache cannot check with hashing
// alone — so § 22.5.1 permits either verifying signatures or not caching it, and
// this implementation takes the second path: feed reads are a bounded, revalidated
// passthrough that stores nothing. An unverifiable object is never held.
//
// Reads are anonymous by protocol requirement, so all limits are per-source-address
// and aggregate, and the role is OFF unless the operator turns it on (§ 22.6.1).

// Config configures a pubcache Service. The zero value is NOT a serving node:
// with no Upstreams the role answers 404 to everything, which is the correct
// "this holder does not serve that" (§ 22.6.2) rather than a broken endpoint.
type Config struct {
	// PathPrefix is the mount prefix. Default "/.well-known/dmtap-pub".
	PathPrefix string

	// Upstreams is the OPERATOR-CONFIGURED list of § 22.5.1 gateway base URLs
	// this cache reads through to, tried in order. This list is the ONLY set of
	// hosts the role will ever contact — a client can never name one, which is
	// what makes the role SSRF-free by construction rather than by filtering.
	Upstreams []string

	// MaxObjectBytes caps a single object. 0 => 16 MiB (comfortably above the
	// § 16.4 reference 1 MiB chunk, with room for a large manifest).
	MaxObjectBytes int64

	// MaxCacheBytes is the total store cap, enforced by LRU eviction.
	// 0 => 256 MiB.
	MaxCacheBytes int64

	// TTL is the per-object cache lifetime. Objects are immutable, so this is a
	// freshness/space policy, never a correctness one. 0 => 1h.
	TTL time.Duration

	// UpstreamTimeout bounds one upstream read. 0 => 15s.
	UpstreamTimeout time.Duration

	// MaxUpstreamInflight bounds concurrent upstream fetches across the whole
	// role, so a miss storm cannot be amplified onto the swarm. 0 => 16.
	MaxUpstreamInflight int

	// Rate limits. rate<=0 disables that limiter; 0 => a safe default.
	// RequestRate is per source address; GlobalRate is the aggregate.
	RequestRate, RequestBurst float64
	GlobalRate, GlobalBurst   float64
	RateLimitIdleTTL          time.Duration
	RateLimitMaxKeys          int

	// ServeFeeds enables the mutable feed passthrough (head/range). OFF by
	// default: it is the one part of the surface this node cannot verify, so an
	// operator opts into proxying it separately from opting into the cache.
	ServeFeeds bool

	// MaxFeedRange caps the span of a feed range request. 0 => 1024 entries.
	MaxFeedRange uint64

	// ServeProofs enables the OPTIONAL § 5.3 chunk-tree range-proof endpoint,
	// `manifest/{id}/proof?chunk=i`. OFF by default, which is not timidity: the
	// spec makes the endpoint advertised BY PRESENCE, so a 404 is the correct
	// and complete way to say "not offered here" and a fetcher simply falls back
	// to whole-manifest verification. Serving it costs a manifest fetch and an
	// O(n) tree walk per proof, so it stays an operator's explicit choice like
	// every other thing this role does.
	ServeProofs bool

	// HTTPClient overrides the upstream client (tests, custom transports).
	// A nil client gets one that does NOT follow redirects.
	HTTPClient *http.Client

	// ClientIP extracts the rate-limit key from a request. nil => RemoteAddr
	// host. The relay passes its own trusted-proxy-aware extractor; a bare
	// deployment must NOT trust forwarded headers, hence the conservative default.
	ClientIP func(*http.Request) string

	// Logger is the structured logger. nil => slog default.
	Logger *slog.Logger

	// now overrides the clock (tests). nil => time.Now.
	now func() time.Time
}

// Service is the cache/pin role as an http.Handler.
type Service struct {
	cfg       Config
	prefix    string
	log       *slog.Logger
	store     *store
	fetch     *fetcher
	upstreams []*url.URL

	reqLimiter    *limiter
	globalLimiter *limiter
}

const (
	defaultPrefix       = "/.well-known/dmtap-pub"
	defaultMaxObject    = 16 << 20
	defaultMaxCache     = 256 << 20
	defaultTTL          = time.Hour
	defaultUpstreamTO   = 15 * time.Second
	defaultInflight     = 16
	defaultMaxFeedRange = 1024
	// immutableMaxAge is the § 22.5.1 "long" max-age for content-addressed
	// objects. A year is the conventional ceiling; the object cannot change, so
	// the only reason to revalidate is that this holder stopped serving it.
	immutableMaxAge = 365 * 24 * 60 * 60
	// maxFeedKeyB64Len bounds the {pub} path component before any decoding.
	maxFeedKeyB64Len = 64
)

// New builds the service. It returns an error only for an unusable
// configuration (a malformed upstream URL); an EMPTY upstream list is legal and
// yields a node that serves only what it already holds — which is nothing, so it
// answers 404 (ERR_PUB_NOT_SERVED) to everything. That is a valid holder.
func New(cfg Config) (*Service, error) {
	if cfg.PathPrefix == "" {
		cfg.PathPrefix = defaultPrefix
	}
	cfg.PathPrefix = "/" + strings.Trim(cfg.PathPrefix, "/")
	if cfg.MaxObjectBytes <= 0 {
		cfg.MaxObjectBytes = defaultMaxObject
	}
	if cfg.MaxCacheBytes <= 0 {
		cfg.MaxCacheBytes = defaultMaxCache
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.UpstreamTimeout <= 0 {
		cfg.UpstreamTimeout = defaultUpstreamTO
	}
	if cfg.MaxUpstreamInflight <= 0 {
		cfg.MaxUpstreamInflight = defaultInflight
	}
	if cfg.MaxFeedRange == 0 {
		cfg.MaxFeedRange = defaultMaxFeedRange
	}
	if cfg.RequestRate == 0 {
		cfg.RequestRate, cfg.RequestBurst = 20, 60
	}
	if cfg.GlobalRate == 0 {
		cfg.GlobalRate, cfg.GlobalBurst = 500, 1000
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	ups, err := parseUpstreams(cfg.Upstreams)
	if err != nil {
		return nil, err
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: cfg.UpstreamTimeout,
			// A redirect is the one way a config allowlist could be talked out
			// of its allowlist, so it is refused outright.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("pubcache: upstream redirects are not followed")
			},
		}
	}

	s := &Service{
		cfg:           cfg,
		prefix:        cfg.PathPrefix,
		log:           cfg.Logger,
		store:         newStore(cfg.MaxCacheBytes, cfg.MaxObjectBytes, cfg.TTL, cfg.now),
		upstreams:     ups,
		fetch:         newFetcher(client, ups, cfg.MaxObjectBytes, cfg.MaxUpstreamInflight),
		reqLimiter:    newLimiter(cfg.RequestRate, cfg.RequestBurst, cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
		globalLimiter: newLimiter(cfg.GlobalRate, cfg.GlobalBurst, cfg.RateLimitIdleTTL, cfg.RateLimitMaxKeys),
	}
	return s, nil
}

// Prefix is the mount prefix this service answers on.
func (s *Service) Prefix() string { return s.prefix }

// Close releases the service's state. A stopped role holds nothing.
func (s *Service) Close() { s.store.purge() }

// Handles reports whether a request path belongs to this service.
func (s *Service) Handles(path string) bool {
	return path == s.prefix || strings.HasPrefix(path, s.prefix+"/")
}

func (s *Service) clientKey(r *http.Request) string {
	if s.cfg.ClientIP != nil {
		return s.cfg.ClientIP(r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.Handles(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	// Reads only. The role has no write surface at all: an operator's cache is
	// filled by reads through it, never by anyone pushing objects into it.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, s.prefix), "/")
	parts := strings.Split(rest, "/")

	if len(parts) == 1 && parts[0] == "healthz" {
		s.serveHealth(w)
		return
	}

	if !s.globalLimiter.allow("global") || !s.reqLimiter.allow(s.clientKey(r)) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	switch {
	case len(parts) == 2 && parts[0] == "announce":
		s.serveObject(w, r, KindAnnounce, parts[1], "application/cbor")
	case len(parts) == 2 && parts[0] == "manifest":
		s.serveObject(w, r, KindManifest, parts[1], "application/cbor")
	case len(parts) == 2 && parts[0] == "chunk":
		s.serveObject(w, r, KindChunk, parts[1], "application/octet-stream")
	case len(parts) == 3 && parts[0] == "manifest" && parts[2] == "proof":
		s.serveChunkProof(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "feed" && (parts[2] == "head" || parts[2] == "range"):
		s.serveFeed(w, r, parts[1], parts[2])
	default:
		s.notServed(w)
	}
}

// notServed is the § 22.6.2 refusal: a 404 meaning "this holder does not serve
// that" (ERR_PUB_NOT_SERVED, 0x090C). A fetcher rotates to another holder. It is
// used for every failure mode on purpose — missing, oversize, unverifiable, or
// policy-declined all look identical from outside, because a cache's refusal is
// never a statement about the object's existence.
func (s *Service) notServed(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "not served by this holder", http.StatusNotFound)
}

// serveObject handles the three content-addressed, cacheable endpoints.
func (s *Service) serveObject(w http.ResponseWriter, r *http.Request, kind Kind, addrStr, contentType string) {
	addr, err := ParseAddr(addrStr)
	if err != nil {
		s.notServed(w)
		return
	}
	key := cacheKey(kind, addr)

	body, cached := s.lookup(r, kind, key, addr)
	if !cached {
		s.notServed(w)
		return
	}

	etag := `"` + addr.String() + `"`
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("ETag", etag)
	// § 22.5.1: content-addressed objects are immutable and MAY be fronted by
	// any ordinary HTTP cache that need not understand DMTAP.
	h.Set("Cache-Control", "public, immutable, max-age="+strconv.Itoa(immutableMaxAge))
	h.Set("X-Content-Type-Options", "nosniff")

	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// lookup returns verified bytes for an address, from the store or by reading
// through to an upstream. It is the only path by which anything reaches the
// store, and Verify gates it unconditionally.
func (s *Service) lookup(r *http.Request, kind Kind, key string, addr Addr) ([]byte, bool) {
	if body, _, ok := s.store.get(key); ok {
		return body, true
	}

	suffix := "/" + kind.String() + "/" + addr.String()
	ctx := r.Context()
	body, _, err := s.fetch.do(ctx, key, suffix)
	if err != nil {
		return nil, false
	}

	// THE GATE. Bytes that do not match the address they were fetched by are
	// discarded and never stored — a poisoned upstream stops here rather than
	// being amplified by this node. The event is logged because a verify failure
	// means an upstream is broken or hostile, which an operator wants to know.
	if err := Verify(kind, addr, body); err != nil {
		s.log.Warn("pubcache: upstream object failed verification, refusing to cache or serve",
			"kind", kind.String(), "addr", addr.String(), "err", err)
		return nil, false
	}

	s.store.put(key, body)
	return body, true
}

// serveChunkProof implements the OPTIONAL § 5.3 endpoint:
//
//	GET {p}/manifest/{id}/proof?chunk=i  →  [i, [siblings…]]  (application/cbor)
//
// The manifest is resolved through the ordinary verified path, so a proof can
// only ever be built over a chunk list this node has already proved roots to
// {id}. That ordering is the whole safety argument: the node cannot serve a
// path over a list it has not verified, so the only proofs it can emit are true
// ones — and a client still verifies for itself, because a proof from a cache
// is a convenience, never a trust root (§ 5.3).
//
// The response is immutable and content-addressed by (id, i), so it carries the
// same long-lived Cache-Control as the other content-addressed reads and an
// ETag naming both coordinates.
func (s *Service) serveChunkProof(w http.ResponseWriter, r *http.Request, addrStr string) {
	// Advertised by presence: an operator who has not enabled it serves the
	// plain "not offered here" 404 and clients fall back (§ 5.3).
	if !s.cfg.ServeProofs {
		s.notServed(w)
		return
	}
	addr, err := ParseAddr(addrStr)
	if err != nil {
		s.notServed(w)
		return
	}
	idx, ok := parseChunkIndex(r.URL.Query())
	if !ok {
		s.notServed(w)
		return
	}

	body, cached := s.lookup(r, KindManifest, cacheKey(KindManifest, addr), addr)
	if !cached {
		s.notServed(w)
		return
	}
	// Re-derives the chunk list from bytes that already passed the gate; the
	// error is unreachable for stored bytes but is handled rather than asserted.
	chunks, err := verifiedManifestChunks(addr, body)
	if err != nil {
		s.notServed(w)
		return
	}
	path, err := ChunkProof(chunks, idx)
	if err != nil {
		// Out of range for this manifest. It collapses to the same refusal as
		// everything else: a holder's 404 is never a statement about what exists.
		s.notServed(w)
		return
	}
	proof := EncodeChunkProof(idx, path)

	etag := `"` + addr.String() + "." + strconv.Itoa(idx) + `"`
	h := w.Header()
	h.Set("Content-Type", "application/cbor")
	h.Set("ETag", etag)
	h.Set("Cache-Control", "public, immutable, max-age="+strconv.Itoa(immutableMaxAge))
	h.Set("X-Content-Type-Options", "nosniff")

	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(proof)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(proof)
	}
}

// parseChunkIndex reads the `chunk=i` query parameter. It is strict — a missing,
// negative, non-numeric, or non-canonical index is refused rather than coerced
// to 0, so a client can never be handed a proof for a chunk it did not ask about.
func parseChunkIndex(q url.Values) (int, bool) {
	raw := q.Get("chunk")
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, false
	}
	// Reject "007" and friends: the response is content-addressed by (id, i), so
	// two spellings of one index must not become two cache entries downstream.
	if strconv.FormatUint(v, 10) != raw {
		return 0, false
	}
	return int(v), true
}

// serveFeed proxies the two MUTABLE feed endpoints without ever storing them.
//
// A FeedHead's authenticity is a signature under the publisher's key, not a
// content address, so this node cannot prove one correct — and an object it
// cannot verify is an object it does not hold. Per § 22.5.1 the response carries
// must-revalidate so no downstream cache holds it either, and the reader does
// what only the reader can do: check the signature and apply § 22.4.2
// anti-rollback against the highest seq it has already accepted.
func (s *Service) serveFeed(w http.ResponseWriter, r *http.Request, pub, op string) {
	if !s.cfg.ServeFeeds {
		s.notServed(w)
		return
	}
	if !validFeedKey(pub) {
		s.notServed(w)
		return
	}

	suffix := "/feed/" + pub + "/" + op
	if op == "range" {
		from, to, ok := parseFeedRange(r.URL.Query(), s.cfg.MaxFeedRange)
		if !ok {
			s.notServed(w)
			return
		}
		suffix += "?from=" + strconv.FormatUint(from, 10) + "&to=" + strconv.FormatUint(to, 10)
	}

	// No single-flight coalescing for mutable reads: two readers asking at the
	// same moment may legitimately be entitled to two different heads, and
	// sharing one response would let a stale tip be served to a reader who would
	// otherwise have seen a newer one.
	body, ct, err := s.fetch.do(r.Context(), "", suffix)
	if err != nil {
		s.notServed(w)
		return
	}
	if ct == "" {
		ct = "application/cbor"
	}

	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Cache-Control", "no-cache, must-revalidate, max-age=0")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// validFeedKey checks the {pub} path component is a canonical unpadded-base64url
// Ed25519 public key, so nothing else can ever be interpolated into an upstream
// path.
func validFeedKey(s string) bool {
	if s == "" || len(s) > maxFeedKeyB64Len {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(raw) == s
}

// parseFeedRange validates and bounds a feed range query. An unbounded or
// inverted range is refused rather than clamped, so a client always knows what
// it asked for.
func parseFeedRange(q url.Values, max uint64) (from, to uint64, ok bool) {
	fs, ts := q.Get("from"), q.Get("to")
	if fs == "" || ts == "" {
		return 0, 0, false
	}
	from, err := strconv.ParseUint(fs, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	to, err = strconv.ParseUint(ts, 10, 64)
	if err != nil || to < from {
		return 0, 0, false
	}
	if to-from+1 > max {
		return 0, 0, false
	}
	return from, to, true
}

// etagMatches implements the If-None-Match comparison for our strong ETags,
// including the "*" wildcard and comma-separated lists.
func etagMatches(header, etag string) bool {
	for _, cand := range strings.Split(header, ",") {
		cand = strings.TrimSpace(cand)
		if cand == "*" || cand == etag {
			return true
		}
	}
	return false
}

func (s *Service) serveHealth(w http.ResponseWriter) {
	st := s.store.stats()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"role":       "dmtap-pub-cache",
		"upstreams":  len(s.upstreams),
		"serveFeeds": s.cfg.ServeFeeds,
		"objects":    st.Objects,
		"bytes":      st.Bytes,
		"maxBytes":   s.cfg.MaxCacheBytes,
		"hits":       st.Hits,
		"misses":     st.Misses,
		"stores":     st.Stores,
		"evictions":  st.Evictions,
		"expired":    st.Expired,
		"rejected":   st.Rejected,
	})
}
