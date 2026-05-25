// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---- Pool quarantine interface -----------------------------------------------

// IPPool is the subset of the IP pool that BlocklistMonitor needs to quarantine
// and release IPs. It is satisfied by the Pool type from internal/sending when
// that package is compiled in; callers inject it to keep packages decoupled.
type IPPool interface {
	// Quarantine removes ip from active rotation for the given reason.
	Quarantine(ip net.IP, reason string)
	// Unquarantine restores ip to active rotation.
	Unquarantine(ip net.IP)
}

// ---- Resolver abstraction (stub-able in tests) -------------------------------

// DNSResolver performs reverse DNSBL lookups. The default implementation uses
// net.DefaultResolver. Tests inject a stub.
type DNSResolver interface {
	// LookupHost resolves name to addresses. Used as a DNSBL existence check:
	// if the DNSBL-reversed name resolves, the IP is listed.
	LookupHost(ctx context.Context, name string) ([]string, error)
}

type netResolver struct{}

func (netResolver) LookupHost(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, name)
}

// ---- HTTPClient abstraction (stub-able in tests) ----------------------------

// HTTPClient is the minimal HTTP interface used by BlocklistSource
// implementations that query HTTP APIs.
type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

// ---- BlocklistSource interface ----------------------------------------------

// ListingStatus is the result of querying a single blocklist source for one IP.
type ListingStatus struct {
	// Listed is true when the IP is currently on this blocklist.
	Listed bool

	// Reason is the human-readable explanation returned by the source, if any.
	Reason string

	// ReturnCodes is the set of A-record values returned by a DNSBL lookup
	// (each code encodes a listing category).
	ReturnCodes []string

	// DelistURL is the URL at which a delist request can be submitted, if
	// the source provides one.
	DelistURL string
}

// BlocklistSource is the pluggable interface for a single DNSBL/reputation
// source. Implementing this interface is sufficient to add a new source to
// BlocklistMonitor.
type BlocklistSource interface {
	// Name returns a stable identifier for this source (e.g. "spamhaus", "sorbs").
	Name() string

	// Check returns the ListingStatus for ip. A non-nil error indicates a
	// lookup failure; callers should treat errors as transient.
	Check(ctx context.Context, ip net.IP) (ListingStatus, error)

	// Delist attempts to submit an automated delist request for ip. Returns
	// nil if the request was submitted successfully or if the source does not
	// support automated delisting (in which case it is a no-op).
	Delist(ctx context.Context, ip net.IP) error
}

// ---- Listing record (internal state) ----------------------------------------

type listingRecord struct {
	source     string
	detectedAt time.Time
	cleared    bool
	clearedAt  time.Time
	retryAfter time.Time
}

// ---- BlocklistMonitor -------------------------------------------------------

// BlocklistMonitorConfig holds configuration for a BlocklistMonitor.
type BlocklistMonitorConfig struct {
	// PollInterval is how often all sources are polled for all IPs.
	// Default: 30 minutes.
	PollInterval time.Duration

	// RecheckInterval is the initial backoff between re-checks after a listing
	// is detected. It doubles on each re-check (exponential backoff).
	// Default: 10 minutes.
	RecheckInterval time.Duration

	// MaxRecheckInterval caps the exponential backoff.
	// Default: 2 hours.
	MaxRecheckInterval time.Duration

	// QuarantineObserver, if non-nil, is notified each time an IP is newly
	// quarantined (for metrics). It must be non-blocking and concurrency-safe.
	QuarantineObserver QuarantineObserver

	// Logger is used for operational messages. If nil, the standard logger is used.
	Logger *log.Logger
}

// QuarantineObserver receives a notification when the BlocklistMonitor newly
// quarantines an IP, so an external metrics layer can count quarantine events
// without this package importing the prometheus stack.
type QuarantineObserver interface {
	// Quarantined reports that an IP was quarantined by the given blocklist
	// source (e.g. "spamhaus", "sorbs").
	Quarantined(source string)
}

func (c *BlocklistMonitorConfig) pollInterval() time.Duration {
	if c.PollInterval <= 0 {
		return 30 * time.Minute
	}
	return c.PollInterval
}

func (c *BlocklistMonitorConfig) recheckInterval() time.Duration {
	if c.RecheckInterval <= 0 {
		return 10 * time.Minute
	}
	return c.RecheckInterval
}

func (c *BlocklistMonitorConfig) maxRecheckInterval() time.Duration {
	if c.MaxRecheckInterval <= 0 {
		return 2 * time.Hour
	}
	return c.MaxRecheckInterval
}

func (c *BlocklistMonitorConfig) logger() *log.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return log.Default()
}

// Listing is an externally-visible record of a blocklist listing for one IP on
// one source. Used for alerting and metrics.
type Listing struct {
	// IP is the listed address.
	IP net.IP

	// Source is the blocklist source name.
	Source string

	// DetectedAt is when the listing was first observed.
	DetectedAt time.Time

	// Cleared is true if the IP has since been removed from the list.
	Cleared bool

	// ClearedAt is when the clearing was confirmed (zero if not yet cleared).
	ClearedAt time.Time
}

// BlocklistMonitor polls a set of BlocklistSource implementations for every
// IP in its watchlist, quarantines newly-listed IPs via IPPool, submits
// automated delist requests, and unquarantines IPs once they are confirmed
// clear.
//
// Sources can be added or removed via AddSource/RemoveSource. IPs under
// monitoring are managed via WatchIP/UnwatchIP.
//
// Run blocks until ctx is cancelled (graceful shutdown).
type BlocklistMonitor struct {
	mu      sync.Mutex
	sources []BlocklistSource
	ips     []net.IP
	pool    IPPool
	cfg     BlocklistMonitorConfig

	// listings maps "ip|source" → *listingRecord for active/recent listings.
	listings map[string]*listingRecord
}

// NewBlocklistMonitor creates a BlocklistMonitor with the given IP pool and
// configuration. Sources and IPs must be added before (or shortly after)
// calling Run.
func NewBlocklistMonitor(pool IPPool, cfg BlocklistMonitorConfig) *BlocklistMonitor {
	return &BlocklistMonitor{
		pool:     pool,
		cfg:      cfg,
		listings: make(map[string]*listingRecord),
	}
}

// AddSource registers a new BlocklistSource. It is safe to call before or
// during Run.
func (m *BlocklistMonitor) AddSource(s BlocklistSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sources = append(m.sources, s)
}

// RemoveSource unregisters the source with the given name. It is safe to call
// before or during Run.
func (m *BlocklistMonitor) RemoveSource(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	filtered := m.sources[:0]
	for _, s := range m.sources {
		if s.Name() != name {
			filtered = append(filtered, s)
		}
	}
	m.sources = filtered
}

// WatchIP adds ip to the set of IPs monitored by this BlocklistMonitor.
func (m *BlocklistMonitor) WatchIP(ip net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.ips {
		if existing.Equal(ip) {
			return // already watched
		}
	}
	m.ips = append(m.ips, ip)
}

// UnwatchIP removes ip from the monitored set.
func (m *BlocklistMonitor) UnwatchIP(ip net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	filtered := m.ips[:0]
	for _, existing := range m.ips {
		if !existing.Equal(ip) {
			filtered = append(filtered, existing)
		}
	}
	m.ips = filtered
}

// Listings returns a snapshot of all known listings (active and cleared).
func (m *BlocklistMonitor) Listings() []Listing {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Listing, 0, len(m.listings))
	for _, rec := range m.listings {
		// Parse key "ip|source"
		parts := strings.SplitN(rec.source, "|", 2)
		srcName := rec.source
		ipStr := ""
		if len(parts) == 2 {
			ipStr = parts[0]
			srcName = parts[1]
		}
		out = append(out, Listing{
			IP:         net.ParseIP(ipStr),
			Source:     srcName,
			DetectedAt: rec.detectedAt,
			Cleared:    rec.cleared,
			ClearedAt:  rec.clearedAt,
		})
	}
	return out
}

// Poll performs one full poll of all sources for all watched IPs. It is safe
// to call directly (e.g. in tests); Run calls it on the configured interval.
func (m *BlocklistMonitor) Poll(ctx context.Context) {
	m.mu.Lock()
	ips := make([]net.IP, len(m.ips))
	copy(ips, m.ips)
	sources := make([]BlocklistSource, len(m.sources))
	copy(sources, m.sources)
	m.mu.Unlock()

	logger := m.cfg.logger()

	for _, ip := range ips {
		for _, src := range sources {
			status, err := src.Check(ctx, ip)
			if err != nil {
				logger.Printf("blocklist: check %s for %s: %v", src.Name(), ip, err)
				continue
			}

			key := ip.String() + "|" + src.Name()

			m.mu.Lock()
			rec, exists := m.listings[key]

			if status.Listed {
				if !exists {
					// New listing: record, quarantine, and attempt auto-delist.
					rec = &listingRecord{
						source:     key,
						detectedAt: time.Now(),
						retryAfter: time.Now().Add(m.cfg.recheckInterval()),
					}
					m.listings[key] = rec
					m.mu.Unlock()

					logger.Printf("blocklist: NEW LISTING — ip=%s source=%s reason=%q delistURL=%s",
						ip, src.Name(), status.Reason, status.DelistURL)

					if m.pool != nil {
						m.pool.Quarantine(ip, fmt.Sprintf("blocklist:%s:%s", src.Name(), status.Reason))
					}
					if m.cfg.QuarantineObserver != nil {
						m.cfg.QuarantineObserver.Quarantined(src.Name())
					}

					// Fire auto-delist (non-blocking; errors are logged).
					go func(s BlocklistSource, lip net.IP) {
						if delistErr := s.Delist(ctx, lip); delistErr != nil {
							logger.Printf("blocklist: delist request %s for %s: %v", s.Name(), lip, delistErr)
						}
					}(src, ip)

				} else {
					// Still listed — update retry window with exponential backoff.
					rec.retryAfter = nextRetry(rec.retryAfter, m.cfg.recheckInterval(), m.cfg.maxRecheckInterval())
					m.mu.Unlock()
				}
			} else {
				if exists && !rec.cleared {
					// IP just cleared: unquarantine.
					rec.cleared = true
					rec.clearedAt = time.Now()
					m.mu.Unlock()

					logger.Printf("blocklist: CLEARED — ip=%s source=%s", ip, src.Name())
					if m.pool != nil {
						m.pool.Unquarantine(ip)
					}
				} else {
					m.mu.Unlock()
				}
			}
		}
	}
}

// Run starts the periodic polling loop. It returns when ctx is cancelled.
func (m *BlocklistMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.pollInterval())
	defer ticker.Stop()

	// Perform an immediate poll on startup.
	m.Poll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Poll(ctx)
		}
	}
}

// nextRetry computes the next recheck time using exponential backoff with jitter.
func nextRetry(prev time.Time, base, max time.Duration) time.Time {
	elapsed := time.Since(prev)
	next := base
	if elapsed > 0 {
		next = elapsed * 2
	}
	if next > max {
		next = max
	}
	// Add up to 10% jitter.
	jitter := time.Duration(rand.Int63n(int64(next / 10)))
	return time.Now().Add(next + jitter)
}

// ---- DNSBLSource: shared helper for DNSBL-based sources ---------------------

// dnsblCheck performs the standard DNSBL reverse-IP lookup against zone.
// Returns (listed, returnCodes, error).
func dnsblCheck(ctx context.Context, r DNSResolver, ip net.IP, zone string) (bool, []string, error) {
	reversed, err := reverseDNSBL(ip)
	if err != nil {
		return false, nil, fmt.Errorf("reverse ip %s: %w", ip, err)
	}
	query := reversed + "." + zone
	addrs, err := r.LookupHost(ctx, query)
	if err != nil {
		// A NXDOMAIN-type failure means "not listed".
		if isDNSNotFound(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("lookup %s: %w", query, err)
	}
	return len(addrs) > 0, addrs, nil
}

// reverseDNSBL returns the DNSBL-reversed form of ip (e.g. 1.2.3.4 → "4.3.2.1").
func reverseDNSBL(ip net.IP) (string, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("only IPv4 DNSBL reversal supported; got %s", ip)
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0]), nil
}

// isDNSNotFound returns true for "no such host" / NXDOMAIN errors.
func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	if err == nil {
		return false
	}
	// Use errors.As behaviour via type assertion (avoids import of errors pkg
	// purely for this helper; the net package wraps its errors consistently).
	if e, ok := err.(*net.DNSError); ok {
		return e.IsNotFound
	}
	_ = dnsErr
	s := err.Error()
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "NXDOMAIN") ||
		strings.Contains(s, "not exist")
}

// ---- Spamhaus ---------------------------------------------------------------

// SpamhausSource checks the Spamhaus ZEN combined blocklist (SBL+XBL+PBL)
// via DNSBL. Automated delisting is not available for all sub-lists; the
// stub logs the appropriate URL for operator action.
type SpamhausSource struct {
	Resolver DNSResolver
	// Zone is the DNSBL zone; default "zen.spamhaus.org".
	Zone string
}

func (s *SpamhausSource) Name() string { return "spamhaus" }

func (s *SpamhausSource) resolver() DNSResolver {
	if s.Resolver != nil {
		return s.Resolver
	}
	return netResolver{}
}

func (s *SpamhausSource) zone() string {
	if s.Zone != "" {
		return s.Zone
	}
	return "zen.spamhaus.org"
}

func (s *SpamhausSource) Check(ctx context.Context, ip net.IP) (ListingStatus, error) {
	listed, codes, err := dnsblCheck(ctx, s.resolver(), ip, s.zone())
	if err != nil {
		return ListingStatus{}, err
	}
	var reason string
	if listed {
		reason = spamhausReason(codes)
	}
	return ListingStatus{
		Listed:      listed,
		Reason:      reason,
		ReturnCodes: codes,
		DelistURL:   "https://www.spamhaus.org/lookup/",
	}, nil
}

// Delist for Spamhaus is a stub: the SBL requires manual review and the
// PBL/XBL have web-form flows. We log the URL; a future implementation may
// POST to the appropriate endpoint.
func (s *SpamhausSource) Delist(_ context.Context, ip net.IP) error {
	log.Printf("blocklist/spamhaus: manual delist required for %s — visit https://www.spamhaus.org/lookup/", ip)
	return nil
}

func spamhausReason(codes []string) string {
	for _, c := range codes {
		switch {
		case strings.HasPrefix(c, "127.0.0.2"), strings.HasPrefix(c, "127.0.0.3"),
			strings.HasPrefix(c, "127.0.0.4"), strings.HasPrefix(c, "127.0.0.5"),
			strings.HasPrefix(c, "127.0.0.6"), strings.HasPrefix(c, "127.0.0.7"):
			return "SBL (Spamhaus Block List)"
		case strings.HasPrefix(c, "127.0.0.10"), strings.HasPrefix(c, "127.0.0.11"):
			return "XBL (Exploits Block List)"
		case strings.HasPrefix(c, "127.0.0.14"), strings.HasPrefix(c, "127.0.0.15"):
			return "PBL (Policy Block List)"
		}
	}
	if len(codes) > 0 {
		return "listed: " + strings.Join(codes, ",")
	}
	return "listed"
}

// ---- SORBS ------------------------------------------------------------------

// SORBSSource checks the SORBS DNSBL (dnsbl.sorbs.net aggregated zone).
type SORBSSource struct {
	Resolver DNSResolver
	// Zone is the DNSBL zone; default "dnsbl.sorbs.net".
	Zone string
}

func (s *SORBSSource) Name() string { return "sorbs" }

func (s *SORBSSource) resolver() DNSResolver {
	if s.Resolver != nil {
		return s.Resolver
	}
	return netResolver{}
}

func (s *SORBSSource) zone() string {
	if s.Zone != "" {
		return s.Zone
	}
	return "dnsbl.sorbs.net"
}

func (s *SORBSSource) Check(ctx context.Context, ip net.IP) (ListingStatus, error) {
	listed, codes, err := dnsblCheck(ctx, s.resolver(), ip, s.zone())
	if err != nil {
		return ListingStatus{}, err
	}
	return ListingStatus{
		Listed:      listed,
		Reason:      sorbsReason(codes),
		ReturnCodes: codes,
		DelistURL:   "https://www.sorbs.net/cgi-bin/lookup",
	}, nil
}

// Delist for SORBS is a stub: SORBS requires account creation and form
// submission. The URL is logged for operator action.
func (s *SORBSSource) Delist(_ context.Context, ip net.IP) error {
	log.Printf("blocklist/sorbs: manual delist required for %s — visit https://www.sorbs.net/cgi-bin/lookup", ip)
	return nil
}

func sorbsReason(codes []string) string {
	if len(codes) == 0 {
		return ""
	}
	return "listed in SORBS: " + strings.Join(codes, ",")
}

// ---- Barracuda --------------------------------------------------------------

// BarracudaSource checks the Barracuda Reputation Block List (BRBL) via DNSBL
// and submits delist requests to the Barracuda delist portal via HTTP GET.
type BarracudaSource struct {
	Resolver   DNSResolver
	HTTPClient HTTPClient

	// Zone is the DNSBL zone; default "b.barracudacentral.org".
	Zone string

	// DelistBaseURL is the base for automated delist requests.
	// Default: "https://www.barracudacentral.org/rbl/removal-request"
	DelistBaseURL string
}

func (s *BarracudaSource) Name() string { return "barracuda" }

func (s *BarracudaSource) resolver() DNSResolver {
	if s.Resolver != nil {
		return s.Resolver
	}
	return netResolver{}
}

func (s *BarracudaSource) httpClient() HTTPClient {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return http.DefaultClient
}

func (s *BarracudaSource) zone() string {
	if s.Zone != "" {
		return s.Zone
	}
	return "b.barracudacentral.org"
}

func (s *BarracudaSource) delistBaseURL() string {
	if s.DelistBaseURL != "" {
		return s.DelistBaseURL
	}
	return "https://www.barracudacentral.org/rbl/removal-request"
}

func (s *BarracudaSource) Check(ctx context.Context, ip net.IP) (ListingStatus, error) {
	listed, codes, err := dnsblCheck(ctx, s.resolver(), ip, s.zone())
	if err != nil {
		return ListingStatus{}, err
	}
	delistURL := ""
	if listed {
		delistURL = s.delistBaseURL() + "?ip=" + ip.String()
	}
	return ListingStatus{
		Listed:      listed,
		Reason:      barracudaReason(codes),
		ReturnCodes: codes,
		DelistURL:   delistURL,
	}, nil
}

// Delist submits an automated delist request to the Barracuda removal portal.
func (s *BarracudaSource) Delist(_ context.Context, ip net.IP) error {
	url := s.delistBaseURL() + "?ip=" + ip.String()
	resp, err := s.httpClient().Get(url)
	if err != nil {
		return fmt.Errorf("barracuda delist GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("barracuda delist: server returned %d", resp.StatusCode)
	}
	log.Printf("blocklist/barracuda: delist request submitted for %s (status %d)", ip, resp.StatusCode)
	return nil
}

func barracudaReason(codes []string) string {
	if len(codes) == 0 {
		return ""
	}
	return "listed in Barracuda RBL: " + strings.Join(codes, ",")
}

// ---- SenderScore (HTTP) -----------------------------------------------------

// SenderScoreSource queries the SenderScore reputation API (ReturnPath/Validity)
// for an IP score and treats scores below a threshold as a "listing" for
// quarantine purposes. Automated delisting is not supported; the stub logs a
// remediation URL.
type SenderScoreSource struct {
	HTTPClient HTTPClient

	// APIBaseURL is the SenderScore lookup URL template. The string "{ip}" is
	// replaced with the IP. Default: "https://senderscore.org/assess/score/{ip}"
	APIBaseURL string

	// BadThreshold is the score at or below which an IP is treated as listed.
	// SenderScore is 0–100; default threshold is 70.
	BadThreshold int
}

func (s *SenderScoreSource) Name() string { return "senderscore" }

func (s *SenderScoreSource) httpClient() HTTPClient {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return http.DefaultClient
}

func (s *SenderScoreSource) apiURL(ip net.IP) string {
	base := s.APIBaseURL
	if base == "" {
		base = "https://senderscore.org/assess/score/{ip}"
	}
	return strings.ReplaceAll(base, "{ip}", ip.String())
}

func (s *SenderScoreSource) badThreshold() int {
	if s.BadThreshold <= 0 {
		return 70
	}
	return s.BadThreshold
}

// Check queries the SenderScore API. If the HTTP GET returns 200 with a score
// body ≤ threshold, the IP is treated as listed. Any non-200 response or
// parse error is treated as a transient error (not a listing).
func (s *SenderScoreSource) Check(_ context.Context, ip net.IP) (ListingStatus, error) {
	url := s.apiURL(ip)
	resp, err := s.httpClient().Get(url)
	if err != nil {
		return ListingStatus{}, fmt.Errorf("senderscore GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ListingStatus{}, fmt.Errorf("senderscore read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return ListingStatus{}, fmt.Errorf("senderscore: non-200 status %d", resp.StatusCode)
	}

	var score int
	_, err = fmt.Sscanf(strings.TrimSpace(string(body)), "%d", &score)
	if err != nil {
		// Body not parseable as a plain integer — treat as a transient error
		// rather than a false listing.
		return ListingStatus{}, fmt.Errorf("senderscore: parse score %q: %w", string(body), err)
	}

	listed := score <= s.badThreshold()
	reason := ""
	if listed {
		reason = fmt.Sprintf("score %d ≤ threshold %d", score, s.badThreshold())
	}
	return ListingStatus{
		Listed:    listed,
		Reason:    reason,
		DelistURL: "https://senderscore.org/",
	}, nil
}

// Delist is a stub: SenderScore does not have an automated delist endpoint.
func (s *SenderScoreSource) Delist(_ context.Context, ip net.IP) error {
	log.Printf("blocklist/senderscore: no automated delist for %s — visit https://senderscore.org/ for remediation guidance", ip)
	return nil
}
