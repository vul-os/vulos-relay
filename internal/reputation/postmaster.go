// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// ProviderSignal is a normalised reputation data point ingested from either
// Google Postmaster Tools or Microsoft SNDS.
type ProviderSignal struct {
	// IP is the source IP the signal applies to (may be nil for domain-level signals).
	IP net.IP

	// Domain is the sending domain the signal applies to.
	Domain string

	// Provider identifies the data source (e.g. "google", "microsoft-snds").
	Provider string

	// SpamRate is the fraction of messages flagged as spam (0.0–1.0).
	SpamRate float64

	// ComplaintRate is the FBL complaint rate (0.0–1.0).
	ComplaintRate float64

	// FBLCount is the raw feedback loop complaint count, if reported.
	FBLCount int

	// SampledAt is the time the provider reported the data.
	SampledAt time.Time
}

// SignalSource is the read side of a provider reputation data store.  The
// reputation policy and warm-up scheduler read from it to make decisions.
type SignalSource interface {
	// SignalsByIP returns all stored signals for the given IP.
	SignalsByIP(ip net.IP) []ProviderSignal

	// SignalsByDomain returns all stored signals for the given domain.
	SignalsByDomain(domain string) []ProviderSignal
}

// ---- shared in-memory signal store ------------------------------------------

type signalStore struct {
	mu       sync.RWMutex
	byIP     map[string][]ProviderSignal
	byDomain map[string][]ProviderSignal
}

func newSignalStore() *signalStore {
	return &signalStore{
		byIP:     make(map[string][]ProviderSignal),
		byDomain: make(map[string][]ProviderSignal),
	}
}

func (s *signalStore) store(sig ProviderSignal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sig.IP != nil {
		key := sig.IP.String()
		s.byIP[key] = append(s.byIP[key], sig)
	}
	if sig.Domain != "" {
		s.byDomain[sig.Domain] = append(s.byDomain[sig.Domain], sig)
	}
}

func (s *signalStore) SignalsByIP(ip net.IP) []ProviderSignal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := ip.String()
	cp := make([]ProviderSignal, len(s.byIP[key]))
	copy(cp, s.byIP[key])
	return cp
}

func (s *signalStore) SignalsByDomain(domain string) []ProviderSignal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]ProviderSignal, len(s.byDomain[domain]))
	copy(cp, s.byDomain[domain])
	return cp
}

// ---- Google Postmaster Tools client -----------------------------------------

// PostmasterConfig holds credentials and settings for the Google Postmaster
// Tools client.
type PostmasterConfig struct {
	// APIKey is the Google API key.  If empty, the client is a no-op.
	APIKey string

	// Domains is the list of sending domains to query.
	Domains []string

	// BaseURL is the Postmaster Tools REST base URL.
	// Default: "https://gmailpostmastertools.googleapis.com/v1".
	BaseURL string

	// HTTPClient is used for API calls.  If nil, http.DefaultClient is used.
	HTTPClient HTTPClient

	// Logger is used for operational messages.  If nil, log.Default() is used.
	Logger *log.Logger
}

func (c *PostmasterConfig) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return "https://gmailpostmastertools.googleapis.com/v1"
}

func (c *PostmasterConfig) httpClient() HTTPClient {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *PostmasterConfig) logger() *log.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return log.Default()
}

// PostmasterClient pulls domain/IP reputation data from Google Postmaster Tools
// and stores normalised ProviderSignals.
//
// If APIKey is empty, all Sync calls are no-ops (a single warning is logged on
// the first call) — self-hosters without provider access are not penalised.
type PostmasterClient struct {
	cfg        PostmasterConfig
	store      *signalStore
	warnedOnce sync.Once
}

// NewPostmasterClient creates a PostmasterClient.
func NewPostmasterClient(cfg PostmasterConfig) *PostmasterClient {
	return &PostmasterClient{cfg: cfg, store: newSignalStore()}
}

// Sync pulls the latest Postmaster Tools data for all configured domains.
func (c *PostmasterClient) Sync(ctx context.Context) error {
	if c.cfg.APIKey == "" {
		c.warnedOnce.Do(func() {
			c.cfg.logger().Print("postmaster: no API key configured — Google Postmaster Tools sync disabled")
		})
		return nil
	}

	for _, domain := range c.cfg.Domains {
		if err := c.syncDomain(ctx, domain); err != nil {
			c.cfg.logger().Printf("postmaster: sync domain %s: %v", domain, err)
		}
	}
	return nil
}

// postmasterTrafficStats mirrors the relevant fields from the Postmaster Tools
// REST API response for a single day's traffic stats.
type postmasterTrafficStats struct {
	Name                  string  `json:"name"`
	UserReportedSpamRatio float64 `json:"userReportedSpamRatio"`
	DomainReputation      string  `json:"domainReputation"`
}

func (c *PostmasterClient) syncDomain(ctx context.Context, domain string) error {
	url := fmt.Sprintf("%s/domains/%s/trafficStats?key=%s",
		c.cfg.baseURL(), domain, c.cfg.APIKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := c.cfg.httpClient().Get(req.URL.String())
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("postmaster API status %d: %s", resp.StatusCode, string(body))
	}

	// The API returns a list of daily traffic stats.
	var result struct {
		TrafficStats []postmasterTrafficStats `json:"trafficStats"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	for _, stat := range result.TrafficStats {
		sig := ProviderSignal{
			Domain:    domain,
			Provider:  "google",
			SpamRate:  stat.UserReportedSpamRatio,
			SampledAt: time.Now(),
		}
		c.store.store(sig)
	}
	return nil
}

// SignalsByIP implements SignalSource.
func (c *PostmasterClient) SignalsByIP(ip net.IP) []ProviderSignal {
	return c.store.SignalsByIP(ip)
}

// SignalsByDomain implements SignalSource.
func (c *PostmasterClient) SignalsByDomain(domain string) []ProviderSignal {
	return c.store.SignalsByDomain(domain)
}

var _ SignalSource = (*PostmasterClient)(nil)

// ---- Microsoft SNDS client --------------------------------------------------

// SNDSConfig holds credentials and settings for the Microsoft SNDS client.
type SNDSConfig struct {
	// DataKey is the SNDS data-feed key.  If empty, the client is a no-op.
	DataKey string

	// APIURL is the SNDS data-feed CSV URL template.  The string "{key}" is
	// replaced with DataKey.
	// Default: "https://sendersupport.olc.protection.outlook.com/snds/data.aspx?key={key}"
	APIURL string

	// HTTPClient is used for the data-feed download.  If nil, http.DefaultClient.
	HTTPClient HTTPClient

	// Logger is used for operational messages.  If nil, log.Default().
	Logger *log.Logger
}

func (c *SNDSConfig) apiURL() string {
	base := c.APIURL
	if base == "" {
		base = "https://sendersupport.olc.protection.outlook.com/snds/data.aspx?key={key}"
	}
	// Replace {key} with actual key.
	result := ""
	for i := 0; i < len(base); i++ {
		if i+5 <= len(base) && base[i:i+5] == "{key}" {
			result += c.DataKey
			i += 4
		} else {
			result += string(base[i])
		}
	}
	return result
}

func (c *SNDSConfig) httpClient() HTTPClient {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *SNDSConfig) logger() *log.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return log.Default()
}

// SNDSClient pulls IP reputation data from Microsoft SNDS and stores
// normalised ProviderSignals.
//
// If DataKey is empty, all Sync calls are no-ops (one warning logged).
type SNDSClient struct {
	cfg        SNDSConfig
	store      *signalStore
	warnedOnce sync.Once
}

// NewSNDSClient creates an SNDSClient.
func NewSNDSClient(cfg SNDSConfig) *SNDSClient {
	return &SNDSClient{cfg: cfg, store: newSignalStore()}
}

// Sync downloads and parses the SNDS CSV data feed.
func (c *SNDSClient) Sync(ctx context.Context) error {
	if c.cfg.DataKey == "" {
		c.warnedOnce.Do(func() {
			c.cfg.logger().Print("snds: no data key configured — Microsoft SNDS sync disabled")
		})
		return nil
	}

	url := c.cfg.apiURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("snds: build request: %w", err)
	}

	resp, err := c.cfg.httpClient().Get(req.URL.String())
	if err != nil {
		return fmt.Errorf("snds: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("snds: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("snds: status %d", resp.StatusCode)
	}

	sigs, err := parseSNDSCSV(body)
	if err != nil {
		return fmt.Errorf("snds: parse CSV: %w", err)
	}
	for _, sig := range sigs {
		c.store.store(sig)
	}
	c.cfg.logger().Printf("snds: ingested %d signals", len(sigs))
	return nil
}

// parseSNDSCSV parses a Microsoft SNDS CSV feed.
//
// Expected format (tab-separated, with header row):
//
//	IP Range	Activity Start Date	Activity End Date	Sending IP	Spam Trap Hits	Filter Result	Complaint Rate	Trap Hits	...
//
// We parse best-effort: unknown column orders or extra columns are tolerated.
func parseSNDSCSV(data []byte) ([]ProviderSignal, error) {
	lines := splitLines(string(data))
	if len(lines) == 0 {
		return nil, nil
	}

	// Detect separator: SNDS uses comma or tab.
	sep := ','
	if countRune(lines[0], '\t') > countRune(lines[0], ',') {
		sep = '\t'
	}

	headers := splitFields(lines[0], sep)
	colIdx := make(map[string]int, len(headers))
	for i, h := range headers {
		colIdx[normaliseHeader(h)] = i
	}

	var out []ProviderSignal
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		fields := splitFields(line, sep)
		if len(fields) < 2 {
			continue
		}

		sig := ProviderSignal{
			Provider:  "microsoft-snds",
			SampledAt: time.Now(),
		}

		// Parse IP (first column by name, or fall back to index 0).
		ipField := fieldAt(fields, colIdx, "sendingip", 0)
		if ipField == "" {
			ipField = fieldAt(fields, colIdx, "iprange", 0)
		}
		if ip := net.ParseIP(trimSpace(ipField)); ip != nil {
			sig.IP = ip
		}

		// Spam trap hits.
		trapField := fieldAt(fields, colIdx, "spamtraphits", -1)
		if trapField != "" {
			var n int
			fmt.Sscanf(trimSpace(trapField), "%d", &n)
			sig.FBLCount = n
		}

		// Complaint rate.
		complaintField := fieldAt(fields, colIdx, "complaintrate", -1)
		if complaintField != "" {
			var r float64
			// SNDS may express as a percentage string like "0.00%" or "1.5%".
			pct := trimSpace(complaintField)
			if len(pct) > 0 && pct[len(pct)-1] == '%' {
				fmt.Sscanf(pct[:len(pct)-1], "%f", &r)
				r /= 100.0
			} else {
				fmt.Sscanf(pct, "%f", &r)
			}
			sig.ComplaintRate = r
		}

		out = append(out, sig)
	}
	return out, nil
}

// ---- CSV parsing helpers (no "encoding/csv" import to stay simple) ----------

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitFields(s string, sep rune) []string {
	var fields []string
	start := 0
	for i, ch := range s {
		if ch == sep {
			fields = append(fields, s[start:i])
			start = i + 1
		}
	}
	fields = append(fields, s[start:])
	return fields
}

func countRune(s string, r rune) int {
	n := 0
	for _, ch := range s {
		if ch == r {
			n++
		}
	}
	return n
}

func normaliseHeader(h string) string {
	out := make([]byte, 0, len(h))
	for _, ch := range h {
		if ch >= 'A' && ch <= 'Z' {
			out = append(out, byte(ch+32))
		} else if ch == ' ' || ch == '_' || ch == '-' {
			// skip whitespace/separators to normalise
		} else {
			out = append(out, byte(ch))
		}
	}
	return string(out)
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func fieldAt(fields []string, colIdx map[string]int, name string, fallbackIdx int) string {
	if idx, ok := colIdx[name]; ok && idx < len(fields) {
		return fields[idx]
	}
	if fallbackIdx >= 0 && fallbackIdx < len(fields) {
		return fields[fallbackIdx]
	}
	return ""
}

// SignalsByIP implements SignalSource.
func (c *SNDSClient) SignalsByIP(ip net.IP) []ProviderSignal {
	return c.store.SignalsByIP(ip)
}

// SignalsByDomain implements SignalSource.
func (c *SNDSClient) SignalsByDomain(domain string) []ProviderSignal {
	return c.store.SignalsByDomain(domain)
}

var _ SignalSource = (*SNDSClient)(nil)
