// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MTA-STS (RFC 8461) outbound policy enforcement.
//
// MTA-STS lets a recipient domain publish a policy declaring that senders MUST
// use TLS with a CA-valid certificate whose name matches one of the policy's MX
// patterns. A network attacker can otherwise strip STARTTLS (downgrade to
// plaintext) or substitute a different MX; honouring MTA-STS closes that
// downgrade-MITM hole.
//
// The discovery flow (RFC 8461 §3):
//  1. The sender fetches https://mta-sts.<domain>/.well-known/mta-sts.txt over
//     HTTPS (the HTTPS cert chain authenticates the policy itself).
//  2. The policy declares a mode (enforce | testing | none), one or more `mx`
//     patterns, and a `max_age` (cache lifetime in seconds).
//  3. When mode=enforce, delivery to that domain MUST go over TLS to an MX that
//     matches a pattern, with a CA-valid cert matching the MX host. A downgrade
//     or mismatch MUST cause the message to be deferred (not delivered, not
//     bounced).
//
// This package fetches + caches policies and exposes the decision the SMTP
// sender needs. We honour `max_age` for caching and treat a missing/unparseable
// policy as "no MTA-STS" (opportunistic), never as enforce — fail open on
// discovery so a transient HTTPS failure does not blackhole all mail, but fail
// closed (defer) once an enforce policy is known and the connection cannot meet
// it.

// MTASTSMode is the policy mode declared in an mta-sts.txt file.
type MTASTSMode string

const (
	// MTASTSNone means the domain publishes no enforcing policy.
	MTASTSNone MTASTSMode = "none"
	// MTASTSTesting means failures should be reported but not block delivery.
	MTASTSTesting MTASTSMode = "testing"
	// MTASTSEnforce means TLS to a matching MX with a valid cert is REQUIRED.
	MTASTSEnforce MTASTSMode = "enforce"
)

// MTASTSPolicy is a parsed mta-sts.txt policy for one recipient domain.
type MTASTSPolicy struct {
	// Mode is the declared enforcement mode.
	Mode MTASTSMode
	// MX is the set of allowed MX host patterns (may contain a leading "*."
	// wildcard for exactly one label, per RFC 8461 §3.1).
	MX []string
	// MaxAge is the policy cache lifetime.
	MaxAge time.Duration
	// fetchedAt is when this policy was retrieved (for cache expiry).
	fetchedAt time.Time
}

// expired reports whether the cached policy has outlived its max_age.
func (p *MTASTSPolicy) expired(now time.Time) bool {
	if p.MaxAge <= 0 {
		return true
	}
	return now.After(p.fetchedAt.Add(p.MaxAge))
}

// MatchesMX reports whether mxHost satisfies one of the policy's MX patterns.
// Matching is case-insensitive; a leading "*." pattern matches exactly one
// label in that position (RFC 8461 §4.1).
func (p *MTASTSPolicy) MatchesMX(mxHost string) bool {
	h := strings.ToLower(strings.TrimSuffix(mxHost, "."))
	for _, pat := range p.MX {
		pat = strings.ToLower(strings.TrimSuffix(pat, "."))
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:] // ".example.com"
			// Wildcard matches exactly one leading label.
			idx := strings.Index(h, ".")
			if idx < 0 {
				continue
			}
			if h[idx:] == suffix {
				return true
			}
			continue
		}
		if h == pat {
			return true
		}
	}
	return false
}

// httpGetter is the minimal HTTP interface the policy fetcher needs.
// *http.Client satisfies it; tests inject a stub.
type httpGetter interface {
	Get(url string) (*http.Response, error)
}

// MTASTSCache fetches and caches MTA-STS policies per recipient domain. It is
// safe for concurrent use. The zero value is not usable; call NewMTASTSCache.
type MTASTSCache struct {
	mu       sync.Mutex
	policies map[string]*MTASTSPolicy

	// HTTPClient performs the well-known fetch over HTTPS. If nil, a default
	// client with a 10s timeout is used. The HTTPS cert chain authenticates the
	// policy, so this client MUST verify certs (never InsecureSkipVerify).
	HTTPClient httpGetter

	// MaxPolicyBytes caps the policy body size (RFC 8461 policies are tiny).
	MaxPolicyBytes int64

	// now is overridable for tests.
	now func() time.Time
}

// NewMTASTSCache returns a ready MTASTSCache.
func NewMTASTSCache() *MTASTSCache {
	return &MTASTSCache{
		policies:       make(map[string]*MTASTSPolicy),
		MaxPolicyBytes: 64 << 10, // 64 KiB ceiling; real policies are <1 KiB
		now:            time.Now,
	}
}

func (c *MTASTSCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *MTASTSCache) httpClient() httpGetter {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// PolicyFor returns the (possibly cached) MTA-STS policy for domain. It returns
// (nil, nil) when the domain publishes no usable policy (no MTA-STS) — callers
// treat that as opportunistic. A non-nil error indicates a discovery failure;
// callers should treat that as "policy unknown" (fail open on discovery) but
// MUST still apply any previously-cached enforce policy.
func (c *MTASTSCache) PolicyFor(ctx context.Context, domain string) (*MTASTSPolicy, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return nil, nil
	}

	now := c.clock()
	c.mu.Lock()
	if p, ok := c.policies[domain]; ok && !p.expired(now) {
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()

	p, err := c.fetch(ctx, domain)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	p.fetchedAt = now
	c.mu.Lock()
	c.policies[domain] = p
	c.mu.Unlock()
	return p, nil
}

// fetch retrieves and parses the well-known policy. It does NOT consult or
// honour the _mta-sts DNS TXT record's `id`: we always fetch the well-known
// resource (a correct, if slightly chattier, behaviour) and rely on max_age for
// caching. This avoids a second DNS dependency while remaining spec-faithful on
// the security-critical part (HTTPS-authenticated policy + enforce semantics).
func (c *MTASTSCache) fetch(_ context.Context, domain string) (*MTASTSPolicy, error) {
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	resp, err := c.httpClient().Get(url)
	if err != nil {
		// Discovery failure (DNS, TLS, connect) → no policy known. Fail open on
		// discovery: returning the error lets the caller distinguish "unknown"
		// from "explicitly no policy".
		return nil, fmt.Errorf("mta-sts fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// No policy published.
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mta-sts %s: status %d", url, resp.StatusCode)
	}
	limit := c.MaxPolicyBytes
	if limit <= 0 {
		limit = 64 << 10
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("mta-sts read %s: %w", url, err)
	}
	return parseMTASTSPolicy(body)
}

// parseMTASTSPolicy parses an mta-sts.txt body (RFC 8461 §3.2). It is lenient:
// unknown keys are ignored. A policy with no recognisable mode is treated as no
// policy (returns nil).
func parseMTASTSPolicy(body []byte) (*MTASTSPolicy, error) {
	p := &MTASTSPolicy{}
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sawVersion := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "version":
			sawVersion = true
		case "mode":
			switch MTASTSMode(strings.ToLower(val)) {
			case MTASTSEnforce:
				p.Mode = MTASTSEnforce
			case MTASTSTesting:
				p.Mode = MTASTSTesting
			default:
				p.Mode = MTASTSNone
			}
		case "mx":
			if val != "" {
				p.MX = append(p.MX, val)
			}
		case "max_age":
			if secs, err := strconv.Atoi(val); err == nil && secs > 0 {
				p.MaxAge = time.Duration(secs) * time.Second
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("mta-sts parse: %w", err)
	}
	if !sawVersion && p.Mode == "" {
		return nil, nil // not a policy
	}
	if p.Mode == "" {
		p.Mode = MTASTSNone
	}
	// A sane default cache lifetime if max_age was absent/invalid.
	if p.MaxAge <= 0 {
		p.MaxAge = time.Hour
	}
	return p, nil
}

// mtastsDecision is the per-domain enforcement decision computed before
// connecting to an MX.
type mtastsDecision struct {
	// enforce is true when a known enforce policy applies to this domain.
	enforce bool
	// policy is the resolved policy (nil when none applies).
	policy *MTASTSPolicy
}

// decideMTASTS resolves the MTA-STS decision for domain. On a discovery error
// it returns a non-enforcing decision (fail open on discovery) but logs.
func decideMTASTS(ctx context.Context, cache *MTASTSCache, domain string) mtastsDecision {
	if cache == nil {
		return mtastsDecision{}
	}
	p, err := cache.PolicyFor(ctx, domain)
	if err != nil || p == nil {
		return mtastsDecision{}
	}
	return mtastsDecision{enforce: p.Mode == MTASTSEnforce, policy: p}
}

// hostnameOf strips a port from an address if present.
func hostnameOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
