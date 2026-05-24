// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Sentinel errors for the Router.
var (
	// ErrNoRecipients is returned by AcceptOutbound when the message has no
	// recipients.
	ErrNoRecipients = errors.New("relay: message has no recipients")

	// ErrInvalidSender is returned by AcceptOutbound when the envelope sender
	// address is empty or malformed.
	ErrInvalidSender = errors.New("relay: invalid envelope sender address")

	// ErrMessageTooLarge is returned by AcceptOutbound when the raw message
	// exceeds the configured size limit.
	ErrMessageTooLarge = errors.New("relay: message exceeds size limit")

	// ErrUnauthorizedSender is returned by AcceptOutbound when the From address
	// domain does not match any authorized domain for the account.
	ErrUnauthorizedSender = errors.New("relay: sender not authorized to use that From domain")

	// ErrSpoolFull is returned by RouteInbound when the spool directory is
	// unavailable or full.
	ErrSpoolFull = errors.New("relay: inbound spool unavailable")
)

// OutboundMessage is the submission-side view of a message that the Router
// evaluates before it enters the send queue.
type OutboundMessage struct {
	// AccountID is the authenticated sending account identifier.
	AccountID string

	// From is the RFC-5321 envelope sender address (MAIL FROM).
	From string

	// To are the RFC-5321 envelope recipients (RCPT TO).
	To []string

	// RawRFC822 is the wire-format message.
	RawRFC822 []byte

	// AuthorizedDomains is the set of domains the account is allowed to send
	// from.  If nil, no domain restriction is enforced (permissive default for
	// standalone use).
	AuthorizedDomains []string
}

// InboundEnvelope is an encrypted peer envelope arriving from a remote Vulos
// peer for inbound delivery.
type InboundEnvelope struct {
	// From is the RFC-5321 envelope sender.
	From string

	// To are the RFC-5321 envelope recipients.
	To []string

	// RawRFC822 is the decrypted wire-format message.
	RawRFC822 []byte

	// PeerEndpoint identifies the originating peer.
	PeerEndpoint string
}

// SpoolWriter writes an inbound envelope to some spool/mailbox destination.
// Implementations must be safe for concurrent use.
type SpoolWriter interface {
	// Write persists env to the spool.  It returns an error if the write fails.
	Write(ctx context.Context, env InboundEnvelope) error
}

// RouterConfig holds configuration for a Router.
type RouterConfig struct {
	// MaxMessageBytes is the maximum size of the raw RFC-822 message body.
	// 0 means no limit (default for standalone).
	MaxMessageBytes int

	// SpoolDir is the filesystem spool directory for inbound mail.  If empty,
	// inbound delivery falls back to the WebhookURL if set, or is rejected.
	SpoolDir string

	// WebhookURL is an HTTP endpoint for inbound envelope delivery.  Used when
	// SpoolDir is empty.  If both are empty, RouteInbound returns an error.
	WebhookURL string

	// WebhookSecret is the HMAC-SHA256 signing key for webhook payloads.
	// When set, every POST carries an X-Vulos-Signature header.
	WebhookSecret []byte

	// WebhookHTTPClient overrides the HTTP client passed to WebhookDeliverer.
	// Leave nil in production; set in tests to bypass the SSRF guard.
	WebhookHTTPClient *http.Client

	// Spool is an injectable SpoolWriter.  If non-nil it takes precedence over
	// SpoolDir and WebhookURL.
	Spool SpoolWriter

	// PeerResolutionTTL is the TTL for cached peer-resolution results.  If zero
	// the default of 5 minutes is used.  A negative value disables caching.
	PeerResolutionTTL time.Duration
}

// PeerResolver is the subset of the peering.Resolver interface that the Router
// needs: map a recipient domain to a non-nil value if it is a Vulos peer.
type PeerResolver interface {
	// Resolve returns a non-nil descriptor and nil error when the domain belongs
	// to a known Vulos peer.  It returns a non-nil error (typically
	// peering.ErrNotPeer) when the domain is not a peer.
	Resolve(ctx context.Context, domain string) (interface{}, error)
}

// cacheEntry holds a cached peer-resolution outcome.
type cacheEntry struct {
	isPeer  bool
	expires time.Time
}

// Router is the submission-side router. It decides whether to accept outbound
// messages before they enter the send queue, and handles inbound peer-envelope
// dispatch to the local spool or webhook.
//
// Router is safe for concurrent use.
type Router struct {
	cfg RouterConfig

	// peerResolver, when non-nil, is consulted by IsPeer.
	peerResolver PeerResolver

	// cache stores peer-resolution results keyed by domain.
	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// NewRouter creates a Router with the given configuration.
func NewRouter(cfg RouterConfig) *Router {
	return &Router{
		cfg:   cfg,
		cache: make(map[string]cacheEntry),
	}
}

// SetPeerResolver wires the peering resolver into the Router.  It is safe to
// call before any concurrent use begins.
func (r *Router) SetPeerResolver(pr PeerResolver) {
	r.peerResolver = pr
}

// AcceptOutbound validates an outbound message before it enters the queue.
//
// It checks:
//   - From is non-empty and syntactically plausible
//   - To has at least one recipient with a plausible address
//   - RawRFC822 is within the configured size limit (if set)
//   - From domain is in AuthorizedDomains (if the slice is non-nil)
//
// It does NOT perform DNS resolution or reputation checks; those happen later
// in the pipeline.  This gate is strictly structural and authorization.
func (r *Router) AcceptOutbound(ctx context.Context, msg OutboundMessage) error {
	_ = ctx // reserved for future async validation

	// Validate envelope sender.
	if msg.From == "" {
		return ErrInvalidSender
	}
	if !looksLikeAddress(msg.From) {
		return fmt.Errorf("%w: %q", ErrInvalidSender, msg.From)
	}

	// Validate recipients.
	if len(msg.To) == 0 {
		return ErrNoRecipients
	}
	for _, rcpt := range msg.To {
		if !looksLikeAddress(rcpt) {
			return fmt.Errorf("%w: bad recipient %q", ErrNoRecipients, rcpt)
		}
	}

	// Validate size limit.
	if r.cfg.MaxMessageBytes > 0 && len(msg.RawRFC822) > r.cfg.MaxMessageBytes {
		return fmt.Errorf("%w: %d bytes (limit %d)", ErrMessageTooLarge, len(msg.RawRFC822), r.cfg.MaxMessageBytes)
	}

	// Validate sender domain authorization when the account provides a domain
	// list.  An empty/nil AuthorizedDomains means "no restriction" — e.g. in
	// standalone self-hosted deployments.
	if len(msg.AuthorizedDomains) > 0 {
		senderDomain := domainOf(msg.From)
		if senderDomain == "" {
			return fmt.Errorf("%w: cannot determine sender domain from %q", ErrUnauthorizedSender, msg.From)
		}
		found := false
		for _, d := range msg.AuthorizedDomains {
			if strings.EqualFold(d, senderDomain) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: domain %q not in authorized set", ErrUnauthorizedSender, senderDomain)
		}
	}

	return nil
}

// RouteInbound dispatches an inbound peer envelope to the configured spool or
// webhook.  It returns ErrSpoolFull if no delivery backend is configured or the
// write fails.
func (r *Router) RouteInbound(ctx context.Context, env InboundEnvelope) error {
	// Injectable SpoolWriter takes highest precedence.
	if r.cfg.Spool != nil {
		if err := r.cfg.Spool.Write(ctx, env); err != nil {
			return fmt.Errorf("%w: %v", ErrSpoolFull, err)
		}
		return nil
	}

	// FileSpool uses SpoolDir.
	if r.cfg.SpoolDir != "" {
		fs := &fileSpoolWriter{dir: r.cfg.SpoolDir}
		if err := fs.Write(ctx, env); err != nil {
			return fmt.Errorf("%w: %v", ErrSpoolFull, err)
		}
		return nil
	}

	// Webhook path (RELAY-17): POST the envelope to the configured URL via
	// the SSRF-safe, HMAC-signed WebhookDeliverer.
	if r.cfg.WebhookURL != "" {
		wd := NewWebhookDeliverer(WebhookConfig{
			URL:        r.cfg.WebhookURL,
			Secret:     r.cfg.WebhookSecret,
			HTTPClient: r.cfg.WebhookHTTPClient,
		})
		if err := wd.Deliver(ctx, env); err != nil {
			return fmt.Errorf("%w: %v", ErrSpoolFull, err)
		}
		return nil
	}

	return fmt.Errorf("%w: no spool or webhook configured", ErrSpoolFull)
}

// IsPeer reports whether the recipient address belongs to a known Vulos peer.
// Resolution results are cached for PeerResolutionTTL (default 5 min).
//
// When no PeerResolver is configured, IsPeer always returns false (SMTP-only
// mode).
func (r *Router) IsPeer(ctx context.Context, recipient string) bool {
	if r.peerResolver == nil {
		return false
	}
	domain := domainOf(recipient)
	if domain == "" {
		return false
	}

	ttl := r.cfg.PeerResolutionTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	// Check cache (skip cache when TTL is negative).
	if ttl > 0 {
		r.mu.RLock()
		if entry, ok := r.cache[domain]; ok && time.Now().Before(entry.expires) {
			r.mu.RUnlock()
			return entry.isPeer
		}
		r.mu.RUnlock()
	}

	// Resolve and (optionally) cache.
	_, err := r.peerResolver.Resolve(ctx, domain)
	isPeer := err == nil

	if ttl > 0 {
		r.mu.Lock()
		r.cache[domain] = cacheEntry{
			isPeer:  isPeer,
			expires: time.Now().Add(ttl),
		}
		r.mu.Unlock()
	}

	return isPeer
}

// fileSpoolWriter writes inbound envelopes as files under dir.
// It is a minimal reference impl; production deployments inject a SpoolWriter.
type fileSpoolWriter struct {
	dir string
}

// spoolFile is the JSON-framed representation of an inbound envelope written to
// the file spool.
type spoolFile struct {
	From         string    `json:"from"`
	To           []string  `json:"to"`
	PeerEndpoint string    `json:"peer_endpoint"`
	ReceivedAt   time.Time `json:"received_at"`
	RawRFC822    []byte    `json:"raw_rfc822"`
}

// Write persists env as a JSON-framed file under f.dir.  The write is atomic:
// the payload is written to a temp file in the same directory and renamed into
// place, so a reader never observes a partial file.  An error is returned (and
// surfaced as ErrSpoolFull by RouteInbound) if the directory is missing or the
// write fails — the spool never fails silently.
func (f *fileSpoolWriter) Write(_ context.Context, env InboundEnvelope) error {
	if f.dir == "" {
		return errors.New("spool dir not set")
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return fmt.Errorf("create spool dir %q: %w", f.dir, err)
	}

	payload, err := json.Marshal(spoolFile{
		From:         env.From,
		To:           env.To,
		PeerEndpoint: env.PeerEndpoint,
		ReceivedAt:   time.Now().UTC(),
		RawRFC822:    env.RawRFC822,
	})
	if err != nil {
		return fmt.Errorf("marshal spool envelope: %w", err)
	}

	name, err := spoolFileName()
	if err != nil {
		return err
	}
	finalPath := filepath.Join(f.dir, name+".json")
	tmpPath := finalPath + ".tmp"

	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return fmt.Errorf("write spool temp file: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("commit spool file: %w", err)
	}
	return nil
}

// spoolFileName returns a sortable, collision-resistant spool file basename:
// a UTC nanosecond timestamp followed by random hex.
func spoolFileName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("spool filename entropy: %w", err)
	}
	return fmt.Sprintf("%020d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(b[:])), nil
}

// looksLikeAddress returns true when s looks like a plausible RFC-5321 address.
// It does NOT do full RFC-5321 parsing — that is done by the MTA.  The check
// is a quick structural gate: contains exactly one '@' and both local-part and
// domain are non-empty.
func looksLikeAddress(s string) bool {
	at := strings.LastIndex(s, "@")
	return at > 0 && at < len(s)-1
}

// domainOf returns the lowercased domain part of an RFC-5321 address.
func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}
