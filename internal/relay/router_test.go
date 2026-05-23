// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package relay_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/relay"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func makeMsg(from string, to []string, body []byte, authorized []string) relay.OutboundMessage {
	return relay.OutboundMessage{
		AccountID:         "acct1",
		From:              from,
		To:                to,
		RawRFC822:         body,
		AuthorizedDomains: authorized,
	}
}

var body = []byte("Subject: hi\r\n\r\nHello")

// ─── AcceptOutbound tests ─────────────────────────────────────────────────────

func TestAcceptOutbound_Valid(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	msg := makeMsg("sender@example.com", []string{"rcpt@example.org"}, body, nil)
	if err := r.AcceptOutbound(context.Background(), msg); err != nil {
		t.Errorf("expected accept, got: %v", err)
	}
}

func TestAcceptOutbound_EmptySender(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	msg := makeMsg("", []string{"rcpt@example.org"}, body, nil)
	if err := r.AcceptOutbound(context.Background(), msg); !errors.Is(err, relay.ErrInvalidSender) {
		t.Errorf("expected ErrInvalidSender, got: %v", err)
	}
}

func TestAcceptOutbound_MalformedSender(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	msg := makeMsg("not-an-address", []string{"rcpt@example.org"}, body, nil)
	if err := r.AcceptOutbound(context.Background(), msg); !errors.Is(err, relay.ErrInvalidSender) {
		t.Errorf("expected ErrInvalidSender for malformed From, got: %v", err)
	}
}

func TestAcceptOutbound_NoRecipients(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	msg := makeMsg("sender@example.com", nil, body, nil)
	if err := r.AcceptOutbound(context.Background(), msg); !errors.Is(err, relay.ErrNoRecipients) {
		t.Errorf("expected ErrNoRecipients, got: %v", err)
	}
}

func TestAcceptOutbound_BadRecipient(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	msg := makeMsg("sender@example.com", []string{"not-an-addr"}, body, nil)
	if err := r.AcceptOutbound(context.Background(), msg); !errors.Is(err, relay.ErrNoRecipients) {
		t.Errorf("expected ErrNoRecipients for bad recipient, got: %v", err)
	}
}

func TestAcceptOutbound_TooLarge(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{MaxMessageBytes: 10})
	msg := makeMsg("sender@example.com", []string{"rcpt@example.org"}, body, nil)
	if err := r.AcceptOutbound(context.Background(), msg); !errors.Is(err, relay.ErrMessageTooLarge) {
		t.Errorf("expected ErrMessageTooLarge, got: %v", err)
	}
}

func TestAcceptOutbound_SizeExactlyAtLimit_Allowed(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{MaxMessageBytes: len(body)})
	msg := makeMsg("sender@example.com", []string{"rcpt@example.org"}, body, nil)
	if err := r.AcceptOutbound(context.Background(), msg); err != nil {
		t.Errorf("expected accept at exact limit, got: %v", err)
	}
}

func TestAcceptOutbound_AuthorizedDomain_Match(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	msg := makeMsg("alice@example.com", []string{"rcpt@example.org"}, body, []string{"example.com"})
	if err := r.AcceptOutbound(context.Background(), msg); err != nil {
		t.Errorf("expected accept for authorized domain, got: %v", err)
	}
}

func TestAcceptOutbound_AuthorizedDomain_Mismatch(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	msg := makeMsg("alice@evil.com", []string{"rcpt@example.org"}, body, []string{"example.com"})
	if err := r.AcceptOutbound(context.Background(), msg); !errors.Is(err, relay.ErrUnauthorizedSender) {
		t.Errorf("expected ErrUnauthorizedSender for wrong domain, got: %v", err)
	}
}

func TestAcceptOutbound_NoSizeLimitZero(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{MaxMessageBytes: 0})
	big := make([]byte, 1<<20) // 1 MiB — should be accepted with no limit
	msg := makeMsg("sender@example.com", []string{"rcpt@example.org"}, big, nil)
	if err := r.AcceptOutbound(context.Background(), msg); err != nil {
		t.Errorf("expected accept with no size limit (0), got: %v", err)
	}
}

// ─── RouteInbound tests ───────────────────────────────────────────────────────

// captureSpoolWriter records all envelopes written to it.
type captureSpoolWriter struct {
	mu        sync.Mutex
	envelopes []relay.InboundEnvelope
	failWith  error
}

func (c *captureSpoolWriter) Write(_ context.Context, env relay.InboundEnvelope) error {
	if c.failWith != nil {
		return c.failWith
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.envelopes = append(c.envelopes, env)
	return nil
}

func TestRouteInbound_SpoolWriter(t *testing.T) {
	spool := &captureSpoolWriter{}
	r := relay.NewRouter(relay.RouterConfig{Spool: spool})
	env := relay.InboundEnvelope{
		From:      "sender@peer.example",
		To:        []string{"local@example.com"},
		RawRFC822: []byte("Subject: inbound\r\n\r\nHi"),
	}
	if err := r.RouteInbound(context.Background(), env); err != nil {
		t.Fatalf("expected RouteInbound to succeed, got: %v", err)
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	if len(spool.envelopes) != 1 {
		t.Errorf("expected 1 envelope written, got %d", len(spool.envelopes))
	}
}

func TestRouteInbound_SpoolWriterError(t *testing.T) {
	spool := &captureSpoolWriter{failWith: errors.New("disk full")}
	r := relay.NewRouter(relay.RouterConfig{Spool: spool})
	env := relay.InboundEnvelope{From: "x@peer.test", To: []string{"y@local.test"}}
	if err := r.RouteInbound(context.Background(), env); !errors.Is(err, relay.ErrSpoolFull) {
		t.Errorf("expected ErrSpoolFull on writer error, got: %v", err)
	}
}

func TestRouteInbound_NoBackend(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	env := relay.InboundEnvelope{From: "x@peer.test", To: []string{"y@local.test"}}
	if err := r.RouteInbound(context.Background(), env); !errors.Is(err, relay.ErrSpoolFull) {
		t.Errorf("expected ErrSpoolFull when no backend configured, got: %v", err)
	}
}

// ─── IsPeer tests ─────────────────────────────────────────────────────────────

// stubPeerResolver implements relay.PeerResolver.
type stubPeerResolver struct {
	peers map[string]bool
}

func (s *stubPeerResolver) Resolve(_ context.Context, domain string) (interface{}, error) {
	if s.peers[domain] {
		return struct{}{}, nil
	}
	return nil, errors.New("not a peer")
}

func TestIsPeer_KnownPeer(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	r.SetPeerResolver(&stubPeerResolver{peers: map[string]bool{"peer.example": true}})
	if !r.IsPeer(context.Background(), "user@peer.example") {
		t.Error("expected IsPeer=true for known peer")
	}
}

func TestIsPeer_NotPeer(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	r.SetPeerResolver(&stubPeerResolver{peers: map[string]bool{}})
	if r.IsPeer(context.Background(), "user@smtp.example") {
		t.Error("expected IsPeer=false for non-peer")
	}
}

func TestIsPeer_NoResolver(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{})
	// No resolver wired — must default to false (SMTP-only mode).
	if r.IsPeer(context.Background(), "user@anywhere.example") {
		t.Error("expected IsPeer=false when no resolver configured")
	}
}

func TestIsPeer_CachesResult(t *testing.T) {
	calls := 0
	rslv := &countingResolver{peers: map[string]bool{"peer.example": true}, calls: &calls}
	r := relay.NewRouter(relay.RouterConfig{PeerResolutionTTL: 30 * time.Second})
	r.SetPeerResolver(rslv)

	for i := 0; i < 5; i++ {
		r.IsPeer(context.Background(), "user@peer.example")
	}
	if calls != 1 {
		t.Errorf("expected resolver called once due to caching, called %d times", calls)
	}
}

type countingResolver struct {
	peers map[string]bool
	calls *int
}

func (c *countingResolver) Resolve(_ context.Context, domain string) (interface{}, error) {
	(*c.calls)++
	if c.peers[domain] {
		return struct{}{}, nil
	}
	return nil, errors.New("not a peer")
}

func TestIsPeer_MixedRecipients(t *testing.T) {
	r := relay.NewRouter(relay.RouterConfig{PeerResolutionTTL: -1}) // disable cache
	r.SetPeerResolver(&stubPeerResolver{peers: map[string]bool{"peer.example": true}})

	// peer recipient
	if !r.IsPeer(context.Background(), "a@peer.example") {
		t.Error("expected IsPeer=true for peer.example")
	}
	// SMTP recipient
	if r.IsPeer(context.Background(), "b@smtp.example") {
		t.Error("expected IsPeer=false for smtp.example")
	}
}
