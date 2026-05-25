// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/vul-os/vulos-relay/internal/peering"
	"github.com/vul-os/vulos-relay/internal/relay"
	"github.com/vul-os/vulos-relay/internal/sending"
)

// captureSpool records inbound peer envelopes injected via Router.RouteInbound,
// so the cmd-level e2e test can assert what the receiving relay delivered
// locally.
type captureSpool struct {
	mu   sync.Mutex
	msgs []relay.InboundEnvelope
}

func (c *captureSpool) Write(_ context.Context, env relay.InboundEnvelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, env)
	return nil
}

func (c *captureSpool) all() []relay.InboundEnvelope {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]relay.InboundEnvelope, len(c.msgs))
	copy(out, c.msgs)
	return out
}

// captureSMTP records the recipients the SMTP fallback path was asked to send.
type captureSMTP struct {
	mu  sync.Mutex
	got []string
}

func (s *captureSMTP) Send(_ context.Context, msg sending.Message) (sending.SendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, msg.Recipients...)
	return sending.SendResult{State: sending.StateDelivered, Code: 250}, nil
}

func (s *captureSMTP) recipients() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.got))
	copy(out, s.got)
	return out
}

// relayProcess models one in-process vulos-relay with a real HTTP ingress
// (via the production startSubmitListener wiring) and a RoutingSender exactly
// as cmd/relay/main builds it.
type relayProcess struct {
	id       *peering.Identity
	domain   string
	resolver *peering.StaticResolver
	router   *relay.Router
	spool    *captureSpool
	smtp     *captureSMTP
	sender   *peering.RoutingSender
	srv      *http.Server
	url      string
}

// startRelayProcess stands up a relay process authoritative for domain, binding
// the real peering ingress on an httptest listener and wiring the
// production-style RoutingSender (peer path + SMTP fallback).
func startRelayProcess(t *testing.T, domain string) *relayProcess {
	t.Helper()
	id, err := peering.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rp := &relayProcess{
		id:       id,
		domain:   domain,
		resolver: peering.NewStaticResolver(),
		spool:    &captureSpool{},
		smtp:     &captureSMTP{},
	}
	// Router with an injected SpoolWriter so RouteInbound captures locally.
	rp.router = relay.NewRouter(relay.RouterConfig{Spool: rp.spool})

	// Production-style RoutingSender: HTTP peer transport + SMTP fallback.
	rp.sender = &peering.RoutingSender{
		Peer:     peering.NewPeerSender(id, rp.resolver, peering.NewHTTPTransport()),
		SMTP:     rp.smtp,
		Resolver: rp.resolver,
	}

	// Build a Receiver exactly like main() does and serve it via the real
	// IngressHandler on an httptest server.
	authoritative := map[string]bool{domain: true}
	rc := &peering.Receiver{
		Identity:   id,
		Authorized: func(d string) bool { return authoritative[d] },
		PinnedKey:  rp.resolver.PinnedKey,
		Guard:      peering.NewReplayGuard(),
		Resolver:   rp.resolver,
		Sink:       newRouterSink(rp.router),
		Logf:       func(string, ...any) {},
	}
	mux := http.NewServeMux()
	mux.Handle(peering.PeeringPath, peering.IngressHandler(rc))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	rp.url = ts.URL
	return rp
}

func (rp *relayProcess) pin(t *testing.T, other *relayProcess) {
	t.Helper()
	if err := rp.resolver.Add(&peering.PeerDescriptor{
		Domains:     []string{other.domain},
		IdentityPub: other.id.SignPub,
		KexPub:      other.id.KexPub,
		Versions:    []string{peering.ProtoV1},
		Suites:      []string{peering.SuiteV1},
		Endpoint:    other.url + peering.PeeringPath,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestCrossProcessPeeringAndSMTPFallback is the cmd-level end-to-end proof:
// relay A peers a message to relay B over the real HTTP transport + ingress
// (delivered into B's local spool), while a recipient at a non-peer domain in
// the SAME message falls back to A's SMTP sender. This exercises the exact
// components main() wires (RoutingSender, HTTPTransport, IngressHandler,
// routerSink → Router.RouteInbound).
func TestCrossProcessPeeringAndSMTPFallback(t *testing.T) {
	a := startRelayProcess(t, "a.example")
	b := startRelayProcess(t, "b.example")
	a.pin(t, b) // A can send to and authenticate B
	b.pin(t, a) // B can authenticate A's inbound envelope

	res, err := a.sender.Send(context.Background(), sending.Message{
		Sender:     "alice@a.example",
		Recipients: []string{"bob@b.example", "stranger@external.test"},
		RawRFC822:  []byte("Subject: e2e\r\n\r\nhello cross-process\r\n"),
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.State != sending.StateDelivered {
		t.Fatalf("overall state = %s msg=%q", res.State, res.Message)
	}

	// Peer recipient: delivered into B's local spool over the real ingress.
	got := b.spool.all()
	if len(got) != 1 {
		t.Fatalf("B spool received %d, want 1", len(got))
	}
	if !bytes.Contains(got[0].RawRFC822, []byte("hello cross-process")) {
		t.Fatalf("B spool payload = %q", got[0].RawRFC822)
	}
	if len(got[0].To) != 1 || got[0].To[0] != "bob@b.example" {
		t.Fatalf("B spool To = %v", got[0].To)
	}

	// Non-peer recipient: SMTP fallback only (and NOT delivered over peering).
	smtpRcpts := a.smtp.recipients()
	if len(smtpRcpts) != 1 || smtpRcpts[0] != "stranger@external.test" {
		t.Fatalf("SMTP fallback recipients = %v, want [stranger@external.test]", smtpRcpts)
	}
}

// TestCrossProcessUnknownPeerDefers: if A resolves B as a peer but B does not
// know A, B rejects the envelope as unauthorized → A bounces that part (does
// NOT silently downgrade onto public SMTP, spec §10).
func TestCrossProcessUnknownPeerBounces(t *testing.T) {
	a := startRelayProcess(t, "a.example")
	b := startRelayProcess(t, "b.example")
	a.pin(t, b) // A knows B
	// b does NOT pin a.

	res, _ := a.sender.Send(context.Background(), sending.Message{
		Sender:     "alice@a.example",
		Recipients: []string{"bob@b.example"},
		RawRFC822:  []byte("body"),
	})
	if res.State != sending.StateBounced {
		t.Fatalf("unknown-peer rejection should bounce, got %s", res.State)
	}
	if len(b.spool.all()) != 0 {
		t.Fatal("rejected envelope must not be spooled")
	}
	// Must NOT have leaked onto SMTP.
	if len(a.smtp.recipients()) != 0 {
		t.Fatal("peer recipient must never downgrade to SMTP")
	}
}
