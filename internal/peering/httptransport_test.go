// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// memSink is an in-memory DeliverySink capturing what the ingress hands to the
// local mailbox after all §7–§8 checks pass.
type memSink struct {
	mu       sync.Mutex
	messages []deliveredMsg
	failNext bool // when set, the next Deliver returns a transient error
}

type deliveredMsg struct {
	mailFrom string
	rcptTo   []string
	raw      []byte
}

func (s *memSink) Deliver(_ context.Context, mailFrom string, rcptTo []string, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return errors.New("spool unavailable")
	}
	s.messages = append(s.messages, deliveredMsg{mailFrom, rcptTo, append([]byte(nil), raw...)})
	return nil
}

func (s *memSink) all() []deliveredMsg {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]deliveredMsg, len(s.messages))
	copy(out, s.messages)
	return out
}

// peerNode is a self-contained in-process Vulos peer: identity, the domains it
// is authoritative for, a resolver pinning the peers it knows, an ingress HTTP
// server, and a sink. It models one relay process.
type peerNode struct {
	id       *Identity
	domain   string
	resolver *StaticResolver
	sink     *memSink
	srv      *httptest.Server
}

// newPeerNode stands up an in-process peer authoritative for domain, with a
// real HTTP ingress server backed by Receiver.Accept.
func newPeerNode(t *testing.T, domain string) *peerNode {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	n := &peerNode{
		id:       id,
		domain:   domain,
		resolver: NewStaticResolver(),
		sink:     &memSink{},
	}
	rc := &Receiver{
		Identity:   id,
		Authorized: func(d string) bool { return d == domain },
		PinnedKey:  n.resolver.PinnedKey,
		Guard:      NewReplayGuard(),
		Resolver:   n.resolver,
		Sink:       n.sink,
		Logf:       func(string, ...any) {}, // silence in tests
	}
	mux := http.NewServeMux()
	mux.Handle(PeeringPath, IngressHandler(rc))
	n.srv = httptest.NewServer(mux)
	t.Cleanup(n.srv.Close)
	return n
}

// descriptor returns the peer descriptor other nodes use to reach n. The
// endpoint is the test server's URL (httptest is plain HTTP, which is fine: the
// envelope is end-to-end encrypted regardless of transport TLS).
func (n *peerNode) descriptor() *PeerDescriptor {
	return &PeerDescriptor{
		Domains:     []string{n.domain},
		IdentityPub: n.id.SignPub,
		KexPub:      n.id.KexPub,
		Versions:    []string{ProtoV1},
		Suites:      []string{SuiteV1},
		Endpoint:    n.srv.URL + PeeringPath,
	}
}

// pin registers other into n's resolver so n can both send to and authenticate
// inbound envelopes from other.
func (n *peerNode) pin(t *testing.T, other *peerNode) {
	t.Helper()
	if err := n.resolver.Add(other.descriptor()); err != nil {
		t.Fatalf("pin %s into %s: %v", other.domain, n.domain, err)
	}
}

// TestHTTPPeeringEndToEnd is the headline test: two in-process relays A and B,
// each with a real HTTP ingress. A peers a message to B over the HTTPTransport;
// B authenticates + decrypts it and delivers it to its local sink. This proves
// cross-process peering works (not just in-memory loopback).
func TestHTTPPeeringEndToEnd(t *testing.T) {
	a := newPeerNode(t, "a.example")
	b := newPeerNode(t, "b.example")
	a.pin(t, b) // A must know B to send to it
	b.pin(t, a) // B must know A to authenticate A's envelope

	sender := NewPeerSender(a.id, a.resolver, NewHTTPTransport())
	res, err := sender.Send(context.Background(), sending.Message{
		Sender:     "alice@a.example",
		Recipients: []string{"bob@b.example"},
		RawRFC822:  []byte("Subject: cross-process\r\n\r\nhello over http\r\n"),
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.State != sending.StateDelivered {
		t.Fatalf("state = %s msg=%q, want delivered", res.State, res.Message)
	}
	if res.Provider != "vulos-peer" {
		t.Fatalf("provider = %q, want vulos-peer", res.Provider)
	}

	got := b.sink.all()
	if len(got) != 1 {
		t.Fatalf("B received %d messages, want 1", len(got))
	}
	if !bytes.Contains(got[0].raw, []byte("hello over http")) {
		t.Fatalf("B plaintext = %q", got[0].raw)
	}
	if got[0].mailFrom != "alice@a.example" {
		t.Fatalf("mailFrom = %q", got[0].mailFrom)
	}
	if len(got[0].rcptTo) != 1 || got[0].rcptTo[0] != "bob@b.example" {
		t.Fatalf("rcptTo = %v", got[0].rcptTo)
	}
}

// TestHTTPPeeringBadSignatureRejected: a tampered envelope must be rejected by
// the ingress with the unauthenticated outcome, and the sender must classify it
// as a permanent bounce (no retry).
func TestHTTPPeeringBadSignatureRejected(t *testing.T) {
	a := newPeerNode(t, "a.example")
	b := newPeerNode(t, "b.example")
	b.pin(t, a)

	desc := b.descriptor()
	env, err := Seal(SealParams{
		Sender: a.id, SenderDomain: "a.example", Receiver: desc,
		MailFrom: "alice@a.example", RcptTo: []string{"bob@b.example"},
		RawRFC822: []byte("body"), Proto: ProtoV1, Suite: SuiteV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.Payload[0] ^= 0xff // breaks signature + AEAD
	wire := MarshalEnvelope(env)

	err = NewHTTPTransport().Deliver(context.Background(), desc.Endpoint, wire)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want ErrUnauthenticated from ingress, got %v", err)
	}
	if got := classifyHandoff(err); got.State != sending.StateBounced {
		t.Fatalf("bad signature should bounce, got %s", got.State)
	}
	if len(b.sink.all()) != 0 {
		t.Fatal("tampered envelope must not be delivered")
	}
}

// TestHTTPPeeringReplayRejected: delivering the identical wire twice — the
// second is rejected as a replay by B's shared ReplayGuard.
func TestHTTPPeeringReplayRejected(t *testing.T) {
	a := newPeerNode(t, "a.example")
	b := newPeerNode(t, "b.example")
	b.pin(t, a)

	desc := b.descriptor()
	env, err := Seal(SealParams{
		Sender: a.id, SenderDomain: "a.example", Receiver: desc,
		MailFrom: "alice@a.example", RcptTo: []string{"bob@b.example"},
		RawRFC822: []byte("once only"), Proto: ProtoV1, Suite: SuiteV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := MarshalEnvelope(env)
	tr := NewHTTPTransport()

	if err := tr.Deliver(context.Background(), desc.Endpoint, wire); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if err := tr.Deliver(context.Background(), desc.Endpoint, wire); !errors.Is(err, ErrReplay) {
		t.Fatalf("want ErrReplay on second delivery, got %v", err)
	}
	if n := len(b.sink.all()); n != 1 {
		t.Fatalf("replay must not deliver twice, delivered %d", n)
	}
}

// TestHTTPPeeringUnknownPeerRejected: an envelope from a sender domain B has
// never pinned must be rejected as unauthorized (B cannot authenticate it).
func TestHTTPPeeringUnknownPeerRejected(t *testing.T) {
	a := newPeerNode(t, "a.example")
	b := newPeerNode(t, "b.example")
	// NOTE: b does NOT pin a — a is an unknown peer to b.

	desc := b.descriptor()
	env, err := Seal(SealParams{
		Sender: a.id, SenderDomain: "a.example", Receiver: desc,
		MailFrom: "alice@a.example", RcptTo: []string{"bob@b.example"},
		RawRFC822: []byte("from a stranger"), Proto: ProtoV1, Suite: SuiteV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := MarshalEnvelope(env)

	err = NewHTTPTransport().Deliver(context.Background(), desc.Endpoint, wire)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized for unknown peer, got %v", err)
	}
	if len(b.sink.all()) != 0 {
		t.Fatal("unknown peer must not be delivered")
	}
}

// TestHTTPPeeringLocalDeliveryFailureTransient: when the local sink fails, the
// ingress returns a transient (503/deferred) outcome so the sender retries on
// the peer path rather than bouncing.
func TestHTTPPeeringLocalDeliveryFailureTransient(t *testing.T) {
	a := newPeerNode(t, "a.example")
	b := newPeerNode(t, "b.example")
	b.pin(t, a)
	b.sink.failNext = true

	desc := b.descriptor()
	env, err := Seal(SealParams{
		Sender: a.id, SenderDomain: "a.example", Receiver: desc,
		MailFrom: "alice@a.example", RcptTo: []string{"bob@b.example"},
		RawRFC822: []byte("retry me"), Proto: ProtoV1, Suite: SuiteV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := MarshalEnvelope(env)

	err = NewHTTPTransport().Deliver(context.Background(), desc.Endpoint, wire)
	if err == nil {
		t.Fatal("want transient error on local delivery failure")
	}
	// A transient error must NOT classify as a permanent bounce.
	if got := classifyHandoff(err); got.State != sending.StateDeferred {
		t.Fatalf("local failure should defer, got %s", got.State)
	}
}

// TestHTTPPeeringMisroutedRejected: an envelope sealed to B's key but listing a
// recipient at a domain B is not authoritative for is misrouted.
func TestHTTPPeeringMisroutedRejected(t *testing.T) {
	a := newPeerNode(t, "a.example")
	b := newPeerNode(t, "b.example")
	b.pin(t, a)

	desc := b.descriptor()
	env, err := Seal(SealParams{
		Sender: a.id, SenderDomain: "a.example", Receiver: desc,
		MailFrom: "alice@a.example", RcptTo: []string{"carol@c.example"}, // not B's domain
		RawRFC822: []byte("x"), Proto: ProtoV1, Suite: SuiteV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = NewHTTPTransport().Deliver(context.Background(), desc.Endpoint, MarshalEnvelope(env))
	if !errors.Is(err, ErrMisrouted) {
		t.Fatalf("want ErrMisrouted, got %v", err)
	}
}

// TestHTTPTransportEndpointForms checks normalizeEndpoint accepts a full URL, a
// scheme+authority, and a bare authority.
func TestHTTPTransportEndpointForms(t *testing.T) {
	cases := map[string]string{
		"https://peer.example/peering/v1/deliver": "https://peer.example/peering/v1/deliver",
		"https://peer.example":                    "https://peer.example" + PeeringPath,
		"peer.example:8443":                       "https://peer.example:8443" + PeeringPath,
	}
	for in, want := range cases {
		got, err := normalizeEndpoint(in)
		if err != nil {
			t.Fatalf("normalizeEndpoint(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := normalizeEndpoint(""); err == nil {
		t.Error("empty endpoint should error")
	}
}

// TestHTTPPeeringMethodNotAllowed: the ingress only accepts POST.
func TestHTTPPeeringMethodNotAllowed(t *testing.T) {
	b := newPeerNode(t, "b.example")
	resp, err := http.Get(b.srv.URL + PeeringPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", resp.StatusCode)
	}
}

// TestHTTPPeeringTransportDeadlineDefers: a transport-level (connection) failure
// classifies as deferred, never a bounce (spec §10 — peer path retries).
func TestHTTPPeeringTransportDeadlineDefers(t *testing.T) {
	tr := &HTTPTransport{Client: &http.Client{Timeout: time.Millisecond}}
	// Point at a closed/black-hole port via a server we immediately close.
	b := newPeerNode(t, "b.example")
	ep := b.srv.URL + PeeringPath
	b.srv.Close() // now connections fail

	err := tr.Deliver(context.Background(), ep, []byte("x"))
	if err == nil {
		t.Fatal("want transport error against closed server")
	}
	if got := classifyHandoff(err); got.State != sending.StateDeferred {
		t.Fatalf("transport failure should defer, got %s", got.State)
	}
}

// compile-time: HTTPTransport satisfies PeerTransport.
var _ PeerTransport = (*HTTPTransport)(nil)

// compile-time: memSink satisfies DeliverySink.
var _ DeliverySink = (*memSink)(nil)

// keep ed25519 import used even if other tests change.
var _ = ed25519.PublicKeySize
