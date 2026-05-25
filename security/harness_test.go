// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Package security_test holds the vulos-relay pentest / adversarial suite.
//
// Every test in this package ATTEMPTS a concrete attack against the real relay
// surfaces (the submission listener, the peering HTTP ingress, the replay
// guard, the per-IP rate cap, the trust-segment gating, the MTA-STS enforce
// path, the suppression send-gate, and the DKIM sign→verify roundtrip) and
// ASSERTS the attack is BLOCKED. A passing run is the proof that none of the
// modelled attacks succeed.
//
// The suite is intentionally black-box: it drives only the EXPORTED relay API
// the way a hostile peer or client would, reusing the production wiring
// (Receiver + IngressHandler over httptest, SubmitHandler over httptest,
// SMTPSender against a capturing SMTP sink). It does not reach into unexported
// state, so a regression that opens a hole is caught at the boundary an
// attacker actually sees.
package security_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/vul-os/vulos-relay/internal/peering"
)

// attackerSink is a peering DeliverySink that records everything the ingress
// hands it AFTER all §7–§8 checks pass. In a pentest it is the canary: if any
// rejected/forged envelope reaches it, the attack succeeded and the relay has a
// hole. delivered() must be 0 for every "rejected" test.
type attackerSink struct {
	mu       sync.Mutex
	messages []sunkMessage
	failNext bool // when set, the next Deliver returns a transient error
}

type sunkMessage struct {
	mailFrom string
	rcptTo   []string
	raw      []byte
}

func (s *attackerSink) Deliver(_ context.Context, mailFrom string, rcptTo []string, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return errSpoolDown
	}
	s.messages = append(s.messages, sunkMessage{mailFrom, rcptTo, append([]byte(nil), raw...)})
	return nil
}

func (s *attackerSink) delivered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

var errSpoolDown = &transientErr{"spool unavailable"}

type transientErr struct{ s string }

func (e *transientErr) Error() string { return e.s }

// peerVictim models one relay process under attack: a long-term identity, the
// domains it is authoritative for, a resolver holding its pins, the real
// peering ingress on an httptest server, and the canary sink. It is the exact
// production receiver wiring (peering.Receiver behind peering.IngressHandler),
// so the attacks below exercise the real code path, not a test stub.
type peerVictim struct {
	id       *peering.Identity
	domain   string
	resolver *peering.StaticResolver
	sink     *attackerSink
	guard    *peering.ReplayGuard
	srv      *httptest.Server
}

// newPeerVictim stands up a relay authoritative for domain with a live HTTP
// peering ingress. guard, when non-nil, replaces the default ReplayGuard so a
// test can pin the clock / cache size.
func newPeerVictim(t *testing.T, domain string, guard *peering.ReplayGuard) *peerVictim {
	t.Helper()
	id, err := peering.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if guard == nil {
		guard = peering.NewReplayGuard()
	}
	v := &peerVictim{
		id:       id,
		domain:   domain,
		resolver: peering.NewStaticResolver(),
		sink:     &attackerSink{},
		guard:    guard,
	}
	rc := &peering.Receiver{
		Identity:   id,
		Authorized: func(d string) bool { return d == domain },
		PinnedKey:  v.resolver.PinnedKey,
		Guard:      guard,
		Resolver:   v.resolver,
		Sink:       v.sink,
		Logf:       func(string, ...any) {},
	}
	mux := http.NewServeMux()
	mux.Handle(peering.PeeringPath, peering.IngressHandler(rc))
	v.srv = httptest.NewServer(mux)
	t.Cleanup(v.srv.Close)
	return v
}

// descriptor returns the descriptor an attacker / peer uses to reach v.
func (v *peerVictim) descriptor() *peering.PeerDescriptor {
	return &peering.PeerDescriptor{
		Domains:     []string{v.domain},
		IdentityPub: v.id.SignPub,
		KexPub:      v.id.KexPub,
		Versions:    []string{peering.ProtoV1},
		Suites:      []string{peering.SuiteV1},
		Endpoint:    v.srv.URL + peering.PeeringPath,
	}
}

// pin registers other into v's resolver so v can authenticate inbound envelopes
// from other (i.e. other is a known/trusted peer of v).
func (v *peerVictim) pin(t *testing.T, other *peerVictim) {
	t.Helper()
	if err := v.resolver.Add(other.descriptor()); err != nil {
		t.Fatalf("pin %s into %s: %v", other.domain, v.domain, err)
	}
}

// pinIdentity registers an arbitrary identity (used for forged-key tests).
func (v *peerVictim) pinIdentity(t *testing.T, domain string, id *peering.Identity) {
	t.Helper()
	if err := v.resolver.Add(&peering.PeerDescriptor{
		Domains:     []string{domain},
		IdentityPub: id.SignPub,
		KexPub:      id.KexPub,
		Versions:    []string{peering.ProtoV1},
		Suites:      []string{peering.SuiteV1},
		Endpoint:    "pinned-endpoint",
	}); err != nil {
		t.Fatalf("pin identity for %s: %v", domain, err)
	}
}

// postWire delivers a raw wire blob straight to v's ingress over real HTTP, the
// way a hostile peer would, and returns the HTTP status and the machine-readable
// X-Vulos-Peer-Outcome header (empty for transient/non-peer responses). This is
// the attacker's exact view of the boundary; the test asserts on it.
func postWire(t *testing.T, v *peerVictim, wire []byte) (status int, outcome string) {
	t.Helper()
	resp, err := http.Post(v.srv.URL+peering.PeeringPath, "application/vulos-peer-envelope", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("POST ingress: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("X-Vulos-Peer-Outcome")
}

// sealFrom builds a normal, valid envelope from sender (authoritative for
// senderDomain) to the victim. Tests then tamper with it to mount an attack.
func sealFrom(t *testing.T, sender *peering.Identity, senderDomain string, victim *peerVictim, mailFrom string, rcpt []string, body []byte) *peering.Envelope {
	t.Helper()
	env, err := peering.Seal(peering.SealParams{
		Sender:       sender,
		SenderDomain: senderDomain,
		Receiver:     victim.descriptor(),
		MailFrom:     mailFrom,
		RcptTo:       rcpt,
		RawRFC822:    body,
		Proto:        peering.ProtoV1,
		Suite:        peering.SuiteV1,
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return env
}

// keep ed25519 referenced for the forged-key tests that import it transitively.
var _ = ed25519.PublicKeySize
