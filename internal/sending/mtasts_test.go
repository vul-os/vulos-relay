// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// stubMTASTSGetter serves a fixed mta-sts.txt body for the well-known URL.
type stubMTASTSGetter struct {
	body   string
	status int
	calls  int
}

func (g *stubMTASTSGetter) Get(string) (*http.Response, error) {
	g.calls++
	status := g.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(g.body)),
	}, nil
}

func newEnforceCache(t *testing.T, body string) *sending.MTASTSCache {
	t.Helper()
	c := sending.NewMTASTSCache()
	c.HTTPClient = &stubMTASTSGetter{body: body}
	return c
}

// TestMTASTSPolicyParseAndMatch verifies parsing and MX-pattern matching,
// including the single-label wildcard form.
func TestMTASTSPolicyParseAndMatch(t *testing.T) {
	cache := newEnforceCache(t, "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.mx.example.com\nmax_age: 86400\n")
	p, err := cache.PolicyFor(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("PolicyFor: %v", err)
	}
	if p == nil || p.Mode != sending.MTASTSEnforce {
		t.Fatalf("want enforce policy, got %+v", p)
	}
	if !p.MatchesMX("mail.example.com") {
		t.Error("exact MX should match")
	}
	if !p.MatchesMX("a.mx.example.com") {
		t.Error("single-label wildcard should match a.mx.example.com")
	}
	if p.MatchesMX("a.b.mx.example.com") {
		t.Error("wildcard must match exactly one label, not two")
	}
	if p.MatchesMX("evil.attacker.net") {
		t.Error("non-listed MX must not match")
	}
}

// TestMTASTSEnforceDefersOnDowngrade is the security proof: a domain with an
// enforce policy whose MX advertises STARTTLS but fails the handshake (a
// downgrade/MITM) MUST defer, never deliver in plaintext.
func TestMTASTSEnforceDefersOnDowngrade(t *testing.T) {
	sink := newCapturingSink(t, true) // advertises STARTTLS but the handshake fails
	defer sink.close()

	host, _, _ := net.SplitHostPort(sink.addr())

	// Enforce policy listing exactly this MX host.
	cache := newEnforceCache(t, "version: STSv1\nmode: enforce\nmx: "+host+"\nmax_age: 86400\n")

	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		// Opportunistic base policy — MTA-STS must override it to enforce TLS.
		TLSPolicy: sending.TLSPolicyOpportunistic,
		MTASTS:    cache,
	}

	msg := sending.Message{
		ID:         "mts1",
		Sender:     "alice@sender.test",
		Recipients: []string{"bob@example.com"},
		RawRFC822:  []byte("From: alice@sender.test\r\nSubject: hi\r\n\r\nbody\r\n"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := s.Send(ctx, msg)
	if res.State != sending.StateDeferred {
		t.Fatalf("want StateDeferred under MTA-STS enforce downgrade, got %s (%s)", res.State, res.Message)
	}
	if got := sink.captured(); got != "" {
		t.Fatalf("message delivered in plaintext despite MTA-STS enforce:\n%s", got)
	}
}

// TestMTASTSEnforceDefersOnNoSTARTTLS verifies that an enforce policy where the
// MX never advertises STARTTLS at all also defers (downgrade refusal), even
// when the base TLS policy is opportunistic.
func TestMTASTSEnforceDefersOnNoSTARTTLS(t *testing.T) {
	sink := newCapturingSink(t, false) // never advertises STARTTLS
	defer sink.close()
	host, _, _ := net.SplitHostPort(sink.addr())
	cache := newEnforceCache(t, "version: STSv1\nmode: enforce\nmx: "+host+"\nmax_age: 86400\n")

	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		TLSPolicy:   sending.TLSPolicyOpportunistic,
		MTASTS:      cache,
	}
	msg := sending.Message{
		ID:         "mts2",
		Sender:     "alice@sender.test",
		Recipients: []string{"bob@example.com"},
		RawRFC822:  []byte("From: alice@sender.test\r\n\r\nbody\r\n"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := s.Send(ctx, msg)
	if res.State != sending.StateDeferred {
		t.Fatalf("want StateDeferred when enforce MX offers no STARTTLS, got %s", res.State)
	}
	if got := sink.captured(); got != "" {
		t.Fatalf("delivered in plaintext despite enforce + no STARTTLS:\n%s", got)
	}
}

// TestMTASTSEnforceDefersOnMXMismatch verifies that under an enforce policy a
// message is NOT delivered to an MX that is not listed in the policy (an
// attacker-substituted MX), even if that MX would happily accept it.
func TestMTASTSEnforceDefersOnMXMismatch(t *testing.T) {
	sink := newCapturingSink(t, false)
	defer sink.close()
	host, _, _ := net.SplitHostPort(sink.addr())

	// Policy lists a DIFFERENT MX than the one DNS returns.
	cache := newEnforceCache(t, "version: STSv1\nmode: enforce\nmx: legit.example.com\nmax_age: 86400\n")

	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host}, // resolves to the sink, which is NOT in policy
		Dialer:      fixedDialer2{addr: sink.addr()},
		TLSPolicy:   sending.TLSPolicyOpportunistic,
		MTASTS:      cache,
	}
	msg := sending.Message{
		ID:         "mts3",
		Sender:     "alice@sender.test",
		Recipients: []string{"bob@example.com"},
		RawRFC822:  []byte("From: alice@sender.test\r\n\r\nbody\r\n"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := s.Send(ctx, msg)
	if res.State != sending.StateDeferred {
		t.Fatalf("want StateDeferred when MX not in enforce policy, got %s", res.State)
	}
	if got := sink.captured(); got != "" {
		t.Fatalf("delivered to a non-policy MX despite enforce:\n%s", got)
	}
}

// TestMTASTSNonePolicyFallsBackToOpportunistic verifies that a domain with no
// enforcing policy (mode: none) does not block delivery: the base TLS policy
// applies. The sink here advertises no STARTTLS and the base policy is
// opportunistic, so delivery should succeed in plaintext.
func TestMTASTSNonePolicyFallsBackToOpportunistic(t *testing.T) {
	sink := newCapturingSink(t, false)
	defer sink.close()
	host, _, _ := net.SplitHostPort(sink.addr())
	cache := newEnforceCache(t, "version: STSv1\nmode: none\nmax_age: 86400\n")

	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		TLSPolicy:   sending.TLSPolicyOpportunistic,
		MTASTS:      cache,
	}
	msg := sending.Message{
		ID:         "mts4",
		Sender:     "alice@sender.test",
		Recipients: []string{"bob@example.com"},
		RawRFC822:  []byte("From: alice@sender.test\r\n\r\nbody\r\n"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := s.Send(ctx, msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.State != sending.StateDelivered {
		t.Fatalf("want delivered under mode:none + opportunistic, got %s (%s)", res.State, res.Message)
	}
}
