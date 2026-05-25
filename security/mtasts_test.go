// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// ─── Attack class 6: MTA-STS enforcement ─────────────────────────────────────
//
// Under an MTA-STS (RFC 8461) enforce policy, a delivery MUST go over TLS to an
// MX that matches the policy with a CA-valid cert. A network attacker who
// strips STARTTLS (downgrade), offers no STARTTLS, or substitutes a non-policy
// MX must cause the message to be DEFERRED — never delivered in plaintext.
// These tests put a hostile SMTP sink in front of the SMTPSender and prove no
// plaintext escapes.

// stsSink is a minimal SMTP server. If advertiseTLS is true it advertises
// STARTTLS but tears the connection on the handshake (a downgrade/MITM). It
// records whether it ever received DATA in the clear (the canary).
type stsSink struct {
	ln           net.Listener
	advertiseTLS bool

	mu            sync.Mutex
	plaintextData string
}

func newSTSSink(t *testing.T, advertiseTLS bool) *stsSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &stsSink{ln: ln, advertiseTLS: advertiseTLS}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *stsSink) addr() string { return s.ln.Addr().String() }

func (s *stsSink) capturedPlaintext() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plaintextData
}

func (s *stsSink) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *stsSink) handle(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	write := func(line string) { _, _ = fmt.Fprintf(w, "%s\r\n", line); _ = w.Flush() }

	write("220 sink.test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			if s.advertiseTLS {
				write("250-sink.test")
				write("250 STARTTLS")
			} else {
				write("250-sink.test")
				write("250 OK")
			}
		case strings.HasPrefix(upper, "STARTTLS"):
			write("220 Go ahead")
			return // tear the connection: the client's TLS handshake fails (downgrade)
		case strings.HasPrefix(upper, "MAIL FROM"):
			write("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			write("250 OK")
		case upper == "DATA":
			write("354 End data")
			var b strings.Builder
			for {
				d, e := r.ReadString('\n')
				if e != nil {
					return
				}
				if strings.TrimRight(d, "\r\n") == "." {
					break
				}
				b.WriteString(d)
			}
			s.mu.Lock()
			s.plaintextData = b.String() // a plaintext delivery happened — the canary fired
			s.mu.Unlock()
			write("250 OK queued")
		case strings.HasPrefix(upper, "QUIT"):
			write("221 Bye")
			return
		default:
			write("500 unknown")
		}
	}
}

// stsDialer forces every dial to a fixed address (the sink).
type stsDialer struct{ addr string }

func (d stsDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.addr)
}

// stsMX resolves any domain to a fixed MX host.
type stsMX struct{ host string }

func (r stsMX) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return []*net.MX{{Host: r.host, Pref: 10}}, nil
}

// stsHTTP serves a fixed mta-sts.txt body so PolicyFor resolves an enforce
// policy without touching the network.
type stsHTTP struct{ body string }

func (g stsHTTP) Get(string) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(g.body))}, nil
}

func enforceCache(t *testing.T, body string) *sending.MTASTSCache {
	t.Helper()
	c := sending.NewMTASTSCache()
	c.HTTPClient = stsHTTP{body: body}
	return c
}

func mtastsSender(sink *stsSink, cache *sending.MTASTSCache, mxHost string) *sending.SMTPSender {
	return &sending.SMTPSender{
		DNSResolver: stsMX{host: mxHost},
		Dialer:      stsDialer{addr: sink.addr()},
		TLSPolicy:   sending.TLSPolicyOpportunistic, // MTA-STS must OVERRIDE this to enforce
		MTASTS:      cache,
	}
}

func sendOne(t *testing.T, s *sending.SMTPSender) sending.SendResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := s.Send(ctx, sending.Message{
		ID:         "sts",
		Sender:     "alice@tenant.example",
		Recipients: []string{"bob@enforced.example"},
		RawRFC822:  []byte("From: alice@tenant.example\r\nSubject: hi\r\n\r\nbody\r\n"),
	})
	return res
}

// ATTACK: STARTTLS downgrade/MITM — the MX advertises STARTTLS but the handshake
// fails. EXPECT: deferred, NO plaintext delivery.
func TestMTASTS_StartTLSDowngrade_DefersNoPlaintext(t *testing.T) {
	sink := newSTSSink(t, true) // advertises STARTTLS but breaks the handshake
	host, _, _ := net.SplitHostPort(sink.addr())
	cache := enforceCache(t, "version: STSv1\nmode: enforce\nmx: "+host+"\nmax_age: 86400\n")

	res := sendOne(t, mtastsSender(sink, cache, host))
	if res.State != sending.StateDeferred {
		t.Fatalf("want deferred under enforce downgrade, got %s (%s)", res.State, res.Message)
	}
	if got := sink.capturedPlaintext(); got != "" {
		t.Fatalf("VULN: message delivered in plaintext despite MTA-STS enforce:\n%s", got)
	}
}

// ATTACK: the MX never offers STARTTLS at all under an enforce policy.
// EXPECT: deferred, no plaintext delivery.
func TestMTASTS_NoStartTLS_DefersNoPlaintext(t *testing.T) {
	sink := newSTSSink(t, false) // never advertises STARTTLS
	host, _, _ := net.SplitHostPort(sink.addr())
	cache := enforceCache(t, "version: STSv1\nmode: enforce\nmx: "+host+"\nmax_age: 86400\n")

	res := sendOne(t, mtastsSender(sink, cache, host))
	if res.State != sending.StateDeferred {
		t.Fatalf("want deferred when enforce MX offers no STARTTLS, got %s", res.State)
	}
	if got := sink.capturedPlaintext(); got != "" {
		t.Fatalf("VULN: plaintext delivery despite enforce + no STARTTLS:\n%s", got)
	}
}

// ATTACK: DNS substitutes an MX that is NOT listed in the enforce policy (an
// attacker-controlled server). EXPECT: deferred, never delivered to the
// off-policy MX.
func TestMTASTS_MXNotInPolicy_DefersNoPlaintext(t *testing.T) {
	sink := newSTSSink(t, false)
	host, _, _ := net.SplitHostPort(sink.addr())
	// The policy lists a DIFFERENT MX than DNS returns (the sink).
	cache := enforceCache(t, "version: STSv1\nmode: enforce\nmx: legit-mx.enforced.example\nmax_age: 86400\n")

	res := sendOne(t, mtastsSender(sink, cache, host))
	if res.State != sending.StateDeferred {
		t.Fatalf("want deferred when MX not in enforce policy, got %s", res.State)
	}
	if got := sink.capturedPlaintext(); got != "" {
		t.Fatalf("VULN: delivered to a non-policy MX despite enforce:\n%s", got)
	}
}
