// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// capturingSink is an SMTP sink that records the DATA payload and advertises a
// configurable extension set.
type capturingSink struct {
	ln           net.Listener
	advertiseTLS bool

	mu   sync.Mutex
	data string
}

func newCapturingSink(t *testing.T, advertiseTLS bool) *capturingSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &capturingSink{ln: ln, advertiseTLS: advertiseTLS}
	go s.serve()
	return s
}

func (s *capturingSink) addr() string { return s.ln.Addr().String() }
func (s *capturingSink) close()       { _ = s.ln.Close() }

func (s *capturingSink) captured() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

func (s *capturingSink) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *capturingSink) handle(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	write := func(line string) {
		_, _ = fmt.Fprintf(w, "%s\r\n", line)
		_ = w.Flush()
	}

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
			// Advertise STARTTLS, then make the handshake fail by sending a 220
			// and immediately tearing the connection (no real TLS server).
			write("220 Go ahead")
			// Closing here causes the client's TLS handshake to fail.
			return
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
			s.data = b.String()
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

type fixedDialer2 struct{ addr string }

func (d fixedDialer2) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.addr)
}

type fixedMX struct{ host string }

func (r fixedMX) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return []*net.MX{{Host: r.host, Pref: 10}}, nil
}

// TestSMTPSenderAppliesDKIM verifies the P0 wiring: when a Signer is set on the
// SMTPSender, the bytes written in the DATA phase carry a DKIM-Signature header.
func TestSMTPSenderAppliesDKIM(t *testing.T) {
	sink := newCapturingSink(t, false)
	defer sink.close()

	store := sending.NewMemKeyStore()
	rotator, err := sending.NewDKIMRotator("example.com", store, sending.DKIMRotatorConfig{KeyBits: 1024, PropagationGrace: 0})
	if err != nil {
		t.Fatalf("rotator: %v", err)
	}
	if _, err := rotator.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	signer, err := sending.NewDKIMSigner(sending.DKIMSignerConfig{Domain: "example.com", Provider: rotator})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	host, _, _ := net.SplitHostPort(sink.addr())
	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		Signer:      signer,
		TLSPolicy:   sending.TLSPolicyOpportunistic, // sink doesn't offer TLS
	}

	msg := sending.Message{
		ID:         "m1",
		Sender:     "alice@example.com",
		Recipients: []string{"bob@example.org"},
		RawRFC822:  []byte("From: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := s.Send(ctx, msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.State != sending.StateDelivered {
		t.Fatalf("want delivered, got %s (%s)", res.State, res.Message)
	}

	data := sink.captured()
	if !strings.Contains(data, "DKIM-Signature:") {
		t.Fatalf("DATA payload missing DKIM-Signature header:\n%s", data)
	}
	if !strings.Contains(data, "d=example.com") {
		t.Errorf("DKIM-Signature missing d=example.com:\n%s", data)
	}
}

// TestSMTPSenderTLSRequiredRefusesDowngrade verifies the P1 fix: with
// TLSPolicyRequired, a failed STARTTLS handshake defers rather than silently
// delivering in plaintext.
func TestSMTPSenderTLSRequiredRefusesDowngrade(t *testing.T) {
	sink := newCapturingSink(t, true) // advertises STARTTLS but handshake fails
	defer sink.close()

	host, _, _ := net.SplitHostPort(sink.addr())
	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		TLSPolicy:   sending.TLSPolicyRequired,
	}

	msg := sending.Message{
		ID:         "m2",
		Sender:     "alice@example.com",
		Recipients: []string{"bob@example.org"},
		RawRFC822:  []byte("From: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := s.Send(ctx, msg)
	if res.State != sending.StateDeferred {
		t.Fatalf("want StateDeferred (refused plaintext downgrade), got %s (%s)", res.State, res.Message)
	}
	// And the message must NOT have been delivered in plaintext.
	if got := sink.captured(); got != "" {
		t.Fatalf("message was delivered in plaintext despite TLS-required policy:\n%s", got)
	}
}

// TestSMTPSenderTLSRequiredRefusesNoSTARTTLS verifies that a remote which does
// not advertise STARTTLS is also refused under the required policy.
func TestSMTPSenderTLSRequiredRefusesNoSTARTTLS(t *testing.T) {
	sink := newCapturingSink(t, false) // never advertises STARTTLS
	defer sink.close()

	host, _, _ := net.SplitHostPort(sink.addr())
	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		TLSPolicy:   sending.TLSPolicyRequired,
	}

	msg := sending.Message{
		ID:         "m3",
		Sender:     "alice@example.com",
		Recipients: []string{"bob@example.org"},
		RawRFC822:  []byte("From: alice@example.com\r\n\r\nbody\r\n"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := s.Send(ctx, msg)
	if res.State != sending.StateDeferred {
		t.Fatalf("want StateDeferred when STARTTLS not offered under required policy, got %s", res.State)
	}
	if got := sink.captured(); got != "" {
		t.Fatalf("delivered despite no STARTTLS under required policy:\n%s", got)
	}
}
