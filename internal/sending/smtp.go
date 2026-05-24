// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"strings"
)

// SMTPSender delivers outbound mail via SMTP.  It resolves MX records for
// each recipient domain, attempts STARTTLS, and classifies the result.
//
// This is the reference implementation; Mox smtpclient (which provides
// DANE/MTA-STS enforcement on top of TLS) can be swapped in by providing an
// alternative Sender implementation.
type SMTPSender struct {
	// Dialer is used to establish TCP connections.  If nil, a plain net.Dialer
	// is used.  Inject a custom dialer to force a source IP (SourceBinding).
	Dialer interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}

	// DNSResolver resolves MX records.  If nil, net.DefaultResolver is used.
	DNSResolver interface {
		LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	}

	// TLSConfig is used for STARTTLS.  If nil, a permissive config is used
	// (InsecureSkipVerify=false; standard verification).  A stricter config
	// with per-MX DANE enforcement can be injected here.
	TLSConfig *tls.Config

	// Signer, if non-nil, signs every outbound message with a DKIM-Signature
	// header before the DATA phase.  Inject a *DKIMSigner wired to the
	// DKIMRotator so all outbound mail is authenticated.
	Signer MessageSigner

	// TLSPolicy controls STARTTLS enforcement.  The zero value
	// (TLSPolicyOpportunistic) preserves the historical opportunistic-TLS
	// behaviour; TLSPolicyRequired refuses to deliver in plaintext when the
	// remote advertises STARTTLS but the handshake fails (no silent downgrade).
	TLSPolicy TLSPolicy

	// Logger is used for operational warnings (e.g. unsigned send, TLS
	// downgrade).  If nil, the standard logger is used.
	Logger *log.Logger
}

// MessageSigner adds authentication headers (e.g. DKIM-Signature) to a raw
// RFC-822 message, returning a new message.  *DKIMSigner implements it.
type MessageSigner interface {
	// Sign returns a copy of raw with signing headers prepended.  It must not
	// mutate raw.
	Sign(raw []byte) ([]byte, error)
}

// TLSPolicy controls how STARTTLS failures are handled on the outbound path.
type TLSPolicy int

const (
	// TLSPolicyOpportunistic attempts STARTTLS when advertised but falls back
	// to plaintext if the handshake fails.  This is the historical default.
	TLSPolicyOpportunistic TLSPolicy = iota

	// TLSPolicyRequired refuses to deliver in plaintext: if the remote
	// advertises STARTTLS but the handshake fails, the attempt is deferred
	// rather than silently downgraded.  Use this as a secure default.
	TLSPolicyRequired
)

func (s *SMTPSender) logger() *log.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return log.Default()
}

// Send implements Sender.
func (s *SMTPSender) Send(ctx context.Context, msg Message) (SendResult, error) {
	if len(msg.Recipients) == 0 {
		return SendResult{State: StateBounced, Message: "no recipients"}, nil
	}

	// Group recipients by domain so we make one SMTP connection per MX domain.
	byDomain := groupByDomain(msg.Recipients)

	// Deliver to each domain group.  Collect results; if any recipient fails
	// we classify the whole call by the worst outcome (bounced > deferred > delivered).
	worst := SendResult{State: StateDelivered}

	for domain, rcpts := range byDomain {
		result, err := s.deliverToDomain(ctx, msg, domain, rcpts)
		if err != nil {
			// Infrastructure error — treat as deferred.
			result = SendResult{State: StateDeferred, Message: err.Error()}
		}
		worst = worseOf(worst, result)
	}

	return worst, nil
}

// deliverToDomain connects to the best MX for domain and delivers the message.
func (s *SMTPSender) deliverToDomain(ctx context.Context, msg Message, domain string, rcpts []string) (SendResult, error) {
	resolver := s.dnsResolver()
	mxs, err := resolver.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		// No MX → fall back to A/AAAA (implicit MX).
		mxs = []*net.MX{{Host: domain, Pref: 10}}
	}

	// Sort by preference (net.LookupMX returns them sorted, but be explicit).
	// Try each MX in order until one succeeds or all fail.
	var lastErr error
	for _, mx := range mxs {
		result, err := s.deliverToMX(ctx, msg, mx.Host, rcpts)
		if err == nil {
			return result, nil
		}
		lastErr = err
		// 5xx permanent → bounce immediately, don't try next MX.
		if result.State == StateBounced {
			return result, nil
		}
	}
	return SendResult{State: StateDeferred}, lastErr
}

// deliverToMX performs the SMTP transaction to a single MX host.
func (s *SMTPSender) deliverToMX(ctx context.Context, msg Message, mxHost string, rcpts []string) (SendResult, error) {
	addr := net.JoinHostPort(mxHost, "25")

	conn, err := s.dialer(msg.Binding).DialContext(ctx, "tcp", addr)
	if err != nil {
		return SendResult{State: StateDeferred}, fmt.Errorf("dial %s: %w", addr, err)
	}

	heloName := heloName(msg.Binding)

	c, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		_ = conn.Close()
		return SendResult{State: StateDeferred}, fmt.Errorf("smtp client %s: %w", mxHost, err)
	}
	defer c.Close() //nolint:errcheck

	// Send EHLO/HELO.  This must be done before any other command
	// (including Extension checks which trigger an implicit greeting).
	if err := c.Hello(heloName); err != nil {
		return SendResult{State: StateDeferred}, fmt.Errorf("EHLO %s: %w", heloName, err)
	}

	// Attempt STARTTLS if the remote advertises it.
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := s.tlsConfig(mxHost)
		if err := c.StartTLS(tlsCfg); err != nil {
			if s.TLSPolicy == TLSPolicyRequired {
				// Secure policy: never deliver in plaintext after a failed
				// STARTTLS handshake.  Defer so the message is retried rather
				// than silently downgraded to an unencrypted channel.
				s.logger().Printf("sending: STARTTLS required but handshake to %s failed: %v — refusing plaintext downgrade", mxHost, err)
				return SendResult{State: StateDeferred, Message: fmt.Sprintf("STARTTLS required but failed: %v", err)},
					fmt.Errorf("starttls to %s: %w", mxHost, err)
			}
			// Opportunistic policy: STARTTLS failure is non-fatal; continue in
			// plain text but log the downgrade for operator visibility.
			s.logger().Printf("sending: STARTTLS to %s failed, continuing in plaintext (opportunistic policy): %v", mxHost, err)
		}
	} else if s.TLSPolicy == TLSPolicyRequired {
		// Remote does not advertise STARTTLS at all; required policy refuses.
		s.logger().Printf("sending: STARTTLS required but %s does not advertise it — refusing plaintext delivery", mxHost)
		return SendResult{State: StateDeferred, Message: "STARTTLS required but not offered by remote"},
			fmt.Errorf("starttls required but %s does not offer it", mxHost)
	}

	// Apply DKIM (or other) signing just before the DATA phase so every
	// outbound message is authenticated.
	rawToSend := msg.RawRFC822
	if s.Signer != nil {
		signed, signErr := s.Signer.Sign(rawToSend)
		if signErr != nil {
			// Signing failure: do not silently send unsigned mail when a signer
			// is configured.  Defer so the operator can fix key material.
			s.logger().Printf("sending: DKIM signing failed for message %s: %v — deferring", msg.ID, signErr)
			return SendResult{State: StateDeferred, Message: fmt.Sprintf("DKIM signing failed: %v", signErr)},
				fmt.Errorf("dkim sign: %w", signErr)
		}
		rawToSend = signed
	}

	if err := c.Mail(msg.Sender); err != nil {
		return classifyErr(err), nil
	}

	for _, rcpt := range rcpts {
		if err := c.Rcpt(rcpt); err != nil {
			return classifyErr(err), nil
		}
	}

	wc, err := c.Data()
	if err != nil {
		return classifyErr(err), nil
	}
	if _, err := wc.Write(rawToSend); err != nil {
		_ = wc.Close()
		return SendResult{State: StateDeferred}, fmt.Errorf("write data: %w", err)
	}
	if err := wc.Close(); err != nil {
		return classifyErr(err), nil
	}

	_ = c.Quit()

	return SendResult{
		State:    StateDelivered,
		Code:     250,
		Provider: inferProvider(mxHost),
	}, nil
}

// classifyErr maps an smtp error (which embeds the reply code) to a SendResult.
func classifyErr(err error) SendResult {
	if err == nil {
		return SendResult{State: StateDelivered, Code: 250}
	}
	text := err.Error()

	// net/smtp wraps SMTP errors as "NNN message"; parse the code.
	code := 0
	if len(text) >= 3 {
		for i := 0; i < 3; i++ {
			if text[i] < '0' || text[i] > '9' {
				code = 0
				break
			}
			code = code*10 + int(text[i]-'0')
		}
	}

	state := StateDeferred
	if code >= 500 {
		state = StateBounced
	}

	// Extract enhanced code if present (e.g. "550 5.1.1 User unknown").
	enhanced := ""
	if len(text) > 4 {
		rest := text[4:]
		parts := strings.SplitN(rest, " ", 2)
		if len(parts[0]) >= 5 && strings.Count(parts[0], ".") == 2 {
			enhanced = parts[0]
		}
	}

	return SendResult{
		State:        state,
		Code:         code,
		EnhancedCode: enhanced,
		Message:      text,
	}
}

// inferProvider returns a canonical provider name from an MX hostname.
func inferProvider(mxHost string) string {
	lower := strings.ToLower(mxHost)
	switch {
	case strings.Contains(lower, "google") || strings.Contains(lower, "gmail"):
		return "gmail"
	case strings.Contains(lower, "outlook") || strings.Contains(lower, "hotmail") || strings.Contains(lower, "microsoft"):
		return "outlook"
	case strings.Contains(lower, "yahoo"):
		return "yahoo"
	case strings.Contains(lower, "amazon") || strings.Contains(lower, "amazonaws"):
		return "ses"
	default:
		return ""
	}
}

// groupByDomain groups addresses by their domain part.
func groupByDomain(addrs []string) map[string][]string {
	out := make(map[string][]string)
	for _, a := range addrs {
		parts := strings.SplitN(a, "@", 2)
		if len(parts) != 2 {
			continue
		}
		domain := strings.ToLower(parts[1])
		out[domain] = append(out[domain], a)
	}
	return out
}

// worseOf returns the result representing the worse delivery state.
func worseOf(a, b SendResult) SendResult {
	rank := map[SendState]int{StateDelivered: 0, StateDeferred: 1, StateBounced: 2}
	if rank[b.State] > rank[a.State] {
		return b
	}
	return a
}

func (s *SMTPSender) dnsResolver() interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
} {
	if s.DNSResolver != nil {
		return s.DNSResolver
	}
	return net.DefaultResolver
}

func (s *SMTPSender) dialer(binding *SourceBinding) interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
} {
	if s.Dialer != nil {
		return s.Dialer
	}
	if binding != nil && binding.LocalIP != nil {
		return &net.Dialer{LocalAddr: &net.TCPAddr{IP: binding.LocalIP}}
	}
	return &net.Dialer{}
}

func (s *SMTPSender) tlsConfig(serverName string) *tls.Config {
	if s.TLSConfig != nil {
		cfg := s.TLSConfig.Clone()
		cfg.ServerName = serverName
		return cfg
	}
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
}

func heloName(binding *SourceBinding) string {
	if binding != nil && binding.HELOName != "" {
		return binding.HELOName
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "localhost"
}

// bufReader is a helper for tests that wraps a bytes.Buffer as an io.Reader.
var _ = bytes.NewBuffer // ensure bytes is used
