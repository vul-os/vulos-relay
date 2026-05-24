// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/queue"
	"github.com/vul-os/vulos-relay/internal/reputation"
	"github.com/vul-os/vulos-relay/internal/sending"
)

// stubSender is an in-process Sender that records calls and immediately
// returns StateDelivered.  It is the stub SMTP target for the wire-up test.
type stubSender struct {
	calls   int
	results []sending.SendResult
}

func (s *stubSender) Send(_ context.Context, _ sending.Message) (sending.SendResult, error) {
	s.calls++
	if len(s.results) == 0 {
		return sending.SendResult{State: sending.StateDelivered, Code: 250}, nil
	}
	r := s.results[0]
	if len(s.results) > 1 {
		s.results = s.results[1:]
	}
	return r, nil
}

// TestWireUpDeliverAck is an end-to-end wire-up test: it builds an in-memory
// queue + Permissive policy + stub SMTP target, enqueues one message, runs
// the pipeline, and confirms the message is acked (removed from queue).
func TestWireUpDeliverAck(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(queue.OutboundMessage{
		ID:            "wire-test-1",
		AccountID:     "test-account",
		Sender:        "sender@example.com",
		Recipients:    []string{"rcpt@example.org"},
		RawRFC822:     []byte("Subject: wire test\r\n\r\nHello world"),
		NextAttemptAt: time.Now().Add(-time.Second), // immediately eligible
	})

	policy := reputation.Permissive{}
	// sentCh is closed by the stub once Send is called, signalling the test.
	sentCh := make(chan struct{})
	stub := &signalSender{ch: sentCh}

	cfg := sending.PipelineConfig{
		Workers:      2,
		LeaseCount:   5,
		RetryBackoff: 50 * time.Millisecond,
		PollInterval: 10 * time.Millisecond,
	}
	pipeline := sending.NewPipeline(q, policy, stub, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		pipeline.Run(ctx)
		close(done)
	}()

	// Wait until the stub signals that Send was called, then cancel.
	select {
	case <-sentCh:
	case <-ctx.Done():
		t.Fatal("timed out waiting for pipeline to call Send")
	}
	cancel()
	<-done

	// After the pipeline drains, the message must be acked (queue empty).
	_, err := q.Lease(context.Background(), 10)
	if err != queue.ErrEmpty {
		t.Errorf("expected queue empty after ack, got err=%v", err)
	}
}

// signalSender closes ch on the first Send call, then returns StateDelivered.
type signalSender struct {
	once sync.Once
	ch   chan struct{}
}

func (s *signalSender) Send(_ context.Context, _ sending.Message) (sending.SendResult, error) {
	s.once.Do(func() { close(s.ch) })
	return sending.SendResult{State: sending.StateDelivered, Code: 250}, nil
}

// TestWireUpBounceDeadLetters verifies that a permanent SMTP failure (5xx)
// dead-letters the message rather than retrying.
func TestWireUpBounceDeadLetters(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(queue.OutboundMessage{
		ID:            "wire-test-bounce",
		AccountID:     "test-account",
		Sender:        "sender@example.com",
		Recipients:    []string{"rcpt@example.org"},
		RawRFC822:     []byte("Subject: bounce test\r\n\r\nBounce"),
		NextAttemptAt: time.Now().Add(-time.Second),
	})

	policy := reputation.Permissive{}
	stub := &stubSender{
		results: []sending.SendResult{
			{State: sending.StateBounced, Code: 550, Message: "550 user unknown"},
		},
	}

	cfg := sending.PipelineConfig{
		Workers:      1,
		LeaseCount:   5,
		RetryBackoff: 1 * time.Hour, // long backoff — message must not retry
		PollInterval: 10 * time.Millisecond,
	}
	pipeline := sending.NewPipeline(q, policy, stub, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		pipeline.Run(ctx)
		close(done)
	}()

	// Wait until dead-lettered.
	deadline := time.Now().Add(2 * time.Second)
	deadLettered := false
	for time.Now().Before(deadline) {
		dls := q.DeadLetters()
		if _, ok := dls["wire-test-bounce"]; ok {
			deadLettered = true
			cancel()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	<-done

	if !deadLettered {
		t.Error("expected wire-test-bounce to be dead-lettered after 5xx response")
	}
}

// TestEnvConfig verifies that parseConfig reads from environment variables
// correctly, using the helper functions.
func TestEnvConfig(t *testing.T) {
	t.Setenv("RELAY_QUEUE_BACKEND", "mem")
	t.Setenv("RELAY_QUEUE_DIR", "/tmp/testqueue")
	t.Setenv("RELAY_POLICY", "capped")
	t.Setenv("RELAY_POLICY_DAILY_CAP", "500")
	t.Setenv("RELAY_POLICY_BOUNCE_THRESHOLD", "0.05")
	t.Setenv("RELAY_POLICY_WINDOW_SIZE", "50")
	t.Setenv("RELAY_SMTP_LOCAL_IP", "")
	t.Setenv("RELAY_SMTP_HELO", "relay.example.com")
	t.Setenv("RELAY_PEER_CONFIG", "/etc/vulos/peers.json")
	t.Setenv("RELAY_WORKERS", "8")

	cfg := parseConfig()

	if cfg.QueueBackend != "mem" {
		t.Errorf("QueueBackend: want mem, got %s", cfg.QueueBackend)
	}
	if cfg.QueueDir != "/tmp/testqueue" {
		t.Errorf("QueueDir: want /tmp/testqueue, got %s", cfg.QueueDir)
	}
	if cfg.Policy != "capped" {
		t.Errorf("Policy: want capped, got %s", cfg.Policy)
	}
	if cfg.PolicyDailyCap != 500 {
		t.Errorf("PolicyDailyCap: want 500, got %d", cfg.PolicyDailyCap)
	}
	if cfg.PolicyBounceThreshold != 0.05 {
		t.Errorf("PolicyBounceThreshold: want 0.05, got %f", cfg.PolicyBounceThreshold)
	}
	if cfg.PolicyWindowSize != 50 {
		t.Errorf("PolicyWindowSize: want 50, got %d", cfg.PolicyWindowSize)
	}
	if cfg.SMTPHelo != "relay.example.com" {
		t.Errorf("SMTPHelo: want relay.example.com, got %s", cfg.SMTPHelo)
	}
	if cfg.PeerConfig != "/etc/vulos/peers.json" {
		t.Errorf("PeerConfig: want /etc/vulos/peers.json, got %s", cfg.PeerConfig)
	}
	if cfg.Workers != 8 {
		t.Errorf("Workers: want 8, got %d", cfg.Workers)
	}
}

// TestBuildPolicy verifies that buildPolicy returns the right types.
func TestBuildPolicy(t *testing.T) {
	permCfg := config{Policy: "permissive"}
	perm := buildPolicy(permCfg)
	if _, ok := perm.(reputation.Permissive); !ok {
		t.Errorf("expected Permissive, got %T", perm)
	}

	cappedCfg := config{
		Policy:                "capped",
		PolicyDailyCap:        200,
		PolicyBounceThreshold: 0.20,
		PolicyWindowSize:      40,
	}
	capped := buildPolicy(cappedCfg)
	cp, ok := capped.(*reputation.CappedPolicy)
	if !ok {
		t.Fatalf("expected *CappedPolicy, got %T", capped)
	}
	if cp.DailyCap != 200 {
		t.Errorf("DailyCap: want 200, got %d", cp.DailyCap)
	}
	if cp.BounceThreshold != 0.20 {
		t.Errorf("BounceThreshold: want 0.20, got %f", cp.BounceThreshold)
	}
	if cp.WindowSize != 40 {
		t.Errorf("WindowSize: want 40, got %d", cp.WindowSize)
	}
}

// TestBuildSMTPSenderBinding confirms that a valid RELAY_SMTP_LOCAL_IP wires a
// custom Dialer and an invalid one logs-and-falls-back (no panic).
func TestBuildSMTPSenderBinding(t *testing.T) {
	validCfg := config{SMTPLocalIP: "127.0.0.1"}
	s := buildSMTPSender(validCfg, nil)
	if s.Dialer == nil {
		t.Error("expected Dialer to be set for valid IP")
	}
	// Verify it is actually backed by the correct local address.
	d, ok := s.Dialer.(*net.Dialer)
	if !ok {
		t.Fatalf("expected *net.Dialer, got %T", s.Dialer)
	}
	if d.LocalAddr == nil {
		t.Error("expected LocalAddr to be set")
	}

	// Invalid IP: should fall back gracefully (Dialer remains nil).
	invalidCfg := config{SMTPLocalIP: "not-an-ip"}
	s2 := buildSMTPSender(invalidCfg, nil)
	if s2.Dialer != nil {
		t.Error("expected Dialer to be nil for invalid IP")
	}
}

// Compile-time sentinel: ensure stubSender satisfies sending.Sender.
var _ sending.Sender = (*stubSender)(nil)

// Suppress unused imports that are needed for completeness.
var (
	_ = smtp.SendMail
	_ = textproto.NewConn
	_ = strings.Contains
)
