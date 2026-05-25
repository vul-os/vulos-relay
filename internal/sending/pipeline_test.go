// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/queue"
	"github.com/vul-os/vulos-relay/internal/reputation"
	"github.com/vul-os/vulos-relay/internal/sending"
)

// --- stubs ---

type stubSender struct {
	mu      sync.Mutex
	results []sending.SendResult
	calls   int
}

func (s *stubSender) setResults(results ...sending.SendResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = results
}

func (s *stubSender) Send(_ context.Context, _ sending.Message) (sending.SendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

type callRecordingPolicy struct {
	reputation.Permissive
	mu      sync.Mutex
	records []reputation.SendResult
}

func (p *callRecordingPolicy) RecordResult(_ context.Context, _ string, r reputation.SendResult) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, r)
	return nil
}

func (p *callRecordingPolicy) recordCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.records)
}

type denyPolicy struct{}

func (denyPolicy) CheckSend(_ context.Context, _ string, _ reputation.Message) (reputation.Decision, error) {
	return reputation.Decision{Allow: false, Reason: "test deny"}, reputation.ErrRateLimited
}

func (denyPolicy) RecordResult(_ context.Context, _ string, _ reputation.SendResult) error {
	return nil
}

type suspendPolicy struct{}

func (suspendPolicy) CheckSend(_ context.Context, _ string, _ reputation.Message) (reputation.Decision, error) {
	return reputation.Decision{Allow: false, Reason: "suspended"}, reputation.ErrSuspended
}

func (suspendPolicy) RecordResult(_ context.Context, _ string, _ reputation.SendResult) error {
	return nil
}

// --- helpers ---

func makeMsg(id, accountID string) queue.OutboundMessage {
	return queue.OutboundMessage{
		ID:            id,
		AccountID:     accountID,
		Sender:        "sender@example.com",
		Recipients:    []string{"rcpt@example.org"},
		RawRFC822:     []byte("Subject: test\r\n\r\nHello"),
		NextAttemptAt: time.Now().Add(-time.Second),
	}
}

func runPipelineUntilEmpty(t *testing.T, q *queue.MemQueue, policy reputation.Policy, sender sending.Sender) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := sending.PipelineConfig{
		Workers:      2,
		LeaseCount:   5,
		RetryBackoff: 50 * time.Millisecond,
		PollInterval: 20 * time.Millisecond,
	}
	p := sending.NewPipeline(q, policy, sender, cfg)

	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	// Cancel once queue is drained (no active messages).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		msgs, err := q.Lease(ctx, 100)
		if err == queue.ErrEmpty {
			cancel()
			break
		}
		// Un-lease them immediately.
		for _, m := range msgs {
			_ = q.Nack(ctx, m.ID, time.Now().Add(-time.Second))
		}
		time.Sleep(10 * time.Millisecond)
	}

	<-done
}

// --- tests ---

// TestPipelineDeliverAck checks that a successfully delivered message is Acked.
func TestPipelineDeliverAck(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(makeMsg("m1", "acct1"))

	policy := &callRecordingPolicy{}
	sender := &stubSender{}
	sender.setResults(sending.SendResult{State: sending.StateDelivered, Code: 250})

	runPipelineUntilEmpty(t, q, policy, sender)

	// Message should be gone (acked).
	msgs, err := q.Lease(context.Background(), 10)
	if err != queue.ErrEmpty {
		t.Fatalf("expected ErrEmpty after ack, got %v msgs, err=%v", len(msgs), err)
	}

	if policy.recordCount() != 1 {
		t.Errorf("expected 1 RecordResult call, got %d", policy.recordCount())
	}
}

// TestPipelineBounceFail checks that a 5xx response dead-letters the message.
func TestPipelineBounceFail(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(makeMsg("m2", "acct1"))

	policy := &callRecordingPolicy{}
	sender := &stubSender{}
	sender.setResults(sending.SendResult{State: sending.StateBounced, Code: 550, Message: "550 user unknown"})

	runPipelineUntilEmpty(t, q, policy, sender)

	dls := q.DeadLetters()
	if _, ok := dls["m2"]; !ok {
		t.Errorf("expected m2 to be dead-lettered, dead letters: %v", dls)
	}
	if policy.recordCount() != 1 {
		t.Errorf("expected 1 RecordResult, got %d", policy.recordCount())
	}
}

// TestPipelineDeferredNack checks that a 4xx response Nacks the message.
func TestPipelineDeferredNack(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(makeMsg("m3", "acct1"))

	policy := &callRecordingPolicy{}
	sender := &stubSender{}
	// First call → deferred; second call → delivered.
	sender.setResults(
		sending.SendResult{State: sending.StateDeferred, Code: 421, Message: "421 try later"},
		sending.SendResult{State: sending.StateDelivered, Code: 250},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := sending.PipelineConfig{
		Workers:      1,
		LeaseCount:   1,
		RetryBackoff: 10 * time.Millisecond, // short backoff for test speed
		PollInterval: 10 * time.Millisecond,
	}
	p := sending.NewPipeline(q, policy, sender, cfg)

	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	// Wait until the message is delivered (acked = gone from queue).
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		msgs, err := q.Lease(ctx, 10)
		if err == queue.ErrEmpty {
			cancel()
			break
		}
		for _, m := range msgs {
			_ = q.Nack(ctx, m.ID, time.Now().Add(-time.Second))
		}
		time.Sleep(20 * time.Millisecond)
	}

	<-done

	msgs, err := q.Lease(context.Background(), 10)
	if err != queue.ErrEmpty {
		t.Fatalf("expected ErrEmpty after eventual deliver, got %v msgs err=%v", len(msgs), err)
	}
}

// TestPipelinePolicyDenyNacks checks that a rate-limited message is Nacked
// and NOT passed to the sender.
func TestPipelinePolicyDenyNacks(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(makeMsg("m4", "acct1"))

	sender := &stubSender{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := sending.PipelineConfig{
		Workers:      1,
		LeaseCount:   1,
		RetryBackoff: 1 * time.Hour, // long backoff so message won't retry
		PollInterval: 20 * time.Millisecond,
	}
	p := sending.NewPipeline(q, denyPolicy{}, sender, cfg)

	go func() {
		// Cancel after a short time (message should be nacked by then).
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	p.Run(ctx)

	if sender.calls != 0 {
		t.Errorf("expected sender not called on policy deny, got %d calls", sender.calls)
	}
}

// TestPipelineSuspendedDeadLetters checks that a suspended account causes the
// message to be dead-lettered, not just nacked.
func TestPipelineSuspendedDeadLetters(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(makeMsg("m5", "acct-suspended"))

	sender := &stubSender{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := sending.PipelineConfig{
		Workers:      1,
		LeaseCount:   1,
		RetryBackoff: 1 * time.Hour,
		PollInterval: 20 * time.Millisecond,
	}
	p := sending.NewPipeline(q, suspendPolicy{}, sender, cfg)

	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	p.Run(ctx)

	dls := q.DeadLetters()
	if _, ok := dls["m5"]; !ok {
		t.Errorf("expected m5 to be dead-lettered for suspended account, dead letters: %v", dls)
	}
	if sender.calls != 0 {
		t.Errorf("sender should not be called for suspended account, got %d calls", sender.calls)
	}
}

// stubSuppression is a SuppressionChecker that drops a fixed set of addresses.
type stubSuppression struct{ suppressed map[string]bool }

func (s stubSuppression) FilterRecipients(rcpts []string) (allowed, dropped []string) {
	for _, r := range rcpts {
		if s.suppressed[r] {
			dropped = append(dropped, r)
		} else {
			allowed = append(allowed, r)
		}
	}
	return allowed, dropped
}

// TestPipelineSuppressedRecipientBlocked proves the send-gate suppression
// check: a message whose only recipient is suppressed (e.g. it hard-bounced)
// is acked WITHOUT being passed to the sender — the relay never re-sends to it.
func TestPipelineSuppressedRecipientBlocked(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(queue.OutboundMessage{
		ID:            "sup1",
		AccountID:     "acct1",
		Sender:        "sender@example.com",
		Recipients:    []string{"deadbox@example.com"},
		RawRFC822:     []byte("Subject: t\r\n\r\nx"),
		NextAttemptAt: time.Now().Add(-time.Second),
	})

	sender := &stubSender{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := sending.PipelineConfig{
		Workers:      1,
		LeaseCount:   1,
		RetryBackoff: time.Hour,
		PollInterval: 20 * time.Millisecond,
		Suppression:  stubSuppression{suppressed: map[string]bool{"deadbox@example.com": true}},
	}
	p := sending.NewPipeline(q, reputation.Permissive{}, sender, cfg)

	go func() {
		time.Sleep(250 * time.Millisecond)
		cancel()
	}()
	p.Run(ctx)

	if sender.calls != 0 {
		t.Errorf("suppressed-only message must NOT reach the sender; got %d calls", sender.calls)
	}
	// And the message must be acked (gone), not stuck in the queue.
	if msgs, err := q.Lease(context.Background(), 10); err != queue.ErrEmpty {
		t.Errorf("suppressed-only message should be acked/removed, but %d still queued (err=%v)", len(msgs), err)
	}
}

// TestPipelinePartialSuppressionDelivers proves that when only some recipients
// are suppressed, the message is still delivered to the survivors.
func TestPipelinePartialSuppressionDelivers(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(queue.OutboundMessage{
		ID:            "sup2",
		AccountID:     "acct1",
		Sender:        "sender@example.com",
		Recipients:    []string{"good@example.org", "bad@example.com"},
		RawRFC822:     []byte("Subject: t\r\n\r\nx"),
		NextAttemptAt: time.Now().Add(-time.Second),
	})

	var got []string
	sender := &recipientRecordingSender{}
	cfg := sending.PipelineConfig{
		Workers:      1,
		LeaseCount:   1,
		RetryBackoff: time.Hour,
		PollInterval: 20 * time.Millisecond,
		Suppression:  stubSuppression{suppressed: map[string]bool{"bad@example.com": true}},
	}
	p := sending.NewPipeline(q, reputation.Permissive{}, sender, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { time.Sleep(250 * time.Millisecond); cancel() }()
	p.Run(ctx)

	got = sender.lastRecipients()
	if len(got) != 1 || got[0] != "good@example.org" {
		t.Errorf("delivery should target only the non-suppressed recipient, got %v", got)
	}
}

type recipientRecordingSender struct {
	mu   sync.Mutex
	last []string
}

func (s *recipientRecordingSender) Send(_ context.Context, msg sending.Message) (sending.SendResult, error) {
	s.mu.Lock()
	s.last = msg.Recipients
	s.mu.Unlock()
	return sending.SendResult{State: sending.StateDelivered, Code: 250}, nil
}

func (s *recipientRecordingSender) lastRecipients() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// TestPipelineGracefulDrain checks that in-flight messages finish after cancel.
func TestPipelineGracefulDrain(t *testing.T) {
	q := queue.NewMemQueue()
	for i := 0; i < 5; i++ {
		q.Enqueue(makeMsg(string(rune('a'+i)), "acct1"))
	}

	var delivered atomic.Int32
	slowSender := &slowDeliverSender{delay: 50 * time.Millisecond, delivered: &delivered}
	_ = slowSender

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	cfg := sending.PipelineConfig{
		Workers:      3,
		LeaseCount:   5,
		RetryBackoff: 100 * time.Millisecond,
		PollInterval: 10 * time.Millisecond,
	}
	p := sending.NewPipeline(q, reputation.Permissive{}, slowSender, cfg)

	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	// Cancel quickly — workers should still finish in-flight.
	time.Sleep(80 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipeline did not drain within timeout")
	}
}

type slowDeliverSender struct {
	delay     time.Duration
	delivered *atomic.Int32
}

func (s *slowDeliverSender) Send(_ context.Context, _ sending.Message) (sending.SendResult, error) {
	time.Sleep(s.delay)
	s.delivered.Add(1)
	return sending.SendResult{State: sending.StateDelivered, Code: 250}, nil
}

var _ sending.Sender = (*slowDeliverSender)(nil)
