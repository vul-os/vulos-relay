// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package security_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/queue"
	"github.com/vul-os/vulos-relay/internal/reputation"
	"github.com/vul-os/vulos-relay/internal/sending"
	"github.com/vul-os/vulos-relay/internal/suppression"
)

// ─── Attack class 7: suppression send-gate ───────────────────────────────────
//
// A recipient that previously hard-bounced or filed an abuse complaint is on
// the suppression list. The send pipeline MUST drop that recipient at the send
// gate — re-sending to a hard-bounce/complaint address damages deliverability
// and is exactly the abuse pattern blocklists watch for. These tests prove a
// suppressed recipient never reaches the Sender.

// recordingSender captures the recipients each Send call is asked to deliver
// to. It is the canary: a suppressed address appearing here is a hole.
type recordingSender struct {
	mu  sync.Mutex
	got [][]string
}

func (s *recordingSender) Send(_ context.Context, msg sending.Message) (sending.SendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, append([]string(nil), msg.Recipients...))
	return sending.SendResult{State: sending.StateDelivered, Code: 250}, nil
}

func (s *recordingSender) allRecipients() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.got {
		out = append(out, r...)
	}
	return out
}

// ATTACK (gate seam): the exact partition the pipeline relies on — a suppressed
// recipient must be classified as dropped, never allowed.
func TestSuppression_HardBounce_DroppedAtGate(t *testing.T) {
	list := suppression.NewList()
	list.Suppress("bounced@victim.example", suppression.ReasonHardBounce, "5.1.1 user unknown")
	list.Suppress("complainer@victim.example", suppression.ReasonComplaint, "arf")

	allowed, dropped := list.FilterRecipients([]string{
		"bounced@victim.example",
		"ok@victim.example",
		"complainer@victim.example",
	})
	if contains(allowed, "bounced@victim.example") || contains(allowed, "complainer@victim.example") {
		t.Fatal("VULN: a hard-bounced/complaint recipient was allowed through the send gate")
	}
	if !contains(allowed, "ok@victim.example") {
		t.Fatal("a non-suppressed recipient was wrongly dropped")
	}
	if !contains(dropped, "bounced@victim.example") || !contains(dropped, "complainer@victim.example") {
		t.Fatal("suppressed recipients not reported as dropped")
	}
}

// ATTACK (end-to-end): drive the real send Pipeline. A message addressed to a
// suppressed recipient (plus a clean one) is leased and processed; the Sender
// must be asked to deliver ONLY to the clean recipient — the suppressed one is
// dropped before delivery.
func TestSuppression_PipelineNeverSendsToSuppressed(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(queue.OutboundMessage{
		ID:         "m1",
		AccountID:  "acct",
		Sender:     "alice@tenant.example",
		Recipients: []string{"bounced@victim.example", "clean@victim.example"},
		RawRFC822:  []byte("Subject: hi\r\n\r\nbody"),
	})

	list := suppression.NewList()
	list.Suppress("bounced@victim.example", suppression.ReasonHardBounce, "5.1.1")

	sender := &recordingSender{}
	pipe := sending.NewPipeline(q, reputation.Permissive{}, sender, sending.PipelineConfig{
		Workers:      1,
		PollInterval: time.Millisecond,
		Suppression:  list,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { pipe.Run(ctx); close(done) }()

	// Wait until the message has been processed (sender called) then stop.
	deadline := time.After(2 * time.Second)
	for {
		if len(sender.allRecipients()) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("pipeline did not process the message in time")
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	<-done

	got := sender.allRecipients()
	if contains(got, "bounced@victim.example") {
		t.Fatalf("VULN: pipeline delivered to a suppressed recipient: %v", got)
	}
	if !contains(got, "clean@victim.example") {
		t.Fatalf("clean recipient should have been delivered to, got %v", got)
	}
}

// ATTACK (all-suppressed): a message whose EVERY recipient is suppressed must
// never reach the Sender at all (it is acked, not sent).
func TestSuppression_AllSuppressed_NeverSent(t *testing.T) {
	q := queue.NewMemQueue()
	q.Enqueue(queue.OutboundMessage{
		ID:         "m2",
		AccountID:  "acct",
		Sender:     "alice@tenant.example",
		Recipients: []string{"a@victim.example", "b@victim.example"},
		RawRFC822:  []byte("Subject: hi\r\n\r\nbody"),
	})
	list := suppression.NewList()
	list.Suppress("a@victim.example", suppression.ReasonComplaint, "")
	list.Suppress("b@victim.example", suppression.ReasonHardBounce, "")

	sender := &recordingSender{}
	pipe := sending.NewPipeline(q, reputation.Permissive{}, sender, sending.PipelineConfig{
		Workers:      1,
		PollInterval: time.Millisecond,
		Suppression:  list,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { pipe.Run(ctx); close(done) }()
	<-ctx.Done()
	<-done

	if got := sender.allRecipients(); len(got) != 0 {
		t.Fatalf("VULN: an all-suppressed message reached the Sender: %v", got)
	}
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}
