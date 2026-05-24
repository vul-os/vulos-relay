// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package queue_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/queue"
)

func makeMsg(id string) queue.OutboundMessage {
	return queue.OutboundMessage{
		ID:         id,
		AccountID:  "acct1",
		Sender:     "sender@example.com",
		Recipients: []string{"rcpt@example.com"},
		RawRFC822:  []byte("From: sender@example.com\r\nTo: rcpt@example.com\r\n\r\nHello\r\n"),
		Metadata:   map[string]string{"key": "val"},
	}
}

// runSuite runs the same behavioural tests against any Queue + enqueue helper.
func runSuite(t *testing.T, q queue.Queue, enqueue func(queue.OutboundMessage)) {
	t.Helper()
	ctx := context.Background()

	t.Run("ErrEmpty when no messages", func(t *testing.T) {
		_, err := q.Lease(ctx, 10)
		if err != queue.ErrEmpty {
			t.Fatalf("want ErrEmpty, got %v", err)
		}
	})

	t.Run("Lease returns enqueued message", func(t *testing.T) {
		enqueue(makeMsg("msg-lease"))
		msgs, err := q.Lease(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(msgs) != 1 || msgs[0].ID != "msg-lease" {
			t.Fatalf("unexpected msgs: %v", msgs)
		}
		// Ack to clean up.
		if err := q.Ack(ctx, "msg-lease"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Ack removes message", func(t *testing.T) {
		enqueue(makeMsg("msg-ack"))
		msgs, _ := q.Lease(ctx, 10)
		if err := q.Ack(ctx, msgs[0].ID); err != nil {
			t.Fatal(err)
		}
		_, err := q.Lease(ctx, 10)
		if err != queue.ErrEmpty {
			t.Fatalf("want ErrEmpty after Ack, got %v", err)
		}
	})

	t.Run("Nack requeues after retryAfter", func(t *testing.T) {
		enqueue(makeMsg("msg-nack"))
		msgs, _ := q.Lease(ctx, 10)

		// Nack with a retryAfter in the future — should not be leasable yet.
		future := time.Now().Add(200 * time.Millisecond)
		if err := q.Nack(ctx, msgs[0].ID, future); err != nil {
			t.Fatal(err)
		}
		_, err := q.Lease(ctx, 10)
		if err != queue.ErrEmpty {
			t.Fatalf("want ErrEmpty before retryAfter, got %v", err)
		}

		// Wait past retryAfter — should be leasable again.
		time.Sleep(250 * time.Millisecond)
		msgs2, err := q.Lease(ctx, 10)
		if err != nil {
			t.Fatalf("want message after retryAfter, got error: %v", err)
		}
		if msgs2[0].ID != "msg-nack" {
			t.Fatalf("unexpected id: %s", msgs2[0].ID)
		}
		_ = q.Ack(ctx, "msg-nack")
	})

	t.Run("Fail dead-letters message", func(t *testing.T) {
		enqueue(makeMsg("msg-fail"))
		msgs, _ := q.Lease(ctx, 10)
		if err := q.Fail(ctx, msgs[0].ID, "bounce"); err != nil {
			t.Fatal(err)
		}
		_, err := q.Lease(ctx, 10)
		if err != queue.ErrEmpty {
			t.Fatalf("want ErrEmpty after Fail, got %v", err)
		}
	})

	t.Run("Lease visibility timeout re-leases unacked message", func(t *testing.T) {
		// Enqueue a message, lease it, then wait for the visibility timeout
		// (MemQueue / FSQueue both use 30 s which is too long; instead we
		// directly test re-lease behaviour by Nack-ing with the past).
		enqueue(makeMsg("msg-requeue"))
		msgs, _ := q.Lease(ctx, 10)
		// Nack immediately with a past time — simulates timeout.
		if err := q.Nack(ctx, msgs[0].ID, time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		msgs2, err := q.Lease(ctx, 10)
		if err != nil {
			t.Fatalf("want re-leased message, got: %v", err)
		}
		if msgs2[0].ID != "msg-requeue" {
			t.Fatalf("unexpected id: %s", msgs2[0].ID)
		}
		_ = q.Ack(ctx, "msg-requeue")
	})

	t.Run("ErrUnknownMessage on invalid id", func(t *testing.T) {
		err := q.Ack(ctx, "no-such-id")
		if err != queue.ErrUnknownMessage {
			t.Fatalf("want ErrUnknownMessage, got %v", err)
		}
	})
}

func TestMemQueue(t *testing.T) {
	q := queue.NewMemQueue()
	runSuite(t, q, func(msg queue.OutboundMessage) { q.Enqueue(msg) })
}

func TestFSQueue(t *testing.T) {
	dir, err := os.MkdirTemp("", "fsqueue-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	q, err := queue.NewFSQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	runSuite(t, q, func(msg queue.OutboundMessage) {
		if err := q.Enqueue(msg); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	})
}

func TestFSQueuePersistence(t *testing.T) {
	dir, err := os.MkdirTemp("", "fsqueue-persist-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()

	// Write via first instance.
	q1, _ := queue.NewFSQueue(dir)
	if err := q1.Enqueue(makeMsg("persist-msg")); err != nil {
		t.Fatal(err)
	}

	// Re-open as a new instance (simulates process restart).
	q2, err := queue.NewFSQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := q2.Lease(ctx, 10)
	if err != nil {
		t.Fatalf("after restart, want message, got: %v", err)
	}
	if len(msgs) != 1 || msgs[0].ID != "persist-msg" {
		t.Fatalf("unexpected: %v", msgs)
	}
	_ = q2.Ack(ctx, "persist-msg")
}
