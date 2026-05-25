// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/vul-os/vulos-relay/internal/queue"
	"github.com/vul-os/vulos-relay/internal/reputation"
)

// defaultLeaseCount is the number of messages claimed per Lease call.
const defaultLeaseCount = 10

// defaultRetryBackoff is the initial backoff duration on a 4xx deferral.
const defaultRetryBackoff = 5 * time.Minute

// PipelineConfig holds configuration for a Pipeline.
type PipelineConfig struct {
	// Workers is the number of concurrent delivery goroutines.  Default: 4.
	Workers int

	// LeaseCount is the number of messages to claim per Lease call.  Default: 10.
	LeaseCount int

	// RetryBackoff is the base backoff added to NextAttemptAt on a 4xx deferral.
	// Default: 5 minutes.
	RetryBackoff time.Duration

	// PollInterval is how long the pipeline sleeps between Lease polls when the
	// queue is empty.  Default: 5 seconds.
	PollInterval time.Duration

	// Suppression, if non-nil, is consulted at the send gate: any recipient on
	// the suppression list (hard-bounced or complained) is dropped before
	// delivery, and a message left with no deliverable recipients is acked
	// (suppressed) rather than sent. This is the deliverability control that
	// stops the relay from re-sending to addresses that hard-bounced or filed
	// complaints. The concrete *suppression.List is injected via this seam so
	// the sending package does not import the suppression package.
	Suppression SuppressionChecker

	// Logger is used for operational messages.  If nil, the standard logger is used.
	Logger *log.Logger
}

// SuppressionChecker is the minimal seam the pipeline needs from a suppression
// list: partition recipients into allowed (deliverable) and dropped
// (suppressed). *suppression.List satisfies it via FilterRecipients.
type SuppressionChecker interface {
	// FilterRecipients returns the recipients that may be delivered to and the
	// recipients that are suppressed (dropped), preserving input order.
	FilterRecipients(rcpts []string) (allowed, dropped []string)
}

func (c *PipelineConfig) workers() int {
	if c.Workers <= 0 {
		return 4
	}
	return c.Workers
}

func (c *PipelineConfig) leaseCount() int {
	if c.LeaseCount <= 0 {
		return defaultLeaseCount
	}
	return c.LeaseCount
}

func (c *PipelineConfig) retryBackoff() time.Duration {
	if c.RetryBackoff <= 0 {
		return defaultRetryBackoff
	}
	return c.RetryBackoff
}

func (c *PipelineConfig) pollInterval() time.Duration {
	if c.PollInterval <= 0 {
		return 5 * time.Second
	}
	return c.PollInterval
}

func (c *PipelineConfig) logger() *log.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return log.Default()
}

// Pipeline is the send pipeline: it leases messages from a Queue, gates them
// through a reputation Policy, delivers them via a Sender, feeds results back
// to the Policy, and Acks or Nacks/Fails accordingly.
//
// Call Run to start the pipeline; it blocks until ctx is cancelled.
// All in-flight deliveries complete before Run returns (graceful drain).
type Pipeline struct {
	q      queue.Queue
	policy reputation.Policy
	sender Sender
	cfg    PipelineConfig
}

// NewPipeline creates a Pipeline.
func NewPipeline(q queue.Queue, policy reputation.Policy, sender Sender, cfg PipelineConfig) *Pipeline {
	return &Pipeline{q: q, policy: policy, sender: sender, cfg: cfg}
}

// Run starts the pipeline and blocks until ctx is cancelled.  It launches
// cfg.Workers goroutines and drains all in-flight messages before returning.
func (p *Pipeline) Run(ctx context.Context) {
	work := make(chan queue.LeasedMessage)
	var wg sync.WaitGroup

	for i := 0; i < p.cfg.workers(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range work {
				p.process(ctx, msg)
			}
		}()
	}

	// Feeder loop: lease messages and push them onto the work channel until
	// ctx is done.
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
		}

		msgs, err := p.q.Lease(ctx, p.cfg.leaseCount())
		if err == queue.ErrEmpty {
			select {
			case <-ctx.Done():
				break loop
			case <-time.After(p.cfg.pollInterval()):
				continue
			}
		}
		if err != nil && err != queue.ErrEmpty {
			p.cfg.logger().Printf("sending: lease error: %v", err)
			select {
			case <-ctx.Done():
				break loop
			case <-time.After(p.cfg.pollInterval()):
				continue
			}
		}

		for _, m := range msgs {
			select {
			case <-ctx.Done():
				// Return the un-sent leased messages to the queue.
				_ = p.q.Nack(context.Background(), m.ID, time.Now().Add(p.cfg.retryBackoff()))
			case work <- m:
			}
		}
	}

	close(work)
	wg.Wait()
}

// process handles a single leased message end-to-end.
func (p *Pipeline) process(ctx context.Context, lm queue.LeasedMessage) {
	logger := p.cfg.logger()

	// Send-gate suppression check: drop recipients on the suppression list
	// (hard-bounced or complained) BEFORE gating/delivery. If every recipient
	// is suppressed there is nothing to send — ack the message so it is removed
	// from the queue rather than retried against addresses we must never contact.
	recipients := lm.Recipients
	if p.cfg.Suppression != nil {
		allowed, dropped := p.cfg.Suppression.FilterRecipients(lm.Recipients)
		if len(dropped) > 0 {
			logger.Printf("sending: message %s — %d recipient(s) suppressed and dropped: %v", lm.ID, len(dropped), dropped)
		}
		if len(allowed) == 0 {
			logger.Printf("sending: message %s — all recipients suppressed; acking without delivery", lm.ID)
			if ackErr := p.q.Ack(ctx, lm.ID); ackErr != nil {
				logger.Printf("sending: Ack (all-suppressed) %s: %v", lm.ID, ackErr)
			}
			return
		}
		recipients = allowed
	}

	// Build the reputation.Message view.
	repMsg := reputation.Message{
		ID:         lm.ID,
		Sender:     lm.Sender,
		Recipients: recipients,
		Size:       len(lm.RawRFC822),
	}

	// 1. Gate through reputation policy.
	decision, err := p.policy.CheckSend(ctx, lm.AccountID, repMsg)
	if err != nil || !decision.Allow {
		reason := "policy denied"
		if err != nil {
			reason = err.Error()
		} else if decision.Reason != "" {
			reason = decision.Reason
		}

		// Suspended accounts are dead-lettered; rate-limited accounts are deferred.
		if err == reputation.ErrSuspended {
			logger.Printf("sending: message %s dead-lettered (suspended): %s", lm.ID, reason)
			_ = p.q.Fail(ctx, lm.ID, reason)
			return
		}

		// Rate-limited or other deny: nack with DelayUntil if set.
		retryAt := time.Now().Add(p.cfg.retryBackoff())
		if decision.DelayUntil != nil {
			retryAt = *decision.DelayUntil
		}
		logger.Printf("sending: message %s nacked (policy deny): %s", lm.ID, reason)
		_ = p.q.Nack(ctx, lm.ID, retryAt)
		return
	}

	// 2. Deliver via the sender (only to the non-suppressed recipients).
	sendMsg := Message{
		ID:         lm.ID,
		AccountID:  lm.AccountID,
		Sender:     lm.Sender,
		Recipients: recipients,
		RawRFC822:  lm.RawRFC822,
	}

	result, deliverErr := p.sender.Send(ctx, sendMsg)
	if deliverErr != nil {
		// Infrastructure error → treat as transient deferral.
		logger.Printf("sending: message %s deferred (infra error): %v", lm.ID, deliverErr)
		result = SendResult{State: StateDeferred, Message: deliverErr.Error()}
	}

	// 3. Feed result back to the policy.
	repResult := toRepResult(result)
	if recErr := p.policy.RecordResult(ctx, lm.AccountID, repResult); recErr != nil {
		logger.Printf("sending: RecordResult for %s: %v", lm.ID, recErr)
	}

	// 4. Ack / Nack / Fail the queue entry.
	switch result.State {
	case StateDelivered:
		if ackErr := p.q.Ack(ctx, lm.ID); ackErr != nil {
			logger.Printf("sending: Ack %s: %v", lm.ID, ackErr)
		}
	case StateBounced:
		reason := result.Message
		if reason == "" {
			reason = "permanent SMTP failure"
		}
		logger.Printf("sending: message %s bounced (code %d): %s", lm.ID, result.Code, reason)
		if failErr := p.q.Fail(ctx, lm.ID, reason); failErr != nil {
			logger.Printf("sending: Fail %s: %v", lm.ID, failErr)
		}
	case StateDeferred:
		retryAt := time.Now().Add(p.cfg.retryBackoff())
		logger.Printf("sending: message %s deferred (code %d), retry at %s", lm.ID, result.Code, retryAt.Format(time.RFC3339))
		if nackErr := p.q.Nack(ctx, lm.ID, retryAt); nackErr != nil {
			logger.Printf("sending: Nack %s: %v", lm.ID, nackErr)
		}
	}
}

// toRepResult converts a sending.SendResult into the reputation.SendResult
// type that Policy.RecordResult expects.
func toRepResult(r SendResult) reputation.SendResult {
	var state reputation.SendState
	switch r.State {
	case StateDelivered:
		state = reputation.SendDelivered
	case StateBounced:
		state = reputation.SendBounced
	case StateDeferred:
		state = reputation.SendDeferred
	default:
		state = reputation.SendDeferred
	}
	return reputation.SendResult{
		State:        state,
		Code:         r.Code,
		EnhancedCode: r.EnhancedCode,
		Provider:     r.Provider,
	}
}
