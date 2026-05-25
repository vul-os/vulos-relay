// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package reputation_test

import (
	"testing"

	"github.com/vul-os/vulos-relay/internal/reputation"
)

// TestCappedTrustTierProgression proves the trust tier is derived from real
// account history: an unknown account is new, a low-volume account is
// untrusted, and an account past the threshold is established.
func TestCappedTrustTierProgression(t *testing.T) {
	p := reputation.NewCappedPolicy()
	p.EstablishedThreshold = 5

	// Unknown account → new (fail closed).
	if got := p.TrustTierFor("nobody"); got != reputation.AccountTrustNew {
		t.Fatalf("unknown account: want AccountTrustNew, got %v", got)
	}

	// One clean delivery → untrusted (some history, below threshold).
	_ = p.RecordResult(ctx, "acct", reputation.SendResult{State: reputation.SendDelivered})
	if got := p.TrustTierFor("acct"); got != reputation.AccountTrustUntrusted {
		t.Fatalf("after 1 delivery: want AccountTrustUntrusted, got %v", got)
	}

	// Cross the threshold → established.
	for i := 0; i < 5; i++ {
		_ = p.RecordResult(ctx, "acct", reputation.SendResult{State: reputation.SendDelivered})
	}
	if got := p.TrustTierFor("acct"); got != reputation.AccountTrustEstablished {
		t.Fatalf("after threshold deliveries: want AccountTrustEstablished, got %v", got)
	}
}

// TestCappedTrustTierSuspendedIsCold proves a suspended account is forced back
// to the coldest tier regardless of accrued history.
func TestCappedTrustTierSuspendedIsCold(t *testing.T) {
	p := reputation.NewCappedPolicy()
	p.EstablishedThreshold = 2
	for i := 0; i < 5; i++ {
		_ = p.RecordResult(ctx, "acct", reputation.SendResult{State: reputation.SendDelivered})
	}
	if got := p.TrustTierFor("acct"); got != reputation.AccountTrustEstablished {
		t.Fatalf("precondition: want established, got %v", got)
	}
	p.Suspend("acct", "abuse")
	if got := p.TrustTierFor("acct"); got != reputation.AccountTrustNew {
		t.Fatalf("suspended account: want AccountTrustNew, got %v", got)
	}
}
