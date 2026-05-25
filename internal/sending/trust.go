// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

// TrustTier classifies a sending account by how much delivery history /
// reputation it has accrued. The tier decides which warm-IP pool segment a
// message may be sent from: an untrusted (new) account must never ride a warm
// "established" IP, since its behaviour can quickly damage that IP's
// reputation. This is the trust-gating that the warm pool depends on.
type TrustTier int

const (
	// TrustNew is a freshly-seen account with little or no clean send history.
	// It is confined to the coldest segment available (new → untrusted).
	TrustNew TrustTier = iota

	// TrustUntrusted is an account that has begun sending but has not yet
	// accrued enough clean volume to be considered established. It rides the
	// ramp/untrusted segment.
	TrustUntrusted

	// TrustEstablished is an account with sufficient clean delivery history to
	// use the warm, fully-ramped established segment.
	TrustEstablished
)

// String renders the tier for logs/metrics.
func (t TrustTier) String() string {
	switch t {
	case TrustNew:
		return "new"
	case TrustUntrusted:
		return "untrusted"
	case TrustEstablished:
		return "established"
	default:
		return "unknown"
	}
}

// Segment maps a trust tier to the pool SegmentName hint used for selection.
// The mapping is intentionally conservative: only an established account is
// permitted the established (warm) segment. New/untrusted accounts map to the
// cold/ramp segments and Pool.Select additionally refuses to hand them an
// established IP even if one is the only option (it defers instead).
func (t TrustTier) Segment() SegmentName {
	switch t {
	case TrustEstablished:
		return SegmentEstablished
	case TrustUntrusted:
		return SegmentUntrusted
	default: // TrustNew and any unknown value → coldest tier
		return SegmentNew
	}
}

// TrustSource maps an account ID to its current TrustTier. The canonical
// (tenant-aware) implementation lives in Vulos's cloud control plane; this
// repository ships a reference implementation derived from the bundled
// reputation policy (see reputation.CappedPolicy.TrustTierFor) and a static
// fallback for self-hosters.
//
// Implementations must be safe for concurrent use.
type TrustSource interface {
	// TrustTierFor returns the current trust tier for accountID. An unknown
	// account MUST be classified as TrustNew (fail-closed: never grant an
	// unknown sender warm-IP access).
	TrustTierFor(accountID string) TrustTier
}

// TrustSourceFunc adapts a plain function to the TrustSource interface.
type TrustSourceFunc func(accountID string) TrustTier

// TrustTierFor implements TrustSource.
func (f TrustSourceFunc) TrustTierFor(accountID string) TrustTier { return f(accountID) }

// StaticTrustSource classifies every account at a single fixed tier. It is the
// fallback used when no reputation-derived trust source is available. The zero
// value classifies all accounts as TrustNew (the safe, fail-closed default).
type StaticTrustSource struct {
	Tier TrustTier
}

// TrustTierFor implements TrustSource.
func (s StaticTrustSource) TrustTierFor(string) TrustTier { return s.Tier }

var _ TrustSource = TrustSourceFunc(nil)
var _ TrustSource = StaticTrustSource{}

// SegmentForTrust returns the SegmentName a given account should be selected
// from, given a TrustSource. A nil TrustSource fails closed to the coldest
// segment (TrustNew), so an absent classifier can never accidentally promote a
// sender to warm IPs.
func SegmentForTrust(src TrustSource, accountID string) SegmentName {
	if src == nil {
		return TrustNew.Segment()
	}
	return src.TrustTierFor(accountID).Segment()
}
