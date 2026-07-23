//! # matcher — the `matcher` coordinator kind (CONTRACT §5)
//!
//! A **matcher** provides real-time supply↔demand matching (rides, delivery): it holds a pool of
//! offers/requests and matches them against each other. CONTRACT §5's table gives its typical
//! visibility as `terminating` (default) / `attested` (TEE) — the matching computation needs to
//! see both sides' plaintext offer/request to pair them, which is a disclosed trust boundary
//! unless run inside attested hardware.
//!
//! ## The §4 derived-view carve-out
//!
//! CONTRACT §4 forbids content classification **on a delivery or canonical/authoritative path**.
//! A matcher's supply/demand pairing looks like it could be that kind of gate, which is why §4's
//! carve-out names it explicitly alongside the labeler and indexer:
//!
//! > "a coordinator MAY classify, annotate, rank, or re-rank content within its own derived,
//! > non-authoritative, opt-in, subscribable view — this is exactly what ... `indexer`/`matcher`
//! > do (they rank their own corpus or match set)."
//!
//! A matcher pairs entries **within its own opt-in supply/demand pool** — a rider or driver who
//! posts into it has opted in, and can withdraw and post into a competing matcher with zero
//! migration cost (COORD-2). Nothing here gates a delivery path or decides what reaches a
//! recipient by default; it decides who gets offered to whom **inside a pool both sides chose to
//! join**. See [`MatcherCoordinator::delivery_path_gate`] and the test module for the concrete
//! distinction from the forbidden case.
//!
//! ## Scaffold disclosure
//!
//! This crate fixes the CONTRACT posture and a signed descriptor — it is **not** a working
//! matching engine. Actual offer/request ingestion, pairing logic, and settlement handoff are
//! future work; nothing here matches real supply and demand yet.

#![forbid(unsafe_code)]

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::{Descriptor, SignedDescriptor, Tariff};
use broker_economics::kinds::CoordinatorKind;
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
use broker_economics::{Cbor, IdentityKey};

/// The visibility a matcher declares over its supply/demand matching channel (CONTRACT §5:
/// `terminating` default / `attested` via TEE).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MatchChannel {
    /// The declared **default** (CONTRACT §5): the matcher sees both sides' offer/request in
    /// plaintext to pair them — a disclosed trust boundary, not a silent one.
    Terminating,
    /// The disclosed **alternative**: matching runs inside a TEE that attests it holds no
    /// readable copy of either side's offer/request (private matching) — CONTRACT §3.3's
    /// `attested` level, trading operator-trust for chip-vendor-trust (§3.4, THREAT-MODEL R-4).
    /// Documented here as an option; **no TEE integration exists in this scaffold**.
    Attested,
}

impl MatchChannel {
    /// The [`ContentVisibility`] a conformant matcher descriptor MUST carry for this channel
    /// choice (COORD-4/COORD-5).
    pub fn declared_visibility(self) -> ContentVisibility {
        match self {
            MatchChannel::Terminating => {
                ContentVisibility::new(VisibilityClass::Terminating, AssuranceLevel::Declared)
            }
            // As with the indexer's query channel: architecturally unreadable by the operator
            // inside the TEE, so the class shifts to `Blind`; the level is `Attested` because the
            // guarantee rests on hardware attestation rather than the structural absence of a key.
            MatchChannel::Attested => {
                ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Attested)
            }
        }
    }
}

/// A `matcher` coordinator's posture for `broker_conformance::check` (CONTRACT §2/§4/§5/§6).
pub struct MatcherCoordinator {
    descriptor: Descriptor,
    /// Whether this matcher meters matches and issues signed receipts (CONTRACT §6/COORD-7).
    metered: bool,
}

impl MatcherCoordinator {
    /// Wrap an already-built `Matcher`-kind [`Descriptor`]. Does not itself validate
    /// `descriptor.kind`/`descriptor.visibility` — a mismatched descriptor surfaces as a
    /// `broker_conformance::check` finding. Prefer [`MatcherCoordinator::signed`] for the common
    /// case of minting a fresh, correctly-shaped descriptor.
    pub fn new(descriptor: Descriptor, metered: bool) -> Self {
        Self { descriptor, metered }
    }

    /// Build **and sign** a fresh, correctly-shaped `matcher` descriptor from a real `kotva-core`
    /// identity (CONTRACT §2.1) declaring `channel`'s visibility.
    pub fn signed(
        ik: &IdentityKey,
        channel: MatchChannel,
        policy: Cbor,
        tariff: Option<Tariff>,
        metered: bool,
    ) -> (Self, SignedDescriptor) {
        let descriptor = Descriptor {
            identity: ik.public(),
            kind: CoordinatorKind::Matcher,
            visibility: channel.declared_visibility(),
            policy,
            tariff,
        };
        let signed = descriptor.sign(ik);
        (Self::new(descriptor, metered), signed)
    }
}

impl Coordinator for MatcherCoordinator {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::Matcher
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // CONTRACT §2.2: leaving a matcher (withdrawing outstanding offers/requests and posting
        // to a different one) is a config change — no identity, keys, or history live with it.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // Not a member of the disclosed scarce-reachability exception class (CONTRACT §2.3) —
        // anyone can run a matching server over their own supply/demand pool.
        SelfHost::Backstop
    }

    fn delivery_path_gate(&self) -> Gate {
        // CONTRACT §4 derived-view carve-out: a matcher pairs its own opt-in supply/demand pool —
        // it does not gate a delivery/authoritative path. See the crate docs' dedicated section.
        Gate::DerivedViewOnly
    }

    fn metering(&self) -> Metering {
        if self.metered {
            Metering::SignedReceiptsToPayer
        } else {
            Metering::NotMetered
        }
    }

    fn settlement(&self) -> Settlement {
        // DIRECTION §5: no protocol token, ever.
        Settlement::ExistingAssetsOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_conformance::check;

    fn ik(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    #[test]
    fn signed_matcher_descriptor_verifies_and_declares_terminating_by_default() {
        let (_coord, signed) =
            MatcherCoordinator::signed(&ik(1), MatchChannel::Terminating, Cbor::empty(), None, false);
        assert!(signed.verify().is_ok(), "a real kotva-core signature must verify");
        assert_eq!(signed.descriptor.kind.as_str(), "matcher");
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Terminating);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Declared);
    }

    #[test]
    fn attested_match_channel_declares_blind_attested() {
        let (_coord, signed) =
            MatcherCoordinator::signed(&ik(2), MatchChannel::Attested, Cbor::empty(), None, false);
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Blind);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Attested);
        assert!(signed.descriptor.visibility.is_verifiably_blind());
    }

    #[test]
    fn a_free_matcher_is_fully_conformant() {
        let (coord, _signed) =
            MatcherCoordinator::signed(&ik(3), MatchChannel::Terminating, Cbor::empty(), None, false);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
    }

    #[test]
    fn a_metered_matcher_is_also_conformant() {
        let (coord, _signed) =
            MatcherCoordinator::signed(&ik(4), MatchChannel::Terminating, Cbor::empty(), None, true);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
        assert!(matches!(coord.metering(), Metering::SignedReceiptsToPayer));
    }

    /// Pairing entries within the matcher's own opt-in pool is `DerivedViewOnly`, never
    /// `Classification` — the distinction §4 draws is the *path*: the same pairing logic gating a
    /// delivery/authoritative path by default would instead need `Gate::Classification(..)` and
    /// would correctly fail COORD-6.
    #[test]
    fn own_pool_matching_is_derived_view_not_classification() {
        let (coord, _signed) =
            MatcherCoordinator::signed(&ik(5), MatchChannel::Terminating, Cbor::empty(), None, false);
        assert!(matches!(coord.delivery_path_gate(), Gate::DerivedViewOnly));
    }

    #[test]
    fn matcher_is_not_the_scarce_reachability_exception() {
        assert!(!CoordinatorKind::Matcher.is_scarce_reachability());
        let (coord, _signed) =
            MatcherCoordinator::signed(&ik(6), MatchChannel::Terminating, Cbor::empty(), None, false);
        assert!(matches!(coord.self_host(), SelfHost::Backstop));
    }

    #[test]
    fn matcher_mints_no_token() {
        let (coord, _signed) =
            MatcherCoordinator::signed(&ik(7), MatchChannel::Terminating, Cbor::empty(), None, false);
        assert!(matches!(coord.settlement(), Settlement::ExistingAssetsOnly));
    }

    #[test]
    fn wrong_kind_descriptor_is_a_coord1_violation() {
        let key = ik(8);
        let descriptor = Descriptor {
            identity: key.public(),
            kind: CoordinatorKind::Relay,
            visibility: MatchChannel::Terminating.declared_visibility(),
            policy: Cbor::empty(),
            tariff: None,
        };
        let coord = MatcherCoordinator::new(descriptor, false);
        let report = check(&coord);
        assert!(!report.is_conformant());
    }
}
