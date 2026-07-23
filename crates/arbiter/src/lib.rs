//! # arbiter — the `arbiter` coordinator kind (CONTRACT §5)
//!
//! An **arbiter** provides dispute resolution (a staked jury): it reviews disclosed evidence from
//! both sides of a trade dispute and issues a ruling. CONTRACT §5's table gives its typical
//! visibility as `terminating` for evidence, disclosed — the arbiter must read the evidence in
//! plaintext to rule on it, which is a deliberate, disclosed trust boundary, not a silent one.
//!
//! ## Not a delivery path — `Gate::NoDeliveryPath`, not `DerivedViewOnly`
//!
//! Unlike the `indexer`/`labeler`/`matcher` trio, an arbiter does not classify, rank, or annotate
//! content within any kind of derived view at all — CONTRACT §4's derived-view carve-out simply
//! does not apply here, because dispute resolution is neither a delivery/authoritative content
//! path (§4's prohibited case) nor a ranking of an opt-in corpus/pool (§4's carve-out case). It is
//! a third thing: a **judgment on a specific, bilateral dispute** two parties brought to it
//! voluntarily, structurally out of the reach of §4's rule either way. [`Gate::NoDeliveryPath`] is
//! the honest answer — see [`ArbiterCoordinator::delivery_path_gate`].
//!
//! ## Stake — verified on-rail, never in the descriptor (CONTRACT §6)
//!
//! An arbiter is one of the two kinds CONTRACT §6 calls out as carrying skin-in-the-game
//! ("`arbiter`, `oracle` — DIRECTION §5, sized to the value at risk"). §2.1 deliberately excludes
//! a stake field from [`broker_economics::Descriptor`] so stake can never become a ranking signal;
//! §6 requires the stake instead be verifiable **on the settlement/staking rail itself** (an
//! on-chain balance/lock a client queries directly), with an unverifiable claim MUST-treated as no
//! stake (SEC-1, fail closed). This crate does not depend on `broker-billing` (kept intentionally
//! thin, matching the other posture scaffolds) — the seam a relying operator wires a real check
//! through is `broker_billing::StakeVerifier` (`crates/broker-billing/src/stake.rs`), whose
//! fail-closed reference implementation `NoStakeRail` treats every claim as unverifiable by
//! default. An arbiter descriptor published by this crate carries no stake field, by construction
//! (`Descriptor` has none) and by design (§6) — a caller who needs to rely on staked trust MUST
//! query a `StakeVerifier`-shaped rail check independently, never read it off this descriptor.
//!
//! ## Scaffold disclosure
//!
//! This crate fixes the CONTRACT posture and a signed descriptor — it is **not** a working
//! dispute-resolution engine. Evidence intake, jury selection, ruling issuance, and the stake-rail
//! integration itself are all future work; nothing here arbitrates a real dispute yet.

#![forbid(unsafe_code)]

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::{Descriptor, SignedDescriptor, Tariff};
use broker_economics::kinds::CoordinatorKind;
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
use broker_economics::{Cbor, IdentityKey};

/// The declared content-visibility every conformant `arbiter` publishes over its evidence channel
/// (CONTRACT §5): `terminating` for disclosed evidence, at `declared` assurance — the arbiter
/// reads submitted evidence in plaintext to rule on it, and says so.
pub const ARBITER_VISIBILITY: ContentVisibility =
    ContentVisibility::new(VisibilityClass::Terminating, AssuranceLevel::Declared);

/// An `arbiter` coordinator's posture for `broker_conformance::check` (CONTRACT §2/§4/§5/§6). See
/// the crate docs for why the stake requirement (§6) is a rail-verification seam, never a
/// descriptor field, and why the delivery-path gate is [`Gate::NoDeliveryPath`].
pub struct ArbiterCoordinator {
    descriptor: Descriptor,
    /// Whether this arbiter meters case reviews and issues signed receipts (CONTRACT
    /// §6/COORD-7).
    metered: bool,
}

impl ArbiterCoordinator {
    /// Wrap an already-built `Arbiter`-kind [`Descriptor`]. Does not itself validate
    /// `descriptor.kind`/`descriptor.visibility` — a mismatched descriptor surfaces as a
    /// `broker_conformance::check` finding. Prefer [`ArbiterCoordinator::signed`] for the common
    /// case of minting a fresh, correctly-shaped descriptor.
    pub fn new(descriptor: Descriptor, metered: bool) -> Self {
        Self { descriptor, metered }
    }

    /// Build **and sign** a fresh, correctly-shaped `arbiter` descriptor from a real `kotva-core`
    /// identity (CONTRACT §2.1). Carries no stake field, by design (§6) — see the crate docs.
    pub fn signed(
        ik: &IdentityKey,
        policy: Cbor,
        tariff: Option<Tariff>,
        metered: bool,
    ) -> (Self, SignedDescriptor) {
        let descriptor = Descriptor {
            identity: ik.public(),
            kind: CoordinatorKind::Arbiter,
            visibility: ARBITER_VISIBILITY,
            policy,
            tariff,
        };
        let signed = descriptor.sign(ik);
        (Self::new(descriptor, metered), signed)
    }
}

impl Coordinator for ArbiterCoordinator {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::Arbiter
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // CONTRACT §2.2: choosing a different arbiter for a future dispute is a config change; an
        // arbiter holds no ongoing custody of a party's identity, keys, or trade history between
        // disputes.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // Not a member of the disclosed scarce-reachability exception class (CONTRACT §2.3) —
        // anyone who can meet the stake requirement can run an arbiter for their own trades.
        SelfHost::Backstop
    }

    fn delivery_path_gate(&self) -> Gate {
        // Dispute resolution sits on no §4 delivery/authoritative content path, and is not a
        // ranking of an opt-in derived view either — it is a bilateral judgment two parties
        // brought to it voluntarily. See the crate docs' dedicated section.
        Gate::NoDeliveryPath
    }

    fn metering(&self) -> Metering {
        if self.metered {
            Metering::SignedReceiptsToPayer
        } else {
            Metering::NotMetered
        }
    }

    fn settlement(&self) -> Settlement {
        // DIRECTION §5: no protocol token, ever. Stake (where required) is verified on the
        // settlement/staking rail itself (§6) — see the crate docs' "Stake" section — never
        // minted as a protocol token and never merely asserted here.
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
    fn signed_arbiter_descriptor_verifies_and_declares_terminating_disclosed() {
        let (_coord, signed) = ArbiterCoordinator::signed(&ik(1), Cbor::empty(), None, false);
        assert!(signed.verify().is_ok(), "a real kotva-core signature must verify");
        assert_eq!(signed.descriptor.kind.as_str(), "arbiter");
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Terminating);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Declared);
    }

    #[test]
    fn a_free_arbiter_is_fully_conformant() {
        let (coord, _signed) = ArbiterCoordinator::signed(&ik(2), Cbor::empty(), None, false);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
    }

    #[test]
    fn a_metered_arbiter_is_also_conformant() {
        let (coord, _signed) = ArbiterCoordinator::signed(&ik(3), Cbor::empty(), None, true);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
        assert!(matches!(coord.metering(), Metering::SignedReceiptsToPayer));
    }

    #[test]
    fn arbiter_has_no_delivery_path_to_gate() {
        let (coord, _signed) = ArbiterCoordinator::signed(&ik(4), Cbor::empty(), None, false);
        assert!(matches!(coord.delivery_path_gate(), Gate::NoDeliveryPath));
    }

    #[test]
    fn arbiter_is_not_the_scarce_reachability_exception() {
        assert!(!CoordinatorKind::Arbiter.is_scarce_reachability());
        let (coord, _signed) = ArbiterCoordinator::signed(&ik(5), Cbor::empty(), None, false);
        assert!(matches!(coord.self_host(), SelfHost::Backstop));
    }

    #[test]
    fn arbiter_mints_no_token() {
        let (coord, _signed) = ArbiterCoordinator::signed(&ik(6), Cbor::empty(), None, false);
        assert!(matches!(coord.settlement(), Settlement::ExistingAssetsOnly));
    }

    #[test]
    fn wrong_kind_descriptor_is_a_coord1_violation() {
        let key = ik(7);
        let descriptor = Descriptor {
            identity: key.public(),
            kind: CoordinatorKind::Gateway,
            visibility: ARBITER_VISIBILITY,
            policy: Cbor::empty(),
            tariff: None,
        };
        let coord = ArbiterCoordinator::new(descriptor, false);
        let report = check(&coord);
        assert!(!report.is_conformant());
    }
}
