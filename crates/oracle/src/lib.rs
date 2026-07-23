//! # oracle — the `oracle` coordinator kind (CONTRACT §5)
//!
//! An **oracle** provides physical-world / real-fact attestation (delivered? ride done?). CONTRACT
//! §5's table gives its typical visibility as `terminating`, disclosed — the oracle needs the
//! plaintext claim/evidence (a photo, a GPS trace, a signed courier scan) to attest to it, a
//! deliberate, disclosed trust boundary.
//!
//! ## ORACLE ⊂ ATTEST (DIRECTION §2)
//!
//! KOTVA's primitive set is `OFFER · MATCH · RESERVE · REPUTATION · ESCROW · ATTEST`; ORACLE is
//! not itself a seventh primitive. DIRECTION §2 is explicit: "**ORACLE** is the oracle coordinator
//! kind (a physical-fact attestation, i.e. **ORACLE ⊂ ATTEST**)" — a *composite role* built on the
//! `ATTEST` primitive, the same way `DISPUTE` in a service recipe names the `arbiter` coordinator
//! kind rather than a primitive of its own. This crate implements the `oracle` **coordinator
//! kind** — the `broker_conformance::Coordinator` posture — not the `ATTEST` primitive itself,
//! which is substrate-level (DIRECTION's own table: "**ATTEST** is ours (a primitive); its claim
//! body binds EAS / W3C Verifiable Credentials").
//!
//! ## Not a delivery path — `Gate::NoDeliveryPath`
//!
//! An oracle attests to a physical-world fact for a specific trade; it does not classify, rank, or
//! gate content on any delivery/authoritative path, nor does it rank an opt-in corpus/pool the way
//! `indexer`/`labeler`/`matcher` do — CONTRACT §4's carve-out and prohibition are both simply out
//! of scope here. [`Gate::NoDeliveryPath`] is the honest answer — see
//! [`OracleCoordinator::delivery_path_gate`].
//!
//! ## Stake — verified on-rail, never in the descriptor (CONTRACT §6)
//!
//! Like `arbiter`, an oracle is one of the two kinds CONTRACT §6 names as carrying skin-in-the-game
//! ("`arbiter`, `oracle` — DIRECTION §5, sized to the value at risk"). §2.1 excludes a stake field
//! from [`broker_economics::Descriptor`] by design, so stake can never become a ranking signal;
//! §6 requires it be verified **on the settlement/staking rail itself**, with an unverifiable claim
//! MUST-treated as no stake (SEC-1, fail closed). This crate does not depend on `broker-billing`
//! (kept thin, matching the other posture scaffolds) — the seam a relying operator wires a real
//! check through is `broker_billing::StakeVerifier` (`crates/broker-billing/src/stake.rs`), whose
//! fail-closed reference implementation `NoStakeRail` treats every claim as unverifiable by
//! default. An oracle descriptor from this crate carries no stake field, by construction and by
//! design — a caller relying on staked trust MUST query a `StakeVerifier`-shaped rail check
//! independently, never read it off this descriptor.
//!
//! ## Scaffold disclosure
//!
//! This crate fixes the CONTRACT posture and a signed descriptor — it is **not** a working
//! attestation service. Claim intake, evidence verification, ruling issuance, and the stake-rail
//! integration itself are all future work; nothing here attests to a real physical-world fact yet.

#![forbid(unsafe_code)]

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::{Descriptor, SignedDescriptor, Tariff};
use broker_economics::kinds::CoordinatorKind;
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
use broker_economics::{Cbor, IdentityKey};

/// The declared content-visibility every conformant `oracle` publishes over its claim/evidence
/// channel (CONTRACT §5): `terminating`, disclosed, at `declared` assurance.
pub const ORACLE_VISIBILITY: ContentVisibility =
    ContentVisibility::new(VisibilityClass::Terminating, AssuranceLevel::Declared);

/// An `oracle` coordinator's posture for `broker_conformance::check` (CONTRACT §2/§4/§5/§6). See
/// the crate docs for the ORACLE ⊂ ATTEST relationship, the stake-on-rail seam, and why the
/// delivery-path gate is [`Gate::NoDeliveryPath`].
pub struct OracleCoordinator {
    descriptor: Descriptor,
    /// Whether this oracle meters attestations and issues signed receipts (CONTRACT §6/COORD-7).
    metered: bool,
}

impl OracleCoordinator {
    /// Wrap an already-built `Oracle`-kind [`Descriptor`]. Does not itself validate
    /// `descriptor.kind`/`descriptor.visibility` — a mismatched descriptor surfaces as a
    /// `broker_conformance::check` finding. Prefer [`OracleCoordinator::signed`] for the common
    /// case of minting a fresh, correctly-shaped descriptor.
    pub fn new(descriptor: Descriptor, metered: bool) -> Self {
        Self { descriptor, metered }
    }

    /// Build **and sign** a fresh, correctly-shaped `oracle` descriptor from a real `kotva-core`
    /// identity (CONTRACT §2.1). Carries no stake field, by design (§6) — see the crate docs.
    pub fn signed(
        ik: &IdentityKey,
        policy: Cbor,
        tariff: Option<Tariff>,
        metered: bool,
    ) -> (Self, SignedDescriptor) {
        let descriptor = Descriptor {
            identity: ik.public(),
            kind: CoordinatorKind::Oracle,
            visibility: ORACLE_VISIBILITY,
            policy,
            tariff,
        };
        let signed = descriptor.sign(ik);
        (Self::new(descriptor, metered), signed)
    }
}

impl Coordinator for OracleCoordinator {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::Oracle
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // CONTRACT §2.2: choosing a different oracle for a future trade is a config change; an
        // oracle holds no ongoing custody of a party's identity, keys, or trade history.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // Not a member of the disclosed scarce-reachability exception class (CONTRACT §2.3) —
        // anyone who can meet the stake requirement can run an oracle for their own trades.
        SelfHost::Backstop
    }

    fn delivery_path_gate(&self) -> Gate {
        // Physical-world attestation sits on no §4 delivery/authoritative content path, and is
        // not a ranking of an opt-in derived view either. See the crate docs' dedicated section.
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
        // settlement/staking rail itself (§6) — see the crate docs' "Stake" section.
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
    fn signed_oracle_descriptor_verifies_and_declares_terminating_disclosed() {
        let (_coord, signed) = OracleCoordinator::signed(&ik(1), Cbor::empty(), None, false);
        assert!(signed.verify().is_ok(), "a real kotva-core signature must verify");
        assert_eq!(signed.descriptor.kind.as_str(), "oracle");
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Terminating);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Declared);
    }

    #[test]
    fn a_free_oracle_is_fully_conformant() {
        let (coord, _signed) = OracleCoordinator::signed(&ik(2), Cbor::empty(), None, false);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
    }

    #[test]
    fn a_metered_oracle_is_also_conformant() {
        let (coord, _signed) = OracleCoordinator::signed(&ik(3), Cbor::empty(), None, true);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
        assert!(matches!(coord.metering(), Metering::SignedReceiptsToPayer));
    }

    #[test]
    fn oracle_has_no_delivery_path_to_gate() {
        let (coord, _signed) = OracleCoordinator::signed(&ik(4), Cbor::empty(), None, false);
        assert!(matches!(coord.delivery_path_gate(), Gate::NoDeliveryPath));
    }

    #[test]
    fn oracle_is_not_the_scarce_reachability_exception() {
        assert!(!CoordinatorKind::Oracle.is_scarce_reachability());
        let (coord, _signed) = OracleCoordinator::signed(&ik(5), Cbor::empty(), None, false);
        assert!(matches!(coord.self_host(), SelfHost::Backstop));
    }

    #[test]
    fn oracle_mints_no_token() {
        let (coord, _signed) = OracleCoordinator::signed(&ik(6), Cbor::empty(), None, false);
        assert!(matches!(coord.settlement(), Settlement::ExistingAssetsOnly));
    }

    #[test]
    fn wrong_kind_descriptor_is_a_coord1_violation() {
        let key = ik(7);
        let descriptor = Descriptor {
            identity: key.public(),
            kind: CoordinatorKind::Gateway,
            visibility: ORACLE_VISIBILITY,
            policy: Cbor::empty(),
            tariff: None,
        };
        let coord = OracleCoordinator::new(descriptor, false);
        let report = check(&coord);
        assert!(!report.is_conformant());
    }
}
