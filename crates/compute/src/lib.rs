//! # compute — the `compute` coordinator kind, *provisional* (CONTRACT §5)
//!
//! A **compute** coordinator provides hosted/outsourced computation — e.g. private-AI inference on
//! rented GPU. CONTRACT §5 marks this kind **provisional** in its own table, and this crate keeps
//! that disclosure: the kind is real (`CoordinatorKind::Compute` exists and is checkable), but its
//! shape is the least settled of the ten in the table.
//!
//! ## Visibility: `terminating` default, `attested` (TEE) for blind compute
//!
//! CONTRACT §5: "`terminating` (default) / `attested` (TEE, for blind compute)". By default the
//! operator's hardware sees the plaintext input/output of the job it runs — a disclosed trust
//! boundary, same shape as the `gateway`/`matcher`/`arbiter`/`oracle` default. The alternative is
//! **blind compute**: the job runs inside a TEE that attests it holds no readable copy of the
//! input/output, at the cost of trading operator-trust for chip-vendor-trust — CONTRACT §3.4 /
//! THREAT-MODEL R-4's honest disclosure applies here in full: attestation is hardware-trust, not
//! the structural absence of a key, and a side-channel history exists. This crate documents the
//! option honestly via [`ComputeChannel::Attested`] but implements **no TEE integration**.
//!
//! ## Not a delivery path — `Gate::NoDeliveryPath`
//!
//! A compute coordinator runs a job for a party that submitted it; it does not classify, rank, or
//! gate content on any delivery/authoritative path, nor rank an opt-in corpus/pool the way
//! `indexer`/`labeler`/`matcher` do. [`Gate::NoDeliveryPath`] is the honest answer — see
//! [`ComputeCoordinator::delivery_path_gate`].
//!
//! ## Scaffold disclosure
//!
//! This crate fixes the CONTRACT posture and a signed descriptor — it is **not** a working
//! compute service. Job submission, execution, result delivery, and any TEE attestation
//! integration are all future work; nothing here runs a real computation yet.

#![forbid(unsafe_code)]

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::{Descriptor, SignedDescriptor, Tariff};
use broker_economics::kinds::CoordinatorKind;
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
use broker_economics::{Cbor, IdentityKey};

/// The visibility a compute coordinator declares over the job it runs (CONTRACT §5: `terminating`
/// default / `attested` via TEE, for blind compute).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ComputeChannel {
    /// The declared **default** (CONTRACT §5): the operator's hardware sees the job's plaintext
    /// input/output to run it — a disclosed trust boundary, not a silent one.
    Terminating,
    /// The disclosed **alternative** — "blind compute": the job runs inside a TEE that attests it
    /// holds no readable copy of the input/output. Honestly trades operator-trust for
    /// chip-vendor-trust (§3.4, THREAT-MODEL R-4) — documented here as an option; **no TEE
    /// integration exists in this scaffold**.
    Attested,
}

impl ComputeChannel {
    /// The [`ContentVisibility`] a conformant compute descriptor MUST carry for this channel
    /// choice (COORD-4/COORD-5).
    pub fn declared_visibility(self) -> ContentVisibility {
        match self {
            ComputeChannel::Terminating => {
                ContentVisibility::new(VisibilityClass::Terminating, AssuranceLevel::Declared)
            }
            // Blind compute: the operator is architecturally unable to read the job, so the class
            // shifts to `Blind`; the level is `Attested` because that guarantee rests on hardware
            // attestation rather than the structural absence of a key.
            ComputeChannel::Attested => {
                ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Attested)
            }
        }
    }
}

/// A `compute` coordinator's posture for `broker_conformance::check` (CONTRACT §2/§4/§5/§6). Kept
/// explicitly *provisional* per CONTRACT §5's own table — see the crate docs.
pub struct ComputeCoordinator {
    descriptor: Descriptor,
    /// Whether this compute coordinator meters jobs and issues signed receipts (CONTRACT
    /// §6/COORD-7).
    metered: bool,
}

impl ComputeCoordinator {
    /// Wrap an already-built `Compute`-kind [`Descriptor`]. Does not itself validate
    /// `descriptor.kind`/`descriptor.visibility` — a mismatched descriptor surfaces as a
    /// `broker_conformance::check` finding. Prefer [`ComputeCoordinator::signed`] for the common
    /// case of minting a fresh, correctly-shaped descriptor.
    pub fn new(descriptor: Descriptor, metered: bool) -> Self {
        Self { descriptor, metered }
    }

    /// Build **and sign** a fresh, correctly-shaped `compute` descriptor from a real `kotva-core`
    /// identity (CONTRACT §2.1) declaring `channel`'s visibility.
    pub fn signed(
        ik: &IdentityKey,
        channel: ComputeChannel,
        policy: Cbor,
        tariff: Option<Tariff>,
        metered: bool,
    ) -> (Self, SignedDescriptor) {
        let descriptor = Descriptor {
            identity: ik.public(),
            kind: CoordinatorKind::Compute,
            visibility: channel.declared_visibility(),
            policy,
            tariff,
        };
        let signed = descriptor.sign(ik);
        (Self::new(descriptor, metered), signed)
    }
}

impl Coordinator for ComputeCoordinator {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::Compute
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // CONTRACT §2.2: submitting a future job to a different compute operator is a config
        // change — no ongoing identity, keys, or data custody lives with a compute coordinator
        // between jobs.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // Not a member of the disclosed scarce-reachability exception class (CONTRACT §2.3) —
        // anyone who can rent or own the hardware can run their own compute coordinator.
        SelfHost::Backstop
    }

    fn delivery_path_gate(&self) -> Gate {
        // Outsourced computation sits on no §4 delivery/authoritative content path, and is not a
        // ranking of an opt-in derived view either. See the crate docs' dedicated section.
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
    fn signed_compute_descriptor_verifies_and_declares_terminating_by_default() {
        let (_coord, signed) =
            ComputeCoordinator::signed(&ik(1), ComputeChannel::Terminating, Cbor::empty(), None, false);
        assert!(signed.verify().is_ok(), "a real kotva-core signature must verify");
        assert_eq!(signed.descriptor.kind.as_str(), "compute");
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Terminating);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Declared);
    }

    #[test]
    fn attested_blind_compute_declares_blind_attested() {
        let (_coord, signed) =
            ComputeCoordinator::signed(&ik(2), ComputeChannel::Attested, Cbor::empty(), None, false);
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Blind);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Attested);
        assert!(signed.descriptor.visibility.is_verifiably_blind());
    }

    #[test]
    fn a_free_compute_coordinator_is_fully_conformant() {
        let (coord, _signed) =
            ComputeCoordinator::signed(&ik(3), ComputeChannel::Terminating, Cbor::empty(), None, false);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
    }

    #[test]
    fn a_metered_compute_coordinator_is_also_conformant() {
        let (coord, _signed) =
            ComputeCoordinator::signed(&ik(4), ComputeChannel::Terminating, Cbor::empty(), None, true);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
        assert!(matches!(coord.metering(), Metering::SignedReceiptsToPayer));
    }

    #[test]
    fn compute_has_no_delivery_path_to_gate() {
        let (coord, _signed) =
            ComputeCoordinator::signed(&ik(5), ComputeChannel::Terminating, Cbor::empty(), None, false);
        assert!(matches!(coord.delivery_path_gate(), Gate::NoDeliveryPath));
    }

    #[test]
    fn compute_is_not_the_scarce_reachability_exception() {
        assert!(!CoordinatorKind::Compute.is_scarce_reachability());
        let (coord, _signed) =
            ComputeCoordinator::signed(&ik(6), ComputeChannel::Terminating, Cbor::empty(), None, false);
        assert!(matches!(coord.self_host(), SelfHost::Backstop));
    }

    #[test]
    fn compute_mints_no_token() {
        let (coord, _signed) =
            ComputeCoordinator::signed(&ik(7), ComputeChannel::Terminating, Cbor::empty(), None, false);
        assert!(matches!(coord.settlement(), Settlement::ExistingAssetsOnly));
    }

    #[test]
    fn wrong_kind_descriptor_is_a_coord1_violation() {
        let key = ik(8);
        let descriptor = Descriptor {
            identity: key.public(),
            kind: CoordinatorKind::Relay,
            visibility: ComputeChannel::Terminating.declared_visibility(),
            policy: Cbor::empty(),
            tariff: None,
        };
        let coord = ComputeCoordinator::new(descriptor, false);
        let report = check(&coord);
        assert!(!report.is_conformant());
    }
}
