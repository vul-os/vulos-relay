//! # labeler — the `labeler` coordinator kind (CONTRACT §5)
//!
//! A **labeler** provides moderation labels over public objects, opt-in and subscribable — it
//! labels; a user subscribes to the labelers it trusts; a user can leave, at zero migration cost
//! (COORD-2). This is CONTRACT §4's **own named example** of the anti-abuse mechanism that *is*
//! allowed: "for moderation — a market of opt-in labelers each of which is itself a coordinator
//! under this contract."
//!
//! ## The §4 derived-view carve-out — the canonical example
//!
//! CONTRACT §4 forbids content classification **on a delivery or canonical/authoritative path**.
//! A labeler classifies content into labels, which reads like exactly that forbidden shape — which
//! is why §4's derived-view carve-out names the labeler first, as the paradigm case:
//!
//! > "a coordinator MAY classify, annotate, rank, or re-rank content within its own derived,
//! > non-authoritative, **opt-in, subscribable view** — this is exactly what the `labeler` kind
//! > does (it classifies content into labels; you subscribe to the ones you trust)."
//!
//! The structural distinction from the forbidden case: a labeler's output is a **label a
//! subscriber chooses to consult**, never a gate that withholds or drops content from a
//! recipient's inbox/mailbox by default. Nothing here decides what a recipient *ever sees*; it
//! only offers an opt-in signal a client MAY use, entirely off the delivery path. See
//! [`LabelerCoordinator::delivery_path_gate`] and the test module for the concrete assertion of
//! this distinction (and how the same classification logic sitting on a delivery path instead
//! would flip to a `Classification` violation).
//!
//! ## Visibility: declared `n/a` in the CONTRACT §5 table, but COORD-4 still requires exactly one
//!
//! CONTRACT §5's table marks the labeler's visibility `n/a` — a labeler classifies **public**
//! objects, so there is no delivery-path ciphertext/plaintext boundary for the visibility property
//! to describe. §2.4 still requires every coordinator to declare exactly one visibility class at
//! one assurance level, though, so this scaffold declares `terminating`/`declared` over the
//! labeler's **label-input channel** — the connection a submitter or subscriber uses to hand it
//! content to label or pull its labels — as the honest, disclosed default for that one channel
//! that does exist, while documenting plainly that this is a channel-of-convenience declaration,
//! not a claim that labeling itself has a meaningful blind/terminating distinction.
//!
//! ## Scaffold disclosure
//!
//! This crate fixes the CONTRACT posture and a signed descriptor — it is **not** a working
//! labeling engine. Actual label ingestion, storage, subscription, and delivery are future work;
//! nothing here labels real content yet.

#![forbid(unsafe_code)]

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::{Descriptor, SignedDescriptor, Tariff};
use broker_economics::kinds::CoordinatorKind;
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
use broker_economics::{Cbor, IdentityKey};

/// The declared content-visibility a conformant `labeler` publishes over its label-input channel
/// (CONTRACT §5's `n/a` cell, resolved per this crate's docs' "Visibility" section): `terminating`
/// at `declared` assurance — a disclosed default for the one channel that exists, not a claim that
/// blindness is architecturally meaningful for a labeler.
pub const LABELER_VISIBILITY: ContentVisibility =
    ContentVisibility::new(VisibilityClass::Terminating, AssuranceLevel::Declared);

/// A `labeler` coordinator's posture for `broker_conformance::check` (CONTRACT §2/§4/§5/§6). See
/// the crate docs for why this is the canonical `Gate::DerivedViewOnly` example.
pub struct LabelerCoordinator {
    descriptor: Descriptor,
    /// Whether this labeler meters (e.g. per-subscriber label-feed access) and issues signed
    /// receipts (CONTRACT §6/COORD-7). A free, community-run labeler (the common case) is `false`.
    metered: bool,
}

impl LabelerCoordinator {
    /// Wrap an already-built `Labeler`-kind [`Descriptor`]. Does not itself validate
    /// `descriptor.kind`/`descriptor.visibility` — a mismatched descriptor surfaces as a
    /// `broker_conformance::check` finding. Prefer [`LabelerCoordinator::signed`] for the common
    /// case of minting a fresh, correctly-shaped descriptor.
    pub fn new(descriptor: Descriptor, metered: bool) -> Self {
        Self { descriptor, metered }
    }

    /// Build **and sign** a fresh, correctly-shaped `labeler` descriptor from a real `kotva-core`
    /// identity (CONTRACT §2.1).
    pub fn signed(
        ik: &IdentityKey,
        policy: Cbor,
        tariff: Option<Tariff>,
        metered: bool,
    ) -> (Self, SignedDescriptor) {
        let descriptor = Descriptor {
            identity: ik.public(),
            kind: CoordinatorKind::Labeler,
            visibility: LABELER_VISIBILITY,
            policy,
            tariff,
        };
        let signed = descriptor.sign(ik);
        (Self::new(descriptor, metered), signed)
    }
}

impl Coordinator for LabelerCoordinator {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::Labeler
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // CONTRACT §2.2: dropping a labeler (unsubscribing) or switching to a competing one is a
        // config change — a client's own moderation policy/keys are unaffected; no user identity
        // or history lives with the labeler.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // Not a member of the disclosed scarce-reachability exception class (CONTRACT §2.3) —
        // anyone can stand up a labeler over their own criteria and publish a feed.
        SelfHost::Backstop
    }

    fn delivery_path_gate(&self) -> Gate {
        // CONTRACT §4 derived-view carve-out, canonical example: a labeler classifies content
        // into labels a subscriber opts into — it never gates, drops, or withholds anything from
        // a recipient's mailbox by default. See the crate docs' dedicated section.
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
    fn signed_labeler_descriptor_verifies_and_declares_terminating() {
        let (_coord, signed) = LabelerCoordinator::signed(&ik(1), Cbor::empty(), None, false);
        assert!(signed.verify().is_ok(), "a real kotva-core signature must verify");
        assert_eq!(signed.descriptor.kind.as_str(), "labeler");
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Terminating);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Declared);
    }

    #[test]
    fn a_free_labeler_is_fully_conformant() {
        let (coord, _signed) = LabelerCoordinator::signed(&ik(2), Cbor::empty(), None, false);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
    }

    #[test]
    fn a_metered_labeler_is_also_conformant() {
        let (coord, _signed) = LabelerCoordinator::signed(&ik(3), Cbor::empty(), None, true);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
        assert!(matches!(coord.metering(), Metering::SignedReceiptsToPayer));
    }

    /// The canonical §4 assertion: labeling content into an opt-in, subscribable label set is
    /// `DerivedViewOnly`, never `Classification`. The distinction §4 draws is the *path*: were
    /// this same label logic instead used to drop/quarantine mail on a delivery path by default
    /// (rather than annotate it for a subscriber who chose to consult the label), `check` would
    /// need a `Gate::Classification(..)` answer and would correctly flag a COORD-6 violation.
    #[test]
    fn labeling_is_derived_view_not_classification() {
        let (coord, _signed) = LabelerCoordinator::signed(&ik(4), Cbor::empty(), None, false);
        assert!(matches!(coord.delivery_path_gate(), Gate::DerivedViewOnly));
    }

    #[test]
    fn labeler_is_not_the_scarce_reachability_exception() {
        assert!(!CoordinatorKind::Labeler.is_scarce_reachability());
        let (coord, _signed) = LabelerCoordinator::signed(&ik(5), Cbor::empty(), None, false);
        assert!(matches!(coord.self_host(), SelfHost::Backstop));
    }

    #[test]
    fn labeler_mints_no_token() {
        let (coord, _signed) = LabelerCoordinator::signed(&ik(6), Cbor::empty(), None, false);
        assert!(matches!(coord.settlement(), Settlement::ExistingAssetsOnly));
    }

    #[test]
    fn wrong_kind_descriptor_is_a_coord1_violation() {
        let key = ik(7);
        let descriptor = Descriptor {
            identity: key.public(),
            kind: CoordinatorKind::Gateway,
            visibility: LABELER_VISIBILITY,
            policy: Cbor::empty(),
            tariff: None,
        };
        let coord = LabelerCoordinator::new(descriptor, false);
        let report = check(&coord);
        assert!(!report.is_conformant());
    }
}
