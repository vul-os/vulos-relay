//! # indexer — the `indexer` coordinator kind (CONTRACT §5)
//!
//! An **indexer** provides search / discovery / a global product-and-price view: it crawls or
//! ingests a **public, plaintext corpus** and ranks it for its subscribers. CONTRACT §5's own
//! table entry is explicit about the visibility story here: "corpus is public plaintext (nothing
//! to be blind about); query-channel `terminating` unless `attested`" — there is no ciphertext to
//! be blind about on the *corpus* side, so the only content-visibility question that applies at
//! all is the **query channel** a subscriber sends its search/lookup over, which is what
//! [`QueryChannel`]/[`declared_visibility`](IndexerCoordinator::descriptor) actually declares.
//!
//! ## The §4 derived-view carve-out — why this is `Gate::DerivedViewOnly`, not `Classification`
//!
//! CONTRACT §4 forbids content classification **on a delivery or canonical/authoritative path** —
//! a coordinator MUST NOT drop, quarantine, re-rank, or annotate what reaches (or is withheld
//! from) a recipient *by default*. An indexer's ranking looks like exactly that kind of
//! classification on the surface (it scores, sorts, and ranks content), which is why §4 carves it
//! out explicitly rather than leaving it to be inferred:
//!
//! > "a coordinator MAY classify, annotate, rank, or re-rank content within its own derived,
//! > non-authoritative, **opt-in, subscribable view** — this is exactly what ... `indexer`
//! > ... do[es] (they rank their own corpus or match set)."
//!
//! An indexer ranks **its own corpus** — a view a user *subscribes to by querying it*, never a
//! path content is forced through to reach someone by default. Nothing is gated, dropped, or
//! withheld from a recipient's mailbox/inbox because the indexer ranked it low; a low-ranked
//! result simply doesn't surface high in *this one, opt-in, swappable search view* the user chose
//! to query. That is the structural difference from the forbidden case: a spam filter sitting on
//! a delivery path decides what a recipient *ever sees by default*; an indexer decides what
//! surfaces *when explicitly asked, in a view the user can drop for a competing indexer with zero
//! migration* (COORD-2). Get this backwards — gate a delivery/authoritative path with the same
//! ranking logic — and it stops being `DerivedViewOnly` and becomes exactly the `Classification`
//! violation §4 forbids; see [`IndexerCoordinator::delivery_path_gate`] and the test module for
//! the concrete assertion of that distinction.
//!
//! ## Scaffold disclosure
//!
//! This crate fixes the CONTRACT posture (kind, declared visibility, the four conformance
//! clauses) and a signed descriptor — it is **not** a working search/ranking engine. Corpus
//! ingestion, indexing, query execution, and ranking are all future work; nothing here reads or
//! ranks real content yet.

#![forbid(unsafe_code)]

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::{Descriptor, SignedDescriptor, Tariff};
use broker_economics::kinds::CoordinatorKind;
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
use broker_economics::{Cbor, IdentityKey};

/// The visibility question that actually applies to an indexer (CONTRACT §5): not the corpus
/// (public plaintext — nothing to be blind about) but the **query channel** a subscriber searches
/// over.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QueryChannel {
    /// The declared **default** (CONTRACT §5): a query terminates at the indexer in plaintext so
    /// it can be matched against the corpus — a disclosed trust boundary over the *query*, not
    /// the (already-public) corpus.
    Terminating,
    /// The disclosed **alternative**: the indexer runs query matching inside a TEE that attests
    /// it holds no readable copy of the query (private search) — CONTRACT §3.3's `attested`
    /// level, honestly trading operator-trust for chip-vendor-trust (§3.4, THREAT-MODEL R-4).
    /// Documented here as an option; **no TEE integration exists in this scaffold**.
    Attested,
}

impl QueryChannel {
    /// The [`ContentVisibility`] a conformant indexer descriptor MUST carry for this channel
    /// choice (COORD-4/COORD-5 — no silent default, no silent downgrade).
    pub fn declared_visibility(self) -> ContentVisibility {
        match self {
            QueryChannel::Terminating => {
                ContentVisibility::new(VisibilityClass::Terminating, AssuranceLevel::Declared)
            }
            // The query is architecturally unreadable by the operator inside the TEE, so the
            // *class* shifts to `Blind` (not `Terminating`); the *level* is `Attested` because
            // that guarantee rests on hardware attestation, not the absence of any key at all.
            QueryChannel::Attested => {
                ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Attested)
            }
        }
    }
}

/// An `indexer` coordinator's posture for `broker_conformance::check` (CONTRACT §2/§4/§5/§6).
/// See the crate docs for why this scaffold's declared visibility is a `QueryChannel` and its
/// delivery-path gate is [`Gate::DerivedViewOnly`], never [`Gate::Classification`].
pub struct IndexerCoordinator {
    descriptor: Descriptor,
    /// Whether this indexer meters queries and issues signed receipts (CONTRACT §6/COORD-7). A
    /// free public-corpus indexer (the common case) is `false`.
    metered: bool,
}

impl IndexerCoordinator {
    /// Wrap an already-built `Indexer`-kind [`Descriptor`]. Does not itself validate
    /// `descriptor.kind`/`descriptor.visibility` — a mismatched descriptor surfaces as a
    /// `broker_conformance::check` finding, not a silent acceptance. Prefer
    /// [`IndexerCoordinator::signed`] to mint a fresh, correctly-shaped descriptor.
    pub fn new(descriptor: Descriptor, metered: bool) -> Self {
        Self { descriptor, metered }
    }

    /// Build **and sign** a fresh, correctly-shaped `indexer` descriptor from a real `kotva-core`
    /// identity (CONTRACT §2.1) declaring `channel`'s visibility.
    pub fn signed(
        ik: &IdentityKey,
        channel: QueryChannel,
        policy: Cbor,
        tariff: Option<Tariff>,
        metered: bool,
    ) -> (Self, SignedDescriptor) {
        let descriptor = Descriptor {
            identity: ik.public(),
            kind: CoordinatorKind::Indexer,
            visibility: channel.declared_visibility(),
            policy,
            tariff,
        };
        let signed = descriptor.sign(ik);
        (Self::new(descriptor, metered), signed)
    }
}

impl Coordinator for IndexerCoordinator {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::Indexer
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // CONTRACT §2.2: switching indexers is a config change — re-point queries at a different
        // indexer. Nothing about a user's identity, mailbox, or listings lives in an indexer; the
        // corpus it ranks is rebuildable from the same public sources any indexer crawls/ingests.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // Not a member of the disclosed scarce-reachability exception class (CONTRACT §2.3,
        // `CoordinatorKind::is_scarce_reachability` — gateway/reachability-adapter only). Anyone
        // who can run a crawler/ingest pipeline and a query server can run their own indexer over
        // the same public corpus.
        SelfHost::Backstop
    }

    fn delivery_path_gate(&self) -> Gate {
        // CONTRACT §4 derived-view carve-out: an indexer ranks its OWN opt-in, non-authoritative,
        // subscribable view — it does not gate, drop, or re-rank what reaches a recipient by
        // default. See the crate docs' dedicated section for the full argument. This is
        // Authorization-exempt via the carve-out, not a Classification violation.
        Gate::DerivedViewOnly
    }

    fn metering(&self) -> Metering {
        // CONTRACT §6/COORD-7: unmetered by default; a metered indexer issues signed receipts
        // directly to the payer. Wiring real receipts rides `broker-billing`'s `ReceiptLog` —
        // left to the operator composing this crate.
        if self.metered {
            Metering::SignedReceiptsToPayer
        } else {
            Metering::NotMetered
        }
    }

    fn settlement(&self) -> Settlement {
        // DIRECTION §5: no protocol token, ever. A metered indexer settles in an existing
        // stablecoin/fiat rail.
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
    fn signed_indexer_descriptor_verifies_and_declares_terminating_by_default() {
        let (_coord, signed) =
            IndexerCoordinator::signed(&ik(1), QueryChannel::Terminating, Cbor::empty(), None, false);
        assert!(signed.verify().is_ok(), "a real kotva-core signature must verify");
        assert_eq!(signed.descriptor.kind.as_str(), "indexer");
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Terminating);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Declared);
    }

    #[test]
    fn attested_query_channel_declares_blind_attested() {
        let (_coord, signed) =
            IndexerCoordinator::signed(&ik(2), QueryChannel::Attested, Cbor::empty(), None, false);
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Blind);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Attested);
        assert!(signed.descriptor.visibility.is_verifiably_blind());
    }

    #[test]
    fn a_free_indexer_is_fully_conformant() {
        let (coord, _signed) =
            IndexerCoordinator::signed(&ik(3), QueryChannel::Terminating, Cbor::empty(), None, false);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
    }

    #[test]
    fn a_metered_indexer_is_also_conformant() {
        let (coord, _signed) =
            IndexerCoordinator::signed(&ik(4), QueryChannel::Terminating, Cbor::empty(), None, true);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
        assert!(matches!(coord.metering(), Metering::SignedReceiptsToPayer));
    }

    /// The load-bearing assertion for the crate's whole reason to exist: an indexer's own-corpus
    /// ranking is the §4 derived-view carve-out (`DerivedViewOnly`), never `Classification`. Were
    /// this same ranking logic instead used to gate a *delivery* path — deciding what reaches a
    /// recipient's inbox by default rather than what surfaces in an opt-in search view — it would
    /// need to report `Gate::Classification(..)` and `check` would correctly flag it a COORD-6
    /// violation. This scaffold only ever ranks its own subscribable view, so `DerivedViewOnly` is
    /// the honest answer.
    #[test]
    fn own_corpus_ranking_is_derived_view_not_classification() {
        let (coord, _signed) =
            IndexerCoordinator::signed(&ik(5), QueryChannel::Terminating, Cbor::empty(), None, false);
        assert!(matches!(coord.delivery_path_gate(), Gate::DerivedViewOnly));
    }

    #[test]
    fn indexer_is_not_the_scarce_reachability_exception() {
        assert!(!CoordinatorKind::Indexer.is_scarce_reachability());
        let (coord, _signed) =
            IndexerCoordinator::signed(&ik(6), QueryChannel::Terminating, Cbor::empty(), None, false);
        assert!(matches!(coord.self_host(), SelfHost::Backstop));
    }

    #[test]
    fn indexer_mints_no_token() {
        let (coord, _signed) =
            IndexerCoordinator::signed(&ik(7), QueryChannel::Terminating, Cbor::empty(), None, false);
        assert!(matches!(coord.settlement(), Settlement::ExistingAssetsOnly));
    }

    #[test]
    fn wrong_kind_descriptor_is_a_coord1_violation() {
        let key = ik(8);
        let descriptor = Descriptor {
            identity: key.public(),
            kind: CoordinatorKind::Relay,
            visibility: QueryChannel::Terminating.declared_visibility(),
            policy: Cbor::empty(),
            tariff: None,
        };
        let coord = IndexerCoordinator::new(descriptor, false);
        let report = check(&coord);
        assert!(!report.is_conformant());
    }
}
