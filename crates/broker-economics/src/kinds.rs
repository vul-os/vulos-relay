//! Coordinator kinds — all instances of the one contract (CONTRACT §5).
//!
//! Every kind inherits the four conformance clauses (§2) and the content-visibility
//! property (§3) unchanged. `gateway` (KOTVA-Mail §7) and the legacy adapters (§26)
//! are the first fully-worked instances; the rest inherit them.

use crate::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};

/// The coordinator kinds of the CONTRACT §5 table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CoordinatorKind {
    /// Legacy-mail bridge (MX, DKIM egress, legacy client surfaces). The mail
    /// *adapter*; keep the name "gateway" for it only (STYLE §6).
    Gateway,
    /// Mesh reachability for NAT'd peers (Circuit Relay v2).
    Relay,
    /// Forwards SFrame-encrypted call/stream media; scales calls (RFC 9605).
    MediaRelay,
    /// ngrok-style public subdomains for arbitrary box services (REACH profile).
    ReachabilityAdapter,
    /// Search / discovery / global product-and-price view.
    Indexer,
    /// Moderation labels, opt-in, subscribable.
    Labeler,
    /// Real-time supply↔demand matching (rides, delivery).
    Matcher,
    /// Hosted/outsourced computation (e.g. private-AI inference). Provisional.
    Compute,
    /// Dispute resolution (staked jury).
    Arbiter,
    /// Physical-world / real-fact attestation (delivered? ride done?).
    Oracle,
    /// Holds the trade float for a trade window — the family's one load-bearing
    /// exception (CONTRACT §1, ESCROW §9–§10), disclosed not hidden.
    CustodialEscrow,
}

impl CoordinatorKind {
    /// The stable string id of the kind (as it appears in a descriptor).
    pub fn as_str(self) -> &'static str {
        match self {
            CoordinatorKind::Gateway => "gateway",
            CoordinatorKind::Relay => "relay",
            CoordinatorKind::MediaRelay => "media-relay",
            CoordinatorKind::ReachabilityAdapter => "reachability-adapter",
            CoordinatorKind::Indexer => "indexer",
            CoordinatorKind::Labeler => "labeler",
            CoordinatorKind::Matcher => "matcher",
            CoordinatorKind::Compute => "compute",
            CoordinatorKind::Arbiter => "arbiter",
            CoordinatorKind::Oracle => "oracle",
            CoordinatorKind::CustodialEscrow => "custodial-escrow",
        }
    }

    /// The *typical* visibility from the CONTRACT §5 table. This is the default a
    /// well-behaved operator declares; the actual declaration is the operator's and
    /// is authoritative — a client checks the operator's declared value, never this
    /// table. `None` means the kind has no single default (e.g. the indexer, whose
    /// corpus is public plaintext but whose query channel varies).
    pub fn typical_visibility(self) -> Option<ContentVisibility> {
        use AssuranceLevel::*;
        use VisibilityClass::*;
        let v = |c, l| Some(ContentVisibility::new(c, l));
        match self {
            // Legacy leg is plaintext — a disclosed trust boundary.
            CoordinatorKind::Gateway => v(Terminating, Declared),
            CoordinatorKind::Relay => v(Blind, Structural),
            // Media payload sealed by SFrame; per-frame metadata/RTP routing visible.
            CoordinatorKind::MediaRelay => v(BlindRouting, Structural),
            // SNI-passthrough preferred; assurance is scoped by cert ownership
            // (REACH-1a) — structural for an own-domain name, declared for a bare
            // adapter-zone vanity. Structural is the RECOMMENDED profile.
            CoordinatorKind::ReachabilityAdapter => v(BlindRouting, Structural),
            // Corpus is public plaintext (nothing to be blind about); the query
            // channel is terminating unless attested — no single default.
            CoordinatorKind::Indexer => None,
            // Labels public objects — visibility is n/a to a delivery path.
            CoordinatorKind::Labeler => None,
            CoordinatorKind::Matcher => v(Terminating, Declared),
            CoordinatorKind::Compute => v(Terminating, Declared),
            CoordinatorKind::Arbiter => v(Terminating, Declared),
            CoordinatorKind::Oracle => v(Terminating, Declared),
            CoordinatorKind::CustodialEscrow => v(Terminating, Declared),
        }
    }

    /// Whether this kind is the disclosed load-bearing exception — the only kind
    /// that does not fade once hired (CONTRACT §1, SEC-6/R-6). Everything else is
    /// hired-not-depended-on: removing it degrades reach, never function.
    pub fn is_load_bearing_exception(self) -> bool {
        matches!(self, CoordinatorKind::CustodialEscrow)
    }

    /// Parse the stable string id back into a kind (the inverse of [`Self::as_str`]), failing
    /// closed (`None`) on any unknown value — used decoding a wire descriptor (`descriptor.rs`),
    /// never guessing at an unrecognized kind string.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "gateway" => CoordinatorKind::Gateway,
            "relay" => CoordinatorKind::Relay,
            "media-relay" => CoordinatorKind::MediaRelay,
            "reachability-adapter" => CoordinatorKind::ReachabilityAdapter,
            "indexer" => CoordinatorKind::Indexer,
            "labeler" => CoordinatorKind::Labeler,
            "matcher" => CoordinatorKind::Matcher,
            "compute" => CoordinatorKind::Compute,
            "arbiter" => CoordinatorKind::Arbiter,
            "oracle" => CoordinatorKind::Oracle,
            "custodial-escrow" => CoordinatorKind::CustodialEscrow,
            _ => return None,
        })
    }

    /// Whether this kind belongs to the disclosed scarce-network-reachability
    /// class (CONTRACT §2.3, THREAT-MODEL R-6) — a resource an ISP/host allocates,
    /// not something a user can always self-provision. Two members: the `gateway`
    /// (reputable IP + unblocked port 25) and the `reachability-adapter` (public
    /// reachable ingress).
    pub fn is_scarce_reachability(self) -> bool {
        matches!(
            self,
            CoordinatorKind::Gateway | CoordinatorKind::ReachabilityAdapter
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_from_str_round_trips_every_kind() {
        for k in [
            CoordinatorKind::Gateway,
            CoordinatorKind::Relay,
            CoordinatorKind::MediaRelay,
            CoordinatorKind::ReachabilityAdapter,
            CoordinatorKind::Indexer,
            CoordinatorKind::Labeler,
            CoordinatorKind::Matcher,
            CoordinatorKind::Compute,
            CoordinatorKind::Arbiter,
            CoordinatorKind::Oracle,
            CoordinatorKind::CustodialEscrow,
        ] {
            assert_eq!(CoordinatorKind::from_wire_str(k.as_str()), Some(k));
        }
        assert_eq!(CoordinatorKind::from_wire_str("not-a-kind"), None);
    }

    #[test]
    fn relay_is_structurally_blind() {
        let v = CoordinatorKind::Relay.typical_visibility().unwrap();
        assert!(v.is_verifiably_blind());
    }

    #[test]
    fn gateway_is_terminating_and_scarce() {
        assert_eq!(
            CoordinatorKind::Gateway.typical_visibility().unwrap().class,
            VisibilityClass::Terminating
        );
        assert!(CoordinatorKind::Gateway.is_scarce_reachability());
    }

    #[test]
    fn only_custodial_escrow_is_load_bearing() {
        for k in [
            CoordinatorKind::Gateway,
            CoordinatorKind::Relay,
            CoordinatorKind::MediaRelay,
            CoordinatorKind::ReachabilityAdapter,
            CoordinatorKind::Matcher,
            CoordinatorKind::Oracle,
        ] {
            assert!(!k.is_load_bearing_exception(), "{} must fade", k.as_str());
        }
        assert!(CoordinatorKind::CustodialEscrow.is_load_bearing_exception());
    }

    #[test]
    fn exactly_two_scarce_reachability_members() {
        let scarce: Vec<_> = [
            CoordinatorKind::Gateway,
            CoordinatorKind::Relay,
            CoordinatorKind::MediaRelay,
            CoordinatorKind::ReachabilityAdapter,
            CoordinatorKind::Indexer,
            CoordinatorKind::Labeler,
            CoordinatorKind::Matcher,
            CoordinatorKind::Compute,
            CoordinatorKind::Arbiter,
            CoordinatorKind::Oracle,
            CoordinatorKind::CustodialEscrow,
        ]
        .into_iter()
        .filter(|k| k.is_scarce_reachability())
        .collect();
        assert_eq!(scarce.len(), 2);
    }
}
