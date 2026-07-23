//! # relay — the mesh `relay` coordinator kind (CONTRACT §5, `blind`/`structural`)
//!
//! A **relay** forwards ciphertext for NAT'd mesh peers over libp2p **Circuit Relay v2**
//! ([`libp2p::relay`]) so two peers that cannot dial each other directly can still reach each
//! other through a third, publicly-reachable party. It holds **no key** that decrypts the
//! payload it forwards — declared visibility `blind` at assurance level `structural`
//! (`coordinator/CONTRACT.md` §3.1/§3.3), the strongest, provable level: the role structurally
//! *cannot* read the traffic, not merely promises not to.
//!
//! This crate has two halves:
//! - [`server`] — [`RelayServer`], the real libp2p Circuit Relay v2 server wrapper (a Swarm
//!   composing `relay` + `identify` over TCP/Noise/Yamux). This is the thing that actually
//!   forwards bytes on the wire.
//! - [`RelayCoordinator`] (this module) — the `broker_conformance::Coordinator` posture: kind,
//!   descriptor, and the CONTRACT §2/§4/§6 answers a relay operator gives. It composes a
//!   [`broker_economics::Descriptor`] signed by a real `kotva-core` `IdentityKey`; it does not
//!   itself run the swarm (an operator wires a `RelayServer` alongside it — see the crate's
//!   integration tests for the shape).
//!
//! ## Honest scope: Circuit Relay v2 ≠ the reachability-adapter's SNI-passthrough ingress
//!
//! **Do not conflate these two coordinator kinds** (a ROLES §4-style conflation warning, worth
//! stating plainly since both are "a middlebox that forwards bytes it can't read"):
//!
//! | | `relay` (this crate) | `reachability-adapter` (`crates/reachability-adapter`) |
//! |---|---|---|
//! | Relays between | two **libp2p peers**, both speaking libp2p (Noise/Yamux) | one **arbitrary box service** and one **arbitrary TCP/TLS client** — neither has to speak libp2p at all |
//! | Protocol | Circuit Relay v2 (`libp2p::relay`), a libp2p-native primitive | TLS SNI-passthrough demux onto a yamux reverse tunnel (REACH profile) — libp2p is not on the client's leg |
//! | Blindness comes from | the relay never terminates the Noise session running *between* the two peers inside the circuit | the adapter never terminates TLS — it routes on the ClientHello SNI byte string alone and splices raw bytes onto the box's tunnel |
//! | Assurance level | always `structural` — Circuit Relay v2 gives the relay no key by protocol design, full stop | depends on **who controls the served name's DNS zone** (REACH-1a): `structural` for the box's own domain, `declared` for a bare adapter-zone vanity the adapter itself could MITM |
//! | Self-host posture | [`SelfHost::Backstop`] — anyone can run a relay for their own mesh traffic | [`SelfHost::ScarceReachabilityException`] — needs a public reachable IP/port, a resource an ISP/host allocates |
//!
//! They solve adjacent but distinct problems (mesh NAT traversal for libp2p peers vs. public
//! ingress for arbitrary non-libp2p services) and MUST NOT be presented to an operator or a
//! spec reader as interchangeable — see `coordinator/CONTRACT.md` §5's own separate table rows
//! for `relay` and `reachability-adapter`.
//!
//! ## `SelfHost::Backstop`, not the scarce-reachability exception
//!
//! CONTRACT §2.3 discloses exactly **one** exception class to "every coordinator kind has a
//! self-host backstop": scarce network reachability, whose two members are the `gateway`
//! (reputable IP + unblocked port 25) and the `reachability-adapter` (public reachable ingress).
//! `relay` is **not** a member of that class: Circuit Relay v2 needs a peer with *some* public
//! or better-connected address to serve as the relay, but that is exactly the same
//! "run this on a cheap VPS" resource every self-hosted internet service needs, not a scarce
//! ISP-allocated one — and, structurally, a relay never needs to be dialable *by the peers using
//! it* the way a mail MX or an adapter's public ingress does; it only needs one confirmed
//! reachable address to hand out in a reservation ack (see [`RelayServer::add_external_address`]
//! and its doc comment for the mechanism). Anyone who can run any libp2p node at all can run a
//! relay for themselves. Getting this backwards — claiming the scarce exception for `relay` — is
//! exactly the mistake [`tests::backstop_relay_is_not_the_scarce_exception`] guards against.

#![forbid(unsafe_code)]

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::{Descriptor, SignedDescriptor, Tariff};
use broker_economics::kinds::CoordinatorKind;
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
use broker_economics::{Cbor, IdentityKey};

pub mod server;

pub use server::{BuildError, RelayServer};

/// The declared content-visibility every conformant `relay` MUST publish (CONTRACT §5): forwards
/// ciphertext, holds no key, structurally blind. Not a default an operator can weaken without it
/// becoming a COORD-5 silent-downgrade violation the moment it diverges from the descriptor.
pub const RELAY_VISIBILITY: ContentVisibility =
    ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural);

/// A `relay` coordinator's posture for `broker_conformance::check` (CONTRACT §2/§4/§6). Pairs a
/// signed [`Descriptor`] with the answers a relay operator gives to the four conformance clauses.
///
/// This type does not itself run a swarm — pair it with a [`RelayServer`] (same process or a
/// sibling) for the actual Circuit Relay v2 forwarding; this is the discovery/posture half.
pub struct RelayCoordinator {
    descriptor: Descriptor,
    /// Whether this relay meters usage and issues signed receipts (CONTRACT §6/COORD-7). A
    /// relay that forwards for free (the common case — see the crate docs' `SelfHost::Backstop`
    /// point: anyone can run one) is `false`.
    metered: bool,
}

impl RelayCoordinator {
    /// Wrap an already-built `Relay`-kind, `blind`/`structural` [`Descriptor`]. Panics-free but
    /// does not itself validate `descriptor.kind`/`descriptor.visibility` — a caller that hands
    /// in the wrong kind/visibility gets exactly what `broker_conformance::check` is for: a
    /// COORD-1/COORD-4 finding, not a silent acceptance. Prefer [`RelayCoordinator::signed`] for
    /// the common case of minting a fresh, correctly-shaped descriptor.
    pub fn new(descriptor: Descriptor, metered: bool) -> Self {
        Self { descriptor, metered }
    }

    /// Build **and sign** a fresh, correctly-shaped `relay` descriptor from a real `kotva-core`
    /// identity — the [`Descriptor::sign`] path (CONTRACT §2.1: every coordinator MUST publish a
    /// signed descriptor under an attested identity, never a placeholder key).
    ///
    /// Returns both the [`RelayCoordinator`] (for local posture/conformance use) and the
    /// [`SignedDescriptor`] (the wire form an operator actually publishes for discovery,
    /// independently verifiable via [`SignedDescriptor::verify`]).
    pub fn signed(
        ik: &IdentityKey,
        policy: Cbor,
        tariff: Option<Tariff>,
        metered: bool,
    ) -> (Self, SignedDescriptor) {
        let descriptor = Descriptor {
            identity: ik.public(),
            kind: CoordinatorKind::Relay,
            visibility: RELAY_VISIBILITY,
            policy,
            tariff,
        };
        let signed = descriptor.sign(ik);
        (Self::new(descriptor, metered), signed)
    }
}

impl Coordinator for RelayCoordinator {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::Relay
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // CONTRACT §2.2: switching relays is a config change (a new listen multiaddr / a new
        // relay PeerId to reserve a slot on) — no user identity, keys, or history live on a
        // relay, so there is nothing to migrate.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // NOT the scarce-reachability exception (see the crate docs' dedicated section above) —
        // a relay is self-hostable by anyone who can run any libp2p node at all.
        SelfHost::Backstop
    }

    fn delivery_path_gate(&self) -> Gate {
        // A relay forwards opaque Noise-secured circuit bytes; it sits on no §4 delivery or
        // canonical/authoritative path to gate at all (it cannot classify what it cannot read).
        Gate::NoDeliveryPath
    }

    fn metering(&self) -> Metering {
        // CONTRACT §6/COORD-7: if metered, signed usage receipts to the payer; else unmetered.
        // Wiring real receipts rides `broker-billing`'s `Meter`/`ReceiptLog` (optional; not
        // required for a conformant, free relay) — left to the operator composing this crate.
        if self.metered {
            Metering::SignedReceiptsToPayer
        } else {
            Metering::NotMetered
        }
    }

    fn settlement(&self) -> Settlement {
        // DIRECTION §5: no protocol token, ever. A metered relay settles in an existing
        // stablecoin/fiat rail; `broker-billing::SettlementRail` is where that composes in.
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
    fn signed_relay_descriptor_verifies_and_declares_blind_structural() {
        let (_coord, signed) = RelayCoordinator::signed(&ik(1), Cbor::empty(), None, false);
        assert!(signed.verify().is_ok(), "a real kotva-core signature must verify");
        assert_eq!(signed.descriptor.kind.as_str(), "relay");
        assert!(
            signed.descriptor.visibility.is_verifiably_blind(),
            "relay MUST declare blind/structural — a verifiable, not merely declared, claim"
        );
        assert_eq!(signed.descriptor.visibility.class, VisibilityClass::Blind);
        assert_eq!(signed.descriptor.visibility.level, AssuranceLevel::Structural);
    }

    #[test]
    fn a_free_relay_is_fully_conformant() {
        let (coord, _signed) = RelayCoordinator::signed(&ik(2), Cbor::empty(), None, false);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
    }

    #[test]
    fn a_metered_relay_is_also_conformant() {
        let (coord, _signed) = RelayCoordinator::signed(&ik(3), Cbor::empty(), None, true);
        let report = check(&coord);
        assert!(report.is_conformant(), "{:?}", report.findings);
        assert!(matches!(coord.metering(), Metering::SignedReceiptsToPayer));
    }

    /// The specific footgun the crate docs' "not the scarce exception" section calls out: a
    /// relay MUST claim [`SelfHost::Backstop`], never [`SelfHost::ScarceReachabilityException`]
    /// (that exception's two members are `gateway` and `reachability-adapter`, per
    /// `CoordinatorKind::is_scarce_reachability`). Assert both the posture *and* that the
    /// underlying kind is genuinely not in the scarce class, so this test would fail loudly if
    /// either the coordinator's `self_host()` answer or `CoordinatorKind`'s own membership table
    /// ever drifted.
    #[test]
    fn backstop_relay_is_not_the_scarce_exception() {
        let (coord, _signed) = RelayCoordinator::signed(&ik(4), Cbor::empty(), None, false);
        assert!(matches!(coord.self_host(), SelfHost::Backstop));
        assert!(
            !CoordinatorKind::Relay.is_scarce_reachability(),
            "relay must not be a member of the disclosed scarce-reachability exception class"
        );

        // A relay that mis-declared the scarce exception would still *pass* COORD-3 today only
        // if it really were a member of that class (broker-conformance checks membership, see
        // `broker_conformance::check`'s COORD-3 arm) — demonstrate the violation directly.
        struct MisclaimedRelay(Descriptor);
        impl Coordinator for MisclaimedRelay {
            fn kind(&self) -> CoordinatorKind {
                CoordinatorKind::Relay
            }
            fn descriptor(&self) -> &Descriptor {
                &self.0
            }
            fn lock_in(&self) -> LockIn {
                LockIn::None
            }
            fn self_host(&self) -> SelfHost {
                SelfHost::ScarceReachabilityException
            }
            fn delivery_path_gate(&self) -> Gate {
                Gate::NoDeliveryPath
            }
            fn metering(&self) -> Metering {
                Metering::NotMetered
            }
            fn settlement(&self) -> Settlement {
                Settlement::ExistingAssetsOnly
            }
        }
        let (_coord, signed) = RelayCoordinator::signed(&ik(5), Cbor::empty(), None, false);
        let misclaimed = MisclaimedRelay(signed.descriptor);
        let report = check(&misclaimed);
        assert!(
            !report.is_conformant(),
            "claiming the scarce-reachability exception for `relay` must be a COORD-3 violation"
        );
    }

    #[test]
    fn relay_has_no_delivery_path_to_gate() {
        let (coord, _signed) = RelayCoordinator::signed(&ik(6), Cbor::empty(), None, false);
        assert!(matches!(coord.delivery_path_gate(), Gate::NoDeliveryPath));
    }

    #[test]
    fn relay_mints_no_token() {
        let (coord, _signed) = RelayCoordinator::signed(&ik(7), Cbor::empty(), None, false);
        assert!(matches!(coord.settlement(), Settlement::ExistingAssetsOnly));
    }

    #[test]
    fn wrong_kind_descriptor_is_a_coord1_violation() {
        // A relay coordinator built over a descriptor that claims a *different* kind (an
        // operator/config bug, not a spec-conformant relay) must fail the checklist rather than
        // be silently accepted — COORD-1 checks `descriptor.kind == coordinator.kind()`.
        let ik = ik(8);
        let descriptor = Descriptor {
            identity: ik.public(),
            kind: CoordinatorKind::Gateway,
            visibility: RELAY_VISIBILITY,
            policy: Cbor::empty(),
            tariff: None,
        };
        let coord = RelayCoordinator::new(descriptor, false);
        let report = check(&coord);
        assert!(!report.is_conformant());
    }
}
