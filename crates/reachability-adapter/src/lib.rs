//! # reachability-adapter — the REACH coordinator kind
//!
//! Public HTTPS reach for arbitrary box services (`svc.alice.reach.example`) with
//! the adapter **content-blind by construction**: it routes inbound connections by
//! TLS SNI onto the box's reverse tunnel and **the box terminates TLS**
//! (profiles/reachability.md, REACH-1). The adapter forwards ciphertext it holds no
//! key to read — declared visibility `blind-routing`, assurance scoped by cert
//! ownership (REACH-1a): `structural` for an own-domain name, `declared` for a bare
//! adapter-zone vanity.
//!
//! ## Why this crate exists — the honesty-gap fix
//!
//! The Go relay this replaces is a **TLS-terminating L7 reverse proxy** (it
//! terminates TLS and forwards HTTP), so "the relay never decrypts" does not hold
//! for it (vulos-security-audit MEDIUM-1). This crate retires that L7-visible
//! behavior for the SNI-passthrough path the spec mandates. The Go code stays
//! preserved until this port is proven (HANDOVER §Guardrails-3).
//!
//! ## Module plan (implementation order)
//!
//! | Module | REACH rule | Substrate-typed? | Status |
//! |---|---|---|---|
//! | `sni`     | Peek the TLS ClientHello SNI without terminating; demux (REACH-1). | no — unblocked | **done** (W4) |
//! | `tunnel`  | The box↔adapter reverse tunnel (yamux); adapter opens one stream per inbound conn (REACH profile §2). | no — unblocked | **done** (W4), transport-level only |
//! | `ingress` | The public :443 listener + fail-closed routing (REACH-1/-5/-6). | no — unblocked | **done** (W4) |
//! | `auth`   | Mutual **key-auth** of the tunnel to the box `IK` (DMTAP-Auth-shaped challenge-response, REACH-2). | yes — kotva-core | **done** (W4b), key-auth only — see residual below |
//! | `zone`   | Single-writer subdomain namespace + `LocationRecord` hints (REACH-3/-7, RESERVE). | partly — needs kotva-core naming | not started |
//! | `descriptor` | Signed discovery-only adapter descriptor + tariff + receipts (REACH-11). | yes — kotva-core | not started |
//!
//! The `sni` + `tunnel` + `ingress` transport core is pure plumbing and was built
//! first (W4), ahead of the substrate. `kotva-core` is now tag-pinned in the
//! workspace (`core-v0.2.0`, W3); `auth` (W4b) uses its real `IdentityKey` /
//! `verify_domain` to close REACH-2's key-authentication half. `zone`/`descriptor`
//! are still not started; that build-out is separate future work.
//!
//! **REACH-2 status — key-auth closed, transport security still open (disclosed
//! plainly, see `auth` module docs for the full statement):** the box↔adapter
//! control connection now runs a challenge-response handshake
//! ([`auth::authenticate_box_connection`]) before [`ingress::AdapterServer::accept_box_connection`]
//! will spawn a tunnel or touch the registry — the box must sign a fresh,
//! single-use, adapter-issued nonce (bound to its claimed name) under the `IK`
//! it claims, verified via `kotva_core::identity::verify_domain`; a wrong-key
//! signature, a replayed nonce, or a malformed frame all fail closed
//! (REACH-6), and [`tunnel::TunnelRegistry`] now binds a name to the
//! *authenticated* `IK` that registered it — a different `IK` can never
//! hijack or overwrite it (REACH-7-style, extended from "per name" to "per
//! name, bound to the identity that proved it"). **What remains open:** the
//! control connection carrying that handshake, and the yamux session after
//! it, is still **plain, unencrypted TCP** — REACH-2's further requirement
//! that this leg run over a **libp2p Noise-secured transport** is not
//! implemented. An on-path attacker can observe or tamper with/drop control
//! frames (denial of service on that connection attempt); it **cannot**
//! forge a box's identity or hijack a name, because that requires a valid
//! Ed25519 signature under a key it does not hold. Do not present this crate
//! as "fully REACH-2 compliant" on that basis — key-authentication is closed,
//! transport confidentiality/integrity of the control leg is not. This crate
//! is materially more public-safe than the plain-TCP W4 cut (name
//! registration can no longer be claimed by any TCP client that merely
//! speaks the frame format), but is still not the profile's full target
//! posture until Noise lands on this leg.
//!
//! ## Fail-closed posture (REACH-6)
//!
//! A REACH adapter holds no certificate for any name it routes blind, so it can
//! complete no TLS handshake and emit no application-layer error. Its **only**
//! fail-closed action for an unregistered/expired name, an absent/unusable SNI, or a
//! non-allow-listed service is to **reset or close the TCP connection** — never a
//! guess, never a fallback that could intercept another name (REACH-6, SEC-1).

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::Descriptor;
use broker_economics::kinds::CoordinatorKind;
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};

pub mod auth;
pub mod ingress;
pub mod sni;
pub mod tunnel;

pub use auth::{AuthError, AuthenticatedRegistration, NonceRegistry};
pub use ingress::{AdapterServer, IngressError, TunnelAcceptError};
pub use tunnel::{RegistryError, TunnelError, TunnelHandle, TunnelRegistry};

/// The assurance level of a served name, fixed by who controls its DNS zone
/// (REACH-1a). This is the one place the adapter's blindness is `structural` vs
/// merely `declared`, so it is modeled explicitly rather than assumed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameKind {
    /// A name under a zone the adapter does not control (the box's own domain). A
    /// CAA record can bar the adapter from ever issuing a cert → blindness is
    /// `structural` (REACH-1a, RECOMMENDED profile).
    OwnDomain,
    /// A bare vanity in the adapter's own zone. The adapter is the zone's sole
    /// writer and can mint its own cert and MITM a non-pinning client → blindness
    /// is `declared`, a disclosed MITM residual (REACH-1a, §8), never `structural`.
    AdapterZoneVanity,
}

impl NameKind {
    /// The visibility an adapter MUST declare for a name of this kind (REACH-10).
    pub fn declared_visibility(self) -> ContentVisibility {
        let level = match self {
            NameKind::OwnDomain => AssuranceLevel::Structural,
            NameKind::AdapterZoneVanity => AssuranceLevel::Declared,
        };
        ContentVisibility::new(VisibilityClass::BlindRouting, level)
    }
}

/// A reachability-adapter instance, for conformance purposes. The transport
/// (`sni`/`tunnel`) attaches once implemented; this fixes the contract posture.
pub struct ReachabilityAdapter {
    descriptor: Descriptor,
    /// Whether this adapter meters bandwidth/connections (REACH-11).
    metered: bool,
}

impl ReachabilityAdapter {
    /// A blind-routing adapter serving names of `name_kind`. The descriptor's
    /// declared visibility MUST match the name kind (REACH-1a/-10); constructing it
    /// any other way would be the silent-downgrade violation COORD-5 guards.
    pub fn new(descriptor: Descriptor, metered: bool) -> Self {
        Self {
            descriptor,
            metered,
        }
    }
}

impl Coordinator for ReachabilityAdapter {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::ReachabilityAdapter
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // REACH-8: switching/dropping an adapter is a config change; the box keeps
        // its keypair, services, and — for an own domain — its name and cert.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // REACH-9: anyone with a VPS may run an adapter; the one disclosed exception
        // is that a public IP + reachable ingress is a scarce resource a NAT'd box
        // cannot conjure (the port-25 analog).
        SelfHost::ScarceReachabilityException
    }

    fn delivery_path_gate(&self) -> Gate {
        // REACH-2: the adapter gates on identity + rate and MUST NOT inspect, score,
        // re-rank, drop, or annotate tunneled content. It carries ciphertext it
        // cannot read — no delivery/authoritative path in the §4 sense.
        Gate::NoDeliveryPath
    }

    fn metering(&self) -> Metering {
        // REACH-11: if metered, signed usage receipts to the payer; else not metered.
        if self.metered {
            Metering::SignedReceiptsToPayer
        } else {
            Metering::NotMetered
        }
    }

    fn settlement(&self) -> Settlement {
        // REACH-11: prices are operator policy; settlement is an existing stablecoin
        // or fiat; REACH mints no protocol token.
        Settlement::ExistingAssetsOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_conformance::check;
    use broker_economics::{Cbor, IdentityKey};

    fn adapter(name_kind: NameKind, metered: bool) -> ReachabilityAdapter {
        // A real kotva-core keypair, not a placeholder `[7u8; 32]` array.
        let ik = IdentityKey::from_seed(&[7u8; 32]);
        ReachabilityAdapter::new(
            Descriptor {
                identity: ik.public(),
                kind: CoordinatorKind::ReachabilityAdapter,
                visibility: name_kind.declared_visibility(),
                policy: Cbor(Vec::new()),
                tariff: None,
            },
            metered,
        )
    }

    #[test]
    fn own_domain_adapter_is_structurally_blind_and_conformant() {
        let a = adapter(NameKind::OwnDomain, false);
        assert!(a.descriptor().visibility.is_verifiably_blind());
        let r = check(&a);
        assert!(r.is_conformant(), "{:?}", r.findings);
    }

    #[test]
    fn bare_vanity_is_declared_not_structural() {
        let a = adapter(NameKind::AdapterZoneVanity, true);
        let v = a.descriptor().visibility;
        // A real, disclosed MITM residual — must be surfaced as unverified (REACH-1a).
        assert!(!v.is_verifiably_blind());
        assert!(v.must_not_present_as_verified());
        // Still contract-conformant: the residual is declared, not hidden.
        let r = check(&a);
        assert!(r.is_conformant(), "{:?}", r.findings);
    }
}
