//! The gateway as a KOTVA coordinator kind (CONTRACT §5, the mail `adapter`).
//!
//! This is the one Wakala kind that is **not** content-blind: the legacy SMTP leg is unavoidably
//! plaintext, so it declares visibility `terminating` at assurance `declared` (CONTRACT §3.1). Every
//! other clause it satisfies like any coordinator — accountable, swappable (a DNS change, spec §7),
//! self-hostable behind the one disclosed scarce-reachability exception (a reputable IP + unblocked
//! port 25), and **authorize-never-classify**: it gates inbound on sender identity + rate
//! (SPF/DKIM/DMARC authentication + the pre-`DATA` anti-abuse gate) and does **not** run spam
//! scoring or ML content filters on the delivery path (CONTRACT §4, spec §7.11.4).

use broker_conformance::{Coordinator, Gate, LockIn, Metering, SelfHost, Settlement};
use broker_economics::descriptor::Descriptor;
use broker_economics::kinds::CoordinatorKind;
use broker_economics::kotva_core::{Cbor, IdentityKey};
use broker_economics::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};

/// The gateway's coordinator-contract posture. Constructed from the running gateway's operator
/// config; here it fixes the declared visibility and the four-clause posture that the COORD-1..8
/// harness checks.
pub struct GatewayCoordinator {
    descriptor: Descriptor,
    /// Whether this operator meters send volume (the `GatewayMeter`/`authz` seam). If so it MUST
    /// issue signed usage receipts to the payer (CONTRACT §6).
    metered: bool,
}

impl GatewayCoordinator {
    /// A gateway declaring the mandatory `terminating` visibility (the legacy leg is plaintext).
    ///
    /// `identity` is the gateway's own substrate IK (the domain-anchored attestation key, spec
    /// §7.2a). It is carried as the [`broker_economics::kotva_core`] placeholder until
    /// `broker-economics` adopts the real `kotva-core` identity type (the next wave now that the
    /// substrate tag exists) — the declared *posture* below is already authoritative.
    pub fn new(identity: IdentityKey, policy: Cbor, metered: bool) -> Self {
        Self {
            descriptor: Descriptor {
                identity,
                kind: CoordinatorKind::Gateway,
                // Terminating, declared: the operator promises correct handling of plaintext it can
                // structurally read — nothing makes this blind, and it is disclosed, never hidden.
                visibility: ContentVisibility::new(
                    VisibilityClass::Terminating,
                    AssuranceLevel::Declared,
                ),
                policy,
                tariff: None,
            },
            metered,
        }
    }
}

impl Coordinator for GatewayCoordinator {
    fn kind(&self) -> CoordinatorKind {
        CoordinatorKind::Gateway
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // Spec §7: a gateway is swapped with a DNS change; the user's keys, mailbox, and history
        // live at the edge. Zero data migration, zero identity change.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        // The disclosed exception: a reputable IP + unblocked port 25 is a scarce network resource
        // an ISP/host allocates (CONTRACT §2.3, THREAT-MODEL R-6).
        SelfHost::ScarceReachabilityException
    }

    fn delivery_path_gate(&self) -> Gate {
        // Authorization only: SPF/DKIM/DMARC authenticate the sender; the pre-`DATA` gate limits by
        // identity + rate. No spam scoring, ML filter, or content-basis drop on the delivery path
        // (CONTRACT §4, spec §7.11.4) — "wanted" is the recipient's judgement, at the edge.
        Gate::Authorization
    }

    fn metering(&self) -> Metering {
        if self.metered {
            Metering::SignedReceiptsToPayer
        } else {
            Metering::NotMetered
        }
    }

    fn settlement(&self) -> Settlement {
        // No token; prices are operator policy; settlement is an existing stablecoin or fiat.
        Settlement::ExistingAssetsOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_conformance::check;

    fn gw(metered: bool) -> GatewayCoordinator {
        GatewayCoordinator::new(IdentityKey([0x11; 32]), Cbor(Vec::new()), metered)
    }

    #[test]
    fn gateway_declares_terminating_and_is_contract_conformant() {
        let g = gw(false);
        assert_eq!(
            g.descriptor().visibility.class,
            VisibilityClass::Terminating
        );
        // Terminating is disclosed, not mispresented as verified-blind.
        assert!(!g.descriptor().visibility.is_verifiably_blind());
        assert!(!g.descriptor().visibility.must_not_present_as_verified());

        let r = check(&g);
        assert!(r.is_conformant(), "{:?}", r.findings);
    }

    #[test]
    fn a_metered_gateway_must_issue_receipts_and_still_conforms() {
        let r = check(&gw(true));
        assert!(r.is_conformant(), "{:?}", r.findings);
    }
}
