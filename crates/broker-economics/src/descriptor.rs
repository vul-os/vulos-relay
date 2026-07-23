//! The coordinator descriptor, tariff, and usage receipt (CONTRACT §2.1, §6).
//!
//! The descriptor is **discovery-only and self-asserted**: it carries the kind,
//! the policy, the declared content-visibility, and — where the coordinator charges
//! — a signed tariff. It carries **no** global reputation score, **no** price
//! ranking, and **no** stake field (CONTRACT §2.1). Reputation is measured locally
//! by each client from its own results; stake, where a kind needs it, is verified
//! on the settlement/staking rail, never asserted here (§6).
//!
//! Signing + deterministic-CBOR encoding ride [`crate::kotva_core`] and are stubbed
//! until that crate is tagged. This module fixes the *shape* and the invariants; it
//! does no cryptography yet.

use crate::kinds::CoordinatorKind;
use crate::kotva_core::{Cbor, IdentityKey, Signature};
use crate::visibility::ContentVisibility;

/// A discovery-only, self-asserted coordinator descriptor (CONTRACT §2.1).
///
/// By construction this type has no field for a global score, a price rank, or a
/// stake amount — those are excluded so they cannot become ranking signals (§2.1).
#[derive(Clone, Debug)]
pub struct Descriptor {
    /// The coordinator's attested substrate identity (§2.1).
    pub identity: IdentityKey,
    /// The kind it operates as.
    pub kind: CoordinatorKind,
    /// Exactly one declared visibility class at one assurance level (§2.4, §3).
    pub visibility: ContentVisibility,
    /// Opaque operator policy (region, capabilities, contact) — self-asserted.
    pub policy: Cbor,
    /// A signed tariff, where the coordinator charges (§6). `None` = no charge.
    pub tariff: Option<Tariff>,
}

/// A signed price schedule (CONTRACT §6). The *numbers* are operator policy; the
/// *mechanism* (a signed, published tariff) is contract-normative.
#[derive(Clone, Debug)]
pub struct Tariff {
    /// Opaque deterministic-CBOR price schedule.
    pub schedule: Cbor,
    /// Operator signature over the schedule. Stub until kotva-core (see module note).
    pub sig: Signature,
}

/// A signed usage receipt delivered directly to the paying party (CONTRACT §6).
///
/// The audit is **one-directional** (§6, R-6): a receipt lets the payer confirm a
/// claimed operation was real; it cannot disconfirm one the coordinator fabricated
/// or silently omitted. Disclosed here, not hidden.
#[derive(Clone, Debug)]
pub struct UsageReceipt {
    /// The metered operation, deterministic-CBOR.
    pub operation: Cbor,
    /// Coordinator signature over the operation. Stub until kotva-core.
    pub sig: Signature,
}
