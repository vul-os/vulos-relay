//! The coordinator descriptor, tariff, and usage receipt (CONTRACT §2.1, §6).
//!
//! The descriptor is **discovery-only and self-asserted**: it carries the kind,
//! the policy, the declared content-visibility, and — where the coordinator charges
//! — a signed tariff. It carries **no** global reputation score, **no** price
//! ranking, and **no** stake field (CONTRACT §2.1). Reputation is measured locally
//! by each client from its own results; stake, where a kind needs it, is verified
//! on the settlement/staking rail, never asserted here (§6).
//!
//! Signing rides the real, tag-pinned `kotva-core` (`core-v0.2.0`): Ed25519 via
//! [`kotva_core::identity::IdentityKey`]/[`kotva_core::identity::verify_domain`], a
//! per-object-type domain-separation tag (§18.9), and canonical §18.1.1 deterministic
//! CBOR ([`kotva_core::cbor`]) as the signing preimage. This is real cryptography: a
//! forged or tampered descriptor/tariff/receipt fails [`SignedDescriptor::verify`]
//! / [`Tariff::verify`] / [`UsageReceipt::verify`].
//!
//! ## Wire layout — **ratified**, KOTVA spec §18.8a / §18.9
//!
//! This crate originally minted its own `EPHOR-v0/...` object family and DS tags before the
//! spec had ratified a wire form (see the superseded `[2026-07-23 wire]` entry in
//! `COORDINATION.md`'s "Ephor → Spec" section). The spec has since ratified §18.8a
//! (`CoordinatorDescriptor`/`Tariff`/`UsageReceipt`) and the §18.9 preimage table rows for all
//! three objects. **This module now implements that ratified layout exactly** — the two no
//! longer disagree. See the `[2026-07-24 wire]` entry in `COORDINATION.md` recording the fix.
//!
//! `kotva-core`/DMTAP conventions are followed throughout (integer-keyed canonical CBOR maps,
//! §18.1.1/§18.1.2, unknown keys rejected in every signed object).
//!
//! `CoordinatorDescriptor` (signing body — the map with key `7` omitted, §18.8a.1):
//! ```text
//! {
//!   1: suite,             u8     — signature-suite id (§18.1.4); see "Suite" below
//!   2: kind,               tstr   — CoordinatorKind::as_str() (CONTRACT §5 canonical string)
//!   3: identity,            bstr   — suite-0x01 Ed25519 public key (32 bytes)
//!   4: visibility,          map    — { 1: class tstr, 2: level tstr }
//!   5: policy,              bstr   — opaque operator policy (Cbor, may be empty)
//!   6: tariff,              map?   — OPTIONAL, present iff Some: { 1: suite, 2: identity bstr,
//!                                    3: schedule bstr, 4: valid_until ts?, 5: sig bstr }
//!   7: sig,                 bstr   — ONLY on the wire / in SignedDescriptor, never part of the
//!                                    signing body
//! }
//! ```
//! `visibility.class` ∈ `{"blind","blind-routing","terminating"}`,
//! `visibility.level` ∈ `{"structural","attested","declared"}` — the [`Display`]
//! strings already used by [`crate::visibility`].
//!
//! `Tariff` (signing body — the map with key `5` omitted, §18.8a.1):
//! ```text
//! {
//!   1: suite,             u8     — signature-suite id
//!   2: identity,           bstr   — the tariff's OWN signer (self-certifying, see below)
//!   3: schedule,            bstr   — opaque det_cbor price schedule
//!   4: valid_until,         ts?    — OPTIONAL; absent ⇒ no expiry (§18.8a.1, §26.10/§21)
//!   5: sig,                 bstr   — wire-only
//! }
//! ```
//!
//! `UsageReceipt` (signing body — the map with key `4` omitted, §18.8a.2):
//! ```text
//! {
//!   1: suite,             u8     — signature-suite id
//!   2: identity,            bstr   — own signer (self-certifying)
//!   3: operation,           bstr   — opaque det_cbor metered operation
//!   4: sig,                 bstr   — wire-only
//! }
//! ```
//!
//! `Tariff` and `UsageReceipt` are independently self-certifying (a receipt is
//! delivered directly to the payer, CONTRACT §6, and must be verifiable without
//! needing the coordinator's current descriptor), so each carries its own signer
//! `identity` rather than relying on an enclosing descriptor's.
//!
//! ## Suite — honest disclosure, do not paper over this (§1.1, §18.1.4)
//!
//! §18.1.4's normative suite table marks `0x01` (classical Ed25519) **LEGACY — verify only, MUST
//! NOT originate**, and `0x02` (Ed25519 + ML-DSA-65 hybrid) the **v0 REQUIRED originating suite**.
//! The pinned `kotva-core@core-v0.2.0` implements only `0x01` for this object family — its
//! [`kotva_core::suite::Suite::is_supported`] (the predicate the multi-suite `Identity` object
//! machinery uses) returns `true` only for [`kotva_core::suite::Suite::Classical`], and this
//! crate's own [`verify_domain`] call only knows the suite-`0x01` Ed25519 key/signature lengths
//! and the suite-`0x01` single-component preimage (§18.9: `M = DS-tag ‖ 0x00 ‖ body`, vs. the
//! composite `M' = DS-tag ‖ 0x00 ‖ u8(suite) ‖ body` a real `0x02` signer would need). **This crate
//! therefore emits `suite = 0x01` and can only verify `suite = 0x01` — it does not, and currently
//! cannot, originate the spec-required `0x02`.** That gap cannot be closed inside this repo; it
//! needs `kotva-core` to implement `0x02` end-to-end (PQ-hybrid keys/signatures for this object
//! family, not just the MOTE layer's [`kotva_core::pq`]). Recorded honestly, not silently
//! papered over, at the `SUITE` constant below, in `COORDINATION.md` ("Ephor → Spec",
//! `[2026-07-24 wire]`), and in `DECISIONS.md`.
//!
//! On decode, the `suite` field is **never** defaulted or ignored: an absent key is a hard
//! `MissingKey` reject (it is a MUST field, §18.8a.1/.2), and any value other than `0x01` —
//! whether an unregistered byte or one of the registered-but-unimplemented-here `0x02`-`0x05` —
//! is a hard [`DescriptorError::UnsupportedSuite`] reject (fail closed, §1.1/§18.1.4: "a decoder
//! MUST reject an object whose suite it does not implement... it MUST NOT guess").

use kotva_core::cbor::{self, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use kotva_core::identity::{verify_domain, IdentityError, IdentityKey};
use kotva_core::suite::Suite;
use kotva_core::TimestampMs;

use crate::kinds::CoordinatorKind;
use crate::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};

// Domain-separation tags (§18.9), an ASCII string terminated by one `0x00` byte, distinct per
// object type so a signature over one object can never be replayed as another. The signing
// preimage is `DS-tag ‖ 0x00 ‖ det_cbor(body)` for the single-component suite `0x01` this crate
// implements (`kotva_core::identity::sign_domain`/`verify_domain` concatenate `domain ‖ msg`, and
// these constants already carry the trailing NUL, so `msg` below is exactly `det_cbor(body)`).
//
// Ratified in KOTVA §18.9's preimage table (§18.8a) — these are the *spec's* tags, not this
// crate's invention (see the module doc's honest-disclosure section for what changed and why).
const DESCRIPTOR_DS: &[u8] = b"DMTAP-COORD-v0/descriptor\x00";
const TARIFF_DS: &[u8] = b"DMTAP-COORD-v0/tariff\x00";
const USAGE_RECEIPT_DS: &[u8] = b"DMTAP-COORD-v0/usage-receipt\x00";

/// The only signature suite this crate originates or can verify (classical Ed25519, §18.1.4).
/// **Honest disclosure:** §1.1/§18.1.4 mark `0x01` LEGACY (verify-only, MUST NOT originate) and
/// `0x02` the v0 REQUIRED originating suite; the pinned `kotva-core@core-v0.2.0` has no `0x02`
/// path for this object family, so this crate cannot conform to that MUST yet. See the module
/// doc's "Suite" section, `COORDINATION.md` ("Ephor → Spec", `[2026-07-24 wire]`), and
/// `DECISIONS.md`. This is a real, disclosed gap — not treated here as if `0x01` were conformant.
const SUITE: u8 = 0x01;

/// Errors signing or verifying a [`Descriptor`]/[`Tariff`]/[`UsageReceipt`]. Every variant is a
/// hard reject — callers MUST treat any error here as "not verified" (SEC-1 fail-closed), never
/// fall back to presenting the value as authentic.
#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("signature verification failed: {0}")]
    BadSignature(#[from] IdentityError),
    #[error("malformed canonical CBOR: {0}")]
    BadEncoding(#[from] CborError),
    #[error("descriptor is malformed: {0}")]
    Malformed(&'static str),
    /// Fail-closed on any suite this implementation does not verify (§1.1/§18.1.4) — an
    /// unregistered byte, or one of the registered-but-unimplemented-here `0x02`-`0x05`. Never
    /// defaulted, never guessed at.
    #[error(
        "unsupported/unrecognized signature suite {0:#04x} (fail closed, §1.1/§18.1.4) — this \
         implementation only verifies suite 0x01 (Ed25519); see COORDINATION.md \"Ephor → Spec\""
    )]
    UnsupportedSuite(u8),
    /// §18.8a.1 `Tariff.valid_until` / §26.10 / §21: a tariff presented past its own signed
    /// expiry is treated as expired and fails closed, not silently accepted as still-priced.
    #[error("tariff expired: valid_until={valid_until}ms has passed (now={now}ms), §18.8a.1")]
    Expired { valid_until: TimestampMs, now: TimestampMs },
}

/// Decode + validate a `suite` field (key 1 on every §18.8a object), failing closed on anything
/// this crate cannot verify. Never defaults, never ignores: callers reach this only after
/// `Fields::req` already turned an *absent* key into a hard `MissingKey` reject, so this function
/// only has to reject a *present-but-wrong* value.
fn require_supported_suite(cv: Cv) -> Result<(), DescriptorError> {
    let b = as_u8(cv)?;
    match Suite::from_u8(b) {
        // Only the classical suite has a verification path in this crate (see the module doc's
        // honest-disclosure section) — every other registered id (`0x02`-`0x05`, real PQ-hybrid/
        // reserved suites) is a real gap, not a decode error, but the outcome is the same reject.
        Some(Suite::Classical) => Ok(()),
        _ => Err(DescriptorError::UnsupportedSuite(b)),
    }
}

/// The current wall-clock time in ms since the Unix epoch, for [`Tariff::verify`]'s expiry check.
fn now_ms() -> TimestampMs {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as TimestampMs)
        .unwrap_or(0)
}

/// Opaque deterministic-CBOR bytes (RFC 8949 §4.2 / kotva-core §18.1.1). Used for the operator
/// policy, the tariff price schedule, and the usage-receipt operation — content this crate does
/// not interpret, only carries and signs over. An empty `Cbor` means "no payload" and is valid
/// (not itself required to be a decodable CBOR item); non-empty content SHOULD be built via
/// [`Cbor::from_cv`] so it rides the real canonical codec.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Cbor(pub Vec<u8>);

impl Cbor {
    /// An empty payload ("nothing declared").
    pub fn empty() -> Self {
        Cbor(Vec::new())
    }

    /// Encode a [`Cv`] value tree as canonical deterministic CBOR (kotva-core §18.1.1) and wrap
    /// the bytes — the way real (non-empty) policy/schedule/operation content should be built.
    pub fn from_cv(cv: &Cv) -> Self {
        Cbor(cbor::encode(cv))
    }

    /// Decode this payload as canonical deterministic CBOR. Fails closed on any non-canonical or
    /// malformed byte (kotva-core §18.1.1) — never guesses at a lenient re-encoding.
    pub fn decode(&self) -> Result<Cv, CborError> {
        cbor::decode(&self.0)
    }
}

/// A discovery-only, self-asserted coordinator descriptor (CONTRACT §2.1).
///
/// By construction this type has no field for a global score, a price rank, or a
/// stake amount — those are excluded so they cannot become ranking signals (§2.1).
///
/// `Descriptor` itself carries no signature — it is the plain data a coordinator constructs and
/// then signs with [`Descriptor::sign`], producing a [`SignedDescriptor`]. This mirrors
/// kotva-core's own `Identity`/`DeviceCert` shape (a `to_cv(include_sig: bool)` body + a
/// detached signature) and keeps the unsigned type trivially constructible for tests/posture
/// fixtures that don't need a real key.
#[derive(Clone, Debug)]
pub struct Descriptor {
    /// The coordinator's attested substrate identity: a suite-`0x01` (classical Ed25519) public
    /// key, 32 bytes (§2.1). kotva-core represents identity public keys as raw bytes throughout
    /// (`DeviceCert.ik`, gateway `Attestation.gateway_key`, …); this follows that convention
    /// rather than inventing a wrapper type kotva-core itself does not have.
    pub identity: Vec<u8>,
    /// The kind it operates as.
    pub kind: CoordinatorKind,
    /// Exactly one declared visibility class at one assurance level (§2.4, §3).
    pub visibility: ContentVisibility,
    /// Opaque operator policy (region, capabilities, contact) — self-asserted.
    pub policy: Cbor,
    /// A signed tariff, where the coordinator charges (§6). `None` = no charge.
    pub tariff: Option<Tariff>,
}

impl Descriptor {
    /// The §18.1.1-canonical CBOR value tree for this descriptor's signing body (sig omitted —
    /// see the module doc's wire layout, §18.8a.1).
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(SUITE as u64)),
            (2, Cv::Text(self.kind.as_str().to_string())),
            (3, Cv::Bytes(self.identity.clone())),
            (4, visibility_to_cv(self.visibility)),
            (5, Cv::Bytes(self.policy.0.clone())),
        ];
        if let Some(t) = &self.tariff {
            m.push((6, t.to_cv()));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, DescriptorError> {
        let mut f = Fields::from_cv(cv)?;
        require_supported_suite(f.req(1)?)?;
        let kind = CoordinatorKind::from_wire_str(&as_text(f.req(2)?)?)
            .ok_or(DescriptorError::Malformed("unknown coordinator kind"))?;
        let identity = as_bytes(f.req(3)?)?;
        let visibility = visibility_from_cv(f.req(4)?)?;
        let policy = Cbor(as_bytes(f.req(5)?)?);
        let tariff = f.take(6).map(Tariff::from_cv).transpose()?;
        f.deny_unknown()?;
        Ok(Descriptor {
            identity,
            kind,
            visibility,
            policy,
            tariff,
        })
    }

    /// The exact deterministic-CBOR signing body (§18.1.1): what [`Self::sign`] signs and
    /// [`SignedDescriptor::verify`] re-derives to check against the carried signature.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Sign this descriptor with the coordinator's real kotva-core identity (CONTRACT §2.1). The
    /// preimage is `DESCRIPTOR_DS ‖ det_cbor(self)` (§18.9), so a descriptor signature can never
    /// be replayed as a tariff, a usage receipt, or any other DMTAP/KOTVA signed object.
    ///
    /// `ik`'s public key SHOULD equal `self.identity` — the descriptor is self-certifying, like
    /// kotva-core's own `Identity` object signing its own embedded public key. A mismatch is not
    /// rejected here (the type doesn't know which is authoritative), but `verify()` always checks
    /// the signature against `self.identity`, so signing under a different key than the one
    /// declared produces a `SignedDescriptor` that fails its own verification.
    pub fn sign(&self, ik: &IdentityKey) -> SignedDescriptor {
        let sig = ik.sign_domain(DESCRIPTOR_DS, &self.signing_body());
        SignedDescriptor {
            descriptor: self.clone(),
            sig,
        }
    }
}

/// A [`Descriptor`] with its coordinator signature attached — the form that actually travels on
/// the wire / is published for discovery (CONTRACT §2.1).
#[derive(Clone, Debug)]
pub struct SignedDescriptor {
    pub descriptor: Descriptor,
    /// Ed25519 signature over `DESCRIPTOR_DS ‖ det_cbor(descriptor)`, by `descriptor.identity`.
    pub sig: Vec<u8>,
}

impl SignedDescriptor {
    /// Verify the signature against the descriptor's own declared identity (fail-closed, SEC-1:
    /// any error means NOT verified — callers must not present an `Err` result as authentic).
    pub fn verify(&self) -> Result<(), DescriptorError> {
        verify_domain(
            &self.descriptor.identity,
            DESCRIPTOR_DS,
            &self.descriptor.signing_body(),
            &self.sig,
        )
        .map_err(DescriptorError::from)
    }

    /// The full wire bytes: `{ 1..6 as Descriptor::to_cv, 7: sig }` (§18.8a.1).
    pub fn det_cbor(&self) -> Vec<u8> {
        let mut m = match self.descriptor.to_cv() {
            Cv::Map(m) => m,
            _ => unreachable!("Descriptor::to_cv always returns a Cv::Map"),
        };
        m.push((7, Cv::Bytes(self.sig.clone())));
        cbor::encode(&Cv::Map(m))
    }

    /// Decode + verify in one step: the fail-closed entry point for an untrusted wire descriptor.
    /// Returns the verified [`SignedDescriptor`] only if the signature checks out.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, DescriptorError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let sig = as_bytes(f.req(7)?)?;
        // Re-wrap the remaining fields (1..6) as the descriptor body for `Descriptor::from_cv`.
        let descriptor = Descriptor::from_cv(Cv::Map(f.into_pairs()))?;
        let signed = SignedDescriptor { descriptor, sig };
        signed.verify()?;
        Ok(signed)
    }
}

/// A signed price schedule (CONTRACT §6). The *numbers* are operator policy; the
/// *mechanism* (a signed, published tariff) is contract-normative.
///
/// Self-certifying (carries its own signer `identity`) so it can be handed to a relying party
/// independent of the descriptor that references it.
#[derive(Clone, Debug)]
pub struct Tariff {
    /// The coordinator identity that signed this schedule.
    pub identity: Vec<u8>,
    /// Opaque deterministic-CBOR price schedule.
    pub schedule: Cbor,
    /// §18.8a.1 key 4, OPTIONAL: end of this tariff's validity window (ms since Unix epoch).
    /// **Absent ⇒ no expiry.** Covered by `sig` like every other field — tampering with it
    /// invalidates the signature just like tampering with `schedule`.
    pub valid_until: Option<TimestampMs>,
    /// Ed25519 signature over `TARIFF_DS ‖ det_cbor(Tariff ∖ {sig})` (§18.9).
    pub sig: Vec<u8>,
}

impl Tariff {
    fn signing_body(identity: &[u8], schedule: &Cbor, valid_until: Option<TimestampMs>) -> Vec<u8> {
        let mut m = vec![
            (1u64, Cv::U64(SUITE as u64)),
            (2, Cv::Bytes(identity.to_vec())),
            (3, Cv::Bytes(schedule.0.clone())),
        ];
        if let Some(v) = valid_until {
            m.push((4, Cv::U64(v)));
        }
        cbor::encode(&Cv::Map(m))
    }

    /// Sign a price `schedule` with no expiry (`valid_until` absent — §18.8a.1 "absent ⇒ no
    /// expiry"). Back-compat entry point for callers that never need an expiring tariff; see
    /// [`Tariff::sign_with_validity`] to set one.
    pub fn sign(schedule: Cbor, ik: &IdentityKey) -> Tariff {
        Self::sign_with_validity(schedule, None, ik)
    }

    /// Sign a price `schedule` with an explicit `valid_until` (`None` ⇒ no expiry, §18.8a.1).
    pub fn sign_with_validity(
        schedule: Cbor,
        valid_until: Option<TimestampMs>,
        ik: &IdentityKey,
    ) -> Tariff {
        let identity = ik.public();
        let sig = ik.sign_domain(
            TARIFF_DS,
            &Self::signing_body(&identity, &schedule, valid_until),
        );
        Tariff {
            identity,
            schedule,
            valid_until,
            sig,
        }
    }

    /// Verify the tariff's own signature against its own carried identity (fail-closed), **and**
    /// that it has not expired (§18.8a.1, §26.10/§21): a `Tariff` presented past `valid_until`
    /// MUST be treated as expired and fails closed here rather than silently accepted as still
    /// priced. `valid_until` absent ⇒ no expiry, and this check never fires.
    pub fn verify(&self) -> Result<(), DescriptorError> {
        verify_domain(
            &self.identity,
            TARIFF_DS,
            &Self::signing_body(&self.identity, &self.schedule, self.valid_until),
            &self.sig,
        )?;
        if let Some(valid_until) = self.valid_until {
            let now = now_ms();
            if now > valid_until {
                return Err(DescriptorError::Expired { valid_until, now });
            }
        }
        Ok(())
    }

    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(SUITE as u64)),
            (2, Cv::Bytes(self.identity.clone())),
            (3, Cv::Bytes(self.schedule.0.clone())),
        ];
        if let Some(v) = self.valid_until {
            m.push((4, Cv::U64(v)));
        }
        m.push((5, Cv::Bytes(self.sig.clone())));
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, DescriptorError> {
        let mut f = Fields::from_cv(cv)?;
        require_supported_suite(f.req(1)?)?;
        let identity = as_bytes(f.req(2)?)?;
        let schedule = Cbor(as_bytes(f.req(3)?)?);
        let valid_until = f.take(4).map(as_u64).transpose()?;
        let sig = as_bytes(f.req(5)?)?;
        f.deny_unknown()?;
        Ok(Tariff {
            identity,
            schedule,
            valid_until,
            sig,
        })
    }
}

/// A signed usage receipt delivered directly to the paying party (CONTRACT §6).
///
/// The audit is **one-directional** (§6, R-6): a receipt lets the payer confirm a
/// claimed operation was real; it cannot disconfirm one the coordinator fabricated
/// or silently omitted. Disclosed here, not hidden.
///
/// Self-certifying like [`Tariff`]: it carries the issuing coordinator's `identity`, so the
/// payer can verify it in isolation, without a live descriptor lookup.
#[derive(Clone, Debug)]
pub struct UsageReceipt {
    /// The coordinator identity that issued (signed) this receipt.
    pub identity: Vec<u8>,
    /// The metered operation, deterministic-CBOR.
    pub operation: Cbor,
    /// Ed25519 signature over `USAGE_RECEIPT_DS ‖ det_cbor(UsageReceipt ∖ {sig})` (§18.9).
    pub sig: Vec<u8>,
}

impl UsageReceipt {
    fn signing_body(identity: &[u8], operation: &Cbor) -> Vec<u8> {
        cbor::encode(&Cv::Map(vec![
            (1, Cv::U64(SUITE as u64)),
            (2, Cv::Bytes(identity.to_vec())),
            (3, Cv::Bytes(operation.0.clone())),
        ]))
    }

    /// Sign a metered `operation` with the coordinator's real kotva-core identity.
    pub fn sign(operation: Cbor, ik: &IdentityKey) -> UsageReceipt {
        let identity = ik.public();
        let sig = ik.sign_domain(USAGE_RECEIPT_DS, &Self::signing_body(&identity, &operation));
        UsageReceipt {
            identity,
            operation,
            sig,
        }
    }

    /// Verify the receipt's own signature against its own carried identity (fail-closed). This
    /// is the payer-side check (§6): it proves the coordinator really signed this claimed
    /// operation, never that the coordinator omitted no other operation (one-directional audit).
    pub fn verify(&self) -> Result<(), DescriptorError> {
        verify_domain(
            &self.identity,
            USAGE_RECEIPT_DS,
            &Self::signing_body(&self.identity, &self.operation),
            &self.sig,
        )
        .map_err(DescriptorError::from)
    }
}

// --- Visibility <-> CBOR (module-private: `ContentVisibility`'s wire shape is this module's
// concern, not `crate::visibility`'s — that module stays substrate-independent). ---

fn visibility_to_cv(v: ContentVisibility) -> Cv {
    let class = match v.class {
        VisibilityClass::Blind => "blind",
        VisibilityClass::BlindRouting => "blind-routing",
        VisibilityClass::Terminating => "terminating",
    };
    let level = match v.level {
        AssuranceLevel::Structural => "structural",
        AssuranceLevel::Attested => "attested",
        AssuranceLevel::Declared => "declared",
    };
    Cv::Map(vec![
        (1, Cv::Text(class.to_string())),
        (2, Cv::Text(level.to_string())),
    ])
}

fn visibility_from_cv(cv: Cv) -> Result<ContentVisibility, DescriptorError> {
    let mut f = Fields::from_cv(cv)?;
    let class = match as_text(f.req(1)?)?.as_str() {
        "blind" => VisibilityClass::Blind,
        "blind-routing" => VisibilityClass::BlindRouting,
        "terminating" => VisibilityClass::Terminating,
        _ => return Err(DescriptorError::Malformed("unknown visibility class")),
    };
    let level = match as_text(f.req(2)?)?.as_str() {
        "structural" => AssuranceLevel::Structural,
        "attested" => AssuranceLevel::Attested,
        "declared" => AssuranceLevel::Declared,
        _ => return Err(DescriptorError::Malformed("unknown assurance level")),
    };
    f.deny_unknown()?;
    Ok(ContentVisibility::new(class, level))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ik(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn descriptor(identity: Vec<u8>) -> Descriptor {
        Descriptor {
            identity,
            kind: CoordinatorKind::Relay,
            visibility: ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural),
            policy: Cbor::empty(),
            tariff: None,
        }
    }

    #[test]
    fn descriptor_signs_and_verifies() {
        let key = ik(1);
        let d = descriptor(key.public());
        let signed = d.sign(&key);
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn tampered_descriptor_fails_verification() {
        let key = ik(2);
        let d = descriptor(key.public());
        let mut signed = d.sign(&key);
        // Flip a field after signing — the signature must no longer match.
        signed.descriptor.policy = Cbor(vec![0xaa]);
        assert!(signed.verify().is_err());
    }

    #[test]
    fn tampered_signature_bytes_fail_verification() {
        let key = ik(3);
        let d = descriptor(key.public());
        let mut signed = d.sign(&key);
        signed.sig[0] ^= 0xff;
        assert!(signed.verify().is_err());
    }

    #[test]
    fn signature_does_not_verify_under_a_different_identity() {
        let signer = ik(4);
        let other = ik(5);
        // The descriptor claims `other`'s identity but is actually signed by `signer` — a forged
        // "who signed this" claim. Verification MUST fail (checked against the claimed identity).
        let d = descriptor(other.public());
        let signed = d.sign(&signer);
        assert!(signed.verify().is_err());
    }

    #[test]
    fn descriptor_round_trips_through_det_cbor() {
        let key = ik(6);
        let mut d = descriptor(key.public());
        d.tariff = Some(Tariff::sign(Cbor::from_cv(&Cv::U64(42)), &key));
        let signed = d.sign(&key);
        let bytes = signed.det_cbor();
        let decoded = SignedDescriptor::from_det_cbor(&bytes).expect("verified round trip");
        assert_eq!(decoded.descriptor.identity, signed.descriptor.identity);
        assert_eq!(decoded.sig, signed.sig);
    }

    #[test]
    fn tariff_signs_and_verifies_and_detects_tamper() {
        let key = ik(7);
        let t = Tariff::sign(Cbor::from_cv(&Cv::Text("1 unit = $0.001".into())), &key);
        assert!(t.verify().is_ok());
        let mut tampered = t.clone();
        tampered.schedule = Cbor(vec![0x01]);
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn usage_receipt_signs_and_verifies_and_detects_tamper() {
        let key = ik(8);
        let r = UsageReceipt::sign(Cbor::from_cv(&Cv::U64(7)), &key);
        assert!(r.verify().is_ok());
        let mut tampered = r.clone();
        tampered.operation = Cbor(vec![0x02]);
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn declared_level_blind_claim_is_still_surfaced_as_unverified() {
        // A descriptor's CRYPTOGRAPHIC signature verifying says only "this coordinator really
        // published this descriptor" — it says nothing about whether a `declared`-assurance
        // blindness claim is itself trustworthy (CONTRACT §3.4). The two are independent axes:
        // a perfectly-signed descriptor can still declare a claim that MUST NOT be presented to a
        // user as verified.
        let key = ik(9);
        let mut d = descriptor(key.public());
        d.visibility = ContentVisibility::new(VisibilityClass::BlindRouting, AssuranceLevel::Declared);
        let signed = d.sign(&key);
        assert!(signed.verify().is_ok(), "the signature itself is genuinely valid");
        assert!(
            signed.descriptor.visibility.must_not_present_as_verified(),
            "a declared-level blind claim must still not be shown as verified, even though the \
             descriptor carrying it is authentically signed"
        );
        assert!(!signed.descriptor.visibility.is_verifiably_blind());
    }

    // --- Wire-break proof: the OLD (pre-ratification) layout/DS-tags must NOT verify under the
    // NEW (§18.8a-ratified) code. This is intentional and load-bearing, not a regression: it
    // proves the two wire forms are genuinely incompatible, not accidentally byte-compatible. ---

    const OLD_DESCRIPTOR_DS: &[u8] = b"EPHOR-v0/coordinator-descriptor\x00";
    const OLD_TARIFF_DS: &[u8] = b"EPHOR-v0/tariff\x00";
    const OLD_USAGE_RECEIPT_DS: &[u8] = b"EPHOR-v0/usage-receipt\x00";

    #[test]
    fn old_layout_descriptor_bytes_do_not_verify_under_new_code() {
        let key = ik(10);
        // Reconstruct exactly the OLD signing body this file used to produce: no `suite` field,
        // and the OLD key numbering (1: kind, 2: identity, 3: visibility, 4: policy, 5: tariff?).
        let old_body = Cv::Map(vec![
            (1u64, Cv::Text("relay".to_string())),
            (2, Cv::Bytes(key.public())),
            (
                3,
                Cv::Map(vec![
                    (1, Cv::Text("blind".to_string())),
                    (2, Cv::Text("structural".to_string())),
                ]),
            ),
            (4, Cv::Bytes(Vec::new())),
        ]);
        let old_sig = key.sign_domain(OLD_DESCRIPTOR_DS, &cbor::encode(&old_body));
        // Wire it up the OLD way: old body + `6: sig` (the old sig-field key number).
        let mut wire = match old_body {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        wire.push((6, Cv::Bytes(old_sig)));
        let old_wire_bytes = cbor::encode(&Cv::Map(wire));

        // The NEW decoder expects `suite` at key 1 (a `u8`) and `sig` at key 7 — old bytes have
        // `kind` (a `tstr`) at key 1 and no key 7 at all, so this MUST fail closed, not silently
        // decode into something that then happens to verify.
        let result = SignedDescriptor::from_det_cbor(&old_wire_bytes);
        assert!(
            result.is_err(),
            "an old-layout descriptor must not verify under the new §18.8a-ratified decoder"
        );
    }

    #[test]
    fn old_layout_tariff_does_not_verify_under_new_code() {
        let key = ik(11);
        let schedule = Cbor::from_cv(&Cv::Text("old schedule".into()));
        // OLD Tariff signing body: `{1: identity, 2: schedule}`, no suite, no valid_until.
        let old_body = cbor::encode(&Cv::Map(vec![
            (1u64, Cv::Bytes(key.public())),
            (2, Cv::Bytes(schedule.0.clone())),
        ]));
        let old_sig = key.sign_domain(OLD_TARIFF_DS, &old_body);
        let old_style_tariff = Tariff {
            identity: key.public(),
            schedule,
            valid_until: None,
            sig: old_sig,
        };
        // The new `verify()` recomputes the NEW DS-tag + NEW body (with the `suite` field) — the
        // old signature was over neither, so this MUST fail closed.
        assert!(
            old_style_tariff.verify().is_err(),
            "an old-layout tariff signature must not verify under the new preimage/DS-tag"
        );
    }

    #[test]
    fn old_layout_usage_receipt_does_not_verify_under_new_code() {
        let key = ik(12);
        let operation = Cbor::from_cv(&Cv::U64(99));
        // OLD UsageReceipt signing body: `{1: identity, 2: operation}`, no suite.
        let old_body = cbor::encode(&Cv::Map(vec![
            (1u64, Cv::Bytes(key.public())),
            (2, Cv::Bytes(operation.0.clone())),
        ]));
        let old_sig = key.sign_domain(OLD_USAGE_RECEIPT_DS, &old_body);
        let old_style_receipt = UsageReceipt {
            identity: key.public(),
            operation,
            sig: old_sig,
        };
        assert!(
            old_style_receipt.verify().is_err(),
            "an old-layout usage receipt signature must not verify under the new preimage/DS-tag"
        );
    }

    // --- suite handling: fail closed, never default, never ignore ---

    #[test]
    fn descriptor_missing_suite_is_rejected() {
        let key = ik(13);
        // Build a wire map with NO key 1 at all (an absent MUST field).
        let body = Cv::Map(vec![
            (2u64, Cv::Text("relay".to_string())),
            (3, Cv::Bytes(key.public())),
            (
                4,
                Cv::Map(vec![
                    (1, Cv::Text("blind".to_string())),
                    (2, Cv::Text("structural".to_string())),
                ]),
            ),
            (5, Cv::Bytes(Vec::new())),
        ]);
        let mut wire = match body {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        wire.push((7, Cv::Bytes(vec![0u8; 64])));
        let bytes = cbor::encode(&Cv::Map(wire));
        let err = SignedDescriptor::from_det_cbor(&bytes).expect_err("absent suite must reject");
        assert!(matches!(err, DescriptorError::BadEncoding(_)));
    }

    #[test]
    fn descriptor_unsupported_suite_is_rejected() {
        let key = ik(14);
        let d = descriptor(key.public());
        let mut m = match d.to_cv() {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        // Flip the (well-formed) suite byte to the v0-REQUIRED PQ-hybrid suite `0x02` — this
        // implementation does not support it and MUST reject, never silently accept or downgrade.
        m[0] = (1, Cv::U64(0x02));
        let tampered_body = cbor::encode(&Cv::Map(m.clone()));
        let sig = key.sign_domain(DESCRIPTOR_DS, &tampered_body);
        m.push((7, Cv::Bytes(sig)));
        let bytes = cbor::encode(&Cv::Map(m));
        let err = SignedDescriptor::from_det_cbor(&bytes).expect_err("suite 0x02 must reject");
        assert!(matches!(err, DescriptorError::UnsupportedSuite(0x02)));
    }

    #[test]
    fn descriptor_unrecognized_suite_byte_is_rejected() {
        let key = ik(15);
        let d = descriptor(key.public());
        let mut m = match d.to_cv() {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        // A totally unregistered suite id (not even in the spec's §18.1.4 table).
        m[0] = (1, Cv::U64(0xfe));
        let tampered_body = cbor::encode(&Cv::Map(m.clone()));
        let sig = key.sign_domain(DESCRIPTOR_DS, &tampered_body);
        m.push((7, Cv::Bytes(sig)));
        let bytes = cbor::encode(&Cv::Map(m));
        let err = SignedDescriptor::from_det_cbor(&bytes).expect_err("suite 0xfe must reject");
        assert!(matches!(err, DescriptorError::UnsupportedSuite(0xfe)));
    }

    #[test]
    fn descriptor_unknown_map_key_is_rejected() {
        let key = ik(16);
        let d = descriptor(key.public());
        let mut m = match d.to_cv() {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        // Smuggle in an undefined key (e.g. a would-be reputation/price-rank field, exactly what
        // §2.1 says this object structurally excludes) — a decoder MUST reject it (§18.1.2).
        m.push((99, Cv::U64(1)));
        let tampered_body = cbor::encode(&Cv::Map(m.clone()));
        let sig = key.sign_domain(DESCRIPTOR_DS, &tampered_body);
        m.push((7, Cv::Bytes(sig)));
        let bytes = cbor::encode(&Cv::Map(m));
        let err = SignedDescriptor::from_det_cbor(&bytes).expect_err("unknown key must reject");
        assert!(matches!(err, DescriptorError::BadEncoding(CborError::UnknownKey(99))));
    }

    #[test]
    fn tariff_missing_suite_is_rejected() {
        let key = ik(17);
        // Wire tariff bytes with NO key 1: {2: identity, 3: schedule, 5: sig}.
        let body = Cv::Map(vec![
            (2u64, Cv::Bytes(key.public())),
            (3, Cv::Bytes(vec![0xaa])),
        ]);
        let mut wire = match body {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        wire.push((5, Cv::Bytes(vec![0u8; 64])));
        let cv = Cv::Map(wire);
        let err = Tariff::from_cv(cv).expect_err("absent suite must reject");
        assert!(matches!(err, DescriptorError::BadEncoding(_)));
    }

    #[test]
    fn tariff_unsupported_suite_is_rejected() {
        let key = ik(18);
        let t = Tariff::sign(Cbor::from_cv(&Cv::Text("x".into())), &key);
        let mut m = match t.to_cv() {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        m[0] = (1, Cv::U64(0x02));
        let cv = Cv::Map(m);
        let err = Tariff::from_cv(cv).expect_err("suite 0x02 tariff must reject");
        assert!(matches!(err, DescriptorError::UnsupportedSuite(0x02)));
    }

    #[test]
    fn usage_receipt_unsupported_suite_is_rejected_at_the_wire_level() {
        // UsageReceipt has no `from_cv`/wire decoder in this crate today (it is never carried as
        // a standalone wire object here — see the module doc), so exercise the same fail-closed
        // rule the way it's actually reachable: `require_supported_suite` directly.
        let err = require_supported_suite(Cv::U64(0x02)).expect_err("suite 0x02 must reject");
        assert!(matches!(err, DescriptorError::UnsupportedSuite(0x02)));
        let err2 = require_supported_suite(Cv::U64(0x01));
        assert!(err2.is_ok(), "suite 0x01 (classical) must be accepted");
    }

    // --- valid_until: absent ⇒ no expiry; past ⇒ expired/fail closed ---

    #[test]
    fn tariff_valid_until_absent_means_no_expiry() {
        let key = ik(19);
        let t = Tariff::sign(Cbor::from_cv(&Cv::Text("no expiry".into())), &key);
        assert_eq!(t.valid_until, None);
        assert!(t.verify().is_ok(), "absent valid_until must never expire");
    }

    #[test]
    fn tariff_valid_until_in_the_past_is_expired_and_fails_closed() {
        let key = ik(20);
        let long_ago: TimestampMs = 1_000; // 1970-01-01T00:00:01Z — long past for any real clock.
        let t = Tariff::sign_with_validity(
            Cbor::from_cv(&Cv::Text("expired".into())),
            Some(long_ago),
            &key,
        );
        let err = t.verify().expect_err("a tariff past its valid_until must fail closed");
        assert!(matches!(err, DescriptorError::Expired { valid_until: 1_000, .. }));
    }

    #[test]
    fn tariff_valid_until_in_the_future_still_verifies() {
        let key = ik(21);
        let far_future: TimestampMs = now_ms() + 1_000 * 60 * 60 * 24 * 365 * 50; // +50 years
        let t = Tariff::sign_with_validity(
            Cbor::from_cv(&Cv::Text("not yet expired".into())),
            Some(far_future),
            &key,
        );
        assert!(t.verify().is_ok());
    }

    // --- tariff/receipt verify standalone against their OWN identity, never an enclosing
    // descriptor's ---

    #[test]
    fn tariff_verifies_standalone_against_its_own_identity_not_the_enclosing_descriptor() {
        let tariff_signer = ik(22);
        let descriptor_signer = ik(23);
        let tariff = Tariff::sign(Cbor::from_cv(&Cv::Text("2 USD/GB".into())), &tariff_signer);

        let mut d = descriptor(descriptor_signer.public());
        d.tariff = Some(tariff.clone());
        let signed = d.sign(&descriptor_signer);

        // The descriptor (signed by a DIFFERENT key than the tariff) verifies on its own terms.
        assert!(signed.verify().is_ok());
        // The embedded tariff independently verifies against ITS OWN identity, not the
        // descriptor's — a relying party handed just the tariff (e.g. directly by the operator)
        // never needs the descriptor to check it.
        assert!(signed.descriptor.tariff.as_ref().unwrap().verify().is_ok());
        assert_ne!(
            signed.descriptor.tariff.as_ref().unwrap().identity,
            signed.descriptor.identity,
            "sanity: the tariff and descriptor really are signed by different identities here"
        );
        // And the standalone tariff value (never embedded in any descriptor) verifies identically.
        assert!(tariff.verify().is_ok());
    }

    #[test]
    fn usage_receipt_verifies_standalone_against_its_own_identity() {
        let receipt_signer = ik(24);
        let r = UsageReceipt::sign(Cbor::from_cv(&Cv::U64(123)), &receipt_signer);
        assert_eq!(r.identity, receipt_signer.public());
        assert!(r.verify().is_ok());
        // A receipt claiming a different identity than its actual signer must not verify (mirrors
        // the descriptor-level `signature_does_not_verify_under_a_different_identity` case).
        let other = ik(25);
        let mut forged = r.clone();
        forged.identity = other.public();
        assert!(forged.verify().is_err());
    }
}
