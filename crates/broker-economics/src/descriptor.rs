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
//! per-object-type domain-separation tag (SEC-2, `kotva_core::identity`'s own
//! `*_DS` convention), and canonical §18.1.1 deterministic CBOR
//! ([`kotva_core::cbor`]) as the signing preimage. This is real cryptography: a
//! forged or tampered descriptor/tariff/receipt fails [`SignedDescriptor::verify`]
//! / [`Tariff::verify`] / [`UsageReceipt::verify`].
//!
//! ## Wire layout (not yet spec-ratified — see `COORDINATION.md` "Wakala → Spec")
//!
//! `kotva-core`/DMTAP conventions are followed (integer-keyed canonical CBOR maps,
//! §18.1.1/§18.1.2, unknown keys rejected). This crate mints its own object types
//! and DS tags (`WAKALA-v0/...`) rather than DMTAP-core ones, since the coordinator
//! descriptor is a Wakala/CONTRACT.md concept, not a DMTAP-core wire object.
//!
//! `Descriptor` (signing body — the map with key `6` omitted):
//! ```text
//! {
//!   1: kind,              tstr   — CoordinatorKind::as_str()
//!   2: identity,          bstr   — suite-0x01 Ed25519 public key (32 bytes)
//!   3: visibility,        map    — { 1: class tstr, 2: level tstr }
//!   4: policy,            bstr   — opaque operator policy (Cbor, may be empty)
//!   5: tariff,            map?   — OPTIONAL, present iff Some: { 1: identity bstr,
//!                                  2: schedule bstr, 3: sig bstr }
//!   6: sig,               bstr   — ONLY on the wire / in SignedDescriptor, never
//!                                  part of the signing body
//! }
//! ```
//! `visibility.class` ∈ `{"blind","blind-routing","terminating"}`,
//! `visibility.level` ∈ `{"structural","attested","declared"}` — the [`Display`]
//! strings already used by [`crate::visibility`].
//!
//! `Tariff` and `UsageReceipt` are independently self-certifying (a receipt is
//! delivered directly to the payer, CONTRACT §6, and must be verifiable without
//! needing the coordinator's current descriptor), so each carries its own signer
//! `identity` rather than relying on an enclosing descriptor's.

use kotva_core::cbor::{self, as_bytes, as_text, CborError, Cv, Fields};
use kotva_core::identity::{verify_domain, IdentityError, IdentityKey};

use crate::kinds::CoordinatorKind;
use crate::visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};

// Domain-separation tags (SEC-2 style, matching kotva-core's own `identity.rs` convention: an
// ASCII string terminated by one `0x00` byte, distinct per object type so a signature over one
// object can never be replayed as another). The signing preimage is `DS-tag ‖ det_cbor(body)`.
const DESCRIPTOR_DS: &[u8] = b"WAKALA-v0/coordinator-descriptor\x00";
const TARIFF_DS: &[u8] = b"WAKALA-v0/tariff\x00";
const USAGE_RECEIPT_DS: &[u8] = b"WAKALA-v0/usage-receipt\x00";

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
    /// see the module doc's wire layout).
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Text(self.kind.as_str().to_string())),
            (2, Cv::Bytes(self.identity.clone())),
            (3, visibility_to_cv(self.visibility)),
            (4, Cv::Bytes(self.policy.0.clone())),
        ];
        if let Some(t) = &self.tariff {
            m.push((5, t.to_cv()));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, DescriptorError> {
        let mut f = Fields::from_cv(cv)?;
        let kind = CoordinatorKind::from_wire_str(&as_text(f.req(1)?)?)
            .ok_or(DescriptorError::Malformed("unknown coordinator kind"))?;
        let identity = as_bytes(f.req(2)?)?;
        let visibility = visibility_from_cv(f.req(3)?)?;
        let policy = Cbor(as_bytes(f.req(4)?)?);
        let tariff = f.take(5).map(Tariff::from_cv).transpose()?;
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
    /// preimage is `DESCRIPTOR_DS ‖ det_cbor(self)` (SEC-2/SEC-3), so a descriptor signature can
    /// never be replayed as a tariff, a usage receipt, or any other DMTAP/Wakala signed object.
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

    /// The full wire bytes: `{ 1..5 as Descriptor::to_cv, 6: sig }`.
    pub fn det_cbor(&self) -> Vec<u8> {
        let mut m = match self.descriptor.to_cv() {
            Cv::Map(m) => m,
            _ => unreachable!("Descriptor::to_cv always returns a Cv::Map"),
        };
        m.push((6, Cv::Bytes(self.sig.clone())));
        cbor::encode(&Cv::Map(m))
    }

    /// Decode + verify in one step: the fail-closed entry point for an untrusted wire descriptor.
    /// Returns the verified [`SignedDescriptor`] only if the signature checks out.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, DescriptorError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let sig = as_bytes(f.req(6)?)?;
        // Re-wrap the remaining fields (1..5) as the descriptor body for `Descriptor::from_cv`.
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
    /// Ed25519 signature over `TARIFF_DS ‖ det_cbor({identity, schedule})`.
    pub sig: Vec<u8>,
}

impl Tariff {
    fn signing_body(identity: &[u8], schedule: &Cbor) -> Vec<u8> {
        cbor::encode(&Cv::Map(vec![
            (1, Cv::Bytes(identity.to_vec())),
            (2, Cv::Bytes(schedule.0.clone())),
        ]))
    }

    /// Sign a price `schedule` with the coordinator's real kotva-core identity.
    pub fn sign(schedule: Cbor, ik: &IdentityKey) -> Tariff {
        let identity = ik.public();
        let sig = ik.sign_domain(TARIFF_DS, &Self::signing_body(&identity, &schedule));
        Tariff {
            identity,
            schedule,
            sig,
        }
    }

    /// Verify the tariff's own signature against its own carried identity (fail-closed).
    pub fn verify(&self) -> Result<(), DescriptorError> {
        verify_domain(
            &self.identity,
            TARIFF_DS,
            &Self::signing_body(&self.identity, &self.schedule),
            &self.sig,
        )
        .map_err(DescriptorError::from)
    }

    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::Bytes(self.identity.clone())),
            (2, Cv::Bytes(self.schedule.0.clone())),
            (3, Cv::Bytes(self.sig.clone())),
        ])
    }

    fn from_cv(cv: Cv) -> Result<Self, DescriptorError> {
        let mut f = Fields::from_cv(cv)?;
        let identity = as_bytes(f.req(1)?)?;
        let schedule = Cbor(as_bytes(f.req(2)?)?);
        let sig = as_bytes(f.req(3)?)?;
        f.deny_unknown()?;
        Ok(Tariff {
            identity,
            schedule,
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
    /// Ed25519 signature over `USAGE_RECEIPT_DS ‖ det_cbor({identity, operation})`.
    pub sig: Vec<u8>,
}

impl UsageReceipt {
    fn signing_body(identity: &[u8], operation: &Cbor) -> Vec<u8> {
        cbor::encode(&Cv::Map(vec![
            (1, Cv::Bytes(identity.to_vec())),
            (2, Cv::Bytes(operation.0.clone())),
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
}
