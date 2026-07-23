//! The content-visibility property (CONTRACT §3).
//!
//! This is the checkable property at the core of the coordinator contract: every
//! intermediary declares exactly one [`VisibilityClass`] at one [`AssuranceLevel`]
//! and MUST surface it to users. Advertising one class while operating another is
//! non-conformant misrepresentation, not policy (CONTRACT §2.4).

use core::fmt;

/// What an intermediary can read of the traffic it carries — declare exactly one
/// (CONTRACT §3.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum VisibilityClass {
    /// Forwards/holds ciphertext, holds no key that decrypts the payload, reads
    /// neither content nor routing beyond what the wire exposes. E.g. mesh relay
    /// (Circuit Relay v2), mix, TURN-over-SFrame.
    Blind,
    /// Cannot read the payload; sees routing metadata (envelope, SNI, addresses,
    /// size, timing). E.g. SNI-passthrough ingress, buffer/mailbox, SFU
    /// media-relay (RFC 9605).
    BlindRouting,
    /// Terminates encryption and sees plaintext — a deliberate, disclosed trust
    /// boundary. E.g. legacy mail gateway, TLS-terminating ingress.
    Terminating,
}

/// How blindness is guaranteed (CONTRACT §3.3). "Blind" is not one strength.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AssuranceLevel {
    /// The role *has no key* — E2E encryption makes reading impossible.
    /// Strongest; provable.
    Structural,
    /// The role runs in a TEE that proves the code only forwards and holds no
    /// key. Hardware-trust — and it trades operator-trust for chip-vendor-trust
    /// with a side-channel history (CONTRACT §3.4 / THREAT-MODEL R-4), disclosed
    /// not trustless.
    Attested,
    /// The operator *promises* it is blind; nothing structurally prevents
    /// cheating. Honest-trust only.
    Declared,
}

impl AssuranceLevel {
    /// Whether the blindness claim is *checkable* by a relying party. Only
    /// `structural` (no key) and `attested` (TEE) are verifiable; a `declared`
    /// claim is an intent, never a proof (CONTRACT §3.4, THREAT-MODEL SEC-4/R-4).
    ///
    /// The honest residual: this proves a coordinator's architecture and intent,
    /// never that a `declared`-level operator is not secretly logging.
    pub fn is_verifiable(self) -> bool {
        matches!(self, AssuranceLevel::Structural | AssuranceLevel::Attested)
    }
}

/// A declared content-visibility: exactly one class at one assurance level
/// (CONTRACT §2.4). This is what a descriptor carries and a client surfaces.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ContentVisibility {
    pub class: VisibilityClass,
    pub level: AssuranceLevel,
}

impl ContentVisibility {
    pub const fn new(class: VisibilityClass, level: AssuranceLevel) -> Self {
        Self { class, level }
    }

    /// A `blind`/`blind-routing` claim whose blindness a relying party can check
    /// (structural or attested). A `terminating` boundary is honestly disclosed,
    /// not "verified blind", so it is never a *verified-blind* claim.
    pub fn is_verifiably_blind(self) -> bool {
        !matches!(self.class, VisibilityClass::Terminating) && self.level.is_verifiable()
    }

    /// Whether presenting this to a user as a *verified* blind claim would be a
    /// SEC-4 violation. A `declared`-level blind claim MUST NOT be shown as
    /// verified (CONTRACT §3.4).
    pub fn must_not_present_as_verified(self) -> bool {
        !matches!(self.class, VisibilityClass::Terminating) && !self.level.is_verifiable()
    }
}

impl fmt::Display for VisibilityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VisibilityClass::Blind => "blind",
            VisibilityClass::BlindRouting => "blind-routing",
            VisibilityClass::Terminating => "terminating",
        })
    }
}

impl fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AssuranceLevel::Structural => "structural",
            AssuranceLevel::Attested => "attested",
            AssuranceLevel::Declared => "declared",
        })
    }
}

impl fmt::Display for ContentVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} / {}", self.class, self.level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_structural_and_attested_are_verifiable() {
        assert!(AssuranceLevel::Structural.is_verifiable());
        assert!(AssuranceLevel::Attested.is_verifiable());
        assert!(!AssuranceLevel::Declared.is_verifiable());
    }

    #[test]
    fn declared_blind_must_not_be_shown_as_verified() {
        // A bare adapter-zone vanity: blind-routing, but only `declared` (REACH-1a).
        let v = ContentVisibility::new(VisibilityClass::BlindRouting, AssuranceLevel::Declared);
        assert!(!v.is_verifiably_blind());
        assert!(v.must_not_present_as_verified());
    }

    #[test]
    fn structural_blind_routing_is_verifiable() {
        // An own-domain SNI-passthrough adapter: the box holds the TLS key (REACH-1a).
        let v = ContentVisibility::new(VisibilityClass::BlindRouting, AssuranceLevel::Structural);
        assert!(v.is_verifiably_blind());
        assert!(!v.must_not_present_as_verified());
    }

    #[test]
    fn terminating_is_never_a_verified_blind_claim() {
        let v = ContentVisibility::new(VisibilityClass::Terminating, AssuranceLevel::Declared);
        assert!(!v.is_verifiably_blind());
        // It is disclosed as terminating, not mispresented as blind.
        assert!(!v.must_not_present_as_verified());
    }
}
