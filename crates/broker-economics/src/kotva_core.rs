//! The `kotva-core` seam — a placeholder until the crate is carved + tagged.
//!
//! `kotva-core` is the pinned substrate crate (MOTE + envelope, identity/naming,
//! PUB, SYNC, signing + DS-tags, deterministic CBOR, crypto), carved from envoir's
//! `dmtap-*` crates. Per the isango guardrail (HANDOVER §Guardrails-1) Wakala pins
//! a tag and never builds against a moving core, so until that tag lands every
//! substrate-typed value routes through the stubs here.
//!
//! When the tag exists this whole module is deleted and its names come from the
//! real crate:
//!
//! ```ignore
//! // Cargo.toml
//! kotva-core = { git = "https://github.com/vul-os/kotva", tag = "core-vX.Y.Z" }
//! ```
//!
//! Nothing here does real cryptography. A stub `Signature` is *not* a signature;
//! code that must actually verify a descriptor MUST wait for the real crate rather
//! than treat a stub as verified (SEC-1 fail-closed — never present unverified as
//! verified).

/// A substrate identity key (the coordinator's attested identity, CONTRACT §2.1).
/// Placeholder for `kotva_core::IdentityKey`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct IdentityKey(pub [u8; 32]);

/// A detached signature over a domain-separated preimage (SEC-2). Placeholder for
/// `kotva_core::Signature`. **Not** a real signature — see the module note.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature(pub [u8; 64]);

/// Deterministic-CBOR bytes (RFC 8949 §4.2, SEC-3). Placeholder for the wire
/// encoding kotva-core owns.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Cbor(pub Vec<u8>);

/// Marker: this value's authenticity has NOT been checked because the substrate
/// verifier is not yet wired. Any surface that would present a coordinator claim
/// as verified MUST treat an `Unverified` value as unverified (SEC-1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Unverified;
