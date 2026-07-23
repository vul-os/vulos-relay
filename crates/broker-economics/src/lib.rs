//! # broker-economics
//!
//! The shared model every Wakala coordinator kind is built on: the
//! **content-visibility** property (a checkable class × assurance level), the
//! **coordinator kinds** table, and the discovery-only **descriptor / tariff /
//! usage-receipt** shapes — the machinery of `coordinator/CONTRACT.md` §2–§6.
//!
//! The point of the whole broker contract is that "some centralization, done
//! safely" is a *checkable property*, not a hope. This crate is where that
//! property is made into types: a coordinator declares exactly one
//! [`ContentVisibility`], the crate says when that declaration is
//! [verifiable](AssuranceLevel::is_verifiable) and when it MUST NOT be presented as
//! verified, and a [`Descriptor`] structurally cannot carry a global score, a price
//! rank, or a stake field.
//!
//! Substrate-typed parts — signing, deterministic CBOR, the real descriptor bytes —
//! ride the tag-pinned `kotva-core` (`core-v0.2.0`, HANDOVER §Guardrails-1): see
//! [`descriptor`] for the signing/verification API and the wire layout. This crate
//! re-exports [`kotva_core::identity::IdentityKey`] at the top level as
//! [`IdentityKey`] so consumers construct real identities without a separate
//! `kotva-core` dependency of their own.

pub mod descriptor;
pub mod kinds;
pub mod visibility;

pub use descriptor::{Cbor, Descriptor, DescriptorError, SignedDescriptor, Tariff, UsageReceipt};
pub use kinds::CoordinatorKind;
pub use kotva_core::identity::IdentityKey;
pub use visibility::{AssuranceLevel, ContentVisibility, VisibilityClass};
