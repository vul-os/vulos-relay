//! # broker-billing
//!
//! The CONTRACT §6 economics, made concrete: metering, tariff evaluation, signed usage receipts,
//! and a pluggable no-token settlement seam — built on top of the real signed
//! [`broker_economics::Tariff`]/[`broker_economics::UsageReceipt`] types from W3
//! (`broker-economics/src/descriptor.rs`). This crate does not reinvent signing, canonical CBOR,
//! or identity: it reuses `broker-economics`/`kotva-core` throughout and adds the *policy* layer
//! CONTRACT §6 leaves to the operator — metering, a concrete tariff-schedule shape, and a
//! settlement/stake seam.
//!
//! ## Module map
//! - [`meter`] — kind-agnostic usage counting per payer ([`meter::ResourceKind`], [`meter::Meter`],
//!   [`meter::InMemoryMeter`]).
//! - [`tariff`] — a concrete [`tariff::TariffSchedule`] shape built via
//!   `broker_economics::Cbor::from_cv`, and [`tariff::TariffSchedule::evaluate`] turning usage
//!   into an itemized [`tariff::Bill`].
//! - [`receipt`] — issuing signed [`broker_economics::UsageReceipt`]s for a [`tariff::Bill`]
//!   ([`receipt::ReceiptLog`]), and — importantly — the documented **one-directional audit**
//!   residual (CONTRACT §6, R-6): read `receipt`'s module doc before treating "receipts verify"
//!   as "billing is honest."
//! - [`settlement`] — the [`settlement::SettlementRail`] trait (charge/settle in an *existing*
//!   asset — no token, ever) plus the one reference adapter, [`settlement::InMemoryLedger`], which
//!   is explicitly a mock.
//! - [`stake`] — the [`stake::StakeVerifier`] seam for staked kinds (`arbiter`, `oracle`), with
//!   the CONTRACT §6 fail-closed default ([`stake::NoStakeRail`]): an unverifiable stake claim
//!   MUST be treated as no stake.
//!
//! ## What this crate is, and is not
//! This is a **model + seams**: real, testable metering/tariff/receipt/ledger logic, wired to the
//! real signing primitives — not a live payment integration. [`settlement::InMemoryLedger`] never
//! talks to a chain or a payment processor; [`settlement::PaymentRequired`]/`PaymentProof` are
//! data shapes for an x402-style HTTP 402 challenge, not an HTTP server or a facilitator client;
//! [`stake::NoStakeRail`] never queries a chain. Every one of those is a `trait` a real,
//! operator-supplied adapter implements. See each module's doc for the specific honesty
//! disclosure.
//!
//! No protocol token exists anywhere in this crate, by construction: every amount is
//! denominated in a caller-supplied currency/asset string (DIRECTION §5), never a Wakala-minted
//! unit, and [`meter`]/[`tariff`] never produce or consume anything resembling one.

#![forbid(unsafe_code)]

pub mod meter;
pub mod receipt;
pub mod settlement;
pub mod stake;
pub mod tariff;

pub use meter::{InMemoryMeter, Meter, ResourceKind};
pub use receipt::{BilledOperation, ReceiptError, ReceiptLog};
pub use settlement::{InMemoryLedger, LedgerError, PaymentProof, PaymentRequired, SettlementRail};
pub use stake::{NoStakeRail, StakeVerifier};
pub use tariff::{Bill, BillingError, LineItem, TariffSchedule};

#[cfg(test)]
mod one_directional_audit {
    //! CONTRACT §6, R-6, made concrete: a signed usage receipt lets the payer confirm a claimed
    //! operation was real; it CANNOT disconfirm one the coordinator fabricated or silently
    //! omitted. This module demonstrates both halves end-to-end, using the real
    //! `broker_economics` signing path (not a stand-in) — the residual is a property of the
    //! *model* (what verification proves), not a bug in this crate's crypto.

    use broker_economics::IdentityKey;
    use std::collections::BTreeMap;

    use crate::meter::{InMemoryMeter, Meter, ResourceKind};
    use crate::receipt::{BilledOperation, ReceiptLog};
    use crate::tariff::TariffSchedule;

    fn schedule() -> TariffSchedule {
        let mut prices = BTreeMap::new();
        prices.insert(ResourceKind::BytesForwarded, 1);
        TariffSchedule {
            currency: "USD".to_string(),
            prices,
            free_allowance: BTreeMap::new(),
            period_seconds: None,
        }
    }

    #[test]
    fn a_receipt_for_a_real_metered_operation_verifies() {
        // Half one: verification DOES confirm a claimed operation was real, in the sense that a
        // payer who did the metered work and was handed a matching receipt can check it.
        let key = IdentityKey::from_seed(&[0x11; 32]);
        let payer = b"payer".to_vec();
        let meter = InMemoryMeter::new();
        meter.record(&payer, ResourceKind::BytesForwarded, 200);
        let usage = meter.reset(&payer);
        let bill = schedule().evaluate(&usage).unwrap();

        let mut log = ReceiptLog::new();
        let receipts = log.issue_for_bill(&payer, &bill, &key);
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].verify().is_ok());
    }

    #[test]
    fn fabricated_operation_cannot_be_disconfirmed_by_verification() {
        // Half two — the residual: the coordinator's identity key can sign a receipt for an
        // operation that has NO corresponding record in the meter at all (nothing was ever
        // `record`ed for this payer). From the payer's side, calling `.verify()` on this receipt
        // succeeds — identically to the real-operation case above. `verify()` proves "the
        // coordinator signed this claim," never "this claim corresponds to a real event." A
        // payer holding only this receipt has no cryptographic way to tell it apart from a
        // legitimate one, and no way to prove the coordinator *also* silently metered-and-charged
        // some other operation it issued no receipt for at all.
        let key = IdentityKey::from_seed(&[0x22; 32]);
        let payer = b"payer".to_vec();

        // Note: no `InMemoryMeter` involved at all — the coordinator is simply asserting this
        // happened.
        let fabricated = BilledOperation {
            payer: payer.clone(),
            kind: ResourceKind::BytesForwarded,
            metered_units: 999_999, // never metered anywhere
            billed_units: 999_999,
            amount: 999_999,
            currency: "USD".to_string(),
            sequence: 0,
        };

        let mut log = ReceiptLog::new();
        let receipt = log.issue(&fabricated, &key);

        // The signature check passes — this is the honest, documented residual, not a bug:
        // `verify()` can only ever attest "the coordinator's key produced this," never "and this
        // really happened."
        assert!(
            receipt.verify().is_ok(),
            "a fabricated operation's receipt verifies exactly like a real one's — that is the \
             documented one-directional-audit residual (CONTRACT §6, R-6), not a bypass of the \
             signature check"
        );

        // And the flip side of the same residual: an operation the coordinator metered but
        // simply never issued a receipt for is indistinguishable, from the payer's side, from an
        // operation that never happened — there is nothing to call `.verify()` on at all. A
        // payer's `ReceiptLog` can only attest to what it was actually handed.
        let silently_charged_but_unreceipted = InMemoryMeter::new();
        silently_charged_but_unreceipted.record(&payer, ResourceKind::BytesForwarded, 50);
        // ... the coordinator could bill this, keep the money, and never call `log.issue*` for
        // it. No verification the payer can run detects the omission; only an external audit
        // (out of this crate's/the CONTRACT's scope) could.
        assert_eq!(
            silently_charged_but_unreceipted.usage(&payer).get(&ResourceKind::BytesForwarded),
            Some(&50),
            "usage exists on the coordinator's own meter with nothing forcing a receipt to be \
             issued for it — the other direction of the same one-directional-audit gap"
        );
    }
}
