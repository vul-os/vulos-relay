//! Usage receipts — issuing a signed [`broker_economics::UsageReceipt`] for a billed operation,
//! and the payer-side [`ReceiptLog`] to verify what was issued (CONTRACT §6).
//!
//! ## The one-directional audit (CONTRACT §6, R-6) — read this before trusting a receipt
//!
//! `broker_economics::UsageReceipt::verify()` proves exactly one thing: **the coordinator really
//! signed this claimed operation.** It proves nothing else. In particular it does **not** prove:
//!
//! - that the operation actually happened as described (the coordinator could sign a receipt for
//!   an operation it fabricated);
//! - that the coordinator issued a receipt for *every* chargeable operation it performed (it
//!   could silently meter-and-charge without ever emitting a receipt for some of it).
//!
//! A payer who verifies every receipt they were handed has confirmed a **lower bound**: "at least
//! these signed claims are attributable to the coordinator." They have not confirmed an **upper
//! bound** — there is no cryptographic mechanism here (or in the CONTRACT) that lets a payer
//! prove a negative, i.e. that no unreceipted or fabricated charge exists. See
//! This crate's `one_directional_audit` test module makes this concrete: a receipt for an
//! operation with **no corresponding meter record** verifies successfully, identically to a
//! receipt for a real one.
//!
//! This is disclosed, not hidden (§6: "Disclosed, not hidden") — the honest ceiling is that
//! receipts make a coordinator's *claims* checkable, not the coordinator's *completeness*.
//! Closing that residual would need an independent, coordinator-external usage oracle (comparable
//! to the stake-verification seam in [`crate::stake`]) — out of scope for this crate, which
//! documents the gap rather than papering over it with a false sense of audit completeness.

use kotva_core::cbor::{as_bytes, as_text, as_u64, CborError, Cv, Fields};

use broker_economics::{Cbor, DescriptorError, IdentityKey, UsageReceipt};

use crate::meter::ResourceKind;
use crate::tariff::Bill;

/// Errors building/parsing a [`BilledOperation`] (distinct from [`DescriptorError`], which covers
/// the receipt's cryptographic signature — see [`ReceiptError::Signature`]).
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("malformed canonical CBOR: {0}")]
    BadEncoding(#[from] CborError),
    #[error("usage-receipt operation is malformed: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Signature(#[from] DescriptorError),
}

/// The concrete shape carried inside a [`broker_economics::UsageReceipt::operation`] payload for
/// this crate's billing model — what a payer decodes after `UsageReceipt::verify()` succeeds.
///
/// ## Wire layout (a `BilledOperation`'s `Cv`, before wrapping in `Cbor`/signing)
/// ```text
/// {
///   1: payer,          bstr  — the payer's identity public key
///   2: kind,           u64   — ResourceKind::wire_tag()
///   3: metered_units,  u64   — units metered for this kind, before the free allowance
///   4: billed_units,   u64   — units actually charged for (after the free allowance)
///   5: amount,         u64   — amount charged, in the tariff's currency minor unit
///   6: currency,       tstr  — the tariff's currency/asset code
///   7: sequence,       u64   — a per-payer monotonic counter the coordinator assigns; lets a
///                              payer notice a *gap* in the numbers they were handed, but a
///                              missing receipt and a skipped sequence number look identical from
///                              the payer's side (the coordinator controls both) — this does NOT
///                              close the one-directional-audit gap documented in the module doc,
///                              it only makes an *acknowledged* gap easier to notice
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BilledOperation {
    pub payer: Vec<u8>,
    pub kind: ResourceKind,
    pub metered_units: u64,
    pub billed_units: u64,
    pub amount: u64,
    pub currency: String,
    pub sequence: u64,
}

impl BilledOperation {
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (1, Cv::Bytes(self.payer.clone())),
            (2, Cv::U64(self.kind.wire_tag())),
            (3, Cv::U64(self.metered_units)),
            (4, Cv::U64(self.billed_units)),
            (5, Cv::U64(self.amount)),
            (6, Cv::Text(self.currency.clone())),
            (7, Cv::U64(self.sequence)),
        ])
    }

    fn from_cv(cv: Cv) -> Result<Self, ReceiptError> {
        let mut f = Fields::from_cv(cv)?;
        let payer = as_bytes(f.req(1)?)?;
        let kind = ResourceKind::from_wire_tag(as_u64(f.req(2)?)?)
            .ok_or(ReceiptError::Malformed("unknown resource-kind wire tag"))?;
        let metered_units = as_u64(f.req(3)?)?;
        let billed_units = as_u64(f.req(4)?)?;
        let amount = as_u64(f.req(5)?)?;
        let currency = as_text(f.req(6)?)?;
        let sequence = as_u64(f.req(7)?)?;
        f.deny_unknown()?;
        Ok(BilledOperation {
            payer,
            kind,
            metered_units,
            billed_units,
            amount,
            currency,
            sequence,
        })
    }

    /// Encode as the [`Cbor`] payload a [`UsageReceipt`] carries (built via `Cbor::from_cv`, per
    /// the module doc).
    pub fn to_cbor(&self) -> Cbor {
        Cbor::from_cv(&self.to_cv())
    }

    /// Sign this operation into a [`UsageReceipt`] — thin sugar over
    /// `UsageReceipt::sign(self.to_cbor(), ik)`; this crate does not reimplement signing.
    pub fn sign(&self, ik: &IdentityKey) -> UsageReceipt {
        UsageReceipt::sign(self.to_cbor(), ik)
    }

    /// Decode a [`BilledOperation`] out of a [`UsageReceipt`]'s `operation` payload, *without*
    /// checking the signature — callers MUST call [`UsageReceipt::verify`] first (fail-closed,
    /// SEC-1); this only decodes bytes that are already trusted.
    pub fn from_receipt(receipt: &UsageReceipt) -> Result<Self, ReceiptError> {
        Self::from_cv(receipt.operation.decode()?)
    }
}

/// A payer-side (or coordinator-side audit-trail) log of issued [`UsageReceipt`]s, with the
/// bookkeeping to turn a [`Bill`] into one [`BilledOperation`]-per-[`crate::meter::ResourceKind`]
/// line item, signed and appended.
///
/// This is the coordinator's issuance-side convenience type — a payer receiving receipts over
/// the wire can build their own `Vec<UsageReceipt>` and call [`ReceiptLog::verify_all`] on it
/// just the same; nothing here requires having *issued* the receipts to verify them.
#[derive(Clone, Debug, Default)]
pub struct ReceiptLog {
    receipts: Vec<UsageReceipt>,
    next_sequence: u64,
}

impl ReceiptLog {
    /// A fresh, empty log — sequence numbers start at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue one signed [`UsageReceipt`] per [`crate::tariff::LineItem`] in `bill`, for `payer`,
    /// appending each to the log and returning them in the same order as `bill.line_items`.
    /// Each receipt's `sequence` is this log's next counter value, incremented per receipt.
    pub fn issue_for_bill(
        &mut self,
        payer: &[u8],
        bill: &Bill,
        ik: &IdentityKey,
    ) -> Vec<UsageReceipt> {
        bill.line_items
            .iter()
            .map(|item| {
                let op = BilledOperation {
                    payer: payer.to_vec(),
                    kind: item.kind,
                    metered_units: item.metered_units,
                    billed_units: item.billed_units,
                    amount: item.amount,
                    currency: bill.currency.clone(),
                    sequence: self.next_sequence,
                };
                self.next_sequence += 1;
                let receipt = op.sign(ik);
                self.receipts.push(receipt.clone());
                receipt
            })
            .collect()
    }

    /// Issue one signed [`UsageReceipt`] for an arbitrary, caller-built [`BilledOperation`]
    /// (e.g. a single per-operation charge rather than a period roll-up) — the `sequence` field
    /// is the caller's responsibility in this path.
    pub fn issue(&mut self, op: &BilledOperation, ik: &IdentityKey) -> UsageReceipt {
        let receipt = op.sign(ik);
        self.receipts.push(receipt.clone());
        receipt
    }

    /// Every receipt issued/appended so far, in issuance order.
    pub fn receipts(&self) -> &[UsageReceipt] {
        &self.receipts
    }

    /// Verify every receipt in the log (payer-side check, CONTRACT §6). Fails closed on the
    /// **first** bad signature — see the module doc for what a passing result does and does not
    /// prove.
    pub fn verify_all(&self) -> Result<(), DescriptorError> {
        for r in &self.receipts {
            r.verify()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::InMemoryMeter;
    use crate::meter::Meter as _;
    use crate::tariff::TariffSchedule;
    use std::collections::BTreeMap;

    fn ik(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn schedule() -> TariffSchedule {
        let mut prices = BTreeMap::new();
        prices.insert(ResourceKind::BytesForwarded, 2);
        TariffSchedule {
            currency: "USD".to_string(),
            prices,
            free_allowance: BTreeMap::new(),
            period_seconds: None,
        }
    }

    #[test]
    fn billed_operation_round_trips_through_cbor() {
        let op = BilledOperation {
            payer: b"payer".to_vec(),
            kind: ResourceKind::Messages,
            metered_units: 10,
            billed_units: 10,
            amount: 100,
            currency: "USD".to_string(),
            sequence: 3,
        };
        let decoded = BilledOperation::from_cv(op.to_cbor().decode().unwrap()).unwrap();
        assert_eq!(decoded, op);
    }

    #[test]
    fn receipt_issued_for_a_real_bill_verifies() {
        let key = ik(1);
        let meter = InMemoryMeter::new();
        let payer = b"alice".to_vec();
        meter.record(&payer, ResourceKind::BytesForwarded, 50);
        let usage = meter.reset(&payer);
        let bill = schedule().evaluate(&usage).unwrap();

        let mut log = ReceiptLog::new();
        let receipts = log.issue_for_bill(&payer, &bill, &key);
        assert_eq!(receipts.len(), 1);
        assert!(log.verify_all().is_ok());

        let decoded = BilledOperation::from_receipt(&receipts[0]).unwrap();
        assert_eq!(decoded.payer, payer);
        assert_eq!(decoded.amount, 100); // 50 bytes * 2
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let key = ik(2);
        let op = BilledOperation {
            payer: b"bob".to_vec(),
            kind: ResourceKind::Connections,
            metered_units: 4,
            billed_units: 4,
            amount: 400,
            currency: "USD".to_string(),
            sequence: 0,
        };
        let mut log = ReceiptLog::new();
        let mut receipt = log.issue(&op, &key);
        // Tamper the amount after issuance/signing.
        let mut tampered_op = op.clone();
        tampered_op.amount = 1; // an attacker (or a bug) trying to shrink the charge after the fact
        receipt.operation = tampered_op.to_cbor();
        assert!(receipt.verify().is_err());
    }

    #[test]
    fn sequence_numbers_increment_across_issuances() {
        let key = ik(3);
        let payer = b"carol".to_vec();
        let mut prices = BTreeMap::new();
        prices.insert(ResourceKind::BytesForwarded, 1);
        prices.insert(ResourceKind::Connections, 1);
        let s = TariffSchedule {
            currency: "USD".to_string(),
            prices,
            free_allowance: BTreeMap::new(),
            period_seconds: None,
        };
        let mut usage = BTreeMap::new();
        usage.insert(ResourceKind::BytesForwarded, 10);
        usage.insert(ResourceKind::Connections, 1);
        let bill = s.evaluate(&usage).unwrap();

        let mut log = ReceiptLog::new();
        let receipts = log.issue_for_bill(&payer, &bill, &key);
        let sequences: Vec<u64> = receipts
            .iter()
            .map(|r| BilledOperation::from_receipt(r).unwrap().sequence)
            .collect();
        assert_eq!(sequences.len(), 2);
        assert_ne!(sequences[0], sequences[1]);
    }
}
