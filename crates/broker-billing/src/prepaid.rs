//! Prepaid credit — the **primary** billing model (founder decision, see `DECISIONS.md`): a
//! payer tops up credit ahead of use, and metered usage is debited against that credit as it
//! accrues. CONTRACT §6 / DIRECTION §5.
//!
//! ## Why prepaid is primary
//!
//! - **Zero lock-in** (CONTRACT §2.2): a prepaid balance is just a number a payer can stop
//!   adding to; there is no standing agreement to unwind, no invoice to cancel, no credit check
//!   to fail. Switching coordinators costs nothing but the unspent balance, which
//!   [`PrepaidLedger::refund`] can hand back.
//! - **Anonymous-but-accountable** (CONTRACT §4's allowed anti-abuse list, SEC-7): a prepaid
//!   balance is exactly a "postage" token — it does not require binding a payer's real-world
//!   identity to a monthly billing relationship the way a subscription/card-on-file does.
//! - **Matches the metering model** (§6): usage is metered continuously; debiting continuously
//!   against a standing balance is the natural match, rather than accumulating an unbounded tab
//!   an operator must then collect after the fact.
//!
//! ## Wakala holds no funds — "credit claims," not custody
//!
//! [`PrepaidLedger`] is bookkeeping only. [`PrepaidLedger::top_up`] credits a balance because the
//! caller asserts a `funding_ref` — a pointer to whatever ALREADY happened on a real
//! [`crate::settlement::SettlementRail`] (a deposit, a verified on-rail receipt reference; see
//! `crates/broker-billing-patala` for a real adapter that only calls this after independently
//! verifying a rail receipt). This type never receives, holds, or moves money itself — exactly
//! the same non-custodial split `crate::settlement`'s module doc describes for
//! [`crate::settlement::InMemoryLedger`], and exactly what "patala holds no funds, takes no cut"
//! means for the reference rail adapter. A caller who calls `top_up` without first confirming the
//! funding actually landed is the one taking on risk — this type cannot protect against that any
//! more than [`crate::receipt::ReceiptLog`] can protect against a fabricated receipt (see that
//! module's one-directional-audit doc); it is disclosed here for the same reason.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use broker_economics::{IdentityKey, UsageReceipt};

use crate::receipt::ReceiptLog;
use crate::tariff::Bill;

/// Where a payer's prepaid position currently sits relative to
/// [`PrepaidLedger`]'s configured low-balance threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BillingState {
    /// Balance is above the low-balance threshold.
    Ok,
    /// Balance is positive but at or below the low-balance threshold — a top-up is due soon.
    LowBalance,
    /// Balance is exactly zero — no further metered usage can be debited until a top-up lands.
    Exhausted,
}

/// Everything that can go wrong against a [`PrepaidLedger`]. Every variant is a refusal: none of
/// them ever result in a balance changing (fail-closed, mirroring
/// [`crate::settlement::LedgerError`]).
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PrepaidError {
    /// The bill's currency does not match this ledger's configured currency — refused rather
    /// than silently cross-charged.
    #[error("bill currency {bill_currency} does not match this ledger's currency {ledger_currency}")]
    CurrencyMismatch { bill_currency: String, ledger_currency: String },
    /// The payer's balance is insufficient to cover the bill — [`BillingState::Exhausted`] (or
    /// simply not enough left), never partially debited.
    #[error("insufficient prepaid credit: payer {payer:?} has {balance} {currency}, bill was {amount}")]
    Exhausted { payer: Vec<u8>, balance: u64, amount: u64, currency: String },
    /// A refund request exceeded the payer's current balance — refused, never clamped silently.
    #[error("refund amount {amount} exceeds current balance {balance} for payer {payer:?}")]
    RefundExceedsBalance { payer: Vec<u8>, amount: u64, balance: u64 },
}

/// A record of one accepted [`PrepaidLedger::top_up`] — the credit-claim bookkeeping entry, not a
/// receipt of funds actually moving (see module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopUpRecord {
    pub payer: Vec<u8>,
    pub amount: u64,
    pub currency: String,
    /// The caller's pointer to the on-rail evidence backing this claim (a settlement-rail
    /// transaction reference, a patala receipt reference, ...). Opaque to this crate.
    pub funding_ref: String,
    /// Monotonic per-ledger transaction sequence (ledger-internal bookkeeping only, distinct from
    /// [`crate::receipt::BilledOperation::sequence`]).
    pub tx_seq: u64,
}

/// A record of one accepted [`PrepaidLedger::debit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebitRecord {
    pub payer: Vec<u8>,
    pub amount: u64,
    pub currency: String,
    pub tx_seq: u64,
}

/// A record of one accepted [`PrepaidLedger::refund`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundRecord {
    pub payer: Vec<u8>,
    pub amount: u64,
    pub currency: String,
    pub tx_seq: u64,
}

/// A snapshot of one payer's prepaid position, as returned by [`PrepaidLedger::account`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditAccount {
    pub payer: Vec<u8>,
    pub currency: String,
    pub balance: u64,
    pub low_balance_threshold: u64,
}

impl CreditAccount {
    /// This account's [`BillingState`], derived purely from `balance` vs.
    /// `low_balance_threshold` — see [`BillingState`]'s own docs for the exact boundary.
    pub fn state(&self) -> BillingState {
        if self.balance == 0 {
            BillingState::Exhausted
        } else if self.balance <= self.low_balance_threshold {
            BillingState::LowBalance
        } else {
            BillingState::Ok
        }
    }
}

/// The prepaid ledger: top-up credit claims metered against usage. One ledger tracks every
/// payer's balance in a single `currency` (a [`Bill`] in any other currency is refused —
/// [`PrepaidError::CurrencyMismatch`] — rather than silently converted; currency conversion is
/// out of scope). See the module doc for the custody-free framing.
pub struct PrepaidLedger {
    currency: String,
    low_balance_threshold: u64,
    balances: Mutex<BTreeMap<Vec<u8>, u64>>,
    top_ups: Mutex<Vec<TopUpRecord>>,
    debits: Mutex<Vec<DebitRecord>>,
    refunds: Mutex<Vec<RefundRecord>>,
    next_tx_seq: Mutex<u64>,
    /// funding_refs already credited — top_up is idempotent on this, so a *replayed* funding
    /// confirmation (e.g. a retried payment webhook) credits at most once. A funding_ref is a
    /// pointer to one real on-rail funding event and is unique to it; seeing it twice is a replay,
    /// not two fundings. Mirrors `broker-billing-patala`'s `credited_references` dedup.
    credited_refs: Mutex<BTreeSet<String>>,
}

impl PrepaidLedger {
    /// A fresh, empty ledger tracking balances in `currency`, flagging
    /// [`BillingState::LowBalance`] once a payer's balance drops to or below
    /// `low_balance_threshold`.
    pub fn new(currency: impl Into<String>, low_balance_threshold: u64) -> Self {
        PrepaidLedger {
            currency: currency.into(),
            low_balance_threshold,
            balances: Mutex::new(BTreeMap::new()),
            top_ups: Mutex::new(Vec::new()),
            debits: Mutex::new(Vec::new()),
            refunds: Mutex::new(Vec::new()),
            next_tx_seq: Mutex::new(0),
            credited_refs: Mutex::new(BTreeSet::new()),
        }
    }

    /// This ledger's tracked currency.
    pub fn currency(&self) -> &str {
        &self.currency
    }

    fn next_seq(&self) -> u64 {
        let mut seq = self.next_tx_seq.lock().expect("prepaid ledger mutex poisoned");
        let v = *seq;
        *seq += 1;
        v
    }

    /// Credit `payer`'s balance by `amount` (in this ledger's currency), on the strength of
    /// `funding_ref` — see the module doc: this call trusts the caller that `funding_ref` really
    /// corresponds to funding that landed on a real rail; it does not itself verify anything.
    /// Always succeeds (a top-up can never be "refused" the way a debit can).
    pub fn top_up(&self, payer: &[u8], amount: u64, funding_ref: impl Into<String>) -> TopUpRecord {
        let fref = funding_ref.into();
        // Idempotent on funding_ref. Hold `credited_refs` across the whole credit so the dedup
        // check, the balance credit, and the record push are one atomic step: a replayed
        // funding_ref (e.g. a retried payment webhook) does NOT credit again — it returns the
        // original record unchanged. Guards against double-crediting a single funding event.
        let mut credited = self.credited_refs.lock().expect("prepaid ledger mutex poisoned");
        if credited.contains(&fref) {
            drop(credited);
            return self
                .top_ups
                .lock()
                .expect("prepaid ledger mutex poisoned")
                .iter()
                .find(|r| r.funding_ref == fref)
                .cloned()
                .expect("a credited funding_ref always has its original top-up record");
        }

        let mut balances = self.balances.lock().expect("prepaid ledger mutex poisoned");
        let entry = balances.entry(payer.to_vec()).or_insert(0);
        *entry = entry.saturating_add(amount);
        drop(balances);

        let record = TopUpRecord {
            payer: payer.to_vec(),
            amount,
            currency: self.currency.clone(),
            funding_ref: fref.clone(),
            tx_seq: self.next_seq(),
        };
        self.top_ups.lock().expect("prepaid ledger mutex poisoned").push(record.clone());
        credited.insert(fref);
        drop(credited);
        record
    }

    /// `payer`'s current balance (`0` if never topped up).
    pub fn balance(&self, payer: &[u8]) -> u64 {
        self.balances
            .lock()
            .expect("prepaid ledger mutex poisoned")
            .get(payer)
            .copied()
            .unwrap_or(0)
    }

    /// A snapshot of `payer`'s full prepaid position, including [`BillingState`].
    pub fn account(&self, payer: &[u8]) -> CreditAccount {
        CreditAccount {
            payer: payer.to_vec(),
            currency: self.currency.clone(),
            balance: self.balance(payer),
            low_balance_threshold: self.low_balance_threshold,
        }
    }

    /// `payer`'s current [`BillingState`] — sugar over `self.account(payer).state()`.
    pub fn state(&self, payer: &[u8]) -> BillingState {
        self.account(payer).state()
    }

    /// Debit `bill.amount` from `payer`'s balance for metered usage already evaluated by
    /// [`crate::tariff::TariffSchedule::evaluate`]. Fails closed
    /// ([`PrepaidError::Exhausted`]/[`PrepaidError::CurrencyMismatch`]) with the balance left
    /// **unchanged** on any error — a payer is never driven negative.
    pub fn debit(&self, payer: &[u8], bill: &Bill) -> Result<DebitRecord, PrepaidError> {
        if bill.currency != self.currency {
            return Err(PrepaidError::CurrencyMismatch {
                bill_currency: bill.currency.clone(),
                ledger_currency: self.currency.clone(),
            });
        }
        let mut balances = self.balances.lock().expect("prepaid ledger mutex poisoned");
        let balance = balances.get(payer).copied().unwrap_or(0);
        if balance < bill.amount {
            return Err(PrepaidError::Exhausted {
                payer: payer.to_vec(),
                balance,
                amount: bill.amount,
                currency: self.currency.clone(),
            });
        }
        balances.insert(payer.to_vec(), balance - bill.amount);
        drop(balances);

        let record = DebitRecord {
            payer: payer.to_vec(),
            amount: bill.amount,
            currency: self.currency.clone(),
            tx_seq: self.next_seq(),
        };
        self.debits.lock().expect("prepaid ledger mutex poisoned").push(record.clone());
        Ok(record)
    }

    /// [`Self::debit`], then — only on success — issue one signed [`UsageReceipt`] per
    /// [`Bill`] line item via `log` (CONTRACT §6: "where a coordinator meters, [it] issues signed
    /// usage receipts directly to the payer" — COORD-7). On a debit failure, no receipt is
    /// issued, matching the fail-closed rule: a payer is never handed a receipt for usage that
    /// was not actually paid for.
    pub fn debit_and_receipt(
        &self,
        payer: &[u8],
        bill: &Bill,
        log: &mut ReceiptLog,
        ik: &IdentityKey,
    ) -> Result<(DebitRecord, Vec<UsageReceipt>), PrepaidError> {
        let record = self.debit(payer, bill)?;
        let receipts = log.issue_for_bill(payer, bill, ik);
        Ok((record, receipts))
    }

    /// Refund up to `amount` of `payer`'s remaining balance back out of this ledger's
    /// bookkeeping. This is the custody-free counterpart of [`Self::top_up`]: it only decrements
    /// the local credit-claim balance and returns a [`RefundRecord`] — actually moving money back
    /// to the payer is entirely the settlement/payment rail's job (never this crate's), exactly
    /// as `top_up`'s `funding_ref` never itself moved money in. Fails closed
    /// ([`PrepaidError::RefundExceedsBalance`]) rather than clamping to the available balance.
    pub fn refund(&self, payer: &[u8], amount: u64) -> Result<RefundRecord, PrepaidError> {
        let mut balances = self.balances.lock().expect("prepaid ledger mutex poisoned");
        let balance = balances.get(payer).copied().unwrap_or(0);
        if amount > balance {
            return Err(PrepaidError::RefundExceedsBalance { payer: payer.to_vec(), amount, balance });
        }
        balances.insert(payer.to_vec(), balance - amount);
        drop(balances);

        let record = RefundRecord {
            payer: payer.to_vec(),
            amount,
            currency: self.currency.clone(),
            tx_seq: self.next_seq(),
        };
        self.refunds.lock().expect("prepaid ledger mutex poisoned").push(record.clone());
        Ok(record)
    }

    /// Every accepted top-up, in acceptance order — the ledger's own audit trail (distinct from a
    /// payer-facing [`ReceiptLog`]).
    pub fn top_ups(&self) -> Vec<TopUpRecord> {
        self.top_ups.lock().expect("prepaid ledger mutex poisoned").clone()
    }

    /// Every accepted debit, in acceptance order.
    pub fn debits(&self) -> Vec<DebitRecord> {
        self.debits.lock().expect("prepaid ledger mutex poisoned").clone()
    }

    /// Every accepted refund, in acceptance order.
    pub fn refunds(&self) -> Vec<RefundRecord> {
        self.refunds.lock().expect("prepaid ledger mutex poisoned").clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::ResourceKind;
    use crate::tariff::LineItem;

    fn bill(amount: u64, currency: &str) -> Bill {
        Bill {
            currency: currency.to_string(),
            amount,
            line_items: vec![LineItem {
                kind: ResourceKind::BytesForwarded,
                metered_units: amount,
                free_units_applied: 0,
                billed_units: amount,
                unit_price: 1,
                amount,
            }],
        }
    }

    #[test]
    fn fresh_payer_has_zero_balance_and_is_exhausted() {
        let ledger = PrepaidLedger::new("USD", 100);
        assert_eq!(ledger.balance(b"payer"), 0);
        assert_eq!(ledger.state(b"payer"), BillingState::Exhausted);
    }

    #[test]
    fn top_up_then_debit_reduces_balance() {
        let ledger = PrepaidLedger::new("USD", 100);
        ledger.top_up(b"payer", 1_000, "funding-1");
        assert_eq!(ledger.balance(b"payer"), 1_000);
        let record = ledger.debit(b"payer", &bill(300, "USD")).unwrap();
        assert_eq!(record.amount, 300);
        assert_eq!(ledger.balance(b"payer"), 700);
    }

    #[test]
    fn top_up_is_idempotent_on_funding_ref_no_double_credit() {
        // A replayed funding confirmation (retried webhook / duplicate rail event) with the same
        // funding_ref must credit AT MOST once — never double-credit. Matches the dedup the
        // broker-billing-patala adapter already enforces on its own credited_references.
        let ledger = PrepaidLedger::new("USD", 100);
        let first = ledger.top_up(b"payer", 500, "rail-tx-abc");
        let replay = ledger.top_up(b"payer", 500, "rail-tx-abc"); // same funding_ref
        assert_eq!(ledger.balance(b"payer"), 500, "duplicate funding_ref must not re-credit");
        assert_eq!(replay.tx_seq, first.tx_seq, "replay returns the original record, not a new one");
        assert_eq!(ledger.top_ups().len(), 1, "only one top-up record for one funding event");
        // A genuinely distinct funding event (different funding_ref) still credits.
        ledger.top_up(b"payer", 250, "rail-tx-def");
        assert_eq!(ledger.balance(b"payer"), 750);
    }

    #[test]
    fn debit_beyond_balance_is_rejected_and_balance_unchanged() {
        let ledger = PrepaidLedger::new("USD", 100);
        ledger.top_up(b"payer", 50, "funding-1");
        let err = ledger.debit(b"payer", &bill(51, "USD")).unwrap_err();
        assert!(matches!(err, PrepaidError::Exhausted { .. }));
        assert_eq!(ledger.balance(b"payer"), 50);
    }

    #[test]
    fn currency_mismatch_is_rejected() {
        let ledger = PrepaidLedger::new("USD", 100);
        ledger.top_up(b"payer", 1_000, "funding-1");
        let err = ledger.debit(b"payer", &bill(10, "USDC")).unwrap_err();
        assert!(matches!(err, PrepaidError::CurrencyMismatch { .. }));
        assert_eq!(ledger.balance(b"payer"), 1_000, "no debit on mismatch");
    }

    #[test]
    fn billing_state_transitions_ok_low_exhausted() {
        let ledger = PrepaidLedger::new("USD", 100);
        ledger.top_up(b"payer", 1_000, "funding-1");
        assert_eq!(ledger.state(b"payer"), BillingState::Ok);

        ledger.debit(b"payer", &bill(920, "USD")).unwrap(); // balance -> 80, under threshold 100
        assert_eq!(ledger.state(b"payer"), BillingState::LowBalance);

        ledger.debit(b"payer", &bill(80, "USD")).unwrap(); // balance -> 0
        assert_eq!(ledger.state(b"payer"), BillingState::Exhausted);
    }

    #[test]
    fn refund_returns_remaining_balance_and_is_capped() {
        let ledger = PrepaidLedger::new("USD", 100);
        ledger.top_up(b"payer", 1_000, "funding-1");
        ledger.debit(b"payer", &bill(400, "USD")).unwrap();
        assert_eq!(ledger.balance(b"payer"), 600);

        let refund = ledger.refund(b"payer", 600).unwrap();
        assert_eq!(refund.amount, 600);
        assert_eq!(ledger.balance(b"payer"), 0);

        let err = ledger.refund(b"payer", 1).unwrap_err();
        assert!(matches!(err, PrepaidError::RefundExceedsBalance { .. }));
    }

    #[test]
    fn debit_and_receipt_issues_a_verifiable_receipt_only_on_success() {
        let ledger = PrepaidLedger::new("USD", 100);
        ledger.top_up(b"payer", 1_000, "funding-1");
        let key = IdentityKey::from_seed(&[0x44; 32]);
        let mut log = ReceiptLog::new();

        let (record, receipts) = ledger.debit_and_receipt(b"payer", &bill(300, "USD"), &mut log, &key).unwrap();
        assert_eq!(record.amount, 300);
        assert_eq!(receipts.len(), 1);
        assert!(log.verify_all().is_ok());

        // A failing debit (exhausted) must issue no receipt at all.
        let before = log.receipts().len();
        let err = ledger.debit_and_receipt(b"payer", &bill(999_999, "USD"), &mut log, &key).unwrap_err();
        assert!(matches!(err, PrepaidError::Exhausted { .. }));
        assert_eq!(log.receipts().len(), before, "no receipt issued on a failed debit");
    }

    #[test]
    fn top_up_debit_refund_conservation() {
        // Sum of top-ups minus sum of debits minus sum of refunds equals the current balance —
        // a conservation invariant this ledger's bookkeeping must always satisfy.
        let ledger = PrepaidLedger::new("USD", 0);
        ledger.top_up(b"payer", 1_000, "f1");
        ledger.top_up(b"payer", 500, "f2");
        ledger.debit(b"payer", &bill(300, "USD")).unwrap();
        ledger.debit(b"payer", &bill(200, "USD")).unwrap();
        ledger.refund(b"payer", 100).unwrap();

        let total_topped_up: u64 = ledger.top_ups().iter().map(|r| r.amount).sum();
        let total_debited: u64 = ledger.debits().iter().map(|r| r.amount).sum();
        let total_refunded: u64 = ledger.refunds().iter().map(|r| r.amount).sum();
        assert_eq!(
            ledger.balance(b"payer"),
            total_topped_up - total_debited - total_refunded
        );
    }

    #[test]
    fn balances_are_isolated_per_payer() {
        let ledger = PrepaidLedger::new("USD", 100);
        ledger.top_up(b"alice", 1_000, "f1");
        ledger.top_up(b"bob", 200, "f2");
        assert_eq!(ledger.balance(b"alice"), 1_000);
        assert_eq!(ledger.balance(b"bob"), 200);
        ledger.debit(b"alice", &bill(100, "USD")).unwrap();
        assert_eq!(ledger.balance(b"bob"), 200, "unaffected by alice's debit");
    }

    #[test]
    fn tx_seq_increments_across_kinds_of_operation() {
        let ledger = PrepaidLedger::new("USD", 0);
        let t1 = ledger.top_up(b"payer", 1_000, "f1");
        let d1 = ledger.debit(b"payer", &bill(100, "USD")).unwrap();
        let r1 = ledger.refund(b"payer", 100).unwrap();
        let seqs = [t1.tx_seq, d1.tx_seq, r1.tx_seq];
        assert_eq!(seqs.iter().collect::<std::collections::BTreeSet<_>>().len(), 3, "all distinct");
    }
}
