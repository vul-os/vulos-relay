//! The settlement seam — charging a [`Bill`](crate::tariff::Bill) against an **existing** asset
//! (CONTRACT §6, DIRECTION §5).
//!
//! ## The no-token invariant
//!
//! Wakala/KOTVA mints nothing. There is no protocol token anywhere in this crate, and
//! [`SettlementRail`] is written so there structurally cannot be one smuggled in: it charges an
//! amount denominated in a caller-supplied `currency` string (an ISO 4217 code or an existing
//! stablecoin ticker — whatever [`crate::tariff::TariffSchedule::currency`] says), never in a
//! Wakala-defined unit. Custody and canonical settlement of that asset are **entirely the rail
//! implementation's problem** — a real chain client, a card processor, a bank-transfer API — none
//! of which lives in this crate. Wakala brokers none of it and takes no cut (DIRECTION §5,
//! CONTRACT §6).
//!
//! ## What's real here vs. what's a seam
//!
//! [`SettlementRail`] is the trait a real adapter implements. [`InMemoryLedger`] is the ONE
//! reference implementation in this crate — an in-memory double-entry ledger, clearly a mock: it
//! settles nothing outside the process, has no persistence, and is unsuitable for anything but
//! tests/demos. [`PaymentRequired`]/[`PaymentProof`] are data shapes only — an x402-style
//! (HTTP 402 "Payment Required") challenge/response, per the family of HTTP-native payment
//! bindings the ecosystem is converging on — provided so a coordinator's admin/HTTP surface (W7)
//! has a documented shape to embed, **not** a live x402 facilitator/client integration (no HTTP
//! server, no signature scheme for the payment proof itself is implemented here).

use std::collections::HashMap;
use std::sync::Mutex;

/// A settlement rail: the seam a coordinator charges a payer through, in an existing asset.
///
/// Every real implementation of this trait is **operator-supplied config** (CONTRACT §6:
/// "the settlement rail... is out of scope [of the protocol]") — a stablecoin client, a PSP
/// integration, a bank rail. This crate ships exactly one reference implementation
/// ([`InMemoryLedger`]), which is explicitly a mock (see the module doc).
pub trait SettlementRail {
    /// The rail's own error type (a real adapter's errors — insufficient funds, a network
    /// timeout talking to a chain node, a declined card — are rail-specific).
    type Error;

    /// Charge `payer` `amount` of `currency` (the tariff's minor unit — see
    /// [`crate::tariff::TariffSchedule::currency`]). Returns a settlement receipt on success.
    fn charge(
        &self,
        payer: &[u8],
        amount: u64,
        currency: &str,
    ) -> Result<SettlementReceipt, Self::Error>;

    /// The payer's current balance in `currency`, if the rail tracks one (a prepaid/ledger-style
    /// rail does; a pure pay-per-charge card rail may not — such a rail can return `0` or its own
    /// "not applicable" convention; this trait does not mandate one).
    fn balance(&self, payer: &[u8], currency: &str) -> Result<i64, Self::Error>;
}

/// A rail-issued record of one successful [`SettlementRail::charge`] — deliberately minimal and
/// rail-agnostic (not a `broker_economics::UsageReceipt`; that is the *usage* receipt to the
/// payer, CONTRACT §6, issued regardless of which rail settled the amount — see
/// [`crate::receipt`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub payer: Vec<u8>,
    pub amount: u64,
    pub currency: String,
    /// Monotonic per-rail transaction sequence — rail-internal bookkeeping only, unrelated to
    /// [`crate::receipt::BilledOperation::sequence`].
    pub tx_seq: u64,
}

/// Errors from [`InMemoryLedger`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerError {
    /// The payer's balance would go below the ledger's configured floor (by default `0` — no
    /// credit extended). A real rail's overdraft/credit-line policy is its own operator config;
    /// this mock keeps the simplest possible rule so the "balances" test has something to check.
    #[error("insufficient balance: payer {payer:?} has {balance} {currency}, charge was {amount}")]
    InsufficientBalance {
        payer: Vec<u8>,
        balance: i64,
        amount: u64,
        currency: String,
    },
}

/// An in-memory, double-entry-style ledger — the ONE reference [`SettlementRail`] adapter this
/// crate ships. **This is a mock**, not a real settlement rail: balances live only in process
/// memory, there is no external custody, and [`Self::deposit`] exists purely so tests/demos can
/// simulate funds having arrived from a real rail (a stablecoin transfer, a card capture) without
/// this crate integrating one. See the module doc.
///
/// "Balances" in the literal double-entry sense: every [`Self::deposit`] and every
/// [`SettlementRail::charge`] is mirrored into a single internal house account, so the sum of all
/// payer balances plus the house account is always zero — see the `mock_ledger_balances` test.
#[derive(Default)]
pub struct InMemoryLedger {
    balances: Mutex<HashMap<(Vec<u8>, String), i64>>,
    house: Mutex<HashMap<String, i64>>,
    next_tx_seq: Mutex<u64>,
}

impl InMemoryLedger {
    /// A fresh ledger with every account at a zero balance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Credit `payer`'s `currency` balance by `amount` — simulates funds having arrived via a
    /// real external rail (the mock's stand-in for "the payer topped up their stablecoin/fiat
    /// balance with the operator"). Mirrored as a debit to the house account.
    pub fn deposit(&self, payer: &[u8], amount: u64, currency: &str) {
        let mut balances = self.balances.lock().expect("ledger mutex poisoned");
        let entry = balances
            .entry((payer.to_vec(), currency.to_string()))
            .or_insert(0);
        *entry += amount as i64;
        let mut house = self.house.lock().expect("ledger mutex poisoned");
        *house.entry(currency.to_string()).or_insert(0) -= amount as i64;
    }

    fn next_seq(&self) -> u64 {
        let mut seq = self.next_tx_seq.lock().expect("ledger mutex poisoned");
        let v = *seq;
        *seq += 1;
        v
    }

    /// The sum of every account this ledger knows about (every payer balance plus the house
    /// account, across all currencies encountered) — used by the `mock_ledger_balances` test to
    /// assert the ledger always nets to zero. Not part of [`SettlementRail`] (a real rail would
    /// not expose its internal house-account total).
    #[cfg(test)]
    fn grand_total(&self, currency: &str) -> i64 {
        let balances = self.balances.lock().expect("ledger mutex poisoned");
        let house = self.house.lock().expect("ledger mutex poisoned");
        let payer_sum: i64 = balances
            .iter()
            .filter(|((_, c), _)| c == currency)
            .map(|(_, v)| *v)
            .sum();
        payer_sum + house.get(currency).copied().unwrap_or(0)
    }
}

impl SettlementRail for InMemoryLedger {
    type Error = LedgerError;

    fn charge(
        &self,
        payer: &[u8],
        amount: u64,
        currency: &str,
    ) -> Result<SettlementReceipt, Self::Error> {
        let mut balances = self.balances.lock().expect("ledger mutex poisoned");
        let key = (payer.to_vec(), currency.to_string());
        let balance = balances.get(&key).copied().unwrap_or(0);
        if balance < amount as i64 {
            return Err(LedgerError::InsufficientBalance {
                payer: payer.to_vec(),
                balance,
                amount,
                currency: currency.to_string(),
            });
        }
        *balances.entry(key).or_insert(0) -= amount as i64;
        drop(balances);
        let mut house = self.house.lock().expect("ledger mutex poisoned");
        *house.entry(currency.to_string()).or_insert(0) += amount as i64;
        drop(house);
        Ok(SettlementReceipt {
            payer: payer.to_vec(),
            amount,
            currency: currency.to_string(),
            tx_seq: self.next_seq(),
        })
    }

    fn balance(&self, payer: &[u8], currency: &str) -> Result<i64, Self::Error> {
        let balances = self.balances.lock().expect("ledger mutex poisoned");
        Ok(balances
            .get(&(payer.to_vec(), currency.to_string()))
            .copied()
            .unwrap_or(0))
    }
}

/// An x402-style ("HTTP 402 Payment Required") challenge — the shape an operator's HTTP/admin
/// surface (W7) can serialize when a request needs payment before the coordinator will proceed.
/// **A data shape only** — no HTTP framing, no facilitator/verifier logic, no signature scheme
/// for [`PaymentProof`] is implemented in this crate (see the module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequired {
    /// The amount required, in `currency`'s minor unit.
    pub amount: u64,
    /// An existing asset code (ISO 4217 or a stablecoin ticker) — never a Wakala-defined unit.
    pub currency: String,
    /// The coordinator identity/account payment should be made to — rail-specific in format (an
    /// address, an account id); this crate does not constrain the string's shape.
    pub pay_to: String,
    /// A short, human/machine-readable description of what is being paid for (e.g. the
    /// `ResourceKind`/period this challenge covers).
    pub resource: String,
}

/// The client's response to a [`PaymentRequired`] challenge — a claim that payment was made,
/// carrying whatever the rail needs to check it (e.g. a transaction hash, a signed payment
/// authorization). This crate does not verify a [`PaymentProof`]; a real integration hands it to
/// the actual [`SettlementRail`] implementation, which is the only thing that can check it
/// against the real rail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentProof {
    /// Opaque, rail-specific proof bytes (a signed authorization, a transaction reference).
    pub proof: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_fails_without_a_deposit_first() {
        let ledger = InMemoryLedger::new();
        let err = ledger.charge(b"payer", 100, "USDC").unwrap_err();
        assert!(matches!(err, LedgerError::InsufficientBalance { .. }));
    }

    #[test]
    fn deposit_then_charge_reduces_balance() {
        let ledger = InMemoryLedger::new();
        ledger.deposit(b"payer", 1_000, "USDC");
        assert_eq!(ledger.balance(b"payer", "USDC").unwrap(), 1_000);
        let receipt = ledger.charge(b"payer", 300, "USDC").unwrap();
        assert_eq!(receipt.amount, 300);
        assert_eq!(ledger.balance(b"payer", "USDC").unwrap(), 700);
    }

    #[test]
    fn charge_beyond_balance_is_rejected_and_balance_unchanged() {
        let ledger = InMemoryLedger::new();
        ledger.deposit(b"payer", 50, "USD");
        assert!(ledger.charge(b"payer", 51, "USD").is_err());
        assert_eq!(ledger.balance(b"payer", "USD").unwrap(), 50);
    }

    #[test]
    fn mock_ledger_balances() {
        // The defining property of a double-entry ledger: no matter how many deposits/charges
        // happen, the grand total (every payer balance + the house account) nets to zero — money
        // only ever moves between accounts inside the ledger, never appears or vanishes.
        let ledger = InMemoryLedger::new();
        ledger.deposit(b"alice", 1_000, "USDC");
        ledger.deposit(b"bob", 500, "USDC");
        ledger.charge(b"alice", 300, "USDC").unwrap();
        ledger.charge(b"bob", 500, "USDC").unwrap();
        assert_eq!(ledger.grand_total("USDC"), 0);
    }

    #[test]
    fn per_currency_accounts_are_isolated() {
        let ledger = InMemoryLedger::new();
        ledger.deposit(b"payer", 100, "USD");
        ledger.deposit(b"payer", 100, "USDC");
        ledger.charge(b"payer", 100, "USD").unwrap();
        assert_eq!(ledger.balance(b"payer", "USD").unwrap(), 0);
        assert_eq!(ledger.balance(b"payer", "USDC").unwrap(), 100);
    }

    #[test]
    fn tx_seq_increments_across_charges() {
        let ledger = InMemoryLedger::new();
        ledger.deposit(b"payer", 1_000, "USD");
        let r1 = ledger.charge(b"payer", 10, "USD").unwrap();
        let r2 = ledger.charge(b"payer", 10, "USD").unwrap();
        assert_ne!(r1.tx_seq, r2.tx_seq);
    }

    #[test]
    fn payment_required_and_proof_are_plain_data() {
        // Documents the shape; no behavior to test beyond "it constructs and compares."
        let challenge = PaymentRequired {
            amount: 500,
            currency: "USDC".to_string(),
            pay_to: "0xoperator...".to_string(),
            resource: "bytes-forwarded/2026-07".to_string(),
        };
        let proof = PaymentProof {
            proof: vec![1, 2, 3],
        };
        assert_eq!(challenge.currency, "USDC");
        assert_eq!(proof.proof.len(), 3);
    }
}
