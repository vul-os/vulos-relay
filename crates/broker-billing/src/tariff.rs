//! Tariff evaluation — turning a signed [`broker_economics::Tariff`] + metered usage into an
//! amount owed (CONTRACT §6).
//!
//! `broker_economics::Tariff` carries an opaque, signed `schedule: Cbor` — the *mechanism*
//! (a signed, published price schedule) is contract-normative, but the schedule's own shape is
//! this crate's concern (§6: "the numbers are operator policy"). [`TariffSchedule`] is that
//! concrete shape: it is built with [`broker_economics::Cbor::from_cv`] (so it rides the real
//! §18.1.1 canonical/deterministic codec, the same one the signature is computed over) and
//! parsed back with [`TariffSchedule::from_cbor`].
//!
//! ## Wire layout (a `TariffSchedule`'s `Cv`, before wrapping in `Cbor`/signing as a `Tariff`)
//! ```text
//! {
//!   1: currency,         tstr  — ISO 4217 code ("USD") or asset/stablecoin ticker ("USDC")
//!   2: prices,           map   — { ResourceKind::wire_tag() : price_per_unit u64 }
//!                                 price is in the currency's minor unit (cents, USDC base
//!                                 units, ...) per single metered unit of that resource kind
//!   3: free_allowance,   map   — { ResourceKind::wire_tag() : free_units u64 }, OPTIONAL per
//!                                 kind (a kind absent here has zero free allowance)
//!   4: period_seconds,   u64?  — OPTIONAL nominal billing-period length, informational only;
//!                                 this crate does not schedule timers off it
//! }
//! ```
//! No floats anywhere (kotva-core §18.1.1 forbids them on the wire regardless), which is exactly
//! right for money: every amount here is an integer count of the currency's minor unit.
//!
//! Evaluation is **fail-closed on unpriced usage**: if a payer's metered usage includes a
//! [`crate::meter::ResourceKind`] the schedule has no price entry for, [`TariffSchedule::evaluate`]
//! returns [`BillingError::UnpricedKind`] rather than silently charging zero for it — an operator
//! who metered a kind is expected to have priced it; a silent zero-charge would hide a
//! misconfiguration as "free."

use std::collections::BTreeMap;

use kotva_core::cbor::{as_u64, CborError, Cv, Fields};

use broker_economics::Cbor;

use crate::meter::ResourceKind;

/// Errors building, parsing, or evaluating a [`TariffSchedule`].
#[derive(Debug, thiserror::Error)]
pub enum BillingError {
    #[error("malformed canonical CBOR: {0}")]
    BadEncoding(#[from] CborError),
    #[error("tariff schedule is malformed: {0}")]
    Malformed(&'static str),
    /// A payer's metered usage names a [`ResourceKind`] the schedule has no price entry for.
    /// Fail-closed (never charged as free) — see the module doc.
    #[error("resource kind {0:?} was metered but has no price entry in the tariff schedule")]
    UnpricedKind(ResourceKind),
}

/// A concrete, operator-authored price schedule (CONTRACT §6: "the numbers are operator
/// policy"). Signed into a [`broker_economics::Tariff`] via [`TariffSchedule::sign`]; parsed back
/// from a verified one via [`TariffSchedule::from_tariff`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TariffSchedule {
    /// ISO 4217 code or stablecoin ticker — an *existing* asset, never a protocol token
    /// (DIRECTION §5). This crate does not validate the string against any registry; that is a
    /// settlement-rail concern ([`crate::settlement`]).
    pub currency: String,
    /// Per-unit price, in the currency's minor unit, for each priced [`ResourceKind`]. A kind
    /// absent from this map cannot be billed — evaluating usage for it fails closed
    /// ([`BillingError::UnpricedKind`]).
    pub prices: BTreeMap<ResourceKind, u64>,
    /// Free units granted per billing period, per [`ResourceKind`], before the per-unit price
    /// applies. A kind absent here has zero free allowance (not "unlimited free" — the
    /// conservative default).
    pub free_allowance: BTreeMap<ResourceKind, u64>,
    /// Nominal billing-period length in seconds. Informational only: this crate evaluates
    /// whatever usage snapshot it is given (see [`crate::meter::Meter::reset`]) — it does not
    /// itself run a timer or enforce period boundaries.
    pub period_seconds: Option<u64>,
}

impl TariffSchedule {
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Text(self.currency.clone())),
            (
                2,
                Cv::Map(
                    self.prices
                        .iter()
                        .map(|(k, v)| (k.wire_tag(), Cv::U64(*v)))
                        .collect(),
                ),
            ),
            (
                3,
                Cv::Map(
                    self.free_allowance
                        .iter()
                        .map(|(k, v)| (k.wire_tag(), Cv::U64(*v)))
                        .collect(),
                ),
            ),
        ];
        if let Some(p) = self.period_seconds {
            m.push((4, Cv::U64(p)));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, BillingError> {
        let mut f = Fields::from_cv(cv)?;
        let currency = match f.req(1)? {
            Cv::Text(s) => s,
            _ => return Err(BillingError::Malformed("currency must be a text string")),
        };
        let prices = resource_price_map(f.req(2)?)?;
        let free_allowance = resource_price_map(f.req(3)?)?;
        let period_seconds = f.take(4).map(as_u64).transpose()?;
        f.deny_unknown()?;
        Ok(TariffSchedule {
            currency,
            prices,
            free_allowance,
            period_seconds,
        })
    }

    /// Encode as the [`broker_economics::Cbor`] payload a [`broker_economics::Tariff`] carries
    /// (built via `Cbor::from_cv`, per the module doc).
    pub fn to_cbor(&self) -> Cbor {
        Cbor::from_cv(&self.to_cv())
    }

    /// Sign this schedule into a [`broker_economics::Tariff`] with the coordinator's real
    /// substrate identity — thin sugar over `Tariff::sign(self.to_cbor(), ik)`; this crate does
    /// not reimplement signing (W3's `broker_economics::descriptor`).
    pub fn sign(&self, ik: &broker_economics::IdentityKey) -> broker_economics::Tariff {
        broker_economics::Tariff::sign(self.to_cbor(), ik)
    }

    /// Parse a schedule out of a signed [`broker_economics::Tariff`]'s `schedule` payload,
    /// *without* checking the signature — callers MUST call [`broker_economics::Tariff::verify`]
    /// first (fail-closed, SEC-1); this function only decodes bytes that are already trusted.
    pub fn from_tariff(tariff: &broker_economics::Tariff) -> Result<Self, BillingError> {
        Self::from_cbor(&tariff.schedule)
    }

    /// Decode a schedule from raw [`broker_economics::Cbor`] bytes.
    pub fn from_cbor(cbor: &Cbor) -> Result<Self, BillingError> {
        Self::from_cv(cbor.decode()?)
    }

    /// Evaluate metered `usage` (as produced by [`crate::meter::Meter::usage`]/`reset`) against
    /// this schedule: apply the free allowance per kind, then the per-unit price on the
    /// remainder, and sum into a [`Bill`].
    ///
    /// Fails closed ([`BillingError::UnpricedKind`]) if `usage` names a kind this schedule has no
    /// price for — see the module doc.
    pub fn evaluate(&self, usage: &BTreeMap<ResourceKind, u64>) -> Result<Bill, BillingError> {
        let mut line_items = Vec::with_capacity(usage.len());
        let mut amount: u64 = 0;
        for (&kind, &units) in usage {
            let unit_price = *self
                .prices
                .get(&kind)
                .ok_or(BillingError::UnpricedKind(kind))?;
            let free = self.free_allowance.get(&kind).copied().unwrap_or(0);
            let billed_units = units.saturating_sub(free);
            let line_amount = billed_units.saturating_mul(unit_price);
            amount = amount.saturating_add(line_amount);
            line_items.push(LineItem {
                kind,
                metered_units: units,
                free_units_applied: free.min(units),
                billed_units,
                unit_price,
                amount: line_amount,
            });
        }
        Ok(Bill {
            currency: self.currency.clone(),
            amount,
            line_items,
        })
    }
}

fn resource_price_map(cv: Cv) -> Result<BTreeMap<ResourceKind, u64>, BillingError> {
    let entries = match cv {
        Cv::Map(m) => m,
        _ => return Err(BillingError::Malformed("expected a resource-kind price map")),
    };
    let mut out = BTreeMap::new();
    for (tag, v) in entries {
        let kind = ResourceKind::from_wire_tag(tag)
            .ok_or(BillingError::Malformed("unknown resource-kind wire tag"))?;
        out.insert(kind, as_u64(v)?);
    }
    Ok(out)
}

/// One line of a [`Bill`]: what was metered for a single [`ResourceKind`], how much of it was
/// free, and what the remainder cost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineItem {
    pub kind: ResourceKind,
    /// Total units metered (before the free allowance).
    pub metered_units: u64,
    /// How many of `metered_units` the free allowance covered.
    pub free_units_applied: u64,
    /// `metered_units - free_units_applied` — the units actually charged for.
    pub billed_units: u64,
    /// The per-unit price applied (from the schedule).
    pub unit_price: u64,
    /// `billed_units * unit_price`, in the schedule's currency minor unit.
    pub amount: u64,
}

/// The result of [`TariffSchedule::evaluate`]: an itemized amount owed, in the tariff's currency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bill {
    pub currency: String,
    /// The total amount owed, minor currency units — the sum of every [`LineItem::amount`].
    pub amount: u64,
    pub line_items: Vec<LineItem>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_economics::IdentityKey;

    fn ik(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn sample_schedule() -> TariffSchedule {
        let mut prices = BTreeMap::new();
        prices.insert(ResourceKind::BytesForwarded, 1); // 1 minor unit / byte
        prices.insert(ResourceKind::Connections, 500); // 500 minor units / connection
        let mut free_allowance = BTreeMap::new();
        free_allowance.insert(ResourceKind::BytesForwarded, 1_000);
        TariffSchedule {
            currency: "USDC".to_string(),
            prices,
            free_allowance,
            period_seconds: Some(30 * 24 * 3600),
        }
    }

    #[test]
    fn schedule_round_trips_through_cbor() {
        let s = sample_schedule();
        let decoded = TariffSchedule::from_cbor(&s.to_cbor()).expect("decodes");
        assert_eq!(decoded, s);
    }

    #[test]
    fn schedule_signs_and_verifies_via_tariff() {
        let key = ik(1);
        let s = sample_schedule();
        let tariff = s.sign(&key);
        assert!(tariff.verify().is_ok());
        let decoded = TariffSchedule::from_tariff(&tariff).expect("decodes");
        assert_eq!(decoded, s);
    }

    #[test]
    fn tampered_signed_schedule_fails_verification() {
        let key = ik(2);
        let s = sample_schedule();
        let mut tariff = s.sign(&key);
        tariff.schedule = TariffSchedule {
            currency: "USD".to_string(),
            ..sample_schedule()
        }
        .to_cbor();
        assert!(tariff.verify().is_err());
    }

    #[test]
    fn free_allowance_covers_usage_under_the_cap() {
        let s = sample_schedule();
        let mut usage = BTreeMap::new();
        usage.insert(ResourceKind::BytesForwarded, 800); // under the 1000-byte free allowance
        let bill = s.evaluate(&usage).expect("priced kind");
        assert_eq!(bill.amount, 0);
        assert_eq!(bill.line_items[0].billed_units, 0);
        assert_eq!(bill.line_items[0].free_units_applied, 800);
    }

    #[test]
    fn per_unit_price_applies_above_the_free_allowance() {
        let s = sample_schedule();
        let mut usage = BTreeMap::new();
        usage.insert(ResourceKind::BytesForwarded, 1_500); // 500 over the free allowance
        usage.insert(ResourceKind::Connections, 3);
        let bill = s.evaluate(&usage).expect("priced kinds");
        // 500 billed bytes * 1 + 3 connections * 500 = 500 + 1500 = 2000
        assert_eq!(bill.amount, 2_000);
        assert_eq!(bill.currency, "USDC");
        assert_eq!(bill.line_items.len(), 2);
    }

    #[test]
    fn unpriced_kind_fails_closed_rather_than_billing_zero() {
        let s = sample_schedule(); // has no price for Messages/ComputeSeconds
        let mut usage = BTreeMap::new();
        usage.insert(ResourceKind::Messages, 10);
        let err = s.evaluate(&usage).expect_err("must fail closed");
        assert!(matches!(err, BillingError::UnpricedKind(ResourceKind::Messages)));
    }

    #[test]
    fn zero_usage_bills_zero() {
        let s = sample_schedule();
        let bill = s.evaluate(&BTreeMap::new()).expect("empty usage");
        assert_eq!(bill.amount, 0);
        assert!(bill.line_items.is_empty());
    }
}
