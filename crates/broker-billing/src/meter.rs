//! Metering — counting units of a metered resource per payer (CONTRACT §6).
//!
//! Kept **kind-agnostic**: a coordinator records how many units of a [`ResourceKind`] a payer
//! consumed (bytes forwarded, connections opened, messages relayed, compute-seconds spent), and
//! [`crate::tariff`] turns accumulated usage into an amount owed. What counts as "a unit" for a
//! given kind, and what it costs, is entirely [`crate::tariff::TariffSchedule`] (operator policy)
//! — this module only counts.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// A metered resource kind (CONTRACT §6: "bytes forwarded, connections, messages,
/// compute-seconds"). Deliberately a closed, small enum — every Wakala coordinator kind meters
/// in these terms; a kind that needs a resource not listed here should map it onto the closest
/// fit rather than this crate growing a kind-specific variant per coordinator.
///
/// Each variant has a stable wire tag ([`ResourceKind::wire_tag`]) used as the CBOR map key in a
/// tariff schedule and a usage-receipt operation — never the enum's in-memory discriminant, so
/// reordering variants here can never change wire meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceKind {
    /// Bytes forwarded/relayed on behalf of the payer (e.g. relay, media-relay,
    /// reachability-adapter throughput).
    BytesForwarded,
    /// Connections established/accepted (e.g. a reachability-adapter tunnel, a relay circuit).
    Connections,
    /// Discrete messages handled (e.g. gateway mail deliveries, matcher offers).
    Messages,
    /// Compute-seconds consumed (e.g. the `compute` kind's hosted inference).
    ComputeSeconds,
}

impl ResourceKind {
    /// The stable wire tag — the CBOR map key used in a tariff schedule and a usage-receipt
    /// operation (see `tariff.rs`/`receipt.rs`). Never reuse a tag for a different meaning; a
    /// schedule/receipt built under an old tag must keep decoding to the same kind forever.
    pub fn wire_tag(self) -> u64 {
        match self {
            ResourceKind::BytesForwarded => 1,
            ResourceKind::Connections => 2,
            ResourceKind::Messages => 3,
            ResourceKind::ComputeSeconds => 4,
        }
    }

    /// The inverse of [`Self::wire_tag`], failing closed (`None`) on any unrecognized tag —
    /// used decoding an untrusted wire schedule/operation, never guessing.
    pub fn from_wire_tag(tag: u64) -> Option<Self> {
        Some(match tag {
            1 => ResourceKind::BytesForwarded,
            2 => ResourceKind::Connections,
            3 => ResourceKind::Messages,
            4 => ResourceKind::ComputeSeconds,
            _ => return None,
        })
    }
}

/// A metering store: accumulates units-consumed per payer, per [`ResourceKind`].
///
/// A trait so a real deployment can back this with a durable store (a database, a replicated
/// log) instead of the in-memory reference impl ([`InMemoryMeter`]) below. The payer is
/// identified by their substrate identity public key (the same `Vec<u8>` convention
/// `broker-economics` uses throughout for identity — see `descriptor.rs`).
pub trait Meter {
    /// Record `units` of `kind` consumed by `payer`, adding to any existing accumulated total.
    fn record(&self, payer: &[u8], kind: ResourceKind, units: u64);

    /// The full accumulated usage for `payer` across every kind recorded so far (an empty map if
    /// nothing has been recorded).
    fn usage(&self, payer: &[u8]) -> BTreeMap<ResourceKind, u64>;

    /// Clear `payer`'s accumulated usage — called once a billing period has been evaluated and
    /// receipted, so the next period starts from zero. Returns the usage that was cleared (the
    /// snapshot that was billed), so a caller never has to `usage()` then `reset()` and risk a
    /// race between the two calls under a concurrent store.
    fn reset(&self, payer: &[u8]) -> BTreeMap<ResourceKind, u64>;
}

/// An in-memory reference [`Meter`]. Not durable — a process restart loses unbilled usage. Real
/// deployments back [`Meter`] with a persistent store; this exists to make the model runnable and
/// testable without one.
#[derive(Default)]
pub struct InMemoryMeter {
    // Keyed by the payer's raw identity bytes. A `Mutex` (not `RwLock`) because every access here
    // mutates or is trivially cheap to serialize; no read-heavy hot path to justify the extra
    // complexity.
    usage: Mutex<BTreeMap<Vec<u8>, BTreeMap<ResourceKind, u64>>>,
}

impl InMemoryMeter {
    /// A fresh, empty meter.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Meter for InMemoryMeter {
    fn record(&self, payer: &[u8], kind: ResourceKind, units: u64) {
        let mut table = self.usage.lock().expect("meter mutex poisoned");
        let entry = table.entry(payer.to_vec()).or_default();
        *entry.entry(kind).or_insert(0) = entry.get(&kind).copied().unwrap_or(0).saturating_add(units);
    }

    fn usage(&self, payer: &[u8]) -> BTreeMap<ResourceKind, u64> {
        let table = self.usage.lock().expect("meter mutex poisoned");
        table.get(payer).cloned().unwrap_or_default()
    }

    fn reset(&self, payer: &[u8]) -> BTreeMap<ResourceKind, u64> {
        let mut table = self.usage.lock().expect("meter mutex poisoned");
        table.remove(payer).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_kind_wire_tags_round_trip() {
        for k in [
            ResourceKind::BytesForwarded,
            ResourceKind::Connections,
            ResourceKind::Messages,
            ResourceKind::ComputeSeconds,
        ] {
            assert_eq!(ResourceKind::from_wire_tag(k.wire_tag()), Some(k));
        }
        assert_eq!(ResourceKind::from_wire_tag(999), None);
    }

    #[test]
    fn accumulates_across_multiple_records() {
        let m = InMemoryMeter::new();
        let payer = b"payer-1".to_vec();
        m.record(&payer, ResourceKind::BytesForwarded, 100);
        m.record(&payer, ResourceKind::BytesForwarded, 250);
        m.record(&payer, ResourceKind::Connections, 1);

        let usage = m.usage(&payer);
        assert_eq!(usage.get(&ResourceKind::BytesForwarded), Some(&350));
        assert_eq!(usage.get(&ResourceKind::Connections), Some(&1));
        assert_eq!(usage.get(&ResourceKind::Messages), None);
    }

    #[test]
    fn per_payer_isolation() {
        let m = InMemoryMeter::new();
        m.record(b"alice", ResourceKind::Messages, 5);
        m.record(b"bob", ResourceKind::Messages, 9);
        assert_eq!(m.usage(b"alice").get(&ResourceKind::Messages), Some(&5));
        assert_eq!(m.usage(b"bob").get(&ResourceKind::Messages), Some(&9));
    }

    #[test]
    fn reset_returns_snapshot_and_clears() {
        let m = InMemoryMeter::new();
        let payer = b"payer-2".to_vec();
        m.record(&payer, ResourceKind::ComputeSeconds, 42);

        let snapshot = m.reset(&payer);
        assert_eq!(snapshot.get(&ResourceKind::ComputeSeconds), Some(&42));
        assert!(m.usage(&payer).is_empty());
    }

    #[test]
    fn unrecorded_payer_has_empty_usage() {
        let m = InMemoryMeter::new();
        assert!(m.usage(b"never-seen").is_empty());
    }
}
