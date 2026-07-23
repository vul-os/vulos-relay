//! Stake verification — the seam a staked coordinator kind (`arbiter`, `oracle`) checks
//! skin-in-the-game against, **on the settlement/staking rail**, never in the descriptor
//! (CONTRACT §6, DIRECTION §5).
//!
//! CONTRACT §2.1 excludes a stake field from `broker_economics::Descriptor` on purpose, so stake
//! can never become a ranking signal. §6 says the replacement is that a staked kind's stake MUST
//! be verifiable **on the rail itself** (an on-chain stake balance/lock a client can query
//! directly — Kleros-class staked arbitration, OpenRank-class staked attestation). This module is
//! that seam: [`StakeVerifier`] is the trait a real on-rail query implements. This crate does
//! **not** implement a chain query — that is exactly the kind of operator-supplied/rail-specific
//! integration [`crate::settlement::SettlementRail`] is for.
//!
//! ## Fail-closed default (SEC-1)
//!
//! §6 is explicit: "an unverifiable stake claim MUST be treated as no stake." [`NoStakeRail`] is
//! the reference [`StakeVerifier`] that makes that the *only* thing that happens by default —
//! every query returns "not staked," unconditionally. A coordinator that actually needs staked
//! trust (arbiter, oracle) MUST supply a real [`StakeVerifier`] wired to an actual rail; wiring
//! nothing in and silently treating that as "staked" would be exactly the failure mode §6
//! forbids. [`NoStakeRail`] exists so "no rail configured" and "fail closed" are the same line of
//! code, not two things an integrator has to remember to keep in sync.

/// A stake-verification rail seam: checks whether `identity` has at least `minimum` of `asset`
/// staked/locked, per whatever on-rail mechanism the implementation queries.
///
/// A relying client (or a coordinator checking a peer's staked posture) MUST treat any `Err` or
/// `Ok(false)` result identically: not staked. There is deliberately no "unknown, assume staked"
/// state (SEC-1, fail closed) — see the module doc.
pub trait StakeVerifier {
    /// The rail-specific error type (a chain RPC failure, a timeout, ...).
    type Error;

    /// Returns `Ok(true)` only if `identity` verifiably has at least `minimum` units of `asset`
    /// staked/locked on the rail right now. Any inability to verify — a query failure, an
    /// unrecognized identity, a stale/unreachable rail — MUST surface as `Ok(false)` or `Err`,
    /// never as `Ok(true)` by default.
    fn verify_stake(&self, identity: &[u8], asset: &str, minimum: u64) -> Result<bool, Self::Error>;
}

/// The fail-closed reference [`StakeVerifier`]: no rail is wired in, so every claim is
/// unverifiable, so every claim is treated as no stake (§6, SEC-1) — by construction, not by
/// remembering to check. Use this as the default for any coordinator kind that does not (yet)
/// have a real staking-rail integration; swapping in a real [`StakeVerifier`] is the only way to
/// make a staked claim actually count.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoStakeRail;

impl StakeVerifier for NoStakeRail {
    type Error = std::convert::Infallible;

    fn verify_stake(&self, _identity: &[u8], _asset: &str, _minimum: u64) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_stake_rail_never_verifies_any_claim() {
        let rail = NoStakeRail;
        assert!(!rail.verify_stake(b"anyone", "USDC", 0).unwrap());
        assert!(!rail.verify_stake(b"anyone", "USDC", 1_000_000).unwrap());
    }

    // A minimal fake "rail" standing in for a real on-chain query, used only to demonstrate the
    // seam is pluggable — not a claim that this is a real staking integration.
    struct FixedStakeRail {
        staked: u64,
    }

    impl StakeVerifier for FixedStakeRail {
        type Error = std::convert::Infallible;

        fn verify_stake(
            &self,
            _identity: &[u8],
            _asset: &str,
            minimum: u64,
        ) -> Result<bool, Self::Error> {
            Ok(self.staked >= minimum)
        }
    }

    #[test]
    fn a_real_rail_can_be_plugged_in_via_the_trait() {
        let rail = FixedStakeRail { staked: 5_000 };
        assert!(rail.verify_stake(b"arbiter-1", "USDC", 4_000).unwrap());
        assert!(!rail.verify_stake(b"arbiter-1", "USDC", 6_000).unwrap());
    }
}
