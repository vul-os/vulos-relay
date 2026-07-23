# `gateway` fuzz targets

A self-contained [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) project targeting the
`gateway` crate's attacker-controlled parsing/verification boundaries. **Not** a member of the main
Wakala workspace — `Cargo.toml` detaches it with its own `[workspace]` table, so libFuzzer's
nightly-only build flags never leak into `cargo build --workspace` / `cargo test --workspace` on
stable. This mirrors how envoir's own top-level `fuzz/` project was structured before the gateway
(and this fuzz coverage) moved to Wakala (Wave W2; see the doc comments in each
`fuzz_targets/*.rs` file for the exact provenance and any API adaptation).

## Targets

- **`gateway_admission`** — `gateway::authz::IdentityRegistry::admit` (§7.9, §9): a connecting
  legacy SMTP client presents a fully attacker-controlled key + signature pair before any other
  authentication has happened. Property: never panics; always returns a documented, fail-closed
  `AdmissionError` (or `Ok` for a byte-identical valid signature).
- **`gateway_alias`** — `gateway::forwarded_addr::{encode, decode}` (§7.10.2): the SRS-style
  reversible gateway-alias local-part codec. Properties: `decode` never panics on arbitrary bytes
  and fails closed on anything non-canonical; `encode` → `decode` round-trips for any accepted
  `(local, native_domain)` pair.

## Running

Requires the `nightly` toolchain and `cargo-fuzz` (`cargo install cargo-fuzz`):

```sh
cargo +nightly fuzz run gateway_admission
cargo +nightly fuzz run gateway_alias
```

Bound a single run, e.g. for CI/smoke-check purposes:

```sh
cargo +nightly fuzz run gateway_admission -- -max_total_time=30
```

## Verification status

This project's Cargo manifest and target sources were written against the CURRENT `gateway` public
API (verified to compile and be internally consistent with it) as part of Wave W2. Whether
`cargo +nightly fuzz run` was actually exercised in the environment that produced this project is
recorded in `BUILD-PLAN.md` / the wave's commit message — check there rather than assuming either
way from this file alone, since a from-scratch environment may lack `cargo-fuzz` or a nightly
toolchain.
