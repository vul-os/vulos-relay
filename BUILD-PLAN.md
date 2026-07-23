# Wakala autonomous build plan

The wave backlog for the automated build loop. Each loop iteration: read this + `DECISIONS.md`,
pick the highest-priority unblocked wave, dispatch Sonnet sub-agents to do it, verify
(build+test green), commit+push, then tick the wave and append any decisions to `DECISIONS.md`.

## Autonomous window
- **Start:** 2026-07-23T07:32:13+0200 (epoch 1784784734)
- **Stop at:** 2026-07-23T17:32:13+0200 (epoch 1784820734) — ~10 hours, 15-min cadence (~40 iterations)
- **Stop rule:** when `date +%s` ≥ 1784820734 **or** all waves are `DONE`, delete the cron and stop.

## Hard rules (never violate)
- All-Rust. Depend on `kotva-core`/`kotva-mail` by **pinned tag** (`core-v0.2.0`+), never HEAD/path.
- Every broker kind content-blind per spec (relay=blind, media-relay/reachability-adapter=blind-routing,
  gateway=terminating). Declared visibility must match reality (COORD-4/5).
- No token; stake/settle in existing assets only (DIRECTION §5).
- Preserve the Go relay + JS client until the Rust port is proven. Don't modify the kotva **spec**
  prose (the crates/ Rust is fair game). Log spec gaps to `COORDINATION.md`.
- Keep each repo **green** (build+test) at every commit. Never commit a broken tree.

## Waves

| # | Wave | Status | Notes |
|---|---|---|---|
| W1 | **envoir → node-only, green + committed** | DONE (620a68c) | gateway + its conformance/fuzz removed; substrate consumed from kotva-core@core-v0.2.0 (cargo package-rename alias, zero source churn); conformance-runner carries its own vectors.json snapshot; envoir build+test green, pushed. Unblocks W2 + envoir README |
| W2 | **Relocate gateway conformance + fuzz** envoir→wakala | TODO | the GWALIAS/GWATT/LEG/GWNAME cases + gateway_admission/gateway_alias fuzz targets belong with the gateway in wakala |
| W3 | **broker-economics adopts real kotva-core** | DONE | dropped the stub `kotva_core` seam; real `IdentityKey`/`verify_domain`/deterministic-CBOR from the tag-pinned `kotva-core`; `Descriptor::sign`/`SignedDescriptor::verify`, `Tariff::sign`/`verify`, `UsageReceipt::sign`/`verify` (Ed25519, DS-tagged, canonical §18.1.1 CBOR, CONTRACT §6). Wire layout chosen + logged to `COORDINATION.md` for spec ratification. broker-conformance/gateway/reachability-adapter updated to real keypairs; 349 workspace tests green, clippy clean. |
| W4 | **reachability-adapter SNI/tunnel transport** | DONE (9bd0fc0) | SNI-passthrough peek + yamux reverse tunnel + fail-closed RST ingress; 16 tests. **REACH-2 gap:** box↔adapter control channel is unauthenticated plain TCP (no key-auth to box IK) — kotva-core identity is now pinned in the workspace (W3), but the auth wiring itself is still not built. NOT public-safe until then. |
| W4b | **REACH-2 tunnel key-auth** (closes W4 gap) | IN PROGRESS | mutual key-auth of box↔adapter tunnel to box IK (challenge-response, kotva-core Ed25519); binds SNI registration to authenticated IK, single-writer-per-name. Control-channel transport-security (Noise) still a further step |
| W5 | **relay crate** (mesh, blind/structural) | TODO | libp2p Circuit Relay v2 wrapper; Coordinator posture |
| W6 | **media-relay crate** (blind-routing) | TODO | orchestrate coturn/LiveKit sidecar; SFrame-sealed payload, routing metadata visible (RFC 9605) |
| W7 | **admin surface** | TODO | operator admin for a coordinator: descriptor + tariff config, quota/rate policy, receipts view, key mgmt. Per-kind. HTTP (axum) admin API + auth |
| W8 | **billing model** | DONE | new crate `crates/broker-billing`: kind-agnostic `Meter`/`ResourceKind` + `InMemoryMeter`; `TariffSchedule` (currency, per-`ResourceKind` price, free allowance) built via `broker_economics::Cbor::from_cv`, signed/verified through the real W3 `Tariff`; `ReceiptLog` issuing signed `UsageReceipt`s per billed line item, with the one-directional-audit residual (CONTRACT §6, R-6) documented in-code and demonstrated by a test (a fabricated, never-metered operation's receipt verifies identically to a real one's); `SettlementRail` trait (no-token invariant, DIRECTION §5) + the one reference adapter `InMemoryLedger` (explicitly a mock, double-entry, balances to zero) + x402-style `PaymentRequired`/`PaymentProof` data shapes; `StakeVerifier` seam + fail-closed `NoStakeRail` default (SEC-1, CONTRACT §6). `broker-economics`/`gateway`/`reachability-adapter`/`broker-conformance` untouched (kept self-contained per the wave's constraint). 27 tests, workspace clean (build+test+clippy) verified against the last-known-green HEAD (a concurrent W4b edit to `reachability-adapter` was in flight during verification; excluded from this wave's diff, not touched). |
| W9 | **remaining kind scaffolds** | TODO | indexer / labeler / matcher / arbiter / oracle / compute crates — Coordinator posture + the §4 derived-view carve-out for indexer/labeler/matcher |
| W10 | **conformance harness expansion** | TODO | COORD-1..8 runtime tests per kind; assert declared content-visibility matches observed behavior (discharge the Behavioral findings) |
| W11 | **GitHub metadata + READMEs** | PARTIAL | GH description+topics done for wakala + envoir. wakala README rewritten (624cf9e). TODO: envoir README rewrite (node-only) — do after W1 commits |
| W12 | **docs + CHANGELOG polish** | TODO | crate docs, CHANGELOG entries, honest-limits sections |

## Loop mechanics
- Prefer **Workflow** (multi-agent) or parallel **Agent** (Sonnet) fan-out per wave.
- One writer per repo per iteration (avoid concurrent conflicting edits).
- If a wave needs a founder decision, log it to `COORDINATION.md`, mark the wave BLOCKED, move to the
  next unblocked wave — never guess on an irreversible product/business call.
