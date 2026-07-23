# Wakala / envoir build — decision log

Append-only. One line per decision: `[YYYY-MM-DD tag] decision — rationale`. The autonomous
build loop appends here whenever it makes a non-obvious call.

## Standing decisions (seeded)
- `[2026-07-23 name]` Umbrella term = **wakala** (provisional; repo named). "broker" considered, not adopted.
- `[2026-07-23 lang]` **All-Rust.** The Go reverse-tunnel + `@vulos/relay-client` JS SDK are preserved until the Rust port is proven, then retired.
- `[2026-07-23 core]` `kotva-core`/`kotva-mail` are crates **in the kotva repo**; consumers pin tag **`core-v0.2.0`** (never HEAD). Solves the isango churn failure.
- `[2026-07-23 wire]` DS-tags stay `dmtap-*` (wire byte-identical); only crate identifiers renamed `dmtap_core`→`kotva_core`. Renaming DS-tags to `kotva-*` is a **wire-breaking** change **not** made — deferred, spec-side call.
- `[2026-07-23 fold]` Mail gateway folded envoir → `wakala/crates/gateway` as the `terminating` mail-adapter kind.
- `[2026-07-23 econ]` **No protocol token.** Billing settles in an existing stablecoin; coordinator stake is in existing assets, verified on-rail.
- `[2026-07-23 vis]` Per-kind content-visibility: relay=`blind` · media-relay=`blind-routing` · reachability-adapter=`blind-routing` (SNI-passthrough; `structural` only for own-domain, `declared` for adapter vanities) · gateway=`terminating`.
- `[2026-07-23 sfu]` Large-scale SFU is **orchestrated externally** (coturn/LiveKit sidecar), not embedded — per bind-don't-reinvent.

## Loop decisions
<!-- the build loop appends below -->
- `[2026-07-23 git]` Consolidated all three repos onto `main` (founder ask): committed kotva (39) + envoir (60) WIP; retired the fully-merged `dev` branches (kotva+envoir, local+origin); pushed.
- `[2026-07-23 repoint]` envoir's 14 substrate consumers repointed from `path` to `kotva-core@core-v0.2.0` via `[workspace.dependencies]` + cargo dependency-rename alias (zero source churn). The other envoir substrate crates (auth/mls/naming/sync/p2p/send/deniable) stay in envoir, consuming kotva-core@tag.
- `[2026-07-23 gwtests]` Gateway conformance cases (conformance-runner) + fuzz targets (gateway_admission/gateway_alias) move **with** the gateway to wakala (W2); envoir drops them to become node-only.
- `[2026-07-23 vectors]` envoir's conformance-runner read `../dmtap-core/vectors.json` (deleted in the carve). Fix: it now carries its OWN snapshot `crates/conformance-runner/vectors.json`, copied from kotva-core@core-v0.2.0 (the corpus is pure wire vectors, 0 gateway entries). Re-sync the snapshot on any kotva-core retag. Soft-dep spec paths repointed dmtap→kotva.
- `[2026-07-23 W11]` GH description+topics updated for wakala + envoir; wakala README rewritten to the broker-ref-impl framing with honest status (624cf9e). envoir README pending W1 commit.
- `[2026-07-23 W4]` reachability-adapter SNI-passthrough transport done (9bd0fc0): hand-rolled ClientHello SNI parser (no full-TLS dep), yamux reverse tunnel, fail-closed RST (SO_LINGER=0) on unknown/absent SNI or non-allow-listed service. **Honest residual:** REACH-2 mutual key-auth to box IK NOT done (control channel is plain TCP) — deferred until kotva-core identity is in the wakala workspace (W3). Not public-safe until wired; disclosed in-code.
- `[2026-07-23 W1]` envoir is node-only (620a68c): gateway + gateway conformance/fuzz removed, dmtap-core/dmtap-mail deleted, substrate consumed from kotva-core@core-v0.2.0. Node-only build+test green. Envoir README + W2 (gateway conformance relocation to wakala) now unblocked.
