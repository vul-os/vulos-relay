# Wakala Rust workspace

Wakala is the **broker (coordinator) reference implementation** of the KOTVA standard — the
single project that implements [`coordinator/CONTRACT.md`](https://github.com/vul-os/kotva).
This workspace is the all-Rust rewrite; the Go reverse-tunnel relay + JS client SDK are
**preserved untouched** alongside it until the port is proven (HANDOVER §Guardrails-3).

## Layout

| Crate | Kind / role | Status |
|---|---|---|
| `broker-economics` | Shared model: content-visibility (`VisibilityClass` × `AssuranceLevel`), coordinator kinds (CONTRACT §5), and the discovery-only descriptor / tariff / usage-receipt shapes (§2.1, §6). | **built** — model + tests; substrate-typed bytes stubbed behind the `kotva_core` seam |
| `broker-conformance` | The `Coordinator` trait + the COORD-1..8 checklist harness (CONTRACT §7). | **built** — harness + tests |
| `reachability-adapter` | REACH: content-blind (SNI-passthrough) public reach for box services (profiles/reachability.md). Replaces the Go L7-terminating proxy. | **skeleton** — contract posture done; `sni`/`tunnel` transport next |
| `gateway` | The mail *adapter* — the DMTAP legacy SMTP/IMAP/POP3 bridge (spec §7). The one `terminating` kind. Folded out of envoir; pins `kotva-core@core-v0.2.0`. | **built** — 305 tests green against the pinned tag; `Coordinator` posture wired |

### Pending crates (added as their build-order slot arrives)

`relay` (mesh, blind/structural) · `media-relay` (blind-routing SFU, orchestrated) ·
scaffolding for `indexer` / `labeler` / `matcher` / `arbiter` / `oracle` / `compute`.

### The `kotva-core` carve (done)

`kotva-core` + `kotva-mail` are carved out of envoir and live in the kotva repo
(`crates/`), tag-pinned at **`core-v0.2.0`**. The gateway builds against that tag. The wire is
byte-identical (envoir's conformance vectors pass unchanged). Still open: `broker-economics`
adopting the real `kotva-core` identity/signing types in place of the stub seam, and the
**envoir-side cleanup** (remove the gateway from envoir → node-only; re-point envoir's substrate
crates to `kotva-core@tag`), deferred until envoir's working tree is clear.

## The `kotva-core` seam (the isango guardrail)

Substrate types (MOTE, envelope, identity/naming, PUB, SYNC, signing/DS-tags, CBOR, crypto)
come from **`kotva-core`**, a crate carved from envoir and **pinned by tag** — never tracked at
HEAD (HANDOVER §Guardrails-1). That crate does not exist yet, so every substrate-typed value
routes through [`broker_economics::kotva_core`](broker-economics/src/kotva_core.rs) as an
explicit, non-cryptographic stub. Nothing there is verified; code that must verify waits for the
real crate (SEC-1 fail-closed). When the tag lands, that module is deleted and the pin goes into
the workspace `Cargo.toml`.

## Build

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets
```

The Go tree (`go build ./...`) is unaffected — `Cargo.toml` and `go.mod` coexist at the root.
