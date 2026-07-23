<div align="center">

<img src="logo.png" width="76" alt="Wakala" />

# Wakala

**The broker (coordinator) reference implementation of the KOTVA standard**

[![npm](https://img.shields.io/npm/v/%40vulos%2Frelay-client?label=%40vulos%2Frelay-client)](https://www.npmjs.com/package/@vulos/relay-client)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![CI](https://github.com/vul-os/wakala/actions/workflows/ci.yml/badge.svg)](https://github.com/vul-os/wakala/actions/workflows/ci.yml)

*wakala — Swahili for agent/agency: a swappable, fee-taking service point acting on a
network's behalf. Vulos — rooted in **vula**, the Zulu and Xhosa word for **open**.*

</div>

---

## What is Wakala?

Wakala is the **single project that implements
[`coordinator/CONTRACT.md`](https://github.com/vul-os/kotva/blob/main/coordinator/CONTRACT.md)**
— the KOTVA spec's contract for centralization that is hired, not depended-on. A
**coordinator** is any party providing a function the peer-to-peer substrate can't
provide reciprocally (a global view, a scarce resource, a legal anchor). Wakala houses
**every coordinator kind** behind that one contract:

| Kind | Provides | Declared visibility | Status |
|---|---|---|---|
| `relay` | Mesh reachability for NAT'd peers | `blind` / structural | preserved as the Go reverse-tunnel (below); Rust port not started |
| `media-relay` | Scales calls (SFrame-sealed payload) | `blind-routing` / structural (RFC 9605) | not started |
| `reachability-adapter` | ngrok-style public subdomains for box services | `blind-routing` (SNI-passthrough) | SNI + tunnel transport built; **REACH-2 box↔adapter mutual key-auth not wired — see Status** |
| `gateway` | Legacy mail bridge (MX, DKIM, SMTP/IMAP/POP3) | `terminating` — the one non-blind kind, disclosed | built, 305 tests green, folded out of envoir |
| `indexer` / `labeler` / `matcher` / `arbiter` / `oracle` / `compute` | search, moderation, matching, dispute, attestation, hosted compute | per-kind, spec §5 | scaffolding only |

Every kind is **accountable** (attested identity + signed descriptor), **swappable**
(leaving is a config change, zero migration, zero identity change), **self-hostable**
(one disclosed exception: scarce network reachability — port-25 egress for `gateway`,
public ingress for `reachability-adapter`), and **declares its content-visibility** —
exactly one class (`blind` / `blind-routing` / `terminating`) at one assurance level
(`structural` / `attested` / `declared`), never silently downgraded. A coordinator
**authorizes from identity and rate; it never classifies content** on a delivery or
canonical path — that judgement belongs to the recipient. Full text:
[`coordinator/CONTRACT.md`](https://github.com/vul-os/kotva/blob/main/coordinator/CONTRACT.md).

**No token.** Economics are a signed tariff plus signed usage receipts delivered to the
payer (one-directional audit — proves a claimed operation happened, can't disconfirm a
fabricated one). Settlement rides an existing stablecoin or fiat rail; KOTVA brokers
none and takes no cut. Stake (where a kind requires skin-in-the-game, e.g. `arbiter`,
`oracle`) is verified on the settlement rail itself, never merely asserted.

> **Not** the OS app-gateway. Routing `/app/<id>` to a box's local app ports (with
> auth-token injection) is the VulOS shell's own internal reverse proxy — a separate
> concern that stays in the OS. Wakala crosses the *network* boundary (P2P, public
> exposure, mail egress), not the in-box one.

---

## Status (honest, as of this writing)

Wakala is **mid-rewrite**. Read this before relying on any of it in production.

- **The Rust workspace is in progress, not the shipping implementation yet.** The
  **Go reverse-tunnel relay** (`tunnel/`, `cmd/`) and the **`@vulos/relay-client` JS
  SDK** (`client/`) are the **preserved, working implementation** — keep using them
  until the Rust port is proven and this note is removed. See
  [Preserved Go implementation](#preserved-go-implementation-relay-kind) below.
- **`reachability-adapter`: not public-safe yet.** The SNI-passthrough transport
  (ClientHello parsing, yamux reverse tunnel, fail-closed RST on unmatched SNI) is
  built and tested, but the **box↔adapter control channel is unauthenticated plain
  TCP** — mutual key-auth to the box's identity key (REACH-2) is not wired. It is
  blocked on `kotva-core` identity landing in this workspace. Do not expose it
  publicly until that lands.
- **`gateway` is real and tested** (305 tests) but `broker-economics` — the shared
  descriptor / tariff / usage-receipt signing every kind needs — still runs behind a
  **non-cryptographic stub seam** (`broker_economics::kotva_core`) rather than real
  `kotva-core` identity types. Nothing routed through that stub is verified; adopting
  the real crate is an open wave.
- **`relay`, `media-relay`, and the remaining kinds** (`indexer`, `labeler`,
  `matcher`, `arbiter`, `oracle`, `compute`) have no Rust implementation yet beyond
  scaffolding.
- Live, wave-by-wave status lives in [BUILD-PLAN.md](BUILD-PLAN.md); decisions are
  logged append-only in [DECISIONS.md](DECISIONS.md).

---

## The Rust workspace

All-Rust, one crate per coordinator kind plus two shared crates. Substrate types
(MOTE, envelope, identity/naming, PUB, SYNC, signing/DS-tags, CBOR, crypto) come from
**`kotva-core`** / **`kotva-mail`** — crates carved out of envoir, living in the kotva
repo, and **pinned by tag** (`core-v0.2.0`), **never tracked at HEAD** (the *isango*
guardrail: extracting this same gateway from envoir failed twice before against a
moving core).

| Crate | Kind / role | Status |
|---|---|---|
| [`broker-economics`](crates/broker-economics) | Shared model: content-visibility (`VisibilityClass` × `AssuranceLevel`), coordinator kinds, descriptor/tariff/usage-receipt shapes | built — model + tests; substrate-typed bytes stubbed behind the `kotva_core` seam |
| [`broker-conformance`](crates/broker-conformance) | The `Coordinator` trait + COORD-1..8 checklist harness | built — harness + tests |
| [`reachability-adapter`](crates/reachability-adapter) | `blind-routing` SNI-passthrough public reach for box services | SNI/tunnel transport built; REACH-2 key-auth pending (see Status) |
| [`gateway`](crates/gateway) | The mail adapter — legacy SMTP/IMAP/POP3 bridge, the one `terminating` kind | built — 305 tests green against `kotva-core@core-v0.2.0` |

Pending (added as their build-order wave arrives): `relay` (mesh, `blind`),
`media-relay` (`blind-routing`, orchestrated SFU), and scaffolding for
`indexer` / `labeler` / `matcher` / `arbiter` / `oracle` / `compute`. Full crate map
and the `kotva-core` seam mechanics: [crates/README.md](crates/README.md).

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets
```

The Go tree (`go build ./...`) and the Rust workspace coexist at the repo root
(`Cargo.toml` + `go.mod`) — building one does not affect the other.

---

## Preserved Go implementation (`relay` kind)

Until the Rust `relay` crate is built and proven, this repo's **working relay** is the
original Go reverse-tunnel + the JS peer-fabric SDK. Both are frozen-but-maintained,
not deprecated — see [Status](#status-honest-as-of-this-writing).

### `@vulos/relay-client` (JS/TS SDK)

Wires browser peers together with **WebRTC peer-to-peer data channels**, falling back
to a relay circuit when a direct connection can't be established. It's a **client
only** — it talks to its host app's `/api/peering/*` endpoints for signaling and ICE
credentials, and only ever speaks `https`/`wss`.

```bash
npm install @vulos/relay-client
```

```js
import { selectEndpoint }  from '@vulos/relay-client/endpoints'
import { FabricClient }    from '@vulos/relay-client/fabric'
import { PresenceManager } from '@vulos/relay-client/presence'

const base = await selectEndpoint()               // LAN-direct → cloud → same-origin

const fabric = new FabricClient({
  sessionId:    'doc-abc123',
  peerId:       currentUser.id,
  signalingUrl: `${base.replace(/^http/, 'ws')}/api/peering/stream`,
  iceUrl:       `${base}/api/peering/ice`,
  authToken:    session.jwt,                       // optional Bearer JWT
})

fabric.addEventListener('message', ({ detail: { from, data } }) => console.log(from, data))
await fabric.join()
fabric.send(JSON.stringify({ op: 'insert', pos: 0, text: 'hello' }))

const presence = new PresenceManager({ fabric, localIdentity: { accountId: currentUser.id } })
presence.join()
```

Key properties: **E2E peer authentication** (per-session ECDSA P-256, every
offer/answer/ICE frame and relay deposit signed, TOFU + replay cache),
**endpoint failover** (LAN ↔ cloud, 400 ms debounce), **presence + live cursors**
(React hooks), **P2P mesh calls** (`createCall`; the LiveKit SFU path was removed
before 1.0). Full option list: [docs/CONFIGURATION.md](docs/CONFIGURATION.md); design:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); subpath map:
[client/README.md](client/README.md).

### Sovereign reverse tunnel (Go)

A self-hosted **replacement for `frp` / ngrok / Cloudflare Tunnel**: a loopback-bound
box dials one outbound `wss://` connection to a relay **you control**, which serves a
public URL and reverse-proxies HTTP + WebSocket back down it — no inbound ports, no
static IP, no third-party relay.

```bash
./scripts/install.sh --domain relay.example.com   # one command, needs Docker Compose
```

or run the binaries directly:

```bash
go run ./cmd/vulos-relayd -domain relay.example.com -tokens-file grants.json
go run ./cmd/vulos-relay-agent -server wss://relay.example.com -token SECRET1 -name box1 -local 127.0.0.1:8080
```

```sh
go build ./...
go test -race ./...
go vet ./...
```

**Security posture — honest, no overclaim.** The relay is a **content-visible Layer-7
terminating proxy**, not an end-to-end-encrypted pipe: it (or its fronting edge)
terminates the client's TLS, so the **relay operator can read and modify all tunneled
HTTP**. Confidentiality rests on **who runs the relay**: self-host it (you are the
operator), or use a **verified direct endpoint** (TLS runs client↔box, bypassing the
relay). This is exactly the honesty gap the Rust `reachability-adapter`'s
SNI-passthrough transport is built to close for NAT'd boxes — see
[Status](#status-honest-as-of-this-writing) for why it isn't public-safe yet either.

Other hardening already in the Go relay: bearer-token agent auth (constant-time,
hashed at rest), token-bound names, an SSRF guard on the agent's forward target,
per-IP/per-tunnel/global rate limiting (`429`), over-quota cut (`402`), token
revocation (file/env list + runtime API + periodic sweep), a verified **direct-IP
fast path** (near-native latency, unmetered, bypasses the relay entirely), request
bounds (256 MiB body cap, slow-body ingestion deadline), a loopback/token-gated admin
listener for `/metrics` + `/healthz` + `/readyz` (never on the public tunnel), and a
geo-distributed pool with a CP-driven, make-before-break autoscaler (fully
CP-optional — a self-host relay runs none of it). Real-time media (RTP) never rides
the tunnel — it goes over ICE/TURN directly, preferring the box's verified direct
endpoint. Full trust model and deploy notes:
[docs/SECURITY.md](docs/SECURITY.md) · [docs/TUNNEL.md](docs/TUNNEL.md) ·
[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).

The relay also serves two **open, opt-in roles** any conforming operator can run: a
**rendezvous** role (signed, content-blind announce/resolve/signal/mailbox + ICE
substrate for OS-free P2P signaling — [docs/RENDEZVOUS.md](docs/RENDEZVOUS.md)), and a
**pubcache/pin** role (a verifying read-through cache + durable pin store for public,
self-verifying DMTAP-PUB objects, refusing anything that doesn't match its content
address — [docs/PUBCACHE.md](docs/PUBCACHE.md), [docs/PINNING.md](docs/PINNING.md)).
Pubcache is the one role that is **not** content-blind (it serves public plaintext by
design) and is off by default, explicit opt-in.

---

## Documentation

| Document | Description |
|----------|-------------|
| [HANDOVER.md](HANDOVER.md) | The build brief: target architecture, guardrails, build order |
| [BUILD-PLAN.md](BUILD-PLAN.md) | Live wave-by-wave status of the Rust port |
| [DECISIONS.md](DECISIONS.md) | Append-only decision log |
| [COORDINATION.md](COORDINATION.md) | Cross-repo sync log with the kotva spec session |
| [crates/README.md](crates/README.md) | Rust workspace map, per-crate status, the `kotva-core` seam |
| [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) | Zero-to-reachable-box walkthrough (Go relay) |
| [docs/SECURITY.md](docs/SECURITY.md) | Go relay trust model — what the operator can/cannot see |
| [docs/TUNNEL.md](docs/TUNNEL.md) | Full server flag/env reference & deploy notes (Go relay) |
| [docs/TUNNEL-GUIDE.md](docs/TUNNEL-GUIDE.md) | Protocol/lifecycle deep dive — wss+yamux, reconnects |
| [docs/METERING-BILLING.md](docs/METERING-BILLING.md) | How Go-relay transfer is metered (opt-in; unbilled self-host by default) |
| [docs/RENDEZVOUS.md](docs/RENDEZVOUS.md) | The open rendezvous role — wire protocol, auth, signing |
| [docs/PUBCACHE.md](docs/PUBCACHE.md) | The open cache/pin role — verification gate, bounds |
| [docs/PINNING.md](docs/PINNING.md) | Durable pin store — budget, refusal semantics, signed wire protocol |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | JS SDK fabric / signaling / endpoint-failover design |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | All JS SDK options and constructor params |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Symptom → cause → fix field guide (Go relay) |
| [client/README.md](client/README.md) | JS SDK subpath exports + migration notes |
| [ROADMAP.md](ROADMAP.md) | Planned directions for the JS SDK |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

The KOTVA spec itself (`coordinator/CONTRACT.md`, `DIRECTION.md`, and the per-kind
`profiles/`) lives in the [kotva repo](https://github.com/vul-os/kotva) and is owned by
that project, not duplicated here.

---

## Development

```sh
# Rust workspace
cargo build --workspace && cargo test --workspace

# Go relay (server + agent)
go build ./... && go test -race ./...

# JS SDK
cd client && npm ci && npm run build && npm test
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) builds and tests the JS
client on Node 20 and runs a Trivy filesystem scan (HIGH/CRITICAL gating). The
publishable JS package lives in `client/`; the repository root holds dev tooling
(screenshot capture, etc.) under `scripts/`.

### Release (JS SDK)

```bash
# bump version in client/package.json first, then:
git tag v1.2.3 && git push origin v1.2.3
```

The [release workflow](.github/workflows/release.yml) builds, tests, verifies the tag
matches `client/package.json`, and publishes to npm with OIDC provenance.

---

## Security

**Vulnerability disclosure.** Report via GitHub Security Advisories (preferred) or
`security@vulos.org`. In-scope areas include the Go relay's endpoint probe/cache
integrity, signaling session isolation, peer-auth bypass, and offline-queue integrity,
as well as the Rust workspace's coordinator conformance and content-visibility
enforcement. Acknowledgement within 72 hours. Full policy: [SECURITY.md](SECURITY.md).

**JS SDK peer authentication.** Every `FabricClient` session generates an ephemeral
ECDSA P-256 key pair; the public key is published in the signaling `join` frame and
every outgoing `offer`/`answer`/`ice` frame and relay deposit is signed over its
canonical form. By default (`requirePeerAuth: true`) unsigned frames from unknown
peers are rejected (TOFU on first signed frame); replayed `(from, nonce)` pairs are
dropped (bounded FIFO cache). Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev-environment setup, branch and commit
conventions, and scope constraints.

---

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) — © VulOS. Wakala is a VulOS
project; source and issues at
[github.com/vul-os/wakala](https://github.com/vul-os/wakala).

---

<p align="center">
  <a href="https://vulos.org"><img src="docs/assets/vulos-logo.png" alt="vulos" height="20"></a><br>
  <sub><a href="https://vulos.org"><b>vulos</b></a> — open by design</sub>
</p>
