<div align="center">

# Vulos Relay

**`@vulos/relay-client` — the peer-fabric client SDK for Vulos web surfaces**

[![npm](https://img.shields.io/npm/v/%40vulos%2Frelay-client?label=%40vulos%2Frelay-client)](https://www.npmjs.com/package/@vulos/relay-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/vul-os/vulos-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/vul-os/vulos-relay/actions/workflows/ci.yml)

<img src="docs/assets/vulos-logo.png" alt="Vulos" width="48" />

Part of the **[Vulos](https://vulos.org)** OS suite

*Vulos — rooted in **vula**, the Zulu and Xhosa word for **open**.*

![Vulos Relay](docs/screenshots/hero.png)

</div>

---

## Overview

This repository provides **`@vulos/relay-client`**, the shared JavaScript SDK
used by every Vulos web surface (the OS shell and
[vulos-office](https://github.com/vul-os/vulos-office)) for peer-fabric and
connectivity concerns.

The SDK runs entirely in the browser and talks to the **host application's own
peering backend** (e.g. the Vulos OS `/api/peering/*` endpoints) over HTTP and
WebSocket. It does not bundle a server.

---

## Screenshots

Because `@vulos/relay-client` is a headless JS SDK with no app UI, the visual
documentation uses an **interactive demo harness** (`demo/index.html`) that
exercises the real SDK behaviour in a browser. The images below are captured
from that harness.

### Demo harness — endpoint failover + presence panels

![Demo harness overview](docs/screenshots/hero.png)

*Live endpoint probe cycle (cloud ↔ LAN failover), simulated two-peer fabric
session with presence roster and connection-state transitions, message broadcast
log. No real backend required — peers are simulated in-process.*

### Architecture diagram — signaling + relay-fallback flow

![Architecture diagram](docs/screenshots/architecture.png)

*Sequence diagram showing the six phases of a fabric session: join, SDP
offer/answer, ICE candidate exchange, P2P data channel, relay-circuit fallback
(when P2P fails within 8 s), and presence heartbeat layer.*

See [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md) for how to regenerate these.

---

## Features

- **Endpoint failover** — cloud ↔ LAN backend selection with concurrent health
  probing, 400 ms debounce for Wi-Fi handoffs, 30 s TTL + immediate invalidation
  on API failure.
- **Offline bootstrap** — offline-first shell boot with an IndexedDB write
  queue; optional `tierHint` callback for per-surface Pro-tier injection.
- **WebRTC signaling** — `SignalingClient` over the host's `/api/peering/stream`
  WebSocket with exponential back-off (1 s → 30 s, 10-attempt budget) and a
  terminal `"offline"` event for degraded-mode UI.
- **Fabric sessions** — `FabricClient` providing per-document P2P data channels
  (DTLS-SRTP) with a relay-circuit fallback, polite-peer SDP negotiation, and
  ECDSA P-256 signed relay deposits.
- **Presence** — `PresenceManager` + `usePresence` React hook: multi-peer
  awareness, 10 s heartbeat, 25 s GC, status values (`online` / `away` / `dnd`
  / `in-a-call`), auto-generated guest identities.
- **Live cursors** — `useLiveCursors` React hook multiplexed on the fabric
  channel with pointer-event debouncing.
- **P2P mesh calls** — `createCall` (audio/video, ≤ 5 peers); LiveKit SFU
  removed before 1.0.
- **Dual build** — ESM (`.js`) + CJS (`.cjs`) bundles; React and xlsx are
  optional peer dependencies.

---

## Quick start

```bash
npm install @vulos/relay-client
```

Or as a monorepo `file:` dependency:

```jsonc
// package.json
"@vulos/relay-client": "file:../vulos-relay/client"
```

**Minimal usage:**

```js
import { configure, selectEndpoint } from '@vulos/relay-client/endpoints'
import { FabricClient }              from '@vulos/relay-client/fabric'
import { PresenceManager }           from '@vulos/relay-client/presence'

// 1. Configure endpoint keys (preserves existing localStorage cache)
configure({ lsKeyPrefix: 'vulos.os.endpoints.v1' })

// 2. Select the best reachable backend
const base = await selectEndpoint()

// 3. Open a fabric session
const fabric = new FabricClient({
  sessionId:    'doc-abc123',
  peerId:       currentUser.id,
  signalingUrl: `${base.replace('http', 'ws')}/api/peering/stream`,
  authToken:    session.jwt,
})

fabric.addEventListener('message', ({ detail: { from, data } }) => {
  console.log('CRDT op from', from, data)
})

await fabric.join()
fabric.send(JSON.stringify({ op: 'insert', pos: 0, text: 'hello' }))

// 4. Add presence
const pm = new PresenceManager({ fabric, localIdentity: { accountId: currentUser.id, displayName: currentUser.name } })
pm.addEventListener('roster', ({ detail: peers }) => console.log(peers))
pm.join()
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) | Install + first integration walkthrough |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Fabric/signaling/endpoint-failover design |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | All SDK options and constructor params |
| [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md) | What the demo shows + how to regenerate |
| [client/README.md](client/README.md) | Subpath exports + migration notes |
| [ROADMAP.md](ROADMAP.md) | Planned directions (1.x / 2.x) |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [SECURITY.md](SECURITY.md) | Security policy and disclosure |

---

## Development

### Build and test (client SDK)

```bash
cd client
npm ci
npm run build
npm test
```

Tests run under Vitest with jsdom. The SDK targets browser environments
(WebSocket, BroadcastChannel, WebRTC).

### Regenerate screenshots

```bash
npm run screenshots
```

This installs Playwright (headless Chromium, ~170 MB on first run), serves
`demo/index.html` on a local static server, and captures `docs/screenshots/`.
See [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md) for prerequisites and details.

### Release

Releases are cut by tagging:

```bash
# bump version in client/package.json first, then:
git tag v1.2.3 && git push origin v1.2.3
```

The [release workflow](.github/workflows/release.yml) builds, tests, verifies
the tag matches `client/package.json`, and publishes to npm with OIDC
provenance (gated on `NPM_TOKEN` repository secret).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev-environment setup, branch
conventions, commit style, and scope constraints (no `.tsx`, no Go, no Rust,
no OAuth, no Stripe).

---

## License

MIT — see [LICENSE](LICENSE).
