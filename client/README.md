# @vulos/relay-client

> <img src="../docs/assets/vulos-logo.png" height="14" alt="VulOS"> Part of **[VulOS](https://vulos.org)** — the open, self-hostable web OS &amp; app suite. This is the client SDK for **Vulos Relay**, the suite's connectivity fabric. Runs standalone, or as an app hosted by the Vulos OS.

MIT-licensed JS client for the Vulos peer-fabric relay. Shared by every
VulOS web surface (the Vulos OS shell, `vulos-office`, `vulos-talk`); previously
duplicated as `src/lib/{endpoints,offlineBootstrap,signaling,fabric,
presence,call,useLiveCursors,roundTripCheck}.js` across those repos.

This package runs in the browser and talks to the **host application's peering
backend** (e.g. the Vulos OS `/api/peering/*` endpoints) over HTTP / WebSocket.
It does not bundle a server.

## Part of VulOS

**Vulos Relay** is the connectivity fabric of the [VulOS](https://vulos.org)
suite — open, self-hostable products (Mail, Talk, Meet, Office, Relay,
Workspace, OS), each usable alone and hosted as apps by the **Vulos OS**
(the shell). This SDK is consumed directly by the suite's web surfaces (the Vulos
OS shell, Vulos Office, Vulos Talk); the Workspace hub app surfaces Relay-powered
surfaces but never imports product code. The package has no Vulos-specific runtime
dependency — it **runs standalone** against any backend that implements the
peering contract, **and** slots into the OS-hosted suite.

## Install

Published to npm:

```bash
npm install @vulos/relay-client
```

Inside the VulOS monorepo, consumed as a `file:` dependency from the sibling
repos:

```jsonc
// vulos/package.json  (sibling, ../vulos-relay/client/)
"@vulos/relay-client": "file:../vulos-relay/client"

// vulos-office/package.json  (sibling)
"@vulos/relay-client": "file:../vulos-relay/client"

// vulos-talk/package.json  (sibling)
"@vulos/relay-client": "file:../vulos-relay/client"
```

## Subpath exports

| Subpath                          | Module                                                  |
| -------------------------------- | ------------------------------------------------------- |
| `@vulos/relay-client`            | root barrel — re-exports everything                     |
| `@vulos/relay-client/endpoints`  | cloud↔LAN endpoint failover (`selectEndpoint`, etc.)    |
| `@vulos/relay-client/offlineBootstrap` | one-call offline-first shell bootstrap            |
| `@vulos/relay-client/signaling`  | `SignalingClient` over `/api/peering/stream` WebSocket  |
| `@vulos/relay-client/fabric`     | `FabricClient` — WebRTC mesh + relay-circuit fallback   |
| `@vulos/relay-client/presence`   | `PresenceManager` + `usePresence` React hook            |
| `@vulos/relay-client/call`       | `createCall` — P2P mesh audio/video call                |
| `@vulos/relay-client/useLiveCursors` | live-cursors React hook (`peerColor`)               |
| `@vulos/relay-client/roundTripCheck` | round-trip fixture runner (`runRoundTripChecks`)    |

Both ESM (`.js`) and CJS (`.cjs`) bundles are emitted into `dist-lib/` by the
vite-lib build (`npm run build`). `react` and `xlsx` are declared as optional
peer dependencies so consumers dedupe them.

## Migration compatibility — `configure()`

`endpoints.js` previously used a per-surface localStorage key
(`vulos.os.endpoints.v1`, `vulos.office.endpoints.v1`). The shared module
defaults to `vulos.relay-client.endpoints.v1` but exposes a `configure()`
seam so consumers can preserve their existing user state during migration:

```js
import { configure } from '@vulos/relay-client/endpoints'

// vulos OS:
configure({ lsKeyPrefix: 'vulos.os.endpoints.v1' })

// vulos-office:
configure({ lsKeyPrefix: 'vulos.office.endpoints.v1' })
```

## OS-specific extensions — `tierHint`

`offlineBootstrap.bootstrapOffline()` accepts an optional `tierHint` callback
so the OS-specific MEET-OS-01 Pro-tier injection (and any future per-surface
tier hint) can be wired in without OS-specific logic leaking into the shared
package. Consumers that don't supply one get `undefined` from
`currentTierHint()` — the shared package is a no-op for them.

## License

MIT — see [LICENSE](./LICENSE).
