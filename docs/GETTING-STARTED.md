# Getting Started — @vulos/relay-client

## Prerequisites

- Node.js 20+ and npm 10+
- A host application that exposes `/api/peering/*` endpoints (e.g. the Vulos OS
  shell or vulos-office)

## Install

### From npm (published package)

```bash
npm install @vulos/relay-client
```

### From the monorepo (file: dependency)

The Vulos repos consume the SDK as a workspace-local dependency:

```jsonc
// vulos/package.json (the OS shell)
"@vulos/relay-client": "file:../vulos-relay/client"

// vulos-office/package.json
"@vulos/relay-client": "file:../vulos-relay/client"

// vulos-talk/package.json
"@vulos/relay-client": "file:../vulos-relay/client"
```

## First integration

### 1. Configure endpoints (once at app entry)

```js
import { configure, selectEndpoint } from '@vulos/relay-client/endpoints'

// Preserve your pre-migration localStorage cache key if you previously used
// one of the per-surface defaults.
configure({ lsKeyPrefix: 'vulos.os.endpoints.v1' })

// Resolve the best reachable backend (cloud ↔ LAN) at boot.
const base = await selectEndpoint()
console.log('Using backend:', base || '(same-origin)')
```

### 2. Bootstrap offline-first

```js
import { bootstrapOffline } from '@vulos/relay-client/offlineBootstrap'

const state = await bootstrapOffline({
  // Optional: inject a Pro-tier hint without leaking OS-specific logic
  // into the shared package.
  tierHint: () => currentUserTier(),
})
```

### 3. Open a fabric session

```js
import { FabricClient } from '@vulos/relay-client/fabric'

const fabric = new FabricClient({
  sessionId: 'doc-abc123',
  peerId:    currentUser.id,
  signalingUrl: `${base.replace('http', 'ws')}/api/peering/stream`,
  authToken: session.jwt,
})

fabric.addEventListener('message', ({ detail: { from, data } }) => {
  console.log('CRDT op from', from, data)
})

fabric.addEventListener('state', ({ detail: { peerId, state } }) => {
  console.log(peerId, 'is now', state) // 'connecting' | 'connected' | 'relay' | 'disconnected'
})

await fabric.join()
fabric.send(JSON.stringify({ op: 'insert', pos: 0, text: 'hello' }))
```

### 4. Add presence

```js
import { PresenceManager } from '@vulos/relay-client/presence'

const pm = new PresenceManager({
  fabric,
  localIdentity: { accountId: currentUser.id, displayName: currentUser.name },
})

pm.addEventListener('roster', ({ detail: peers }) => {
  console.log('Online peers:', peers.map(p => p.displayName))
})

pm.join()
```

### 5. Tear down

```js
pm.leave()
fabric.leave()
```

## React hooks

`@vulos/relay-client/presence` exports `usePresence`, and
`@vulos/relay-client/useLiveCursors` exports `useLiveCursors`. Both require
`react ^18` as a peer dependency.

```jsx
import { usePresence } from '@vulos/relay-client/presence'

function CollabAvatars({ fabric }) {
  const { roster } = usePresence({ fabric, localIdentity: { accountId: 'me', displayName: 'Alice' } })
  return roster.map(p => (
    <Avatar key={p.accountId} name={p.displayName} color={p.color} />
  ))
}
```

## See also

- [Architecture](ARCHITECTURE.md) — how the layers fit together
- [Configuration](CONFIGURATION.md) — all SDK options
- [Subpath exports](../client/README.md) — full API reference
