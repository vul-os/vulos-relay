# Configuration — @vulos/relay-client

All configuration is done at runtime via function calls or constructor options.
There are no build-time-only options (the Vite env vars are read at runtime via
`import.meta.env` and are optional — they are not required for the SDK to work).

---

## Endpoint failover

### `configure(opts)`

Call once at app entry, before `selectEndpoint()` or `bootstrapOffline()`.

```js
import { configure } from '@vulos/relay-client/endpoints'

configure({
  lsKeyPrefix: 'vulos.os.endpoints.v1',  // default: 'vulos.relay-client.endpoints.v1'
  healthPath:  '/api/auth/status',        // default: '/api/auth/status'
})
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `lsKeyPrefix` | `string` | `'vulos.relay-client.endpoints.v1'` | `localStorage` key for caching the endpoint pair. Pass your pre-migration surface-specific key to avoid forcing a re-probe on first post-migration load. |
| `healthPath` | `string` | `'/api/auth/status'` | Relative path appended to each candidate base URL for reachability probes. Any HTTP response (including 401/403) counts as reachable. Surfaces with a different auth endpoint can pass their own path here. |

### `window.__VULOS_ENDPOINTS__`

Injected by the OS shell at serve time:

```js
window.__VULOS_ENDPOINTS__ = {
  cloud: 'https://<box>.vulos.org',
  lan:   'https://box.<id>.lan.vulos.org',
}
```

Takes priority over Vite env vars and `localStorage` cache.

### Vite env vars (optional, build-time)

| Variable | Description |
|----------|-------------|
| `VITE_CLOUD_ENDPOINT` | Cloud base URL (e.g. `https://box.vulos.org`) |
| `VITE_LAN_ENDPOINT` | LAN base URL (e.g. `https://box.lan.vulos.org`) |

### Timing constants (not configurable)

| Constant | Value | Description |
|----------|-------|-------------|
| `HEALTH_TIMEOUT_MS` | 2500 ms | Health probe timeout |
| `REVALIDATE_AFTER_MS` | 30000 ms | Selection TTL |
| `RESELECT_DEBOUNCE_MS` | 400 ms | Network-change debounce |

---

## Offline bootstrap

### `bootstrapOffline(opts)`

```js
import { bootstrapOffline } from '@vulos/relay-client/offlineBootstrap'

const state = await bootstrapOffline({
  tierHint: () => currentUserTier(),  // optional
})
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tierHint` | `() => string \| undefined` | `undefined` | Callback returning the current user's tier (`'pro'`, `'free'`, etc.). Keeps per-surface Pro-tier logic out of the shared package. |

---

## Signaling

### `new SignalingClient(opts)`

```js
import { SignalingClient } from '@vulos/relay-client/signaling'

const sc = new SignalingClient({
  signalingUrl: 'wss://box.vulos.org/api/peering/stream',
  sessionId:    'doc-abc123',
  peerId:       'user-xyz',
  authToken:    'eyJ...',       // optional Bearer JWT
  maxAttempts:  10,             // optional; reconnect budget
})
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `signalingUrl` | `string` | required | WebSocket URL to the peering stream |
| `sessionId` | `string` | required | Fabric session / document ID |
| `peerId` | `string` | required | This client's identity token |
| `authToken` | `string \| null` | `null` | Bearer JWT appended as `?token=…` to the WebSocket URL |
| `maxAttempts` | `number` | `10` | Max reconnect attempts before emitting `'offline'` |

**Events:** `signaling-open`, `signaling-close`, `signal`, `offline`

---

## Fabric

### `new FabricClient(opts)`

```js
import { FabricClient } from '@vulos/relay-client/fabric'

const fabric = new FabricClient({
  sessionId:    'doc-abc123',
  peerId:       'user-xyz',
  signalingUrl: 'wss://box.vulos.org/api/peering/stream',
  iceUrl:       '/api/peering/ice',   // optional
  relayBaseUrl: '',                    // optional
  authToken:    'eyJ...',             // optional
})
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `sessionId` | `string` | required | Document / room ID |
| `peerId` | `string` | required | This peer's identity |
| `signalingUrl` | `string` | required | WebSocket URL for signaling |
| `iceUrl` | `string` | `'/api/peering/ice'` | URL returning `{ ice_servers: [...] }` |
| `relayBaseUrl` | `string` | `''` | Base URL for relay deposit/pickup (empty = same-origin) |
| `authToken` | `string \| null` | `null` | Bearer JWT |

**Timing constants (not configurable):**

| Constant | Value | Description |
|----------|-------|-------------|
| `RELAY_TIMEOUT_MS` | 8000 ms | Time before falling back to relay circuit |
| `RELAY_POLL_MS` | 2000 ms | Relay pickup polling interval |
| `RELAY_TTL_HOURS` | 1 h | Relay blob TTL |

**Events:** `message`, `state`

**Peer states:** `'connecting'` | `'connected'` | `'relay'` | `'disconnected'`

---

## Presence

### `new PresenceManager(opts)`

```js
import { PresenceManager } from '@vulos/relay-client/presence'

const pm = new PresenceManager({
  fabric,
  localIdentity: {
    accountId:   'user-xyz',
    displayName: 'Alice',
    isGuest:     false,
  },
})
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `fabric` | `FabricClient` | required | Active fabric session |
| `localIdentity` | `object \| null` | `null` | Local identity. If null, a guest identity is auto-generated and persisted in `localStorage`. |

**Timing constants:**

| Constant | Value | Description |
|----------|-------|-------------|
| `HEARTBEAT_MS` | 10000 ms | Broadcast interval |
| `TIMEOUT_MS` | 25000 ms | Peer timeout (last heartbeat) |

**Status values:** `'online'` `'away'` `'dnd'` `'in-a-call'`

---

## `configure()` per-surface quick reference

```js
// Vulos OS shell
configure({ lsKeyPrefix: 'vulos.os.endpoints.v1' })

// vulos-office
configure({ lsKeyPrefix: 'vulos.office.endpoints.v1' })

// custom surface with a different health path
configure({ lsKeyPrefix: 'vulos.custom.endpoints.v1', healthPath: '/api/auth/me' })
```
