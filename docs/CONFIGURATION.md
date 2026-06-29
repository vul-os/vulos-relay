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
  signalingUrl:     'wss://box.vulos.org/api/peering/stream',
  sessionId:        'doc-abc123',
  peerId:           'user-xyz',
  authToken:        'eyJ...',       // optional Bearer JWT
  tokenTransport:   'header',       // optional; 'header' (default) or 'query'
  maxAttempts:      10,             // optional; reconnect budget

  // ── Peer-auth / frame signing (advanced) ──────────────────────────────────
  requirePeerAuth:  true,           // default; reject unsigned frames from unknown peers
  getDepositPubKey: () => pubKeyB64, // callback → base64 raw P-256 public key to publish in join frames
  signFrame:        async (msg) => sigB64, // async callback → base64 ECDSA-P256/SHA-256 signature
})
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `signalingUrl` | `string` | required | WebSocket URL to the peering stream |
| `sessionId` | `string` | required | Fabric session / document ID |
| `peerId` | `string` | required | This client's identity token |
| `authToken` | `string \| null` | `null` | Bearer JWT for server-side session auth |
| `tokenTransport` | `'header' \| 'query'` | `'header'` | How the auth token is sent on the WebSocket handshake. `'header'` sends it in `Sec-WebSocket-Protocol` (avoids URL logging); `'query'` appends `?token=…` for environments where custom WS headers are not supported. |
| `maxAttempts` | `number` | `10` | Max reconnect attempts before emitting `'offline'` |
| `requirePeerAuth` | `boolean` | `true` | When `true`, any `offer`/`answer`/`ice` frame received from a peer whose public key is not yet known (via a prior signed `join` or an inline `pubKey`) is silently dropped. Set to `false` only for legacy/test scenarios where frames are not signed. |
| `getDepositPubKey` | `() => string \| null` | `null` | Callback returning the base64-encoded raw (uncompressed) P-256 public key to include as `depositPubKey` in the outgoing `join` frame, so remote peers can verify inbound signed frames. |
| `signFrame` | `async (canonicalMsg: string) => string \| null` | `null` | Async callback that signs a canonical JSON string and returns a base64 ECDSA-P256/SHA-256 signature. Applied to every outgoing `offer`, `answer`, and `ice` frame. The canonical form is the JSON-serialised payload with fixed key order (`from`, `nonce`, `sdp`/`candidate`, `pubKey`). |

#### Signaling-frame signing and DTLS fingerprint pinning

When `signFrame` and `getDepositPubKey` are both provided, the `SignalingClient` will:

1. Include `pubKey` (the raw P-256 public key, base64) in outgoing frames so the remote peer can import it on first sight (TOFU — Trust on First Use).
2. Generate a random UUID `nonce` per frame to enable replay detection.
3. Call `signFrame(canonical)` to sign the canonical form and attach a `sig` field.
4. Mirror the `sdp` or `candidate` field to the top level of the payload so the DTLS fingerprint is included in the signed material — a MITM that rewrites the SDP after signing will produce a signature that fails verification.

On the inbound side, `requirePeerAuth: true` causes the client to:
- Accept `join` frames freely and import `depositPubKey` into its per-peer key registry.
- For `offer`/`answer`/`ice` frames, verify the `sig` against the stored (or inline) `pubKey`.
- Drop frames where no key is known and no inline `pubKey` is provided.
- Drop frames whose `(from, nonce)` pair has already been seen in this session (bounded FIFO cache, max 1000 entries).

#### Per-session nonce cache (replay protection)

Each `SignalingClient` maintains an in-memory `(fromPeerId, nonce)` cache bounded to 1000 entries (eviction is FIFO). The cache is scoped to the session lifetime — it is not persisted across reconnects. Re-join after reconnect issues a fresh nonce, so cache entries from before the reconnect do not block legitimate re-negotiation.

**Events:** `signaling-open`, `signaling-close`, `signal`, `offline`

---

## Fabric

### `new FabricClient(opts)`

```js
import { FabricClient } from '@vulos/relay-client/fabric'

const fabric = new FabricClient({
  sessionId:            'doc-abc123',
  peerId:               'user-xyz',
  signalingUrl:         'wss://box.vulos.org/api/peering/stream',
  iceUrl:               '/api/peering/ice',   // optional
  relayBaseUrl:         '',                   // optional
  authToken:            'eyJ...',             // optional

  // ── Security options ──────────────────────────────────────────────────────
  requirePeerAuth:      true,   // default; require signed frames from unknown peers
  allowUnsignedRelayAuth: false, // default; never send the forged Vulos-Relay header
})
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `sessionId` | `string` | required | Document / room ID |
| `peerId` | `string` | required | This peer's identity |
| `signalingUrl` | `string` | required | WebSocket URL for signaling |
| `iceUrl` | `string` | `'/api/peering/ice'` | URL returning `{ ice_servers: [...] }` |
| `relayBaseUrl` | `string` | `''` | Base URL for relay deposit/pickup (empty = same-origin) |
| `authToken` | `string \| null` | `null` | Bearer JWT sent as `Authorization: Bearer …` on relay HTTP requests |
| `requirePeerAuth` | `boolean` | `true` | Passed through to the internal `SignalingClient`. When `true`, unsigned signaling frames from peers with no stored key are dropped. Set to `false` only for backward-compat scenarios where the remote is not signing frames. |
| `allowUnsignedRelayAuth` | `boolean` | `false` | When `false` (default), the `Vulos-Relay: <peerId>` header is never sent on relay requests — this header is server-controlled and can be forged. When `true`, the header is included for legacy relay backends that use it for identification. Requires explicit opt-in because it is not a secure authentication mechanism. |

#### Per-session deposit key (ECDSA P-256)

`FabricClient` generates a per-session ECDSA P-256 key pair on `join()`. The raw public key is published in the `join` signaling frame as `depositPubKey`. Every outgoing relay deposit and outgoing signaling frame (offer/answer/ice) is signed with this key so that:

- Remote peers can verify inbound relay blobs using the key stored from the `join` frame.
- The signaling server and any relay backend can verify signed deposits without trusting the client-supplied `from` field.

The private key is ephemeral (in-memory only, `extractable: false`) and is discarded when the session ends.

#### Relay inbound signature verification

Relay blobs received during the poll loop are verified client-side before dispatch:

1. If the blob carries a `sig` and `nonce`, the `SignalingClient`'s per-peer key registry is used to verify the ECDSA-P256/SHA-256 signature over `JSON.stringify({ to, from, nonce, blob_b64 })`.
2. If no signature is present but the `from` peer's key IS known (imported from a prior signed `join`), the blob is **dropped** — a blob without a sig from a known peer is suspicious and may indicate relay-level impersonation.
3. If no signature is present and the peer's key is NOT known (early join race or legacy peer), the blob is accepted — this preserves backward compat with unsigned relay backends.

#### DoS limits (hard caps, not configurable)

| Limit | Value | Description |
|-------|-------|-------------|
| `MAX_PENDING_CANDIDATES` | 50 | Max buffered ICE candidates per peer before the remote has set remote description |
| `MAX_PEERS` | 50 | Max concurrent peer states per session; additional join frames are silently ignored |
| `MAX_PAYLOAD_BYTES` | 262144 (256 KiB) | Max size for data-channel messages and relay blobs; oversized payloads are dropped |

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
