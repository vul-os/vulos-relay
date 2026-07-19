# The Rendezvous role — an open, key-addressed reachability protocol

Rendezvous is the **open reachability substrate** a relay can serve so that apps
get **peer discovery** and **content-opaque WebRTC signaling** (plus a short-TTL
mailbox) from **any conforming node** — a self-hosted `vulos-relayd` or a Vulos-run
one — with **no Vulos OS and no host-box `/api/peering/*` backend required**.

`vulos-relayd` is the **reference implementation** (`tunnel/rendezvous`), but this
document is the *protocol*: anyone can implement a compatible node or client. It is
one of the VulOS substrate **Reachability roles**
(`announce` / `resolve` / `signal` / `mailbox`, key-addressed).

> **Sibling role.** Cache/pin — serving **public, self-verifying** DMTAP-PUB
> objects — is documented in **[PUBCACHE.md](PUBCACHE.md)**. It is the one relay
> role that is *not* content-blind, which is why it is opt-in and separate.

> **Content-blind by construction.** A rendezvous node never inspects, decrypts, or
> dials application payloads. It stores opaque bytes keyed by public key, gates
> writes with signatures, and hands blobs to the holder of the private key. It makes
> **no outbound connection** on behalf of a request (announced endpoints are stored
> and echoed, never dialed), so it has **no SSRF surface** of its own.

---

## 1. Identity & addressing

Every participant is an **Ed25519** keypair. A participant's **address** is its
32-byte public key encoded as **unpadded base64url** (`base64url(pub)` — URL-safe,
so it drops straight into a path segment). This single encoding is used everywhere:
URL path segments, JSON fields, and inside the signed canonical message.

- **Signatures**: Ed25519 (64 bytes), unpadded base64url.
- **Nonces / opaque payloads / blob ids**: unpadded base64url.
- **Timestamps**: unix seconds (integer).

## 2. Canonical signing message

Every **write** is signed over a **domain-separated, length-prefixed** byte string
so no delimiter can be forged across fields and a signature minted for one message
type can never be replayed as another.

To build the message: for the **domain tag** and then each **field** in order,
write a **4-byte big-endian length** followed by the field's **UTF-8 bytes**. All
fields are strings — binary values as base64url, numbers as base-10 decimal.

```
msg = concat( for s in [domain, field0, field1, ...]:
                uint32be(len(utf8(s))) || utf8(s) )
sig = ed25519_sign(private_key, msg)          // base64url
```

Reference: `canonicalMessage()` in `tunnel/rendezvous/keyaddr.go` (Go) and
`canonicalMessage()` in `client/src/rendezvous.js` (JS). The two are locked to an
identical **test vector** (`canonical_test.go` ⇄ `rendezvous.test.js`): a one-byte
divergence fails one side.

Domain tags (versioned; bump on any wire change):

| Message | Domain tag |
|---|---|
| announce | `vulos-rdv/announce/1` |
| withdraw | `vulos-rdv/withdraw/1` |
| signal deposit | `vulos-rdv/signal-deposit/1` |
| signal poll | `vulos-rdv/signal-poll/1` |
| signal ack | `vulos-rdv/signal-ack/1` |
| mailbox deposit | `vulos-rdv/mailbox-deposit/1` |
| mailbox poll | `vulos-rdv/mailbox-poll/1` |
| mailbox ack | `vulos-rdv/mailbox-ack/1` |

## 3. Freshness & replay protection

Every write carries a `ts` (unix seconds) and a random `nonce`. A node accepts a
write only if:

- `ts` is within **±clock-skew** of the node's clock (default **5 min**) — bounds
  how long a captured request stays replayable and rejects far-future timestamps; **and**
- the `(signing-key, nonce)` pair has **not been seen** within the freshness window.

Both the timestamp check and the nonce set are what make a captured request
un-replayable. The seen-set is memory-bounded (entries expire after the skew window;
a hard cap sheds a nonce flood).

## 4. Authentication model (fail-closed)

| Operation | Signed by | Why |
|---|---|---|
| `announce`, `withdraw` | the **announcing key** | you may only publish/withdraw presence for your own key |
| `signal`/`mailbox` **deposit** | the **sender key** | accountability + replay protection — **not** a social-graph gate (the node has no contact store; the *recipient's client* discards blobs from unknown senders) |
| `signal`/`mailbox` **poll**, **ack** | the **recipient key** | proves possession of the private key — this is what authorizes **reading** that mailbox |
| `resolve`, `ice` | *(unauthenticated read)* | presence is self-signed public data; ICE is STUN URLs + short-lived TURN creds |

Any signature/freshness failure is rejected (`401`/`409`) with a **bounded, non-leaky**
error string. Nothing is stored on a failed write.

`resolve` reads can be closed off entirely with `DisablePublicResolve` (the directory
becomes signal/mailbox-only).

---

## 5. Endpoints

All routes are mounted under a configurable prefix (default `/rendezvous`) and — on a
relay that also runs the reverse tunnel — served **only on the relay's apex host**, so
a tunnel subdomain `<name>.<domain>` keeps full control of its own `/rendezvous/*`
paths.

```
POST {p}/announce             signed presence upsert            (fail-closed)
POST {p}/withdraw             signed presence removal           (fail-closed)
GET  {p}/resolve/{key}        public presence read              (open by default)
POST {p}/signal/{to}          deposit opaque WebRTC signal      (sender-signed)
POST {p}/signal/{key}/poll    pick up signals (long-poll)       (recipient-signed)
POST {p}/signal/{key}/ack     delete consumed signals           (recipient-signed)
POST {p}/mailbox/{to}         deposit opaque encrypted blob     (sender-signed)
POST {p}/mailbox/{key}/poll   pick up blobs (long-poll)         (recipient-signed)
POST {p}/mailbox/{key}/ack    delete consumed blobs             (recipient-signed)
GET  {p}/ice                  ICE (STUN + ephemeral-cred TURN)  (open)
GET  {p}/healthz              liveness                          (open)
```

### 5.1 ANNOUNCE

Publish/refresh your presence. `endpoints` are **opaque connection hints** (URLs,
multiaddrs, …) the node stores and echoes but **never dials**. `meta` is an opaque
app-defined blob (advertised capabilities, etc.). TTL is clamped to the node's max
(default 30 min; default 5 min when 0).

```
POST /rendezvous/announce
{ "key": "<b64url pub>", "endpoints": ["wss://box/tunnel", "https://1.2.3.4:443"],
  "meta": "caps=chat,files", "ttl": 300,
  "nonce": "<b64url>", "ts": 1700000000, "sig": "<b64url>" }
→ 200 { "ok": true, "key": "...", "ttl": 300, "expires_at": 1700000300 }
```
Canonical fields: `key, ts, ttl, nonce, meta, endpoints[0], endpoints[1], …`

### 5.2 RESOLVE

```
GET /rendezvous/resolve/{key}
→ 200 { "key": "...", "online": true, "endpoints": [...], "meta": "...", "expires_at": 1700000300 }
→ 404 { "key": "...", "online": false }
```

### 5.3 SIGNAL — WebRTC offer / answer / ICE

Short-TTL, content-opaque exchange between two keys. `payload` is opaque base64url
(the WebRTC SDP / ICE candidate blob — the node never parses it; encrypt at the app
layer if you want it hidden from the operator too).

```
POST /rendezvous/signal/{to}
{ "from": "<b64url pub>", "to": "<b64url pub>", "payload": "<b64url opaque>",
  "ttl": 0, "nonce": "...", "ts": ..., "sig": "<by from>" }
→ 201 { "ok": true, "id": "<blob id>", "expires_at": ... }
```
Canonical fields: `from, to, ts, ttl, nonce, payload`

The recipient **long-polls** its own inbox (proving key ownership) and **acks** what
it consumes (delete-on-ack ⇒ at-least-once delivery across a crash):

```
POST /rendezvous/signal/{key}/poll
{ "key": "<b64url pub>", "wait": 20, "nonce": "...", "ts": ..., "sig": "<by key>" }
→ 200 { "key": "...", "blobs": [ { "id","from","payload","ts","exp" }, ... ] }

POST /rendezvous/signal/{key}/ack
{ "key": "...", "ids": ["id1","id2"], "nonce": "...", "ts": ..., "sig": "<by key>" }
→ 200 { "deleted": 2 }
```
Poll canonical fields: `key, ts, nonce` (`wait` is an unsigned hint). Ack canonical
fields: `key, ts, nonce, ids[0], ids[1], …`

`wait` requests a **long-poll**: the node holds the request up to `min(wait,
MaxPollWait)` (default cap 30 s) and returns the moment a blob is deposited — so a
callee learns of an incoming offer with no busy-polling.

### 5.4 MAILBOX — short-TTL content-blind buffer

Identical deposit/poll/ack shape as signal (different domain tags + path), tuned for
**offline delivery** rather than live negotiation: bigger blobs, TTL up to **48 h**.
This is DMTAP §14.3-shaped — a **buffer, not an archive**: a recipient offline past
the TTL loses undelivered blobs; durability lands at the recipient's edge once
picked up.

Default caps (all configurable): per-blob **25 MiB**, per-recipient **256 blobs /
100 MiB**, TTL cap **48 h**. Deposits over a cap return `413` (too large) or `507`
(quota). The signal queue uses tighter caps (64 KiB/blob, 2 min default / 10 min max
TTL) because a stale negotiation is worthless.

### 5.5 ICE

```
GET /rendezvous/ice[?key=<hint>]
→ 200 { "ice_servers": [
    { "urls": ["stun:stun.example:3478"] },
    { "urls": ["turn:turn.example:3478?transport=udp"],
      "username": "1700043200:<hint>", "credential": "<b64 HMAC-SHA1>", "ttl": 43200 } ] }
```

STUN entries are static. TURN entries, when a TURN secret is configured, carry
**short-lived coturn-REST credentials** (`username = "<expiry-unix>[:<hint>]"`,
`credential = base64(HMAC-SHA1(secret, username))`) — the long-term secret never
leaves the node and a leaked credential self-expires. The `key` query param is an
**opaque bookkeeping hint** folded into the TURN username; it authenticates nothing.

---

## 6. A minimal peering handshake

```
A: announce(endpoints=[...])                      # A is discoverable
B: resolve(A.key) -> {online, endpoints}          # B finds A
B: ice() -> iceServers                             # B gets STUN/TURN
B: signal.deposit(to=A.key, payload=OFFER)         # opaque SDP offer
A: signal.poll(wait) -> [{from:B, payload:OFFER}]  # A wakes, reads offer
A: signal.deposit(to=B.key, payload=ANSWER); ack   # SDP answer back
A,B: signal.deposit(... ICE candidates ...)        # trickle ICE, both directions
A,B: <WebRTC data channel / media established>     # relay is now out of the path
```

When a peer is offline, senders fall back to `mailbox.deposit(to=peer, blob)` and the
peer drains it on next connect. The relay only ever moves opaque bytes.

---

## 7. Rate limits & bounds

- Per-key token buckets: announce (by announcing key), deposit (by sender key),
  poll/ack (by recipient key), plus an aggregate global bucket. `429` on exceed.
- Bounded request bodies; unknown JSON fields and trailing garbage rejected.
- Every store (presence, signal, mailbox, replay-nonce set, rate buckets) is
  memory-bounded by TTL sweeps + hard key caps, so a flood of distinct keys/nonces
  can't exhaust the node.
- **No secrets in logs**: only public keys (truncated), endpoint counts, and TTLs are
  logged; payloads, signatures, and the TURN secret never are.

## 8. Reference client & server

- **Server**: `tunnel/rendezvous` in this repo; enable on `vulos-relayd` with
  `-rendezvous` (see `docs/TUNNEL.md` / `--help` for the STUN/TURN/prefix flags). It
  is **CP-optional** and holds only soft-state, so it runs fully self-hosted.
- **Client**: `@vulos/relay-client` exposes `RendezvousClient` + `RendezvousIdentity`
  (`import { RendezvousClient } from '@vulos/relay-client/rendezvous'`), and
  `FabricClient` accepts a `rendezvousBaseUrl` option to use any relayd's rendezvous
  surface instead of a host box's `/api/peering/*`.

---

## 9. Using `FabricClient` without a host box

`FabricClient` normally signals over a host box's `/api/peering/*` WebSocket. Set
**`rendezvousBaseUrl`** and it instead runs its **complete** signaling lifecycle —
presence discovery, offer/answer, trickle-ICE, polite-peer negotiation — over a
relay's open `announce`/`resolve`/`signal` surface. **No Vulos OS, no host box.**
Leave the option unset and the host-box WebSocket path is used exactly as before;
the two paths are both fully supported and chosen per config.

```js
import { FabricClient } from '@vulos/relay-client/fabric'

const fabric = new FabricClient({
  sessionId: 'doc-42',
  peerId:    myUserId,
  rendezvousBaseUrl: 'https://relay.example.com',   // ← turns on OS-free mode
  // rendezvousIdentity: <RendezvousIdentity | 32-byte secret>,  // optional (see below)
})
fabric.addEventListener('message', ({ detail }) => …)
await fabric.join()          // announces, discovers peers, negotiates WebRTC
fabric.send(bytes)           // P2P once the data channel is up
```

`fabric.rendezvous` exposes the underlying `RendezvousClient` (its `.key` is this
peer's Ed25519 rendezvous address). ICE is auto-derived from the relay.

### 9.1 Two distinct identities (identity bridging)

Rendezvous **writes** are authenticated by **Ed25519**; the `FabricClient` **peer
handshake** is authenticated by a per-session **ECDSA-P256** key. These stay
separate and complementary:

| Identity | Signs | Authenticates |
|---|---|---|
| **Ed25519** rendezvous key | the outer rendezvous envelope (announce / deposit / poll) | the write, to the *relay* — accountability + replay protection |
| **ECDSA-P256** session key | the inner `join`/`offer`/`answer`/`ice` payload (carried opaquely) | the *peer*, end to end — DTLS-fingerprint pinning, TOFU key binding, X3DH prekeys, anti-downgrade |

The ECDSA pubkey rides **inside** the opaque signal payload the relay never parses,
so the peer-auth handshake is **byte-for-byte identical** to the host-box path — the
relay only moves opaque bytes keyed by Ed25519 public key and can neither read nor
forge the inner handshake.

By default the Ed25519 rendezvous identity is **ephemeral per session** (generated
fresh, matching the ephemeral per-session ECDSA key — this preserves the existing
security model, which has no persistent cross-session identity). Pass
**`rendezvousIdentity`** (a `RendezvousIdentity` or a 32-byte secret) to use a
**stable** rendezvous address across sessions.

> **Open-mode trust.** With no host-box JWT, a `peerId` is *self-asserted* and bound
> **TOFU** (first ECDSA key seen for a peerId wins), exactly as in the host-box
> model — the boundary is just "knows the sessionId" rather than "authenticated by
> the host". The real cryptographic identity is the pinned ECDSA key; the
> peerId↔rendezvous-key mapping is a routing hint the handshake does not trust. Use
> **unguessable session ids** for private rooms.

### 9.2 How discovery works (the session "room" board)

Rendezvous is key-addressed point-to-point, so there is no server-side room to
broadcast joins into. `FabricClient` synthesises one: a **deterministic Ed25519
"room" identity is derived from the `sessionId`** (every member computes the same
key), and its signal inbox is used as a shared, **content-blind presence board**.
Each member deposits its signed `join` (the same payload the WS path broadcasts,
plus its own rendezvous address) onto the board and long-polls the board to
discover peers; `offer`/`answer`/`ice` are then addressed point-to-point to each
peer's own rendezvous inbox. Board pickups are a **non-destructive peek** (§4), so
every member sees every member; heartbeats refresh presence and a `leave` tombstone
drops it. The room key is *not secret* — knowing the `sessionId` grants membership.

### 9.3 Presence, live cursors, and the relay fallback

- **Roster + live cursors work unchanged.** `PresenceManager` (`usePresence`) and
  `useLiveCursors` ride `FabricClient`'s **data channel** (`send()` / `message` /
  `state`), which is transport-agnostic — they behave identically whether signaling
  ran over the host box or over rendezvous. The dedicated host **`/api/peering`
  presence WebSocket** is a *separate* feature and remains **host-box-only**.
- **P2P-failure fallback** (when WebRTC cannot connect) uses the rendezvous
  **mailbox** in this mode: the same ECDSA-signed, XChaCha20-Poly1305-sealed
  envelope the host-box relay circuit uses, opaque to the relay. Forward secrecy
  degrades gracefully to **signed-prekey-only X3DH** (there is no host-box
  one-time-prekey *claim* endpoint), and is never dropped silently for a v2 peer.
