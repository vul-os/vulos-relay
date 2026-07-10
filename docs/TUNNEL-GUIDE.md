# Tunnel Guide

This chapter is the operator's deep dive into the Vulos reverse tunnel: the wss+yamux
protocol and its exact handshake, the connection lifecycle from dial to teardown, how
reconnects and dead-peer detection behave, how one connection multiplexes many requests,
the SSRF guards on both ends, the direct-first/relay-fallback negotiation, and — just as
important — what traffic deliberately does **not** traverse the relay. Everything here is
grounded in `tunnel/agent`, `tunnel/server`, `tunnel/internal/wire`, and `tunnel/direct`;
file references point at the authoritative code.

---

## Transport stack

```
public HTTPS request ──► relay ──► yamux stream ──► agent ──► TCP to 127.0.0.1:PORT
                                     inside ONE
                          wss:// WebSocket the agent dialed
```

Layer by layer, from the agent's point of view:

1. **TLS** — the agent dials `wss://` to the relay's control endpoint. TLS uses system
   roots by default; a pinned CA can be supplied (`agent.Options.TLSConfig`), and
   `-insecure` / `InsecureSkipVerify` exists for local testing only.
2. **WebSocket** — one outbound connection to `/_vulos-relay/control`
   (`wire.ControlPath`) with subprotocol `vulos-relay.v1` (`wire.Subprotocol`) and
   `Authorization: Bearer <token>`. WebSocket is the transport because it is
   edge/CDN/TLS-termination friendly and needs only outbound 443.
3. **JSON handshake** — a single request/response before anything else (below).
4. **yamux** — after the ack, both sides hand the same `net.Conn` to
   [`hashicorp/yamux`](https://github.com/hashicorp/yamux). The **relay is the yamux
   client** (it opens streams); the **agent is the yamux server** (it accepts them).
5. **HTTP/1.1 per stream** — each yamux stream carries exactly one plain HTTP/1.1
   request and its response, with no extra framing. `http.ReadRequest` /
   `Request.Write` / `http.ReadResponse` are used directly on the stream, which is
   also what makes WebSocket-upgrade passthrough transparent.

### The register handshake

Defined in [`tunnel/internal/wire/wire.go`](../tunnel/internal/wire/wire.go). Bounded at
8 KiB per message (`wire.MaxControlMessage`); the server reads it under a 15 s deadline.

```jsonc
// agent → server
{"type":"register", "name":"box1", "token":"…",
 "agentVersion":"vulos-relay-agent/0.2",       // informational, never trusted
 "directEndpoint":"https://box1.example.com"}  // optional, untrusted until verified

// server → agent
{"type":"register_ack", "ok":true,
 "publicUrl":"https://box1.relay.example.com",
 "directEndpoint":"https://box1.example.com",  // only if the relay VERIFIED it
 "directVerified":true,
 "directError":""}                              // short reason when rejected (advisory)
```

The token travels both in the `Authorization` header and (optionally) in the frame; if
both are present they **must agree** or the registration is rejected with
`token mismatch`. The header is what edge/CDN auth layers can see; the frame token lets
non-header transports work. On failure `ok:false` carries a short, non-leaky `error`:
`bad registration`, `invalid name`, `unauthorized`,
`relay not permitted for this account`, `name unavailable`, or `session error`.

### yamux roles and tuning

From `serverYamuxConfig()` ([control.go](../tunnel/server/control.go)) and
`yamuxConfig()` ([conn.go](../tunnel/agent/conn.go)):

| Setting | Relay (yamux client) | Agent (yamux server) |
|---|---|---|
| Keepalive | on, every **10 s** | on, every **20 s** |
| ConnectionWriteTimeout | 10 s | 15 s |

Keepalive is the dead-peer detector: a hard-killed agent's name frees on the next missed
keepalive (order of ~10 s), while a clean `Stop()` frees it immediately. The WebSocket
read limit is disabled on both sides (`SetReadLimit(-1)`) because yamux frames and
tunneled bodies can be large — bounding happens at the HTTP layer instead (below).

---

## Connection lifecycle

The agent's observable states (mirroring wede's tunnel manager vocabulary):
`stopped` → `starting` → `connected` → (`error` | `starting` …). See
[`tunnel/agent/agent.go`](../tunnel/agent/agent.go).

1. **`Start(ctx)`** validates options — server URL, token, name, and the loopback check
   on `LocalAddr` — and returns immediately; a background `maintain` loop does
   everything else. `Start` never blocks on the network.
2. **Dial + register** run under `HandshakeTimeout` (default 15 s). `http`/`https`
   server URLs are normalized to `ws`/`wss`; any base path the operator mounted the
   relay under is preserved and `/_vulos-relay/control` appended.
3. On the relay, the connect walks a fail-closed gauntlet **in order**
   ([control.go](../tunnel/server/control.go)):
   1. per-source-IP control-connection rate limit (`429` before the WS upgrade is
      spent),
   2. bearer-present pre-check (`401` before upgrade — anonymous clients never cost an
      upgrade),
   3. WS upgrade requiring the `vulos-relay.v1` subprotocol,
   4. register frame read (bounded, deadline-guarded) + name normalization,
   5. `TokenStore.Authorize(token, name)` — constant-time, fail-closed,
   6. entitlement gate for account-bound tokens (fail-closed at connect),
   7. optional direct-endpoint verification (only after auth; non-fatal),
   8. registry add — name collision or `MaxAgents` capacity refuses with
      `name unavailable`.
4. **`connected`** — the ack carries the public URL; the agent starts accepting yamux
   streams, one goroutine per stream. The relay parks in `<-mux.CloseChan()` for the
   session lifetime.
5. **Teardown** — any of: agent `Stop()` (immediate name release), network drop
   (keepalive miss), relay-side revocation sweep cut, or relay shutdown. The registry
   release is guarded against fast-reconnect races (it only removes the entry if it
   still belongs to that exact session).

### Reconnects

The `maintain` loop ([conn.go](../tunnel/agent/conn.go)) retries forever until its
context is cancelled:

- Backoff starts at **500 ms**, doubles per attempt, and is capped at `MaxBackoff`
  (default **30 s**).
- Sleep uses **full jitter**: a uniform random duration in `[0, backoff]`, so a relay
  restart does not produce a thundering herd of synchronized re-dials.
- A *clean* session end (relay closed the session, EOF, yamux shutdown) is treated the
  same as an error for retry purposes — status flips back to `starting` and the loop
  re-dials.
- The backoff is **not** reset on a successful session within the loop's lifetime; it
  re-arms at 500 ms only when the agent is restarted via `Stop()`/`Start()`.
- Each reconnect uses a per-connection watcher context so a dead session never leaks a
  goroutine under churn.

Server-side, a re-registration of a name that departed within the last 2 minutes is
counted as a reconnect in metrics (`vulos_relay_reconnects_total`) — useful for spotting
flapping agents.

**Consequence for name takeover:** a live name is held by exactly one session,
first-come. If the old session is dead-but-not-yet-detected (hard kill), a reconnecting
agent can be refused with `name unavailable` for up to ~one keepalive miss (~10 s) until
the stale session is reaped; its backoff loop then succeeds on a later attempt.

---

## Multiplexing: the request path

Every inbound public request is handled independently
([proxy.go](../tunnel/server/proxy.go)):

1. **Routing.** Subdomain mode extracts a single label from `<name>.<relay-domain>`
   (nested labels are rejected — no `a.b.relay.example.com`); path mode (if
   `-path-mode`) matches `/t/<name>/rest` and forwards `rest` (a bare `/t/<name>`
   forwards `/`). Unmatched → `404 no such tunnel`. The public listener also answers
   `GET /healthz` (`ok agents=N`) and owns a small set of relay control routes matched
   *before* name routing: `/_vulos-direct/resolve`,
   `/api/meet/host/{register,heartbeat,deregister,resolve}`, and `/api/s2s/notify`.
2. **Rate limits.** Global token bucket (default 500 req/s, burst 1000), then
   per-tunnel bucket (default 50 req/s, burst 100). Both return `429` with
   `Retry-After: 1`.
3. **Session lookup.** Known name shape but no live agent → `502 tunnel offline`.
4. **Mid-session entitlement.** Account-bound sessions over quota / denied → `402`
   (fail-open on a transient control-plane error — a blip never cuts a live tunnel).
5. **Stream slot.** Per-agent concurrency cap (`MaxStreamsPerAgent`, default 128
   in-flight streams). Exhausted → `503 tunnel busy`.
6. **Body cap.** `http.MaxBytesReader` at `MaxRequestBytes` (default 256 MiB) — a
   *streaming* wrapper, so the cap bounds abuse duration, not relay RAM. Overflow
   yields a clean `413` with the limit echoed, not a confusing gateway error.
7. **One yamux stream** is opened into the agent; the request is written to it after
   header sanitization (hop-by-hop headers stripped, `X-Forwarded-For` / `X-Real-IP` /
   `X-Forwarded-Proto` rewritten per the trust-proxy posture — see
   [SECURITY.md](SECURITY.md#header-hygiene-no-client-ip-spoofing)).
8. **Time-to-headers deadline.** `RequestTimeout` (default 60 s) bounds how long the
   agent may take to return response *headers*. This exists to defeat half-dead agents
   — ones whose keepalive still answers but which never service a stream — from pinning
   all 128 slots and bricking the tunnel with `503`s. The deadline is **cleared once
   headers arrive**, so long-lived bodies (SSE, big downloads) stream indefinitely.
9. The response is streamed back; response-body bytes are counted for metrics/metering
   as they flow.

On the agent side ([forward.go](../tunnel/agent/forward.go)), each accepted stream is
served by its own goroutine: read one HTTP request, dial the **one configured loopback
target** (10 s dial timeout), rewrite the request to origin form with `Host` set to the
local target, forward, stream the response back. Local dial failure →
`502 bad gateway` to the public client, with `local dial failed: …` in the agent log.

### WebSocket (and other upgrade) passthrough

- **Relay side** ([proxy_ws.go](../tunnel/server/proxy_ws.go)): a request with
  `Upgrade: websocket` + `Connection: upgrade` hijacks the client connection, forwards
  the upgrade over the stream (with `Connection`/`Upgrade` restored after hop-by-hop
  stripping), relays the app's `101`, then splices raw bytes both ways. The
  time-to-headers deadline is cleared after the `101`, so a WS session lives as long as
  both sides keep it. A non-101 answer from the app is relayed as-is.
- **Agent side**: after forwarding the upgrade and seeing the local app's `101`, it
  switches to a raw duplex byte copy, honoring any bytes the buffered readers already
  consumed past the header boundary. A plain request that the local app nevertheless
  answers with `101 Switching Protocols` also falls back to raw duplex copy, so
  non-WS upgrade protocols work too.
- **SSE** needs nothing special: it is a plain response with an unbounded body, which
  is exactly why the server sets no `WriteTimeout` on the public listener and clears
  the stream deadline after headers.

### Bounds recap

| Bound | Default | Overflow behavior |
|---|---|---|
| Concurrent agents | 256 (`-max-agents`) | connect refused: `name unavailable` |
| In-flight streams per agent | 128 | `503 tunnel busy` |
| Request header size | 64 KiB | rejected by the HTTP server |
| Request body size | 256 MiB (`-max-request-bytes`; `0`=default, negative refused) | `413` |
| Control handshake message | 8 KiB | registration fails |
| Control-conn idle timeout | 90 s (`IdleTimeout`, keepalive budget) | dead-peer reap |
| Time-to-response-headers | 60 s (`RequestTimeout`) | `502` |

---

## SSRF guards

Two independent guards, one per direction of "who could make whom dial where".

**Agent side — the loopback lock.** The agent forwards **only** to its single
configured `-local` target. The target must be `localhost` or a loopback IP; this is
enforced at startup (`validateOptions`/`ensureLoopback`) and **re-checked on every
stream** before dialing, so a hostname that later resolves off-loopback is refused
(`403 forbidden`). Nothing in the relayed request — `Host`, URL, headers — influences
where the agent connects. A compromised or malicious relay cannot use an agent as a
proxy into the box's LAN, cloud metadata (`169.254.169.254`), or anything but the one
advertised port.

**Relay side — the direct-probe screen**
([directprobe.go](../tunnel/server/directprobe.go)). When a box advertises a direct
endpoint (or registers an SFU host), the relay must probe a box-supplied URL — classic
SSRF surface, guarded in depth:

- `https://` bare origins only: no path, query, fragment, or userinfo may be smuggled
  in.
- The host is screened at **parse time**: IP literals must be public (not loopback,
  RFC 1918, link-local, CGNAT `100.64/10`, ULA, unspecified, multicast, documentation,
  benchmarking, `240/4`, `0/8`); hostname literals `localhost` / `*.localhost` /
  `*.internal` / `*.local` are refused outright.
- The dialer re-screens **every resolved IP at connect time** — the anti-DNS-rebind
  control. If *any* answer is non-public, the whole dial is refused.
- IPv6 transition addresses are unwrapped and the **embedded IPv4 re-screened**:
  NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32` — so `64:ff9b::7f00:1`
  (which carries `127.0.0.1`) cannot reach an internal service through a NAT64 gateway.
- Redirects are never followed; the probe response read is capped at 1 KiB; the whole
  probe is bounded at 8 s.
- Verification runs **only after** token auth + entitlement pass — an unauthorized box
  can never make the relay probe an arbitrary target.

---

## Direct-first, relay-fallback

The doctrine: reach a box over its **own** public endpoint whenever it has one
(near-native latency, full bandwidth, zero relay metering), and over the always-works
relay tunnel otherwise. It is ICE-like — try the fast candidate, fall back to the
relayed one — and every stage fails **toward the relay path**, never toward
unreachability.

1. **Advertise.** The agent sets `-direct https://box1.example.com` (or
   `VULOS_RELAY_DIRECT_ENDPOINT`). Empty means relay-only — the right choice for
   NAT'd/CGNAT boxes.
2. **Verify.** At register time the relay GETs `{endpoint}/_vulos-direct/probe`
   (`wire.DirectProbePath`) with a fresh 256-bit nonce in the `X-Vulos-Direct-Probe`
   header and requires the box to echo the nonce back (constant-time compared).
   Reachability + ownership proof in one round trip: only the host actually serving
   that TLS endpoint sees the nonce, so a box cannot advertise a victim's address to
   hijack its traffic. The box must serve this path **unauthenticated** on the same
   public TLS listener it advertises (it only ever echoes the relay's own nonce).
   Failure is non-fatal: `directError` in the ack tells the box why (`unreachable`,
   `ownership proof failed`, `not https`, …) and the tunnel comes up relay-only.
3. **Discover.** A client GETs `/_vulos-direct/resolve` on the tunnel's relay URL
   (host-routed to the name like any request) → `{"name","directEndpoint","direct"}`.
   The relay only ever returns an endpoint **it verified this session**;
   unknown/offline tunnels and disabled-direct relays return `direct:false` — never an
   error the client must special-case.
4. **Dial + fall back.** The [`tunnel/direct`](../tunnel/direct/direct.go) client
   package wraps this: `Resolver.Resolve(ctx, relayBase)` returns a `Resolution` whose
   `OrderedBaseURLs()` is `[direct, relay]` or `[relay]`. Any discovery failure (relay
   down for discovery, non-200, decode error) yields a relay-only resolution with a
   **nil error** — a failed fast-path lookup must never break reachability. The client
   only trusts `https` direct endpoints. Both URLs speak the identical app API with the
   identical auth, so fallback is just swapping the base URL.

Relay-wide kill switch: `Config.DisableDirect` (library) ignores advertised endpoints
entirely; resolve then always answers `direct:false`.

**Note on metering:** direct traffic never touches the relay and is therefore never
metered by it — by design. See [METERING-BILLING.md](METERING-BILLING.md).

---

## What traverses the relay — and what doesn't

The relay carries **web-shaped traffic only**: HTTP request/response, WebSocket, and
SSE. It is deliberately not the transport for workloads with a better path:

| Traffic | Path | Relay's role |
|---|---|---|
| App HTTP/API, SSE, WebSocket | relay tunnel (or verified direct endpoint) | full reverse proxy |
| **Real-time media (calls/meetings)** | WebRTC over **ICE/TURN**, mesh or an SFU node | **none on the RTP** — media never rides the tunnel |
| Big-call SFU placement | box's own SFU worker | relay only *registers and resolves* the node (below) |
| Cross-instance notifications | relay `POST /api/s2s/notify` → target box's existing tunnel | forwarder (fixed target path, same-account only) |
| Browser P2P collaboration (`@vulos/relay-client` SDK) | WebRTC data channels + the host app's HTTP relay-circuit | not this subsystem at all |

**The real-time media exception, precisely.** Latency-sensitive RTP does not tolerate a
TCP-based, HTTP-shaped tunnel: one lost packet stalls every multiplexed stream behind it
(head-of-line blocking), and retransmission is the wrong recovery for audio/video. So
calls ride WebRTC — ICE for NAT traversal, TURN as the media-relay fallback — entirely
outside this tunnel. The one thing the tunnel subsystem contributes is *placement*: the
optional **SFU-host registry** ([sfuhost.go](../tunnel/server/sfuhost.go)) lets a
token-authorized box register its own SFU worker (`POST /api/meet/host/register`,
heartbeat within a 90 s TTL, `deregister`), with the endpoint proven by the **same**
nonce-echo, SSRF-guarded verifier as the direct fast path. Clients then
`GET /api/meet/host/resolve?name=<their-own-tunnel-name>` — scoped by name so one
account's clients can never be handed another account's SFU. The whole registry is off
by default (`-sfu-host-registry` / `VULOS_RELAY_SFU_HOST_REGISTRY=1`; off ⇒
register/heartbeat/deregister `404`, resolve says `available:false`), and even enabled
it is inert until a box registers. The SFU's RTP still never touches the relay.

**Honest limitation:** this is not a raw TCP/UDP tunnel. There is no SSH/arbitrary-TCP
mode (unlike `frp`'s TCP proxy). Non-HTTP protocols are out of scope.

---

## Graceful drain and restarts

On `SIGTERM`/`SIGINT` (what Fly and most orchestrators send on deploy),
`vulos-relayd`:

1. flips `/readyz` to `503` (draining) so load balancers stop routing to it,
2. stops accepting new connections and lets in-flight requests finish (bounded — the
   CLI allows 25 s),
3. stops the background loops and performs a **final usage flush** so the last metered
   deltas are not lost,
4. exits; agents notice the drop and reconnect (with jitter) to the replacement
   instance.

A second signal kills hard. Embedders get the same via `Server.Shutdown(ctx)` /
`Server.Close()`.

One flat spot to plan around: there is **no multi-relay HA or shared session
directory** — a name is served by whichever single relay instance its agent connected
to. Run one relay per region/cell and scale vertically, or shard names across relays
yourself.

---

## See also

- [TUNNEL.md](TUNNEL.md) — design summary, full flag/env tables, DNS + deploy shapes.
- [SECURITY.md](SECURITY.md) — trust model, auth, rate limits, revocation.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — symptom-driven diagnosis.
