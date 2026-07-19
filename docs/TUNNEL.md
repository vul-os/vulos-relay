# Vulos Sovereign Reverse Tunnel

A self-hosted reverse tunnel that lets a loopback-bound Vulos box publish itself on
the public internet **without opening any inbound ports, without a static IP, and
without any third-party relay** (it replaces external `frp`).

The box runs an **agent** that dials a **single outbound `wss://` connection** to a
Vulos **relay server** you control. The relay serves a public URL and reverse-
proxies inbound requests back down that one connection to the box's local port.

```
   public client                    relay server (public)                box (loopback only)
        │  https://box1.relay.example.com     │                                 │
        ├────────────────────────────────────►│                                 │
        │                                      │  yamux stream (1 per request)   │
        │                                      ├────────────────────────────────►│  agent
        │                                      │   over ONE outbound wss control │   │ dials localhost:8080
        │                                      │   connection the AGENT opened   │   ▼
        │◄─────────── response ────────────────┤◄────────────────────────────────┤  local app
```

Only **outbound 443** is required from the box. The box binds nothing inbound.

---

## Transport & design

- **One outbound connection.** The agent opens a single `wss://` WebSocket to the
  relay's control endpoint (`/_vulos-relay/control`). WebSocket is edge/CDN/TLS-
  termination friendly and only needs outbound 443.
- **Multiplexing with yamux.** After a JSON handshake, both sides hand that
  WebSocket's `net.Conn` to [`hashicorp/yamux`](https://github.com/hashicorp/yamux).
  The **relay is the yamux client** (opens one stream per inbound public request);
  the **agent is the yamux server** (accepts streams, proxies each to its one local
  target). Each stream carries a plain HTTP/1.1 request/response — no extra framing —
  which is also what makes **WebSocket-upgrade passthrough** transparent.
- **Routing.**
  - **Subdomain mode (primary):** `https://<name>.<relay-domain>` — needs a wildcard
    DNS record `*.relay.example.com`.
  - **Path mode (fallback):** `https://<relay-domain>/t/<name>/…` — enable with
    `-path-mode` when you can't provision wildcard DNS.
- **Reconnect.** The agent maintains the tunnel with exponential backoff + full
  jitter and reconnects automatically after any drop.
- **Graceful drain.** On `SIGTERM`/`SIGINT` (what Fly and most orchestrators send on
  deploy/restart) the relay flips `/readyz` to draining, stops accepting new
  connections, lets in-flight requests finish (bounded), then flushes the final
  metered usage before exiting — so a rolling restart neither drops a live request
  mid-flight nor loses the last usage deltas. Agents reconnect to the replacement.

## Direct-IP fast path (optional, ICE-like)

A box with a public/static IP or hostname can serve the OS on its **own** public TLS
listener and let clients dial it **directly** — near-native latency, full bandwidth,
traffic that never touches (or is metered by) the relay — while still keeping the
relay tunnel as the always-works fallback for NAT'd/CGNAT boxes. It is off unless a
box opts in, and it is **never trusted on the box's word**:

- **Advertise.** The agent may set `DirectEndpoint` (a bare `https://host[:port]`
  origin); it is sent in the register frame alongside the relay tunnel. Empty means
  "relay only" (the default, always-works path).
- **Verify (reachability + ownership).** Before surfacing it to any client, the relay
  probes `{endpoint}/_vulos-direct/probe` over the public internet with a fresh
  256-bit nonce in `X-Vulos-Direct-Probe` and requires the box to **echo the nonce**.
  Only a box that actually serves that TLS endpoint sees the nonce, so echoing it
  proves control (a box cannot advertise a victim's IP/hostname to hijack its
  traffic). The probe is **SSRF-guarded** exactly like the agent's loopback guard:
  the host is screened before dial, the *resolved* IP is re-screened at connect
  (anti-DNS-rebind), only public IPs are allowed, and redirects are refused.
  Verification runs **only after** auth + entitlement pass — an unauthorized box can
  never make the relay probe an arbitrary target. A failure is **non-fatal**: the
  tunnel still comes up on the relay path.
- **Discover + fall back.** A client asks the relay
  `GET /_vulos-direct/resolve` (host-routed to the tunnel name, same as any public
  request); the relay returns the box's **verified** direct endpoint or `direct=false`.
  The client (see `tunnel/direct`) attempts the direct URL first and transparently
  falls back to the relay URL on any failure — same app, same auth, just a faster
  transport. Disable relay-wide with `Config.DisableDirect` (advertised endpoints are
  then ignored and every box is served purely over the relay tunnel).

## Real-time media (calls/meetings)

WebRTC media (RTP) **never rides the tunnel**. A box hosting a real-time app
(Jitsi, Element Call, a Matrix homeserver, etc.) is made **reachable** through the
relay for its HTTP/WS signalling and page load exactly like any other app, while the
media plane uses **ICE/TURN** directly. When a box also advertises a public
**direct endpoint**, the relay verifies it (below) and clients prefer that faster
path — which is the ideal transport for a self-hosted TURN/SFU node. The relay
itself is the **TURN-equivalent fallback** for HTTP/WS reachability; it is deliberately
**not** a first-party SFU or a media-placement service.

## Security model (fails closed — this is internet-facing)

- **Agent auth:** a per-agent **bearer token** (`Authorization: Bearer …`, also
  echoed in the register frame; they must agree). Validated with **constant-time**
  comparison. Unauthenticated control connections are rejected before/after upgrade.
- **Name binding:** a token may serve **only the name(s) it is granted**. Names
  cannot be hijacked — a live name is held by exactly one session (first-come);
  a second claimant is rejected, not swapped in.
- **SSRF guard:** the agent forwards **only** to its one configured `localhost:PORT`
  target — never to a host named by the relay or the request. Non-loopback targets
  (private IPs, `169.254.169.254`, arbitrary hosts, `0.0.0.0`) are refused at
  startup and re-checked per stream.
- **Bounds:** max concurrent agents, max concurrent streams/agent, request header
  size cap, request body size cap, control-message size cap, idle timeout, and
  keepalive-based dead-peer detection. The keepalive is **adaptive and idle-aware**
  (`tunnel/internal/keepalive`): it pings at the base interval (relay 10s / agent 20s)
  while a tunnel is active and backs off to a 60s idle interval after 2min of no
  streams, restoring on activity — cutting idle cost without ever evicting the session.
  Memory is bounded.
- **Rate limiting (429):** three memory-bounded token-bucket limiters sit on top of
  the hard caps above — control-connection attempts **per source IP** (throttles
  auth/CP churn *before* spending a WS upgrade; keyed on the real client IP — the
  observed peer when directly exposed, the left-most `X-Forwarded-For` entry behind a
  trusted edge, so one edge IP can't collapse a fleet into one bucket), public requests
  **per tunnel**, and
  an **aggregate global** cap across all tunnels. Each returns `429` (with
  `Retry-After`). Buckets are lazily created, idle-evicted, and key-capped so a flood
  of distinct keys cannot grow memory. All are configurable with safe defaults; a
  negative rate disables a limiter (trusted-edge / self-host).
- **Over-quota cut (402):** an account past its billing cap is cut with `402` on its
  next request (the CP's over-quota verdict from the usage report is fed straight into
  the entitlement gate instead of waiting for the gate TTL to lapse).
- **Token / credential revocation:** a leaked or retired credential is revoked without
  hand-editing the grants file. A file/env static revoked-list
  (`{"tokens":[],"names":[],"accounts":[]}`) and a runtime `RevokeToken` /
  `RevokeName` / `RevokeAccount` API are consulted **at connect** (refused) and by a
  periodic **live-session revocation sweep** that drops any matching tunnel promptly.
  For CP-linked installs, an entitlement `revoked:true` or a `404` for a
  previously-valid credential is a definitive revoke (reuses the existing entitlement
  poll — no new CP round trip). Connect stays fail-closed; mid-session stays fail-open
  on a transient CP blip but cuts on a definitive revoke.
- **Header hygiene / no client IP spoofing:** hop-by-hop headers are stripped both
  ways. The relay is the **ingress trust boundary**, so by default (directly
  internet-facing) it **overwrites** `X-Forwarded-For` / `X-Real-IP` /
  `X-Forwarded-Proto` with the **observed peer** — a public client cannot forge the
  source IP the box's app reads for allowlists/rate-limits/audit/geo.
  `-trust-proxy-headers` (env `VULOS_RELAY_TRUST_PROXY_HEADERS=1`) flips this to
  **trust a fronting proxy**: the incoming `X-Forwarded-For` is preserved and the
  peer (the edge) is appended, and the edge's `X-Forwarded-Proto` is honored. Enable
  it **only** when a trusted TLS-terminating edge/CDN actually fronts the relay (the
  Fly deployment — `fly.toml` sets it); enabling it while directly exposed re-opens
  the spoof. Internal errors are never leaked to clients (generic `502`/`403`/etc.).
- **Direct-endpoint SSRF guard (relay side):** before the relay surfaces a
  box-advertised direct endpoint it **probes** it, and the probe is
  screened both at parse time and at connect time (resolved-IP re-screen defeats
  DNS-rebind), refusing loopback/private/link-local/CGNAT/metadata/documentation
  targets. The screen also unwraps **IPv6 transition addresses** (NAT64
  `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32`) and re-screens the embedded
  IPv4, so an address like `64:ff9b::7f00:1` (which carries `127.0.0.1`) cannot be
  used to reach an internal service through a NAT64/6to4 gateway.
- **TLS everywhere:** run the relay behind an edge/CDN that terminates TLS, or give
  it `-cert`/`-key` to terminate itself. On the self-terminating path the relay pins an
  explicit hardened floor — **TLS 1.2 minimum + ALPN (`h2`, `http/1.1`)** — rather than
  inheriting Go-version-dependent stdlib defaults, and preserves an operator-supplied
  `TLSConfig` verbatim (e.g. a stricter TLS 1.3 floor).

## Honest limitations

- **HTTP(S)/WS only.** This tunnels HTTP and WebSocket. It is not a raw TCP/UDP
  tunnel (no SSH/arbitrary-TCP mode like `frp`'s TCP proxy). That covers Vulos web
  surfaces; non-HTTP protocols are out of scope for now.
- **Token stores.** Two are built in: a JSON grants file / env var (`server.NewStaticTokenStore`,
  with a static + runtime revoked-list), and a CP-backed store (`-cp-token-store`)
  that resolves each agent's install credential to its Vulos account against the
  control plane. `server.TokenStore` is still the seam for a signed-token or fully
  DB-backed store — those aren't implemented yet.
- **No multi-relay HA / sticky sessions.** A name is served by whichever single
  relay instance the agent connected to. Horizontal scaling of the relay tier needs
  a shared session directory (future work); today, run one relay per region/cell.
- **Dead-peer detection latency.** A hard-killed agent's name frees on the next
  keepalive miss — ~10s while the tunnel was active (base ping), up to ~70s (idle
  interval + write timeout) if it had already gone idle under the adaptive keepalive.
  A clean `Stop()` frees it at once. Note this is *slowed heartbeat*, not eviction:
  **true idle-session eviction** — closing an idle tunnel outright — is **planned, not
  implemented**.
- **Hosted-relay plaintext for NAT'd boxes.** A NAT'd box with no direct path is
  reached over a relay that terminates TLS, so a *hosted* relay sees that leg's
  plaintext (cookies/tokens included). This is the ratified posture, not a bug — use a
  verified direct endpoint or a self-run relay for relay-blindness. **SNI / TLS
  passthrough** (which would make a NAT'd box↔user leg opaque to a hosted relay) is
  **planned, not implemented**. See [SECURITY.md](SECURITY.md#planned-hardening).
- **Egress-metering billing model.** The meter counts proxied bytes as documented in
  [METERING-BILLING.md](METERING-BILLING.md); a move to an egress-based billing model
  is a future direction, **not** current behavior.
- **No per-request auth on the public side.** The relay exposes whatever the local
  app exposes; auth is the app's job (same as `frp`). The relay only authenticates
  *agents*, not *public visitors* (it does rate-limit them — see the security model).
- **Revocation latency is bounded, not instant.** A mid-session revoke cuts on the
  next sweep tick (`-revoke-sweep`, default 20s), plus — for the CP path — up to one
  gate TTL for the entitlement poll to observe it. A runtime `Revoke*` call sweeps
  immediately.

---

## Running the relay server (`vulos-relayd`)

```
go build -o vulos-relayd ./cmd/vulos-relayd

# Behind a TLS-terminating edge/CDN (recommended), plain HTTP on a private port:
VULOS_RELAY_TOKENS='[{"token":"SECRET1","names":["box1"]}]' \
  ./vulos-relayd -addr :8443 -domain relay.example.com

# Or terminate TLS itself:
./vulos-relayd -addr :443 -domain relay.example.com \
  -cert /etc/tls/fullchain.pem -key /etc/tls/privkey.pem \
  -tokens-file /etc/vulos/relay-tokens.json

# No wildcard DNS? Use path mode:
./vulos-relayd -domain relay.example.com -path-mode -tokens-file grants.json
```

### Flags / env

**Core**

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-addr` | `VULOS_RELAY_ADDR` | `:8443` | Public tunnel listen address. |
| `-domain` | `VULOS_RELAY_DOMAIN` | — (required) | Base relay domain. |
| `-tokens-file` | `VULOS_RELAY_TOKENS` (inline JSON) | — (required unless `-cp-token-store`) | Agent grants. |
| `-path-mode` | `VULOS_RELAY_PATH_MODE=1` | `false` | Also serve `/t/<name>/` fallback. |
| `-trust-proxy-headers` | `VULOS_RELAY_TRUST_PROXY_HEADERS=1` | `false` | Trust `X-Forwarded-*` from a fronting proxy. **Off** (default, directly internet-facing) overwrites them with the observed peer so a client cannot spoof its source IP. Enable **only** behind a trusted TLS-terminating edge/CDN (the Fly deployment sets it). |
| `-cert` / `-key` | | — | Terminate TLS here (omit if behind an edge). |
| `-max-agents` | | `256` | Max concurrent agents. |
| `-max-request-bytes` | `VULOS_RELAY_MAX_REQUEST_BYTES` | `0` (⇒ 256 MiB) | Max public-request body in bytes; overflow returns `413`. `0` uses the 256 MiB default (covers the vast majority of single-file uploads); a negative value is refused. |
| `-request-body-timeout` | `VULOS_RELAY_REQUEST_BODY_TIMEOUT` | `0` (⇒ 30s) | Overall deadline to ingest a public client's request body (slow-body/slowloris DoS guard). A dribbling/stalled upload is cut with `408` and its per-agent stream slot freed; it is cleared before the response streams, so SSE/downloads are unaffected. `0` uses the 30s default; a negative value disables it. |
| `-ratelimit-direct-probe-rate` / `-ratelimit-direct-probe-burst` | `VULOS_RELAY_DIRECT_PROBE_RATE` / `_BURST` | `0` (⇒ 1/s, burst 5) | Budget for how often the relay emits an outbound direct-endpoint verification GET, per account (per name for unbilled) — a probe-reflection guard so a box cannot re-register in a loop to bounce GETs off the relay. Over-budget ⇒ the probe is skipped (tunnel still comes up on the relay path). `0`=default, `<0`=disable. |

**Admin / metrics (WAVE50-RELAY-OBSERVABILITY)** — a SEPARATE listener from the
public tunnel, serving `/metrics`, `/healthz`, `/readyz`.

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-admin-addr` | `VULOS_RELAY_ADMIN_ADDR` | `127.0.0.1:9090` | Admin/metrics listen address. Empty disables it. Loopback-only unless a metrics token is set. |
| `-metrics-token` | `VULOS_RELAY_METRICS_TOKEN` | — | Bearer token required for **non-loopback** `/metrics` access. Binding `-admin-addr` to a routable address **requires** this (refuses to start otherwise). |
| | `VULOS_RELAY_LOG_LEVEL` | `info` | Structured-log level (`debug`\|`info`\|`warn`\|`error`). |
| | `VULOS_RELAY_LOG_FORMAT` | JSON | Set `text` for text-format logs. |

**Rate limiting (WAVE34-RELAY-HARDEN)** — `0` uses the built-in default; a **negative**
value DISABLES that limiter.

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-ratelimit-control-rate` / `-ratelimit-control-burst` | `VULOS_RELAY_CTRL_RATE` / `_BURST` | `5`/s, burst `20` | Control-conn attempts per source IP. |
| `-ratelimit-req-rate` / `-ratelimit-req-burst` | `VULOS_RELAY_REQ_RATE` / `_BURST` | `50`/s, burst `100` | Public requests per tunnel. |
| `-ratelimit-global-rate` / `-ratelimit-global-burst` | `VULOS_RELAY_GLOBAL_RATE` / `_BURST` | `500`/s, burst `1000` | Aggregate public requests across all tunnels. |

**Revocation (WAVE41-RELAY-REVOCATION)**

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-revoked-file` | `VULOS_RELAY_REVOKED` (inline JSON) | — | Static revoked-list `{"tokens":[],"names":[],"accounts":[]}`. |
| `-revoke-sweep` | `VULOS_RELAY_REVOKE_SWEEP` | `20s` | Live-session recheck cadence. `<0` disables the sweep (connect-time revocation still applies). |

**Account-linking + billing (WAVE24-RELAY-BILLING, optional)** — omit all to run
UNBILLED (pure self-host).

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-cp-url` | `VULOS_CP_URL` | — | Vulos Cloud base URL for entitlement/usage. |
| `-cp-shared-secret` | `CP_SHARED_SECRET` | — | Shared secret for the usage HMAC + entitlement service auth. |
| `-pop-id` | `VULOS_RELAY_POP_ID` | derived from domain | This relay's PoP id (usage dedup per-PoP). |
| `-cp-token-store` | `VULOS_RELAY_CP_TOKENS=1` | `false` | Resolve agent tokens as CP install credentials instead of a static grants file (requires `-cp-url` + `-cp-shared-secret`). |

**Geo-distributed pool + autoscale (optional)** — make the node self-aware and
publish a saturation signal for pool scaling. All optional; leaving the soft caps
at `0` keeps single-node behavior (no sampler runs).

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-node-id` | `VULOS_RELAY_NODE_ID` | — | Stable pool id for this node (e.g. `hel1-a`); surfaced on `/healthz`. |
| `-region` | `VULOS_RELAY_REGION` | — | Coarse geo tag (e.g. `eu-central`, `af-south`) a router uses to steer a client to the nearest node. |
| `-provider` | `VULOS_RELAY_PROVIDER` | — | Informational host tag (e.g. `hetzner`, `vultr`). |
| `-soft-max-agents` | `VULOS_RELAY_SOFT_MAX_AGENTS` | `0` (ignore) | Soft agent cap — one saturation dimension. |
| `-soft-max-streams` | `VULOS_RELAY_SOFT_MAX_STREAMS` | `0` (ignore) | Soft in-flight-stream cap. |
| `-soft-max-bytes-per-sec` | `VULOS_RELAY_SOFT_MAX_BPS` | `0` (ignore) | Soft throughput cap (bytes/sec). |
| `-saturation-sample-period` | `VULOS_RELAY_SAT_PERIOD` | `0` (⇒ 15s) | How often to recompute the saturation gauge. `<0` disables the sampler. |

These are **soft** (scaling) limits, distinct from the hard `-max-agents` / rate
caps that bound abuse. When any soft cap is set, the node publishes
`vulos_relay_saturation_ratio` on `/metrics`. See the pool/autoscale section below.

**Smart autoscaler — CP PoP registration + heartbeat (optional, CP-driven)** —
register this PoP with Vulos Cloud and heartbeat its load so a CP-side autoscaler
can place agents and drive graceful drains (see "Smart autoscaler — the CP↔relay
contract" below). Requires the CP link (`-cp-url`/`-cp-shared-secret`); with no CP
or no `-public-endpoint` the relay runs unregistered (self-host / CP-optional).

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-public-endpoint` | `VULOS_RELAY_PUBLIC_ENDPOINT` | — | This PoP's agent-facing base URL announced to the CP (e.g. `wss://hel1.relay.example.com`). Empty ⇒ not CP-registered (no heartbeat). |
| `-heartbeat-period` | `VULOS_RELAY_HEARTBEAT` | `0` (⇒ 12s) | PoP load-heartbeat cadence to the CP. `<0` disables it. |
| `-host-mem-limit-bytes` | `VULOS_RELAY_HOST_MEM_LIMIT` | `0` | Host/cgroup memory limit for the heartbeat `mem_pct` gauge (`0` ⇒ report 0). |

The CP→relay **graceful-drain** control endpoints (`/control/drain`,
`/control/undrain`, `/control/status`) live on the **admin surface** and are gated by
`X-Relay-Auth: CP_SHARED_SECRET` — they are **disabled on a relay with no CP secret**.

**Rendezvous role** (open announce/resolve/signal/mailbox + ICE — see
[RENDEZVOUS.md](RENDEZVOUS.md)). CP-optional / self-hostable; off by default; served
on the relay's apex host.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-rendezvous` | `VULOS_RELAY_RENDEZVOUS` | `off` | Enable the rendezvous role. |
| `-rendezvous-prefix` | `VULOS_RELAY_RENDEZVOUS_PREFIX` | `/rendezvous` | Mount prefix for the role's routes. |
| `-rendezvous-no-public-resolve` | `VULOS_RELAY_RENDEZVOUS_NO_RESOLVE` | `off` | Disable unauthenticated presence resolve reads (directory becomes signal/mailbox-only). |
| `-rendezvous-stun` | `VULOS_RELAY_STUN` | — | Comma-separated STUN URLs advertised via `/rendezvous/ice` (empty ⇒ public default list). |
| `-rendezvous-disable-public-stun` | `VULOS_RELAY_DISABLE_PUBLIC_STUN` | `off` | Drop the built-in public STUN fallback (sovereign deployments). |
| `-rendezvous-turn` | `VULOS_RELAY_TURN` | — | Comma-separated TURN URLs (needs `-rendezvous-turn-secret` to emit ephemeral creds). |
| `-rendezvous-turn-secret` | `VULOS_RELAY_TURN_SECRET` | — | coturn static-auth-secret used to mint short-lived TURN credentials; **never sent to clients**. |
| `-rendezvous-turn-ttl` | `VULOS_RELAY_TURN_TTL` | `0` (⇒ 12h) | Lifetime of a minted TURN credential. |

**Cache/pin role** (DMTAP-PUB public objects — see [PUBCACHE.md](PUBCACHE.md)).
Off by default and **explicit operator opt-in**: unlike every other role, it serves
**public plaintext the operator can read**. Served on the relay's apex host; nothing
is cached or served unless its bytes match its content address.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-pubcache` | `VULOS_RELAY_PUBCACHE` | `off` | Enable the cache/pin role. |
| `-pubcache-prefix` | `VULOS_RELAY_PUBCACHE_PREFIX` | `/.well-known/dmtap-pub` | Mount prefix for the role's routes. |
| `-pubcache-upstreams` | `VULOS_RELAY_PUBCACHE_UPSTREAMS` | — | Comma-separated § 22.5.1 gateway base URLs, tried in order. **The only hosts this role will contact** — a client can never name one. Empty ⇒ a holder that holds nothing (404s everything). |
| `-pubcache-max-object-bytes` | `VULOS_RELAY_PUBCACHE_MAX_OBJECT` | `0` (⇒ 16 MiB) | Per-object size cap; an oversize object is refused, not stored. |
| `-pubcache-max-bytes` | `VULOS_RELAY_PUBCACHE_MAX_BYTES` | `0` (⇒ 256 MiB) | Total cache cap, enforced by LRU eviction. |
| `-pubcache-ttl` | `VULOS_RELAY_PUBCACHE_TTL` | `0` (⇒ 1h) | Per-object cache lifetime (a space/freshness policy — objects are immutable). |
| `-pubcache-upstream-timeout` | `VULOS_RELAY_PUBCACHE_UPSTREAM_TIMEOUT` | `0` (⇒ 15s) | Timeout for one upstream read. |
| `-pubcache-max-inflight` | `VULOS_RELAY_PUBCACHE_MAX_INFLIGHT` | `0` (⇒ 16) | Concurrent upstream fetches across the whole role (bounded fan-out). |
| `-pubcache-serve-feeds` | `VULOS_RELAY_PUBCACHE_SERVE_FEEDS` | `off` | Also proxy the **mutable** feed head/range reads. Never cached — a feed head is signature-authenticated, which this node cannot verify. |

**Grants JSON:** each grant is a token, the names it may serve, and an optional
`account_id` (link the token to a Vulos account for gating + metering; omit it to
serve the token unbilled).
```json
[
  {"token": "SECRET1", "names": ["box1"]},
  {"token": "SECRET2", "names": ["alice", "alice-staging"], "account_id": "acct-42"}
]
```

### DNS it needs

- **Subdomain mode (primary):** a wildcard `A`/`AAAA` (or `CNAME`) record
  `*.relay.example.com → <relay host>`, plus `relay.example.com` itself. TLS needs a
  wildcard cert (`*.relay.example.com`) — trivial with an ACME edge/CDN.
- **Path mode (fallback):** just `relay.example.com → <relay host>`; no wildcard.

### Observability

The relay serves metrics + health on a **separate admin listener** (`-admin-addr`,
default `127.0.0.1:9090`), never on the public tunnel port:

- `GET /metrics` — Prometheus text-exposition metrics (`vulos_relay_*`): active
  agents/streams, agent connects/disconnects, requests by outcome, auth failures by
  reason, `429`s by surface, tunnel cuts by reason, proxied bytes by direction, and
  **`vulos_relay_saturation_ratio`** (this node's load vs its soft capacity — the
  autoscale signal). Every label is a fixed enum, so cardinality is bounded and no
  attacker-controlled value (host/path/name/account/IP/token) ever becomes a series.
  Loopback-only unless `-metrics-token` is set (required for a non-loopback bind).
- `GET /healthz` — `ok agents=<n>` liveness ping for load balancers (also echoes
  `node=<id> region=<r>` when `-node-id`/`-region` are set, so a pool health checker
  can tell which node answered).
- `GET /readyz` — `ready` (200) once the background loops are up; `503` while draining.

Structured `slog` logs (JSON by default) cover the security-relevant lifecycle
events with a bounded field set (`name`, `account`, `remote`, `reason`) and never
emit a token or secret.

---

## Geo-distributed pool & autoscale-on-saturation

The relay is the suite's **core reachability product**, so it is built to run as a
**geo-distributed pool of N nodes** — Hetzner as the primary region, Vultr for a JHB
edge / HA — on **flat-bandwidth hosts**. Those hosts have **no managed autoscaler**,
so capacity control is **app-level**. It has three provider-agnostic pieces, in the
`tunnel/autoscale` package (a library the deploy-side orchestrator wires):

1. **Saturation detection.** Each node samples its own load — live agents, in-flight
   streams, and derived throughput (bytes/sec) — and normalizes it to a `0..1+`
   **saturation ratio** against its soft capacity (the `-soft-max-*` flags). A
   `Detector` applies **hysteresis**: it only signals **scale-up** when the ratio
   stays above a high-watermark for a sustained window, and **scale-down** when it
   stays below a low-watermark (with more than the floor of nodes), separated by a
   cooldown — so a brief spike never thrashes the pool. The current ratio is published
   as **`vulos_relay_saturation_ratio`** on `/metrics`.

2. **The `Provisioner` seam.** A tiny two-method interface —
   `Provision(ctx) (Node, error)` and `Decommission(ctx, id) error` — that an
   **orchestrator implements** to actually boot / tear down a relay node on whatever
   host it uses (a Hetzner Cloud API call, a Vultr instance, a Terraform run, a Fly
   machine, …). **The relay never hardcodes a cloud provider**; it only calls these.
   Wiring a real provider behind this interface is the deploy-side integration.

3. **Health-checked pool membership.** A `Pool` tracks the live nodes with a
   background **health checker** (polls each node's `/readyz`) and a
   **nearest-healthy** selector (region-preference, least-loaded tiebreak), so a
   router / geo-DNS layer can steer a client to the closest live node and a **drained
   node stops receiving new traffic** before it is torn down. The node running the
   autoscaler is never chosen as a decommission target.

The in-process `autoscale.Autoscaler` ties them together (read a `LoadSource` each
interval → `Detector` → `Provisioner` + `Pool`); `*server.Server` implements
`autoscale.LoadSource` directly, so it can be handed straight to an autoscaler. An
operator who prefers to scale from **outside** the process can instead just scrape
`vulos_relay_saturation_ratio` and drive their own control loop — the metric is the
same signal, and the `Provisioner` is left unset.

**No single-node assumption.** A node is self-aware (`-node-id` / `-region`) and a
public request for a tunnel name it does **not** hold fails **clean** — `502` for a
well-formed name with no local session (e.g. a misroute for a name that lives on
another node), `404` for a host outside the relay domain. Which node actually holds a
given box's tunnel is **deploy-side affinity**: a box dials one home node, and per-name
routing to that node is done by DNS / a directory, not by this process.

**What's deploy-only.** Real **geo-DNS / anycast** client steering, and a **real
`Provisioner`** that talks to Hetzner/Vultr, are deployment concerns — this repo ships
the **seams + logic + tests**, not a live multi-node fabric. Per-GB-per-region metering
rides the existing account-linking usage path (`POST /api/relay/usage`), tagged by the
node's `-pop-id` (set it per node/region so usage dedups and attributes per PoP).

---

## Smart autoscaler — the CP↔relay contract

The pool above is the in-process/library view; the **managed** service adds a
**CP-driven** control loop so a Vulos Cloud autoscaler can place agents on the
nearest, least-loaded PoP and scale the pool up/down **gracefully** (relay tunnels
are sticky and stateful — a scale-down must never drop a live tunnel). It is
**CP-OPTIONAL**: a self-host relay with no CP configured runs none of this; a
standalone agent with no directory dials `-server` statically. All of it reuses the
existing CP link (`CP_SHARED_SECRET` + the same `X-Pop-Sig` HMAC as usage reports).

**1. PoP registration + load heartbeat (relay → CP).** A relay started with
`-cp-url`/`-cp-shared-secret` **and** `-public-endpoint` announces itself and then
heartbeats its live load every `-heartbeat-period` (default 12s). The load sample is
taken off the hot path from counters the data path already maintains.

```
POST {cp}/api/relay/pop/register        # once on startup (retried)
  X-Pop-Sig: hex(HMAC-SHA256(CP_SHARED_SECRET, body))
  { "pop_id", "region", "provider", "public_endpoint",
    "capacity": { "max_agents", "max_streams", "max_bytes_per_sec" } }

POST {cp}/api/relay/pop/heartbeat       # every -heartbeat-period (~12s)
  X-Pop-Sig: hex(HMAC-SHA256(CP_SHARED_SECRET, body))
  { "pop_id", "region", "active_tunnels", "bytes_per_sec",
    "cpu_pct", "mem_pct", "saturation", "draining" }
```

The CP drops a PoP that stops heartbeating (its own TTL) and excludes a
`draining:true` PoP from new assignments.

**2. Routing hook (agent → CP).** An agent started with `-directory` asks the CP for
its assigned PoP on connect **and** every reconnect, then dials it — so when a PoP
drains and the CP stops handing it out, the agent's next resolve returns a different
PoP. Falls back to `-server` on any directory error (never stranded).

```
GET {directory}/api/relay/assign?name=<name>[&region=<pref>]
  Authorization: Bearer <token>
  → { "endpoint": "wss://hel1.relay.example.com", "region": "eu-central", "pop_id": "hel1-a" }
```

**3. Graceful drain (CP → relay).** To scale a PoP down the CP calls the authed
control endpoint on the relay's **admin surface** (gated by `X-Relay-Auth:
CP_SHARED_SECRET`, not the metrics token; **disabled entirely on a CP-less relay**):

```
POST {admin}/control/drain     X-Relay-Auth: <CP_SHARED_SECRET>
  → 200 { "ok", "draining": true, "signaled": <n>, "active_tunnels": <n>, "pop_id", "region" }
POST {admin}/control/undrain   X-Relay-Auth: <CP_SHARED_SECRET>   # abort a drain
GET  {admin}/control/status    X-Relay-Auth: <CP_SHARED_SECRET>
  → 200 { "draining", "active_tunnels", "saturation", "pop_id", "region", "node_id" }
```

`drain` makes the PoP **(a)** refuse new tunnel registrations and flip `/readyz` to
draining (so a fronting LB stops routing here), and **(b)** send a **proactive
reconnect** control signal to **every** connected agent. The CP polls
`active_tunnels` (control `/status` or the heartbeat) and terminates the machine
once it reaches **0**.

**4. Proactive reconnect signal (relay → agent) — zero-drop migration.** The relay
delivers the reconnect over the existing yamux tunnel as an **agent-terminated**
control stream (path `/_vulos-relay/agent-control`, header `X-Vulos-Relay-Command:
reconnect`) — it is handled by the agent itself and **never proxied to the box's
local app** (a control stream causes no local dial, so the SSRF guard is untouched).
On receipt the agent migrates **make-before-break**: it re-resolves its PoP, brings
up the **new** tunnel, and only **then** winds down the old one (GoAway + brief
in-flight drain). Because the old tunnel stays up until the new one is live, a drain
moves every tunnel with **no dropped connectivity**.

**Efficiency.** The forwarding data path uses a `sync.Pool` of 64 KiB buffers via
`io.CopyBuffer` (no per-request/per-splice scratch allocation — the relay is
bandwidth-bound, so bytes are direct COGS), streams bodies with backpressure (never
buffers a whole response), bounds concurrency by the per-agent stream cap, and keeps
the load heartbeat **off the hot path** (it only reads aggregate counters). The new
control signals are event-driven (a drain), not per-packet.

---

## Running the agent CLI (`vulos-relay-agent`)

```
go build -o vulos-relay-agent ./cmd/vulos-relay-agent

vulos-relay-agent \
  -server wss://relay.example.com \
  -token  SECRET1 \
  -name   box1 \
  -local  127.0.0.1:8080

# Optionally advertise a Direct-IP fast path (a box with a public IP). The relay
# verifies reachability + ownership before advertising it; falls back to the relay
# tunnel if verification fails. Also VULOS_RELAY_DIRECT_ENDPOINT.
vulos-relay-agent -server wss://relay.example.com -token SECRET1 -name box1 \
  -local 127.0.0.1:8080 -direct https://box1.example.com
```

`-local` must be a loopback address. The agent binds nothing inbound. `-direct` (if
set) must be a bare `https://` origin the box serves publicly.

**Smart-autoscale routing (optional).** Point the agent at a directory so it dials
its **CP-assigned** PoP (nearest + least-loaded) instead of a fixed `-server`, and
migrates automatically when its PoP drains:

```
vulos-relay-agent -directory https://cloud.vulos.org -region eu-central \
  -server wss://relay.example.com \   # fallback if the directory is unreachable
  -token SECRET1 -name box1 -local 127.0.0.1:8080
```

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-directory` | `VULOS_RELAY_DIRECTORY` | — | CP/directory base URL for assigned-PoP resolution. Empty ⇒ dial `-server` statically. |
| `-region` | `VULOS_RELAY_REGION` | — | Preferred-region hint sent to the directory. |

---

## Account-linking + usage metering (optional)

A self-host relay runs **UNBILLED** by default: tokens are authorized (name grants)
but no account gating or metering happens — no Vulos account required.

Linking is opt-in. Run `vulos-relayd` with `-cp-url` + `-cp-shared-secret` (+
`-pop-id`) to connect it to Vulos Cloud, after which the relay:

- **Gates** each account-bound token against its relay entitlement
  (`GET /api/relay/entitlement`) — fails **closed** at connect (a denied or
  un-vettable account is refused) and **open** mid-session (a transient CP blip never
  cuts a live tunnel; a definitive deny/revoke does).
- **Meters** per-account byte + session deltas and flushes them to
  `POST /api/relay/usage`, HMAC-signed (`X-Pop-Sig`) with a monotonic, idempotent
  `report_id`. The flush runs off the data path with retry/restore.

A grant's `account_id` (in the grants JSON) is what links a token to an account. A
grant with no `account_id` is served but never metered. Alternatively,
`-cp-token-store` resolves each agent's install credential to its account directly
against the CP.

---

## Embedding the agent (library API)

The `agent` package mirrors wede's `internal/tunnel.Manager` so wede can swap its
frp subprocess for this in-process client. Status vocabulary is identical:
`stopped` / `starting` / `connected` / `error`.

```go
import "github.com/vul-os/vulos-relay/tunnel/agent"

a := agent.New(agent.Options{
    ServerURL: "wss://relay.example.com", // http/https normalized to ws/wss
    Token:     "SECRET1",
    Name:      "box1",
    LocalAddr: "127.0.0.1:8080",          // must be loopback (SSRF guard)
})

// Start returns immediately; it dials + registers + maintains async with backoff.
if err := a.Start(ctx); err != nil { /* bad options */ }

url  := a.PublicURL()   // "https://box1.relay.example.com" when connected, else ""
snap := a.Snapshot()    // { Status, PublicURL, Connected, LastError, Log }

a.Stop()                // tears down; frees the name immediately
```

`Snapshot()` never includes the token. `Options` also has `TLSConfig` (pin a CA for
a self-hosted relay) and `InsecureSkipVerify` (testing only).
