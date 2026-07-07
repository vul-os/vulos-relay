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
  keepalive-based dead-peer detection. Memory is bounded.
- **Rate limiting (429):** three memory-bounded token-bucket limiters sit on top of
  the hard caps above — control-connection attempts **per source IP** (throttles
  auth/CP churn *before* spending a WS upgrade), public requests **per tunnel**, and
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
- **Header hygiene:** hop-by-hop headers are stripped both ways; `X-Forwarded-For`,
  `X-Forwarded-Host`, `X-Forwarded-Proto` are set from the real client (the agent's
  input is never trusted to name itself). Internal errors are never leaked to
  clients (generic `502`/`403`/etc.).
- **TLS everywhere:** run the relay behind an edge/CDN that terminates TLS, or give
  it `-cert`/`-key` to terminate itself.

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
  yamux keepalive miss (~10s), not instantly. A clean `Stop()` frees it at once.
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
| `-addr` | | `:8443` | Public tunnel listen address. |
| `-domain` | `VULOS_RELAY_DOMAIN` | — (required) | Base relay domain. |
| `-tokens-file` | `VULOS_RELAY_TOKENS` (inline JSON) | — (required unless `-cp-token-store`) | Agent grants. |
| `-path-mode` | | `false` | Also serve `/t/<name>/` fallback. |
| `-cert` / `-key` | | — | Terminate TLS here (omit if behind an edge). |
| `-max-agents` | | `256` | Max concurrent agents. |

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
| `-revoke-sweep` | | `20s` | Live-session recheck cadence. `<0` disables the sweep (connect-time revocation still applies). |

**Account-linking + billing (WAVE24-RELAY-BILLING, optional)** — omit all to run
UNBILLED (pure self-host).

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-cp-url` | `VULOS_CP_URL` | — | Vulos Cloud base URL for entitlement/usage. |
| `-cp-shared-secret` | `CP_SHARED_SECRET` | — | Shared secret for the usage HMAC + entitlement service auth. |
| `-pop-id` | `VULOS_RELAY_POP_ID` | derived from domain | This relay's PoP id (usage dedup per-PoP). |
| `-cp-token-store` | `VULOS_RELAY_CP_TOKENS=1` | `false` | Resolve agent tokens as CP install credentials instead of a static grants file (requires `-cp-url` + `-cp-shared-secret`). |

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
  reason, `429`s by surface, tunnel cuts by reason, and proxied bytes by direction.
  Every label is a fixed enum, so cardinality is bounded and no attacker-controlled
  value (host/path/name/account/IP/token) ever becomes a series. Loopback-only unless
  `-metrics-token` is set (required for a non-loopback bind).
- `GET /healthz` — `ok agents=<n>` liveness ping for load balancers.
- `GET /readyz` — `ready` (200) once the background loops are up; `503` while draining.

Structured `slog` logs (JSON by default) cover the security-relevant lifecycle
events with a bounded field set (`name`, `account`, `remote`, `reason`) and never
emit a token or secret.

---

## Running the agent CLI (`vulos-relay-agent`)

```
go build -o vulos-relay-agent ./cmd/vulos-relay-agent

vulos-relay-agent \
  -server wss://relay.example.com \
  -token  SECRET1 \
  -name   box1 \
  -local  127.0.0.1:8080
```

`-local` must be a loopback address. The agent binds nothing inbound.

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
