# Changelog

All notable changes to `@vulos/relay-client` are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

### Docs — verify + docs pass (verify/docs-polish-2026-07)

- **README + TUNNEL.md: Relay framed as the single reachability primitive.**
  Documented the direct-first / relay-fallback doctrine and that Relay carries
  **web-shaped traffic** (HTTP/WS/SSE) — real-time **media** rides ICE/TURN
  (Relay only registers/resolves the SFU node, never forwards RTP) and **mail**
  rides the HTTP spool→forward edge. Documented the **SFU-host registry**
  (`/api/meet/host/*`, `-sfu-host-registry`, off by default): register with the
  same directprobe endpoint verification, **name-scoped `resolve`** so the shared
  relay never leaks one tenant's SFU endpoint to another. Added the
  `-max-request-bytes` (256 MiB body cap, `413` on overflow) and
  `-sfu-host-registry` flags to the flags table. No code change; full suite
  verified green (`go build`, `go test -race`, client vitest 236 tests / 22 files).

### Added

- **Direct-IP fast path (DIRECT-IP)** — a box with a public IP/hostname can advertise
  a direct `https://` endpoint (`agent.Options.DirectEndpoint` / `-direct` /
  `VULOS_RELAY_DIRECT_ENDPOINT`) that clients dial **directly** for near-native
  latency + full bandwidth, with the relay tunnel as the always-works fallback
  (ICE-like: try direct, fall back to relay-as-TURN). The relay **never trusts the
  box's word**: before surfacing an endpoint it probes `{endpoint}/_vulos-direct/probe`
  over the internet with a one-time 256-bit nonce and requires the box to echo it
  (reachability **+** ownership proof), SSRF-guarded (host screened pre-dial, resolved
  IP re-screened at connect against DNS-rebind, public IPs only, no redirects), and
  only **after** auth + entitlement pass. Verification failure is non-fatal (the box
  stays on the relay path). Clients discover the verified endpoint via
  `GET /_vulos-direct/resolve` and the `tunnel/direct` package. Relay-wide off switch:
  `Config.DisableDirect`.

### Fixed

- **Malformed status line on the WS-upgrade error path (finalize pass)** — when the
  relay could not read the agent's response head during a WebSocket upgrade it wrote a
  raw `HTTP/1.1 Bad Gateway` line onto the hijacked client connection, **omitting the
  numeric status code**, so the client could not parse it. It now writes a well-formed
  `HTTP/1.1 502 Bad Gateway` status line. Added a direct regression test.
- **Agent goroutine leak per reconnect (`deep/relay` pass)** — `connectOnce` spawned
  its "close the yamux session when the context ends" watcher on the *long-lived*
  maintain-loop context, so every ended session (each reconnect) left one goroutine
  blocked until the whole agent stopped. Under reconnect churn (a flapping relay)
  goroutines and dead sessions piled up without bound. The watcher is now bound to a
  per-connection context cancelled when `connectOnce` returns.
- **Usage metering could double-bill on a response-lost flush (`deep/relay` pass)** —
  the flush drained deltas, posted them under a `report_id`, and on *any* error
  restored them into the pending pool so the next flush re-sent them under a **fresh**
  id. When the CP had actually applied the batch but its HTTP response was lost
  (timeout / 5xx after commit), the fresh id defeated the CP's idempotent dedup and
  the account was billed twice. Failed batches now retain and **reuse their stable
  `report_id`** on retry (bounded queue), so a re-sent batch is a dedup no-op instead
  of a re-bill. `report_id`s also carry a per-boot nonce so they no longer collide
  across a process restart (which previously let the CP silently drop the first
  post-restart batches → under-billing).
- **`RequestTimeout` is now actually enforced (`deep/relay` pass)** — the config knob
  was defined, defaulted (60s), and documented as "per public request forward
  timeout" but never applied. A *half-dead* agent (yamux keepalive still answering,
  so the session stays up, but never servicing a stream) held the public request and
  its stream slot open forever; once `MaxStreamsPerAgent` such streams accumulated the
  whole tunnel bricked (503 to everyone) with no recovery. The relay now bounds
  time-to-response-headers and frees the slot, failing fast with 502. The deadline is
  cleared before the response body streams, so long-lived SSE/downloads/WS are
  unaffected; `0` disables it.
- **Graceful shutdown for `vulos-relayd`** — the relay now traps `SIGTERM`/`SIGINT`
  (what Fly and most orchestrators send on deploy/restart) and drains: it flips
  `/readyz` to draining, stops accepting new connections on the public + admin
  listeners, lets in-flight requests finish (bounded), and performs the final
  metered-usage flush via `Server.Shutdown` before exiting. Previously the process
  was hard-killed (`log.Fatal` → `os.Exit`), so the last usage deltas were lost and
  a rolling restart could drop live requests. Added `Server.Shutdown(ctx)`.

## [0.2.0] — 2026-07-06

The **sovereign Go reverse tunnel** lands and hardens. `0.1.0` was a pure JS SDK;
`0.2.0` adds a self-hostable relay server + agent (`vulos-relayd` /
`vulos-relay-agent`) that replaces third-party `frp`/ngrok/Cloudflare Tunnel, and
brings it to internet-facing production quality.

### Added

- **Sovereign reverse tunnel (Go)** — `cmd/vulos-relayd` (public relay) +
  `cmd/vulos-relay-agent` (box-side agent) + the embeddable `tunnel/agent` and
  `tunnel/server` packages. A loopback-bound box dials one outbound `wss://`
  control connection; the relay becomes the [`hashicorp/yamux`](https://github.com/hashicorp/yamux)
  client and reverse-proxies public HTTP + WebSocket (transparent upgrade
  passthrough) back down it — no inbound ports, no static IP, no third-party
  relay. Subdomain routing (`<name>.<relay-domain>`) or `-path-mode` (`/t/<name>/`)
  when wildcard DNS is unavailable. The `tunnel/agent` API mirrors wede's
  `internal/tunnel.Manager` so wede embeds it in place of its `frpc` subprocess.
- **Rate limiting (WAVE34-RELAY-HARDEN)** — three memory-bounded token-bucket
  limiters on the internet-facing surfaces, all returning `429`: control-connection
  attempts per source IP (throttles auth/CP churn before spending a WS upgrade),
  public requests per tunnel, and an aggregate global cap across all tunnels.
  Buckets are lazily created, idle-evicted, and key-capped so a flood of distinct
  keys cannot grow memory unbounded. Configurable (flags/env) with safe defaults;
  a negative rate disables a limiter (self-host / trusted-edge).
- **Over-quota cut (WAVE34-RELAY-HARDEN)** — the CP's over-quota verdict returned on
  the usage report is now fed straight into the entitlement gate, so an over-cap
  account is cut with `402` on its **next** request instead of surviving until the
  gate TTL lapses.
- **Token / credential revocation (WAVE41-RELAY-REVOCATION)** — a file/env static
  revoked-list (`{"tokens":[],"names":[],"accounts":[]}`) plus a runtime
  `RevokeToken` / `RevokeName` / `RevokeAccount` API (no config edit + restart). A
  revoked credential is refused at connect **and** a periodic live-session
  revocation sweep drops any matching tunnel promptly (bounded latency, off the
  data path). The CP path treats an entitlement `revoked:true` or a `404` for a
  previously-valid credential as a definitive revoke, reusing the existing
  entitlement poll (no new CP round trip). Connect stays fail-closed; mid-session
  stays fail-open on a transient blip but cuts on a definitive revoke.
- **Prometheus observability (WAVE50-RELAY-OBSERVABILITY)** — a dependency-free
  Prometheus text-format `/metrics` plus `/healthz` and `/readyz`, served on a
  **separate admin listener** that is loopback-only by default and refuses to bind
  a routable address without a `-metrics-token`. Metrics never mount on the public
  tunnel handler. Every label is drawn from a small fixed enum (request outcomes,
  byte directions, auth-fail reasons, cut reasons) so cardinality is bounded by
  construction — no attacker-controlled host/path/name/account/IP/token ever
  becomes a label — and no secret/PII is ever emitted.
- **Structured logging (WAVE50-RELAY-OBSERVABILITY)** — key lifecycle events
  (agent connect / auth-fail / disconnect, tunnel open/close, rate-limit reject,
  revocation cut, over-quota cut) routed through `slog` with a bounded field set
  (`name`, `account`, `remote`, `reason`) that has **no field for a token/secret**,
  configurable level/format via `VULOS_RELAY_LOG_LEVEL` / `VULOS_RELAY_LOG_FORMAT`.
- **Account-linking + usage metering (WAVE24-RELAY-BILLING, optional)** — link a
  self-host relay to a Vulos account so account-bound tokens are gated on their
  relay entitlement (`GET /api/relay/entitlement`) and per-account byte/session
  deltas are flushed to Vulos Cloud (`POST /api/relay/usage`, HMAC `X-Pop-Sig` +
  monotonic idempotent `report_id`). Off the data path with retry/restore. Runs
  **unbilled** with no `-cp-url`/`-cp-shared-secret` — pure sovereign self-host
  needs no Vulos account.
- **Deploy shape** — `Dockerfile` + `fly.toml` + a GHCR image-publish job in the
  release workflow so `vulos-relayd` ships as a container.

### Security

- **Adversarial SSRF + authz test coverage** — an agent forwards **only** to its
  one configured loopback target; non-loopback targets (private IPs,
  `169.254.169.254`, `0.0.0.0`, arbitrary hosts) are refused at startup (`ensureLoopback`)
  and re-checked at dial time. Names are token-bound and cannot be hijacked (a live
  name is held by exactly one session; a second claimant is rejected). Bearer-token
  agent auth uses constant-time comparison, tokens are stored hashed, and the
  authorize path is constant-time over the whole set. Added adversarial regression
  tests covering the SSRF guard, name-hijack attempts, auth bypass, over-quota /
  entitlement denial, and the revocation sweep.

### Changed

- `client/package.json`, the agent protocol-version string, and this changelog
  bumped to `0.2.0`.

## [0.1.0] — 2026-06-28

### Added

- **`@vulos/relay-client` JS SDK** — the repo's sole deliverable. Shared by
  every Vulos web surface (the Vulos OS shell, `vulos-office`, `vulos-talk`).
- **Endpoint failover** (`/endpoints`) — cloud ↔ LAN backend selection with
  health probing, configurable localStorage key prefix, and configurable health
  path per consumer (`configure()`).
- **Offline bootstrap** (`/offlineBootstrap`) — offline-first shell boot with
  an IndexedDB write queue, optional `tierHint` callback for per-surface Pro
  tier injection.
- **WebRTC signaling** (`/signaling`) — `SignalingClient` over the host's
  `/api/peering/stream` WebSocket with reconnect and exponential back-off.
- **Fabric sessions** (`/fabric`) — `FabricClient` providing per-document P2P
  data channels with a relay-circuit fallback.
- **Presence & live cursors** (`/presence`, `/useLiveCursors`) —
  `PresenceManager`, `usePresence` React hook, and `useLiveCursors` for
  multi-peer awareness.
- **Call** (`/call`) — `createCall` (P2P mesh WebRTC) with shared `Emitter`
  and ICE-fetch helpers; Bearer JWT fix on relay pickup.
- **Round-trip check** (`/roundTripCheck`) — `runRoundTripChecks` fixture
  runner for integration testing.
- Dual ESM + CJS build via `vite build --config vite.config.lib.js`.
- Release pipeline: `.github/workflows/release.yml` — tag `v*` triggers build
  + test, optional npm publish with OIDC provenance, and a GitHub Release
  attaching the `dist-lib/` tarball.

### Removed

- **`createLiveKitRoom` (LiveKit SFU support)** — the SFU/large-room path
  was removed before 1.0; it is **not** part of the published package. The
  product uses the P2P mesh (`createCall`) exclusively. Any consumer that once
  referenced `createLiveKitRoom` must migrate to `createCall`.

### Changed

- Deduplicated `src/lib/{endpoints,offlineBootstrap,signaling,fabric,presence,
  call,useLiveCursors,roundTripCheck}.js` that had been copy-pasted across
  `vulos` and `vulos-office` into this single package (`RELAY-CLIENT-01`).
- `vulos-relay` repo is a pure JS SDK; no server-side code is included.

### Security

- Call: Bearer JWT was being overwritten by a dead-code path before relay
  pickup; fixed (commit `ae25886`).
- CRDT quorum-voting: added per-instance signed quorum to block multi-forged
  origin attacks (`CRDT-QUORUM-01`); observation GC added.

---

[0.2.0]: https://github.com/vul-os/vulos-relay/releases/tag/v0.2.0
[0.1.0]: https://github.com/vul-os/vulos-relay/releases/tag/v0.1.0
