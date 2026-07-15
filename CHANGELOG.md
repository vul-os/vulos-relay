# Changelog

All notable changes to `@vulos/relay-client` are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

### Added — smart CP-driven autoscaler (relay side): PoP heartbeat, graceful drain, zero-drop migration

- **PoP registration + load heartbeat (relay → CP).** A managed relay started with
  `-cp-url`/`-cp-shared-secret` **and** `-public-endpoint` registers itself
  (`POST /api/relay/pop/register`) and heartbeats its live load every
  `-heartbeat-period` (default 12s) — `POST /api/relay/pop/heartbeat` with
  `active_tunnels`, `bytes_per_sec`, `cpu_pct`, `mem_pct`, `saturation`, `draining`.
  HMAC-signed (`X-Pop-Sig`, the same scheme as usage reports). Sampled **off the hot
  path** from existing aggregate counters. **CP-OPTIONAL:** a relay with no CP (or no
  public endpoint) runs none of it (`tunnel/server/poplink.go`).
- **Graceful drain control endpoint (CP → relay).** `POST /control/drain` /
  `/control/undrain` / `GET /control/status` on the admin surface, gated by
  `X-Relay-Auth: CP_SHARED_SECRET` and **disabled entirely on a CP-less relay**.
  `drain` stops accepting new tunnels, flips `/readyz` to draining, and broadcasts a
  proactive reconnect to every agent; the CP polls `active_tunnels` to 0 before
  terminating the machine (`tunnel/server/drain.go`, `admin.go`).
- **Proactive reconnect signal (relay → agent).** Delivered as an **agent-terminated**
  yamux control stream (`/_vulos-relay/agent-control`, `X-Vulos-Relay-Command:
  reconnect`) that is **never proxied to the box's local app** — the SSRF guard is
  untouched (`tunnel/internal/wire`, `tunnel/agent/forward.go`).
- **Routing hook (agent → CP) + make-before-break migration.** With `-directory` set,
  the agent resolves its assigned nearest/least-loaded PoP
  (`GET /api/relay/assign?name=…`) on connect **and** reconnect, falling back to
  `-server` on any directory error. On a drain the agent migrates
  **make-before-break** — the new tunnel is established before the old one is torn
  down — so a scale-down drops **zero** connectivity (`tunnel/agent/resolve.go`,
  `conn.go`). Proven end-to-end (`tunnel/drain_e2e_test.go`).
- **Bandwidth-efficient forwarding.** The byte path now reuses **pooled 64 KiB
  buffers** (`sync.Pool` + `io.CopyBuffer`) instead of allocating a 32 KiB scratch
  buffer per request/splice (`tunnel/server/bufpool.go`, `tunnel/agent/bufpool.go`) —
  the relay is bandwidth-bound, so this removes a per-byte-path allocation. Streaming
  + backpressure + the per-agent stream cap are unchanged.

### Removed — dead planning doc

- Deleted `docs/CONSOLIDATION.md` (a "design + plan only, nothing implemented"
  internal doc whose plan — the 256 MiB upload cap — has since shipped).

### Removed — Meet-product SFU-host registry (relay is generic reachability only)

- **Dropped the `/api/meet/host/*` SFU-host registry** (`tunnel/server/sfuhost.go`
  and its `-sfu-host-registry` / `VULOS_RELAY_SFU_HOST_REGISTRY` flag,
  `Config.EnableSFUHostRegistry`). It was a first-party Vulos-Meet placement layer
  (register/heartbeat/deregister/resolve a big-call media node); the relay is a
  **generic reachability fabric**, not a media-placement service. **Generic
  reachability is unchanged and fully retained:** the reverse tunnel, the verified
  direct-endpoint fast path (`directprobe.go`), the SSRF-guarded probe, cross-instance
  notify (`/api/s2s/notify`), and TURN-equivalent HTTP/WS fallback all stay. A box
  that self-hosts a real-time app (Jitsi, Element Call, a Matrix homeserver, its own
  TURN/SFU node) is still made reachable exactly as before — WebRTC media rides
  ICE/TURN directly and prefers the box's verified direct endpoint, as it always did.

### Added — agent public-API + self-host contract tests

- **Agent connect-path coverage** (`tunnel/agent/api_test.go`) — `validateOptions`
  (incl. the config-time SSRF loopback guard), `controlURL` scheme
  normalization/enforcement + path preservation, a Snapshot **token-non-leak**
  regression, lifecycle (`Stop` clears `PublicURL`), bounded log ring, and the
  async maintain-loop error path via an injected dial hook.
- **Self-host / no-CP contract** (`tunnel/server/standalone_test.go`) — pins that a
  relay with no Vulos Cloud link keeps tunnelling: the entitlement gate and usage
  meter are inert (every account admitted, nothing metered, over-quota push a no-op),
  the server constructs + serves without a CP, yet still fails closed on a missing
  domain/token store (never runs open).

### Added — geo-distributed pool + autoscale-on-saturation (Go reverse-tunnel)

- **New `tunnel/autoscale` package** — provider-agnostic, app-level capacity control
  so the relay can run as a **pool of N nodes** (Hetzner primary, Vultr edge) on
  flat-bandwidth hosts with no managed autoscaler. Three pieces: a **saturation
  `Detector`** (load → `0..1` ratio with high/low watermarks, sustain window,
  cooldown, min/max-node bounds — anti-thrash hysteresis), a **`Provisioner` seam**
  (`Provision` / `Decommission`, the only place an orchestrator wires a real
  Hetzner/Vultr/Terraform/Fly integration — the relay never hardcodes a provider),
  and a **health-checked `Pool`** (background `/readyz` checker + nearest-healthy
  selector with region-preference and least-loaded tiebreak; a node never
  decommissions itself). An `Autoscaler` ties them together.
- **Server integration** — `*server.Server` now implements `autoscale.LoadSource`,
  gains optional `-node-id` / `-region` / `-provider` self-identity (surfaced on
  `/healthz`), soft-capacity config (`-soft-max-agents` / `-soft-max-streams` /
  `-soft-max-bytes-per-sec`), and a background sampler that publishes
  **`vulos_relay_saturation_ratio`** on `/metrics` so an external orchestrator can
  drive scaling even without the in-process autoscaler. Opt-in: with no soft capacity
  the node is byte-for-byte unchanged.
- **No single-node assumption verified** — a node fails clean (`502` offline / `404`)
  for a name it does not hold, exactly as a pool member must. Real geo-DNS/anycast
  steering and a live provider `Provisioner` remain deploy-side; this ships the seams,
  logic, and tests. ~40 new Go tests (detector hysteresis, pool membership/health/
  nearest, autoscaler end-to-end, server load/sampler, real-server→autoscaler).

### Security — ingress-choke-point hardening (harden/deep-verify-2026-07)

- **Client IP spoofing prevented at the ingress boundary.** The relay is the trust
  boundary, so by default (directly internet-facing) it now **overwrites**
  `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto` with the observed peer
  instead of appending to whatever a public client sent. Previously a client could
  forge the leftmost `X-Forwarded-For` entry, spoofing the source IP the box's app
  reads for IP allowlists, rate-limits, audit logs and geo. New
  `-trust-proxy-headers` (`VULOS_RELAY_TRUST_PROXY_HEADERS=1`) opts into trusting a
  fronting proxy's headers (preserve chain + honor its `X-Forwarded-Proto`) — enable
  **only** behind a trusted TLS-terminating edge; `fly.toml` sets it (Fly's edge is
  that proxy). Regression tests in `forwardedheaders_test.go`.
- **Direct-endpoint SSRF: IPv6 transition-address bypass closed.** The
  reachability/ownership probe's public-IP screen (`isPublicIP`) now unwraps IPv6
  transition addresses — NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo
  `2001::/32` — and re-screens the embedded IPv4, plus rejects the `2001:db8::/32`
  documentation range and additional reserved IPv4 blocks. Previously an address
  like `64:ff9b::7f00:1` (which carries `127.0.0.1`) passed the screen and, on a
  host with a NAT64/6to4 gateway, would let an attacker box point the relay's probe
  at an internal service. Regression test
  `TestDirect_isPublicIP_IPv6TransitionSSRF`.
- **Control-plane rate limiters keyed on the real client IP behind a trusted edge.**
  With `-trust-proxy-headers` on, `RemoteAddr` is the fronting edge for every
  connection, which would collapse the whole fleet into one shared control-connection
  bucket (per-source throttle defeated; a fleet reconnecting after a redeploy
  false-throttles itself). The control-plane limiters (control connects, S2S-notify,
  SFU-host) now key on the left-most `X-Forwarded-For` entry — the same trusted-edge
  header the request path already trusts — in that mode, and strictly on the observed
  `RemoteAddr` (ignoring client-supplied XFF) when directly internet-facing. Tests in
  `clientip_test.go`.
- **Explicit TLS floor + ALPN on the self-terminating listener.** When the relay
  terminates TLS itself and the operator supplied no `TLSConfig`, it now pins an
  explicit hardened `tls.Config` — **TLS 1.2 minimum** + ALPN (`h2`, `http/1.1`) —
  instead of inheriting Go-version-dependent stdlib defaults. An operator-provided
  `TLSConfig` (e.g. a stricter TLS 1.3 floor) is preserved verbatim. Tests in
  `tlsconfig_test.go`.

### Changed — idle cost (direct-first cost model)

- **Adaptive, idle-aware keepalive.** yamux's built-in fixed-interval keepalive is
  replaced by an injectable driver (`tunnel/internal/keepalive`): it pings at the base
  interval (relay 10s / agent 20s) while a tunnel is active and lengthens to a 60s idle
  interval after 2min of no streams, restoring on activity. Under the ratified
  direct-first / relay-as-metered-fallback model this cuts the standing per-box
  heartbeat cost **without evicting the session** — reachability is unaffected, and
  dead-peer detection stays bounded (worst case idle interval + write timeout). Tests
  in `tunnel/internal/keepalive/keepalive_test.go`. (True idle-session *eviction*
  remains planned, not implemented.)

### Docs — trust/cost-model alignment (docs/relay-trust-cost-2026-07)

- Aligned the DOCS + README with shipped reality and the ratified trust/cost posture:
  direct-first is the **preferred** path (cheaper — unmetered — and more private — E2E
  to the box); the relay is the metered fallback for NAT'd boxes; a **hosted** relay
  sees relayed plaintext (cookies/tokens) for a NAT'd box with no direct path, so
  privacy-sensitive workloads and self-hosters are steered to a verified direct
  endpoint or a self-run relay. Documented the adaptive keepalive, the TLS floor + ALPN,
  and the real-client-IP rate-limit keying; and marked **SNI/TLS-passthrough**, **true
  idle-session eviction**, and an **egress-metering billing-model change** as planned,
  not implemented. Docs only.

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

- **`-path-mode` / `-addr` / `-revoke-sweep` had no env-var twin** —
  `fly.toml`'s commented-out `VULOS_RELAY_PATH_MODE` admitted "wire via CMD if
  needed" because `cmd/vulos-relayd/main.go` only read it via `-path-mode` on the
  command line; Fly's `[env]` block can set env vars but not extra CMD args, so
  path-mode was unreachable on Fly without a custom entrypoint. `-path-mode` and
  `-addr` now fall back to `VULOS_RELAY_PATH_MODE=1` / `VULOS_RELAY_ADDR`, and
  `-revoke-sweep` to `VULOS_RELAY_REVOKE_SWEEP` (new `envDuration` helper); the
  flag still wins when both are set. `docs/TUNNEL.md`'s flag table updated to
  match.
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
