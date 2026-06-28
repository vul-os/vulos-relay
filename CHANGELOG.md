# Changelog

All notable changes to `@vulos/relay-client` are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

## [1.0.0] — 2026-06-15

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

[1.0.0]: https://github.com/vul-os/vulos-relay/releases/tag/v1.0.0
