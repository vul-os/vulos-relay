# Roadmap — @vulos/relay-client

This file tracks planned directions for the SDK. It is a living document;
priorities shift with Vulos OS milestones.

---

## Stable / Shipped (1.0)

- Endpoint failover (cloud ↔ LAN) with health probing and `configure()` seam
- Offline-first bootstrap + IndexedDB write queue
- WebRTC signaling over host `/api/peering/stream` WebSocket
- Fabric sessions — P2P data channels + relay-circuit fallback
- Presence and live cursors (React hooks)
- Call — mesh WebRTC (`createCall`); LiveKit SFU was removed before 1.0
- Round-trip check fixture runner (subpath `@vulos/relay-client/roundTripCheck`)
- Dual ESM + CJS build; optional React / xlsx peer deps
- Release pipeline with npm provenance and GitHub Releases

---

## Near-term (1.x)

### Reliability
- **Reconnect budget** — cap total reconnect attempts and surface a terminal
  `offline` event so UIs can show a degraded-mode banner.
- **Probe debounce** — coalesce rapid network-change events (e.g. Wi-Fi handoff)
  into a single endpoint re-probe instead of parallel storms.

### Signaling
- **Multiplexed signaling** — share one WebSocket across multiple concurrent
  fabric sessions instead of one socket per session.
- **Presence delta compression** — send presence diffs rather than full snapshots
  for high-peer-count rooms.

### Developer experience
- **TypeScript declaration files** — emit `.d.ts` from JSDoc without converting
  source to `.ts`.
- **Structured error types** — replace ad-hoc `Error` throws with exported error
  classes so consumers can `instanceof`-check.

---

## Medium-term (2.x)

### Transport
- **QUIC / WebTransport signaling** — fall back to WebSocket for browsers that
  lack WebTransport support; prefer QUIC when available.
- **Adaptive bitrate hint** — expose an `onNetworkQuality` callback so the OS
  shell and vulos-office can throttle CRDT sync frequency under poor connectivity.

### Security
- **End-to-end key agreement** — optional ECDH handshake over the signaling
  channel so fabric data channels are encrypted at the application layer
  (independent of DTLS-SRTP).

### Multi-surface
- **Shared service worker** — a single registered service worker across all
  Vulos tabs on a given origin to deduplicate endpoint probes and the offline
  write queue.

---

## Out of scope (frozen invariants)

- Shipping a Go server, SMTP daemon, or any server-side process — the daemon
  was retired; server-side concerns belong in vulos-mail / vulos-cloud.
- Google SSO / OAuth.
- Stripe billing.
- Rust rewrites.
- `.tsx` files — JSX only, or plain JS.

---

_Last updated: 2026-06-15_
