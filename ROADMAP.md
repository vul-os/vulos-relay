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
- **Sovereign relay tunnel (Go)** — self-hostable `vulos-relayd` + `vulos-relay-agent`
  replacing the third-party frp server (`tunnel/`, `cmd/`); the repo now ships both
  the JS SDK and this server-side tunnel

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

### Sovereign reverse tunnel (Go) — planned, not implemented
- **SNI / TLS passthrough for NAT'd boxes** — route on SNI and forward the encrypted
  stream for the box to terminate, so a NAT'd box↔user leg is opaque even to a
  *hosted* relay (extends the direct path's end-to-end property to NAT'd boxes). Today
  a hosted relay terminates TLS and sees that leg in plaintext; the direct path and
  self-run relays are the current answers for relay-blindness. See
  [docs/SECURITY.md](docs/SECURITY.md#planned-hardening).
- **True idle-session eviction** — the adaptive keepalive slows an idle tunnel's
  heartbeat but never closes it; evicting genuinely idle tunnels outright is a separate,
  unbuilt change.
- **Egress-based billing model** — the meter currently counts proxied body bytes; a
  shift to egress-based billing is a future direction, not current behavior.

---

## Out of scope (frozen invariants)

- Google SSO / OAuth.
- Stripe billing.
- Rust rewrites.
- `.tsx` files — JSX only, or plain JS.

---

_Last updated: 2026-07-13_
