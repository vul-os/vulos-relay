# Relay Consolidation Design

Two consolidations that collapse duplicate / broken reachability primitives into
the single relay ingress described in the target architecture (box = authority,
relay = single reachability ingress, direct-first / relay-fallback). **Design +
plan only — nothing here is implemented.**

Consolidation A — raise/chunk the 32 MiB upload cap so real file uploads work
through the relay.

Consolidation B — fold peering PEER-40 (server-to-server multi-endpoint
failover) into the relay + `@vulos/relay-client` endpoint discovery so there is
**one** reachability primitive instead of two.

All file:line citations are as of 2026-07-09.

---

## Consolidation A — raise / chunk the 32 MiB relay upload cap

### A.1 What the cap actually is (and is NOT)

The cap is a single default:

- `vulos-relay/tunnel/server/server.go:151-153` — `MaxRequestBytes` defaults to
  `32 << 20` (32 MiB) when left at 0.
- It is enforced in exactly one place:
  `vulos-relay/tunnel/server/proxy.go:104-114` — the inbound request body is
  wrapped in `http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)`. When the
  body exceeds the cap, `MaxBytesReader` makes the next read fail; the box-side
  app sees a truncated/aborted body and the public client gets a 400-class error.

Three properties matter for the design:

1. **It caps request BODIES only (uploads), never responses.** The response
   body is streamed back with an unbounded `io.Copy` at `proxy.go:180`, and the
   `RequestTimeout` deadline is explicitly cleared before the body streams
   (`proxy.go:170-172`). So downloads of any size already work; only *uploads*
   are capped.
2. **WebSocket-tunneled traffic is NOT subject to the cap at all.** An
   `Upgrade: websocket` request is hijacked and byte-spliced in both directions
   (`proxy.go:147-151` → `proxy_ws.go`, splice at `proxy_ws.go:71` /
   `splice.go:31-34`). `MaxBytesReader` is never applied on that path. This is a
   load-bearing fact for option A-3 below: chunked upload over a WS channel
   already bypasses the cap today.
3. **The relay never buffers the whole body.** `MaxBytesReader` is a streaming
   wrapper; the request is written straight to the yamux stream
   (`proxy.go:154`). Raising the cap does **not** increase relay memory per
   request — the relay is a pipe, not a buffer. The memory/abuse cost of a
   bigger cap is about *how long a single stream can hold a slot and how much
   aggregate bandwidth one client can burn*, not about a big in-RAM allocation.

### A.2 The memory / abuse tradeoff, stated honestly

- **A bigger single-request cap** (e.g. 5 GiB) is cheap in RAM (streaming) but
  expands per-request abuse: one request can occupy a stream slot
  (`MaxStreamsPerAgent`, default 128 at `server.go:145-147`) for the entire
  upload, and can burn bandwidth/metered egress in one shot. It also interacts
  badly with `RequestTimeout` (default 60 s, `server.go:157-159`): that deadline
  bounds *time-to-response-headers* and is cleared once headers arrive
  (`proxy.go:135-137, 170-172`), so a slow large upload that never lets the box
  send headers could be cut at 60 s. Large single-shot uploads therefore need
  either a generous cap *and* tolerance in the box app, or chunking.
- **Streamed chunks** (many bounded requests) keep each request small, so the
  existing per-request cap, timeout, and rate limits
  (`PublicReqRate`/`GlobalReqRate`, `server.go:81-90`) all keep working as
  designed. Abuse is bounded per-chunk and naturally rate-limited. The cost is
  protocol complexity (offset/resume state) and it lives in the **box app**, not
  the relay — the relay stays a dumb pipe.

### A.3 Recommendation

**Do both, in order — raise the cap to a sane larger value now, add resumable
chunking as the real answer — but put the chunking protocol in the box app, not
the relay.**

**Step 1 (relay, small): raise + make the cap configurable and observable.**

- Raise the default `MaxRequestBytes` from `32 << 20` to **`256 << 20` (256
  MiB)** at `server.go:151-153`. Rationale: 256 MiB covers the overwhelming
  majority of single-file uploads (photos, documents, short video) in one shot,
  stays well under a size where a single stalled stream is a DoS concern, and is
  already streamed so it costs no relay RAM. It is a value, not unbounded.
- The field is already plumbed through `Config` (`server.go:59`) and applied in
  `applyDefaults` — expose it as a deploy env var (e.g.
  `VULOS_RELAY_MAX_REQUEST_BYTES`) in the relay `main` so operators can tune it
  without a rebuild. Keep the fail-safe: never allow 0/unbounded via env (0 must
  keep meaning "use default", matching the existing `applyDefaults` contract).
- Return a clean, cacheable error on overflow. `MaxBytesReader` already yields a
  413-appropriate condition; ensure the proxy surfaces **413 Payload Too Large**
  (with the limit echoed) rather than a generic 400/502, so the box UI can tell
  the user "file too big for a single upload, use resumable" instead of a
  confusing gateway error. This is the one proxy.go change.

**Step 2 (box app, the real fix): resumable chunked upload behind the relay.**

The relay must stay content-blind and dumb. Chunking is a box-app concern that
rides the relay unchanged:

- The box app exposes a standard **resumable/chunked upload endpoint** (design
  target: [tus.io](https://tus.io) resumable-upload semantics, or a minimal
  `Content-Range`-style `POST /upload/{id}?offset=` protocol). Each chunk is a
  normal HTTP request whose body is ≤ `MaxRequestBytes`, so it passes the relay
  with zero relay changes and full rate-limit/timeout coverage.
- The box reassembles chunks to its own `/data` + Tigris bucket (the authority),
  acks each chunk's committed offset, and supports resume after a dropped
  connection. Total upload size is then unbounded regardless of the relay cap.
- **Direct-first still applies for free:** when the box has advertised a verified
  direct endpoint (`direct.go`, `directlisten`), `@vulos/relay-client` already
  prefers it (see Consolidation B), so large uploads go direct at full bandwidth
  and only fall back to chunk-over-relay when NAT'd.
- **Optional later:** for boxes on the relay path only, chunks can also ride the
  already-exempt **WebSocket splice channel** (`proxy_ws.go`) to avoid
  per-chunk HTTP overhead — but this is an optimization, not required. The
  HTTP-chunk path is the simple, standard, cache-friendly default.

**Net:** one tiny reversible relay change (bigger configurable cap + 413), and
the durable fix (resumable upload) lives where it belongs — in the box app,
keeping the relay a pipe. The 256 MiB cap is what makes "most uploads just work"
true on day one; chunking is what makes "any size works" true and is the thing
that actually removes the ceiling.

---

## Consolidation B — fold peering PEER-40 into the relay + endpoint discovery

### B.1 What PEER-40 does today (exact map)

PEER-40 ("Cluster Anycast") lives entirely in
`vulos/backend/services/peering/endpoints.go` and its transport shim
`vulos/backend/services/peering/transport.go`. It is a **second, independent
reachability primitive** for server-to-server envelope delivery:

- **An in-memory endpoint registry** keyed by Vula ID: a Vula ID may advertise
  several `host:port` server addresses (home node, cloud VPS, office machine)
  each with a `Priority` and a measured `LatencyMS`
  (`endpoints.go:37-46`, store at `endpoints.go:52-55`, singleton at
  `endpoints.go:70-73`). The store is explicitly a placeholder the "orchestrator
  can replace with a persistent implementation later" (`endpoints.go:49-51`).
- **Four REST management routes** to CRUD endpoints:
  `POST /api/peering/endpoints/register`, `DELETE …/{id}`,
  `GET /api/peering/endpoints`, `PUT …/{id}/priority`
  (`RegisterEndpointHandlers`, `endpoints.go:235-240`; handlers
  `endpoints.go:242-333`), wired at `backend/cmd/server/main.go:2413`.
- **Race-by-latency failover delivery**: `EndpointFailoverDeliver`
  (`endpoints.go:381-474`) sorts a peer's endpoints by (priority, latency),
  filters to healthy ones (falling back to all if none are healthy,
  `endpoints.go:411-421`), fires **all healthy endpoints concurrently**
  (`endpoints.go:429-436`), returns on the first 2xx and cancels the rest
  (`endpoints.go:444-461`), and records the winner's latency + marks health
  (`endpoints.go:449-451, 457, 466`).
- **UUIDv7 inbound dedup** so racing two nodes is safe: a seen `MsgID` is a
  no-op (`epDedupeCache`, `endpoints.go:59-63, 203-220`; checked at
  `endpoints.go:383-385`).
- **SSRF guard** at register-time (`endpoints.go:258-271`) and defence-in-depth
  at deliver-time (`endpoints.go:479-492`), via `safedial`.
- **Well-known advertisement helper** `EPFromRegistry` /
  `epWellKnownEndpoint` (`endpoints.go:520-537`) to publish a peer's endpoints
  under `/.well-known/vula-id`.
- **The transport entry point** `PeerClient.PostToEndpoints`
  (`transport.go:139-163`): look up `epRegistry.epList(toVulaID)`; if endpoints
  exist, delegate to `EndpointFailoverDeliver`; **if none, fall back to a single
  `Post` to `baseURL`** (`transport.go:144-148`).

### B.1.1 The critical finding: PEER-40 is built but UNWIRED

`PostToEndpoints` — the *only* entry point that consults the PEER-40 registry —
**is never called from production code.** Every real delivery path uses the
single-address `PeerClient.Post(ctx, baseURL, …)` where `baseURL` is derived
from one stored `contact.Server`:

- `messages.go:248-249` — `baseURL := "https://" + contact.Server`;
  `a.client.Post(...)`.
- `messages.go:519`, `groups.go:656`, `groups.go:869`, `contacts_api.go:251`,
  `contacts_api.go:602`, `outbox.go:412-413` — all `client.Post` to a single
  address.
- The outbox retry queue stores exactly **one** `PeerServer` per item and posts
  to it (`outbox.go:397-413`); it has no notion of an endpoint list.

(Confirmed: `grep PostToEndpoints backend --include=*.go` outside tests returns
only its own definition in `transport.go`.)

So today there are effectively **1.5 reachability primitives** for peering:
the *live* one (single `contact.Server` + a persistent outbox retry queue), and
a *dormant* one (PEER-40 registry + race failover) that nothing invokes. This
makes the consolidation dramatically lower-risk than "migrate a load-bearing
system": we are removing a **dead duplicate** and, where multi-endpoint
resilience is actually wanted, routing it through the relay instead.

### B.2 What the relay + endpoint discovery already provide

The relay already implements the same *ideas* PEER-40 reinvented, but as the
single ingress:

- **Reachability with automatic direct-first / relay-fallback** — the ICE-like
  primitive. `@vulos/relay-client`'s `endpoints.js` caches a cloud endpoint and
  a LAN/direct endpoint, health-probes both concurrently, prefers the reachable
  lowest-latency one, and transparently fails over
  (`vulos-relay/client/src/endpoints.js:20-35, 405-455`). This is exactly
  "race endpoints, prefer the fast reachable one" — PEER-40's core — but as the
  shared client primitive.
- **Verified direct endpoints** — the box advertises a direct endpoint, the
  relay *verifies* reachability + ownership before surfacing it
  (`server.go:100-113`, `direct.go`), and a client discovers it via
  `GET /_vulos-direct/resolve` (`direct.go:26, 45-63`; box side
  `directlisten` with ownership-proof probe, `directlisten.go:44-54`). This is
  strictly stronger than PEER-40's registry, which stores an *unverified*
  `host:port` a peer claimed (only SSRF-filtered, `endpoints.go:258-271`).
- **A stable tunnel name as the peer's canonical address** — a box is reachable
  at `<name>.<relay-domain>` (`proxy.go:187-225`) whether it is home, cloud, or
  behind NAT. The relay tunnel *is* the "always works" endpoint that PEER-40's
  registry was trying to approximate with a manual multi-address list.
- **Priority / latency ordering is subsumed:** "prefer direct, else relay" is a
  two-tier priority list the relay + client already implement, with *measured*
  reachability (health probes) rather than a manually-set `Priority` int.

### B.3 The one thing PEER-40 has that the relay/client don't (yet)

The relay + `@vulos/relay-client` are built for **browser→box** reachability
(the web surface reaching its authority). Peering delivery is
**box→box (server-to-server)** and adds two things not yet on the relay path:

1. **UUIDv7 idempotency/dedup** (`endpoints.go:203-220`) — so that if the sender
   retries or races, the receiver processes the envelope once. This is a
   *receiver-side* property and must be preserved; it is independent of which
   transport carries the envelope.
2. **A persistent, at-least-once retry queue** — this already exists and is the
   *live* mechanism: the peering outbox (`outbox.go`), which survives restarts
   and retries a down peer. PEER-40's in-memory race is a weaker, non-durable
   cousin of this.

Neither of these is a transport; both are envelope-delivery *semantics* that
sit on top of whatever transport is chosen. That is why folding the transport
onto the relay does not endanger them.

### B.4 Migration — fold peering onto the relay WITHOUT breaking envelope delivery

The invariant to protect: **cross-instance envelope delivery must keep working
(signed envelope reaches the peer's `/api/peering/inbound/<type>`, exactly-once
at the receiver, durable retry when the peer is down).** The transport
underneath is the only thing changing.

**Phase B-0 — resolve the peer through the shared primitive (behavioral no-op).**
Introduce a single `resolvePeerBaseURL(toVulaID) (baseURL string)` helper in
peering that returns the peer's reachability address using, in priority order:
(1) a verified direct endpoint if the peer advertises one the relay verified,
else (2) the peer's relay tunnel URL `https://<name>.<relay-domain>`, else
(3) today's `contact.Server` (unchanged fallback). Initially wire it so it
returns exactly `contact.Server` — i.e. it is a pass-through — so nothing
changes yet. This is the seam; it is reversible by construction.

**Phase B-1 — route delivery through the resolved base URL.** Change the live
call sites (`messages.go:248`, `messages.go:519`, `groups.go:656/869`,
`contacts_api.go:251/602`, `outbox.go:412`) to obtain `baseURL` from
`resolvePeerBaseURL` instead of `"https://" + contact.Server`. Still one address,
still `PeerClient.Post`, still the same outbox durability
(`outbox.go`) and dedup on the receiver. Envelope format, signing
(`transport.go:96-99`), SSRF guard (`transport.go:66-74`), and the inbound path
are untouched. This is the migration's load-bearing step and it is
byte-compatible on the wire.

**Phase B-2 — turn on relay/direct as the resolution source.** Flip
`resolvePeerBaseURL` to prefer (1) verified-direct then (2) relay-tunnel URL,
using the *same* verified-direct machinery the browser client uses
(`/_vulos-direct/resolve`, `direct.go`) rather than PEER-40's unverified
registry. Now a peer that is NAT'd/CGNAT — which today simply fails to receive —
becomes reachable via its relay tunnel. This is a pure *gain* in
deliverability; `contact.Server` remains the last-resort fallback so any peer
that predates relay advertisement still works.

**Phase B-3 — delete the PEER-40 duplicate.** With the live paths on the shared
primitive and `PostToEndpoints` still unused, remove: `PostToEndpoints`
(`transport.go:129-163`), `EndpointFailoverDeliver` + the `epRegistry` store +
the four REST routes (`endpoints.go`), and their wiring at `main.go:2413`.
**Keep** the two things that were genuinely PEER-40's and are delivery
*semantics*, relocating them to where they belong:
- **UUIDv7 dedup** (`epDedupeCache`, `endpoints.go:59-63, 203-220`) — move into
  the inbound envelope handler as receiver-side idempotency (it may already be
  partly covered by envelope handling; verify before deleting).
- **`EPFromRegistry`/well-known advertisement** (`endpoints.go:520-537`) — if
  `/.well-known/vula-id` still needs to advertise addresses, have it advertise
  the box's **relay tunnel URL + verified direct endpoint** (the real
  reachability), not a manual endpoint list. If nothing consumes the endpoint
  list on the well-known doc, drop it entirely.

**Why this can't break cross-instance delivery:**
- The wire contract (`POST <base>/api/peering/inbound/<type>` with a signed
  `Envelope`) never changes — only how `<base>` is computed.
- Durability is unchanged: the outbox (`outbox.go`) is the retry mechanism
  throughout, and it is already the live path (PEER-40's in-memory race never
  was).
- Exactly-once is preserved by moving, not dropping, the dedup cache.
- Every phase keeps `contact.Server` as a fallback, so no peer becomes
  unreachable during migration.
- The direct/relay resolution reuses **verified** endpoints, closing the one
  weakness of PEER-40 (storing unverified peer-claimed addresses).

### B.5 What "one reachability primitive" looks like after B

- **Browser → box:** `@vulos/relay-client` endpoint discovery → direct-first,
  relay-fallback. (unchanged)
- **Box → box (peering):** `resolvePeerBaseURL` → direct-first (verified),
  relay-fallback, `contact.Server` last resort → `PeerClient.Post` → durable
  outbox retry → receiver dedup. (same primitive, server-to-server)
- **One discovery surface** (`/_vulos-direct/resolve` + relay tunnel name),
  **one verification path** (relay ownership probe), **one fallback ladder**
  (direct → relay → legacy address). No parallel in-memory endpoint registry,
  no second race-delivery implementation.

---

## Phased plan (reversible)

Each phase is independently shippable and revertible; nothing is a point of no
return until B-3, which is gated on B-1/B-2 having soaked.

| Phase | Change | Repo / files | Reversible by |
|------|--------|--------------|---------------|
| **A-1** | Raise default `MaxRequestBytes` 32→256 MiB; make it env-configurable; return 413 on overflow | `vulos-relay` `server.go:151-153`, proxy.go overflow path, relay `main` | revert the default constant + env read |
| **A-2** | Box-app resumable/chunked upload endpoint (tus-style); reassemble to `/data`+bucket; resume support | `vulos` box app (Files/upload service) | feature-flag off → clients use single-shot ≤ cap |
| **B-0** | Add `resolvePeerBaseURL(toVulaID)` returning `contact.Server` (pass-through no-op) | `vulos` `services/peering` | delete the helper |
| **B-1** | Route live delivery sites through `resolvePeerBaseURL` (still single address) | `messages.go`, `groups.go`, `contacts_api.go`, `outbox.go` | inline `contact.Server` back |
| **B-2** | Make `resolvePeerBaseURL` prefer verified-direct → relay-tunnel → `contact.Server` | `vulos` peering + reuse `/_vulos-direct/resolve` | revert helper body to pass-through (B-0 state) |
| **B-3** | Delete PEER-40 duplicate (`PostToEndpoints`, `EndpointFailoverDeliver`, `epRegistry`, 4 REST routes, `main.go:2413`); RELOCATE dedup + well-known advertisement | `vulos` `endpoints.go`, `transport.go`, `main.go` | git revert (dead code, no live dependents) |

**Sequencing notes**
- A and B are independent; A can ship first (self-contained, tiny relay diff).
- Within B, B-3 is deferred until B-1+B-2 have run in production long enough to
  confirm no peer relies on the (already-dead) PEER-40 path — it is a cleanup,
  not a behavior change.
- B-1 is the only step that touches the live delivery path; because it is a
  pure `baseURL` source-swap with `contact.Server` preserved as fallback, it is
  safe to canary per-envelope-type and revert instantly.
- Do **not** delete the peering **outbox** (`outbox.go`) — it is the durable
  retry primitive and is orthogonal to PEER-40; only the in-memory race
  (`EndpointFailoverDeliver`) is removed.

## Open questions for the founder / follow-up
1. **Chunk protocol choice (A-2):** adopt tus.io (standard, resumable, has
   client libs) vs a minimal home-grown `Content-Range` offset protocol. Tus is
   the lower-risk, interoperable default; confirm before building.
2. **Well-known endpoints (B-3):** does anything still consume the
   `/.well-known/vula-id` `endpoints` array? If yes, re-advertise relay-tunnel +
   verified-direct there; if no, drop it. Needs a consumer grep before deletion.
3. **256 MiB value:** confirm 256 MiB as the single-shot ceiling (vs 128/512).
   It only affects the pre-chunking single-request experience; chunking removes
   the ceiling regardless.
