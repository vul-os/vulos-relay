# Vulos Relay — Roadmap

> **Implementation status:** All 16 tasks in `TASKS.md` are complete. The
> foundation (queue interface, reputation-policy interface, send pipeline),
> sending engine (Mox `smtpclient`, pool segmentation), deliverability
> automation (warm-up ramp, postmaster tools, blocklist monitoring, DKIM
> rotation, Rspamd outbound scan), abuse defense (per-account scoring, instant
> suspension, open-relay-abuse prevention via RELAY-16), and peering
> (versioned wire spec, transport, peer detection + SMTP fallback via RELAY-15)
> are all shipped. The HTTP submission listener is wired (`RELAY_SUBMIT_ADDR`,
> default `:8025`). Static peer config loading (`RELAY_PEER_CONFIG`) is
> documented in `main.go` as a future extension; the relay operates in SMTP-only
> mode when no peer config is provided. Peering wire spec versions are stable in
> `spec/VERSIONS.md`.

Vulos Relay is the open-source outbound delivery path for Vulos mail: a
warmed-IP **relay** and a Vulos-to-Vulos **peering** transport, in one repo.
This roadmap is priority-ordered, top to bottom — the sections near the top are
the spine everything else hangs off; the sections near the bottom are upside.
There are no dates here on purpose. The companion mail *server* lives in
[vulos-mail](https://github.com/vul-os/vulos-mail) (a Mox fork); this repo is
strictly the part that gets a message *out*.

---

## Foundation — pluggable seams

Before any deliverability machinery, the repo must earn the right to be reused.
The two questions a relay cannot answer for itself — *where do I get mail to
send* and *what is my reputation policy* — are the two seams that keep this
project from being hardwired to Vulos's bucket layout. Get the interfaces right
first; everything else is an implementation behind them.

**Goals**

- Make the relay embeddable: a self-hoster can drop it into their own stack
  without inheriting Vulos's storage or cloud assumptions.
- Keep Vulos's bucket-backed queue as just one implementation of a public
  interface, on equal footing with any third party's.
- Establish a single, testable send path that both the relay and peering branch
  flow through.

**Concrete features**

- **Queue interface** — "give me the next message to send, let me ack/nack/retry
  it." Vulos plugs in a bucket-backed queue; the repo ships an in-memory and a
  filesystem reference implementation for standalone use.
- **Reputation-policy interface** — "may this account send right now, and at what
  rate?" The relay asks; the policy answers. Vulos plugs in its tenant-aware
  policy; the repo ships a permissive default and a simple per-account cap.
- **Single send pipeline** — one path from queue → policy check → peering-or-SMTP
  decision → send → result, with the peering decision as one branch.

**Explicit non-goals**

- **Not a mailbox or an MTA-in-full.** No SMTP/IMAP/JMAP server, no storage —
  that is `vulos-mail`. This repo does not receive mail.
- **No hard dependency on Vulos buckets, fabric, or the cloud control plane** in
  the core. Vulos integration is a backend, not a baked-in assumption.

---

## The relay — shared warm pool & sending engine

The heart of the project: a smarthost that most senders use as their *permanent*
outbound path. The counter-intuitive truth driving the design is that a shared
pool of warmed IPs beats a cold dedicated IP for almost everyone, because a
dedicated IP needs thousands of messages a day just to stay warm. The long tail
gets better inbox placement by sharing a well-tended pool than by owning a cold
one.

**Goals**

- Deliver the long tail's mail with better placement than they could achieve
  alone, via a shared pool of warmed IPs.
- Offer dedicated-IP-direct as a premium path for senders with the volume to
  keep an IP warm — without making it the default.
- Keep the sending engine boring and correct by standing on a proven SMTP client.

**Concrete features**

- **Outbound SMTP sending engine** built on Mox's `smtpclient` (STARTTLS, DANE,
  MTA-STS, retries, bounce handling) — not a from-scratch MTA.
- **Shared warm pool** as the default outbound path; per-message selection of a
  pool IP appropriate to the account.
- **Dedicated-IP-direct** as a premium option for high-volume senders, selected
  by the same send pipeline.

**Explicit non-goals**

- **No reinvented SMTP stack.** Mail correctness lives upstream in Mox; we add
  pooling and reputation, not a new TLS/DANE implementation.
- **Dedicated IP is not the default** — it is a deliberate opt-in for senders who
  can keep it warm.

---

## Deliverability automation — keeping the pool warm

A warm pool stays warm only if something actively tends it. This is the operational
muscle that separates a managed relay from "a box that runs `sendmail`": ramping
new IPs slowly, watching every blocklist, rotating signing keys, and registering
with the mailbox providers' own postmaster programs so reputation is observable
rather than guessed at.

**Goals**

- Bring new IPs online without burning them, on a disciplined ramp.
- Know an IP's standing from the source — the mailbox providers themselves — and
  from the public blocklists, in near-real-time.
- Recover from a listing automatically rather than waiting for a human to notice.

**Concrete features**

- **IP warm-up ramp scheduler** enforcing per-IP daily caps on a curve
  (50 → 200 → 500 → 1k → 2.5k/day), with graduation between steps on healthy
  signal.
- **Postmaster Tools + SNDS auto-registration** — register pool IPs/domains with
  Google Postmaster Tools and Microsoft SNDS and ingest their reputation data.
- **Blocklist monitoring + auto-delisting** — poll Spamhaus, SORBS, Barracuda,
  and SenderScore; on a listing, fire the provider's delist flow automatically
  and quarantine the affected IP from the active pool until clear.
- **DKIM rotation** on a schedule, coordinated so signing never lapses.
- **Outbound Rspamd integration** — content-scan messages before they leave, so
  the pool's reputation is protected from its own senders.

**Explicit non-goals**

- **Not an inbound spam filter.** Rspamd here scans *outbound* only; inbound
  filtering belongs to the MX gateway in `vulos-mail`.
- **No manual-only delisting.** A listing that requires a human in the loop is a
  bug in the automation, not the steady state.

---

## Abuse defense — protecting the shared resource

A shared warm pool is a shared *reputation*, which means one abusive account can
poison deliverability for everyone else on its IPs. The relay must treat its own
senders as the primary threat model: score them continuously, suspend them
instantly on abuse, and segment the pool so a bad actor's blast radius is bounded.

**Goals**

- Make per-account sending reputation a first-class, continuously-scored signal.
- Cut off an abusive sender in seconds, not after the damage lands a pool IP on a
  blocklist.
- Bound the blast radius of any single account by segmenting the pool.

**Concrete features**

- **Per-account reputation scoring** — a rolling score from bounce rates, spam
  complaints, Rspamd verdicts, and provider feedback loops.
- **Instant abuse suspension** — a score crossing the abuse threshold suspends
  the account's sending immediately and pulls its mail from the active queue.
- **Pool segmentation by trust/age** — new and untrusted senders ride separate
  pool segments from established ones, so a fresh account cannot taint mature IPs.
- **Open-relay-abuse prevention** — authenticate every submission to a known
  account/policy; the relay never forwards mail for an unauthenticated or
  unknown sender.

**Explicit non-goals**

- **Not a content-moderation or compliance system.** Abuse defense is about
  deliverability and open-relay safety, not policy adjudication of message
  content.
- **No silent best-effort delivery for abusers.** Suspension is hard and
  immediate, not a soft throttle that lets bad mail trickle out.

---

## Peering — Vulos-to-Vulos handoff

When both ends speak Vulos, public SMTP is a liability the message never needs to
take on. Peering hands the message off over the Vulos fabric/bucket transport
instead: encrypted end to end, with no DNS lookup, no blocklist exposure, and no
spam filter in the middle. It is one branch in the send pipeline — a peer
recipient takes the fabric path; everyone else falls back to SMTP.

**Goals**

- Make intra-Vulos mail private-by-default and immune to public-SMTP
  deliverability problems.
- Resolve the peering-vs-SMTP decision cheaply at send time, with a clean
  fallback for non-Vulos recipients.
- Make peering safe to operate without trusting the network — security from
  cryptography, never from secrecy.

**Concrete features**

- **Peer detection** at send time — determine whether the recipient is a Vulos
  peer and route to the fabric path if so.
- **Peering transport implementation** — encrypted handoff over the
  fabric/bucket transport, with replay protection and authenticated peers.
- **SMTP fallback** — any non-peer recipient flows seamlessly back into the
  relay's standard SMTP send path.

**Explicit non-goals**

- **Not a chat or presence system.** Peering moves mail; live collaboration and
  presence are other projects' problems.
- **No falling back to an insecure path on peering failure.** A failed peer
  handoff retries or defers; it does not silently downgrade a peer message onto
  public SMTP without policy.

---

## Open federation — a published, versioned protocol

The upside that makes peering more than a private optimization: if the wire
format is a real spec, anyone can run a Vulos-compatible node and peer with the
network. This section is lower priority than making peering *work*, but it is why
peering is documented as a spec from day one rather than reverse-engineered later.

**Goals**

- Publish the peering wire protocol as a versioned, implementable spec living in
  this repo.
- Make interop a design constraint, so independent implementations can peer.
- Grow a federation of Vulos-compatible nodes as a long-term network effect.

**Concrete features**

- **Versioned peering wire spec** in [`spec/`](spec/) — peer address resolution,
  envelope format, cryptographic handshake, replay protection, and version
  negotiation, written to be implemented by a third party.
- **Cryptographic soundness as a stated property** — the spec defines the trust
  model explicitly; nothing in it relies on the protocol being secret.
- **Interop conformance** — a documented test surface so a new implementation can
  prove it peers correctly.

**Explicit non-goals**

- **Not a standards-body submission (yet).** The spec is published and versioned;
  formal standardization is out of scope until interop is real.
- **No backward-incompatible churn without a version bump.** The wire format is a
  contract; breaking it requires a new protocol version.

---

## Storage backend, multi-location & 2-track billing context (finalized 2026-05-24)

### Relay's role in the storage-backend choice

`vulos-relay` is storage-agnostic at the relay level. The relay transports mail; it does not
touch the customer's document or mail storage bucket. However, the relay is relevant to the
storage-backend story in two ways:

1. **Encrypted queue delivery:** For BYO (Self-Host) accounts using MinIO, the relay routes
   encrypted inbound queue blobs from the MX gateway to the customer's `vulos-mail` instance
   over the peering fabric where possible (RELAY-BYO-01). The relay forwards opaque ciphertext
   — it never sees plaintext regardless of storage backend.

2. **Multi-location health signal:** The relay's fabric-reachability signal (RELAY-BYO-02)
   is one input to the cloud health-check daemon's per-location health store, which drives
   cross-location inbound-mail routing (`CP-MULTLOC-02` in vulos-cloud).

### 2-track billing context

`vulos-relay` serves both billing tracks identically at the relay level:
- **Self-Host (Track A, R3/user + R9 floor):** warm-up relay, MX inbound routing, peering
  transport, and spam filtering are all provided to Self-Host customers.
- **Hosted (Track B, R19/user+):** same relay fleet, same infrastructure.

The relay pool does not distinguish billing tier. Both tracks use the same warmed-IP pool,
DKIM rotation, and DMARC reporting infrastructure.

### Anchor inbox — relay passthrough

Inbound mail destined for an account's anchor inbox (always Tigris, ~1 GB) flows through the
same MX gateway and relay path as any other inbound mail. There is no relay-level distinction
for anchor inbox delivery. The MX gateway handles the routing decision (primary bucket vs
anchor inbox fallback) transparently.

---

## BYO Mail support (in progress — parallel implementation)

`vulos-relay` serves BYO and hosted customers identically for outbound sending (the relay pool
does not care whether the origin is self-hosted or cloud-hosted). The BYO-specific relay work
covers inbound queue routing and health-check signaling.

**BYO-specific relay responsibilities:**
- The warm-up relay pool handles outbound SMTP for both Self-Host (R3 + R9 floor) and Hosted (R19)
  Vulos Mail customers — the relay pool does not distinguish billing tier; both use the same
  warm-up relay fleet and IP reputation infrastructure.
- The MX gateway (inbound) is cloud-side; `vulos-relay` provides the peering transport that
  delivers decrypted mail from the MX bucket to the BYO instance's queue fetch loop.
- BYO uptime is not a relay concern — the health-check daemon lives in `vulos-cloud`. The relay
  queues mail and retries; the 5-day TTL is enforced by the cloud queue.

Cross-repo: see `vulos-cloud/ROADMAP.md §BYO Mail support` and `vulos-mail/ROADMAP.md §BYO Mail support`.

---

## Future work

### Federated peering reputation: ReputationAttestation message + signing/verify path
Define and implement the `ReputationAttestation` peering message: a signed attestation
that a given sender identity has good/poor sending history, emitted by relay nodes to
peering neighbours. Includes key distribution for cross-peer trust, a signing path
(Ed25519 over a canonical JSON envelope), and a verify path that validates the attestation
chain before accepting the score. The vulos-cloud control plane consumes these attestations
to build a cloud-side peer reputation store. Do not touch `internal/peering/reputation.go`
if the spam agent is working in it — coordinate before merging.

### Submit listener per-IP rate cap
Add a per-IP rate cap to the HTTP submission listener (`RELAY_SUBMIT_ADDR`, default `:8025`).
Configurable via environment variable or config file: `RELAY_SUBMIT_RATE_PER_IP` (default
60 requests/min per source IP). Return HTTP 429 with `Retry-After` header on cap breach.
Log rate-cap events to the abuse/reputation pipeline. Small, safe, high-impact DoS defence
for the submission path.

---

## Fabric-P2P sync, streaming signaling & deliverability isolation (v6)

**Fabric-P2P sync:** direct box-to-box CRDT delta + blob sync over the fabric (leaderless, NAT-friendly),
including same-LAN local discovery so two boxes on one LAN sync with the internet down — removing the central
dependency for sync. **Streaming signaling:** WebRTC signaling relay + STUN/TURN NAT-traversal for low-latency
streaming, with media P2P and the relay as an egress-aware TURN fallback only. **Deliverability isolation:**
per-pool-segment circuit-breaker that auto-quarantines a warm-IP segment on a blocklist/complaint threshold so
one bad sender can't blocklist the whole pool. Tasks: `SYNC-P2P-01`, `STREAM-RELAY-01`, `RISK-DELIV-01`.

---

## Audit-fix wave A + video-meet SFU (v7.1 — 2026-05-24)

**Audit-fix wave A** addresses the 3 relay findings from the #125 pass: TURN slot egress double-count math
(`RelayMediaInbound` speculatively charges bytesOut, halving documented quota — split into a post-write
`RelayMediaSent`); a doc/TODO clarifying that operators must wire a single ReplayGuard across both directions
for store-and-forward carriers; a SECURITY note that `tokenSnapshot` is not authenticated (slot-lifetime +
addr-binding are the gates). Tasks: `FIX-TURN-EGRESS-CALC-01`, `FIX-REPLAYGUARD-DOC-01`, `FIX-TOKENSNAP-DOC-01`.

**Video meetings — SFU (Wave B).** STREAM-RELAY-01 was sized for 1:1 game streaming (opaque media relay, no
simulcast/SVC). 500-participant meetings need a real SFU with simulcast + active-speaker + audio-mix-top-N.
The OSS-aligned choice is LiveKit (MIT, Go) wrapped in a new sibling repo `vulos-meet` — same language, same
license as our 4 OSS repos, self-hostable, supports cascading SFU for large rooms. `vulos-meet` becomes the
4th OSS sibling alongside vulos / vulos-mail / vulos-office. Spec addition: `VULOS-MEET/1` token shape in
`spec/VERSIONS.md`. Tasks: `MEET-CORE-01` (this repo's entry point — the task creates the new repo); see
sibling repos for cloud Pro-gate (`MEET-CP-01`), office UI (`MEET-SPACES-01`), OS wrapper (`MEET-OS-01`),
transcription (`MEET-TRANSCRIPT-01`).

---

## Relay-client JS package (v7.2 — Wave C)

vulos-office accumulated the JS peer-fabric client (`src/lib/{signaling,fabric,presence,call,useLiveCursors,
roundTripCheck}.js`); `endpoints.js` + `offlineBootstrap.js` are **triple-duplicated** across office + mail-
webmail + vulos OS (~1k LOC of duplication). Promote into a new MIT JS package `@vulos/relay-client` housed at
`vulos-relay/client/` — sibling to the existing Go relay surfaces (peering / sync / streamsignal / repisolation).
Future apps consume relay primitives from one place; the 3 current consumers migrate and delete their local
copies. Wave-C task graph: `RELAY-CLIENT-01` (this repo, foundation) → `RELAY-CLIENT-02` (office migrate +
`MEET-FRONTEND-POLISH-01`), `RELAY-CLIENT-03` (mail-webmail migrate), `RELAY-CLIENT-04` (vulos OS migrate) all
parallel after the foundation lands. Final step: `#125` verification wave across all 6 sibling repos
(vulos, vulos-mail, vulos-relay, vulos-office, vulos-cloud, vulos-meet).
