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
