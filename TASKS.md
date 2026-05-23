# Vulos Relay — Task Backlog

**Status: 16 / 16 tasks done (100%).** All foundation, sending-engine, deliverability,
abuse-prevention, and peering tasks are complete, including RELAY-15 (peer detection +
SMTP fallback in the router) and RELAY-16 (open-relay-abuse prevention / submission
authentication). The HTTP submission listener (`RELAY_SUBMIT_ADDR`) is wired and
enabled by default. This repo is the open-source (MIT, Go) outbound delivery path for
Vulos mail: a warmed-IP **relay** plus a Vulos-to-Vulos **peering** transport. The mail
*server* (SMTP/IMAP/JMAP + storage) is the sibling
[vulos-mail](https://github.com/vul-os/vulos-mail) repo (a Mox fork); this repo gets
mail *out* and keeps sending reputation healthy. Consumed by the closed `vulos-cloud`
control plane as a multi-tenant warmed-IP service, and fully self-hostable standalone.

> **Invariants (FROZEN):** MIT license; Go. Two pluggable seams — the **queue**
> (where mail to send comes from) and the **reputation policy** (may this account
> send, at what rate) — are interfaces; the core is NEVER hardwired to Vulos's
> bucket layout. Outbound SMTP reuses Mox `smtpclient` (no from-scratch MTA). Rspamd
> here is OUTBOUND-only (inbound filtering is `vulos-mail`'s MX gateway). The peering
> wire format is a versioned spec in `spec/`, designed for cryptographic soundness
> and open federation (security from cryptography, NOT secrecy). The relay NEVER
> forwards mail for an unauthenticated/unknown sender.

---

## How to read a task

Each task is a self-contained chunk of work. Format:

```
### [ID] short title
`todo` · P0|P1|P2|P3 · S|M|L · dep: <IDs or none> · parallel: yes|no — owned file path(s)
Scope: one paragraph; enough for an autonomous agent.
AC: [ ] verifiable outcome 1 [ ] outcome 2 [ ] go build / go test as appropriate
```

**Status token** — line immediately after `### [ID]` carries `` `todo` `` or `` `done` ``.
**Priority** — `P0` highest → `P3` lowest.
**Effort** — `S` / `M` / `L` rough size.
**`parallel: no`** — touches a hot shared file (the send pipeline, main.go); rebase on main before opening PR.
**Picking a task** — any `todo` whose `dep:` entries are all `done` is fair game.

---

## Area: Foundation

_Prefix: `RELAY-*`_

> Go module + MIT license, then the two pluggable seams (queue, reputation policy)
> and the single send pipeline everything flows through. Get the interfaces right
> before any deliverability machinery — the core must stay reusable, never wired to
> Vulos buckets.

### [RELAY-01] Repo skeleton: Go module + MIT LICENSE + layout
`done` · P0 · S · dep: none · parallel: no — go.mod, LICENSE, internal/relay/doc.go, cmd/relay/main.go
Scope: Initialize the Go module `github.com/vul-os/vulos-relay` (Go 1.21+). Add a standard MIT LICENSE file (copyright "Vulos contributors"). Create the package layout: `internal/relay/` (core types), `internal/queue/`, `internal/reputation/`, `internal/sending/`, `internal/peering/`, `spec/`, and a `cmd/relay/main.go` stub that prints version and exits 0. Add a minimal `.gitignore` (binaries, `*.db`). No business logic yet — just a compiling skeleton with package doc comments stating each package's responsibility.
AC: [ ] go.mod declares module github.com/vul-os/vulos-relay, go 1.21+ [ ] LICENSE is MIT [ ] all internal/ packages have a doc.go [ ] cmd/relay prints version [ ] go build ./... && go vet ./...

### [RELAY-02] Queue interface + in-memory & filesystem reference impls
`done` · P0 · M · dep: RELAY-01 · parallel: yes — internal/queue/queue.go, internal/queue/mem.go, internal/queue/fsqueue.go
Scope: Define the `Queue` interface — the seam for "where do I get mail to send." Types: `OutboundMessage` (id, account_id, sender, recipients, raw_rfc822 []byte, attempts, next_attempt_at, metadata map). Methods: `Lease(ctx, n) ([]LeasedMessage, error)` (claim up to n messages with a visibility timeout), `Ack(ctx, id)`, `Nack(ctx, id, retryAfter)` (requeue with backoff), `Fail(ctx, id, reason)` (dead-letter). Provide `MemQueue` (in-process, for tests/standalone) and `FSQueue` (filesystem-backed, JSON-per-message, for simple self-hosting). Sentinel errors: `ErrEmpty`, `ErrUnknownMessage`, `ErrLeaseExpired`. Vulos's bucket-backed queue is OUT of this repo — it implements this interface externally.
AC: [ ] Queue interface documented with the Vulos-bucket-is-external note [ ] MemQueue Lease/Ack/Nack/Fail round-trip [ ] FSQueue survives process restart (messages persist) [ ] Nack reappears only after retryAfter [ ] Lease visibility timeout re-leases unacked messages [ ] go test ./internal/queue/...

### [RELAY-03] Reputation-policy interface + permissive & per-account-cap impls
`done` · P0 · M · dep: RELAY-01 · parallel: yes — internal/reputation/policy.go, internal/reputation/permissive.go, internal/reputation/capped.go
Scope: Define the `Policy` interface — the seam for "may this account send right now, and at what rate." Methods: `CheckSend(ctx, account_id, msg) (Decision, error)` returning `Decision{Allow bool, Reason string, DelayUntil *time.Time, PoolHint string}`; `RecordResult(ctx, account_id, result SendResult)` to feed scoring (result carries delivered/bounced/deferred/complaint + provider). Provide `Permissive` (always allow — standalone default) and `CappedPolicy` (per-account daily cap + simple rolling bounce-rate threshold → deny). Sentinel errors: `ErrSuspended`, `ErrRateLimited`. Vulos's tenant-aware policy implements this interface externally; the core must never assume Vulos's scoring.
AC: [ ] Policy interface documented [ ] Permissive allows everything [ ] CappedPolicy denies past daily cap with DelayUntil set [ ] CappedPolicy denies when rolling bounce-rate exceeds threshold (ErrSuspended) [ ] RecordResult updates the score used by the next CheckSend [ ] go test ./internal/reputation/...

### [RELAY-04] Send pipeline: queue → policy → route → result
`done` · P0 · L · dep: RELAY-02, RELAY-03 · parallel: no — internal/relay/pipeline.go, internal/relay/router.go
Scope: The single path every message flows through. A worker loop calls `Queue.Lease`, runs `Policy.CheckSend` (deny → Nack/Fail per decision), then asks a `Router` whether the recipient is a Vulos peer (peering branch, RELAY-13) or a standard recipient (SMTP branch, RELAY-05). For now stub both senders behind a `Sender` interface (`Send(ctx, msg) (SendResult, error)`) so the pipeline is testable before the engines land. On result, call `Policy.RecordResult` and `Queue.Ack`/`Nack`. The `Router.IsPeer(recipient)` decision is one branch — keep it cheap and injectable. Concurrency via a configurable worker count; graceful drain on context cancel.
AC: [ ] pipeline leases, policy-checks, routes, records result, acks — end to end with stub senders [ ] policy deny → message Nacked/Failed per Decision, never sent [ ] IsPeer=true routes to peer sender, false routes to SMTP sender [ ] worker pool drains gracefully on cancel (in-flight finish, no new leases) [ ] go test ./internal/relay/...

---

## Area: Sending engine

_Prefix: `RELAY-*`_

> Outbound SMTP on Mox `smtpclient` (no from-scratch MTA). The shared warm pool is
> the default path; dedicated-IP-direct is a premium opt-in. Both selected by the
> same pipeline.

### [RELAY-05] Outbound SMTP sender on Mox smtpclient
`done` · P0 · L · dep: RELAY-04 · parallel: yes — internal/sending/smtp.go, go.mod
Scope: Implement the `Sender` for standard recipients using Mox's `smtpclient` as a dependency (add `github.com/mjl-/mox` to go.mod; reuse its dial/STARTTLS/DANE/MTA-STS/SMTP transaction handling — do NOT reimplement). Resolve recipient MX, deliver, classify the result into `SendResult{State: delivered|deferred|bounced, Code, EnhancedCode, Provider}`. Map 4xx → deferred (Nack), 5xx → bounced (Fail), success → delivered. Source-IP/HELO selection comes from the pool selector (RELAY-11) via a `SourceBinding` passed in; default to OS routing if none. No bounce-message generation here (that is the mail server's job) — just classify and return.
AC: [ ] mox/smtpclient wired as the transport (no hand-rolled SMTP) [ ] delivered/deferred/bounced classified from SMTP reply codes [ ] STARTTLS attempted, MTA-STS/DANE honored via smtpclient [ ] SourceBinding selects HELO + source IP when provided [ ] integration test against a local SMTP sink [ ] go build ./... && go test ./internal/sending/...

### [RELAY-11] Pool segmentation by trust/age + source-IP selector
`done` · P1 · M · dep: RELAY-05 · parallel: yes — internal/sending/pool.go
Scope: Implement the warmed-IP pool. `Pool` holds segments (e.g. `new`, `untrusted`, `established`, `dedicated`) each owning a set of source IPs with HELO names and current warm-up step. `Pool.Select(account_id, policyHint) (SourceBinding, error)` returns the IP a given account should send from: new/untrusted accounts ride the low-trust segments, established accounts the mature ones, and a dedicated-IP account gets its own binding. Quarantine API `Pool.Quarantine(ip, reason)` / `Unquarantine(ip)` so blocklist monitoring (RELAY-08) can pull a listed IP out of rotation. The shared pool is the default; dedicated is opt-in via account config. Selection must never hand an untrusted account a mature pool IP.
AC: [ ] segments isolate new/untrusted from established IPs [ ] Select honors the PoolHint from the reputation Decision [ ] dedicated-IP account gets its own binding [ ] Quarantine removes an IP from Select rotation; Unquarantine restores it [ ] go test ./internal/sending/...

---

## Area: Deliverability automation

_Prefix: `RELAY-*`_

> Keep the pool warm: ramp new IPs, register with provider postmaster programs,
> watch blocklists and auto-delist, rotate DKIM, scan outbound with Rspamd
> (OUTBOUND-only).

### [RELAY-06] IP warm-up ramp scheduler
`done` · P1 · M · dep: RELAY-11 · parallel: yes — internal/sending/warmup.go
Scope: Per-IP daily-cap ramp on the curve 50 → 200 → 500 → 1k → 2.5k/day. `RampScheduler` tracks each IP's current step, today's sent count, and step-start date; `RampScheduler.CapFor(ip) int` returns today's remaining allowance; `RampScheduler.Record(ip)` increments. Graduation: an IP advances to the next step after N consecutive healthy days (configurable; healthy = bounce/complaint rate under threshold, fed from RELAY-10 / RELAY-07 signals) and is demoted on a bad signal. The pipeline consults `CapFor` before binding an account to a pool IP; over-cap defers the message. Caps reset at the configured day boundary (UTC default).
AC: [ ] CapFor returns the step allowance minus today's sends [ ] Record increments and rolls over at the day boundary [ ] N healthy days advances the step; a bad signal demotes [ ] over-cap → pipeline defers (Nack), does not drop [ ] go test ./internal/sending/...

### [RELAY-07] Postmaster Tools + SNDS auto-registration & ingest
`done` · P1 · M · dep: RELAY-01 · parallel: yes — internal/reputation/postmaster.go, internal/reputation/snds.go
Scope: Register pool IPs/domains with Google Postmaster Tools (API) and Microsoft SNDS (data-feed key per IP range), and ingest their reputation data on a schedule. `PostmasterClient.Sync(ctx)` pulls domain/IP reputation, spam rate, and feedback-loop data; `SNDSClient.Sync(ctx)` pulls the SNDS CSV feed (complaint rate, trap hits, filter result). Normalize both into a common `ProviderSignal{ip, domain, provider, spam_rate, complaint_rate, fbl_count, sampled_at}` and expose via a `SignalSource` interface the reputation policy and warm-up scheduler can read. Credentials come from config; missing creds → the client is a no-op that logs once (standalone self-hosters may not have provider access).
AC: [ ] PostmasterClient and SNDSClient implement SignalSource [ ] missing credentials → no-op + single log line, never a crash [ ] SNDS CSV parsed into ProviderSignal [ ] signals queryable by ip/domain [ ] unit tests mock both provider endpoints [ ] go test ./internal/reputation/...

### [RELAY-08] Blocklist monitoring + auto-delisting
`done` · P1 · L · dep: RELAY-11 · parallel: yes — internal/reputation/blocklist.go
Scope: Poll the major DNSBLs/reputation sources for every pool IP: Spamhaus (SBL/XBL/PBL), SORBS, Barracuda, and SenderScore. `BlocklistMonitor.Poll(ctx)` checks each IP against each source (DNSBL reverse-lookup where applicable, HTTP API for SenderScore), records listings, and on a new listing: (1) calls `Pool.Quarantine(ip)` to pull it from rotation, (2) fires that source's automated delist request flow where one exists, (3) re-checks on a backoff and `Unquarantine`s when clear. Each source is a `BlocklistSource` interface so sources can be added/removed. Poll interval and per-source endpoints are config. Listings are exposed for alerting/metrics.
AC: [ ] each of Spamhaus/SORBS/Barracuda/SenderScore implemented as a BlocklistSource [ ] new listing quarantines the IP via Pool.Quarantine [ ] auto-delist flow invoked for sources that support it [ ] IP unquarantined after re-check shows clear [ ] BlocklistSource interface lets sources be plugged/removed [ ] unit tests mock DNSBL + HTTP lookups [ ] go test ./internal/reputation/...

### [RELAY-09] DKIM key rotation scheduler
`done` · P2 · M · dep: RELAY-01 · parallel: yes — internal/sending/dkim.go
Scope: Scheduled DKIM key rotation that never lets signing lapse. `DKIMRotator` manages signing keys per domain with overlapping validity: generate a new key + selector, publish it (emit the DNS TXT record the operator/managed-DNS must install), wait for a propagation grace window, switch signing to the new selector, then retire the old key after a retention window (so in-flight mail signed with the old key still verifies). Expose the current signing key/selector for the SMTP sender to use, and the set of TXT records that should exist. Key material persisted via an injectable `KeyStore` interface (filesystem reference impl; Vulos plugs in its own). Rotation interval is config.
AC: [ ] rotate generates a new key+selector and emits the DNS TXT record [ ] old selector retained through the grace+retention window (no signing gap) [ ] sender always gets a currently-valid signing key [ ] KeyStore interface with a filesystem reference impl [ ] go test ./internal/sending/...

### [RELAY-10] Outbound Rspamd content scanning
`done` · P1 · M · dep: RELAY-04 · parallel: yes — internal/sending/rspamd.go
Scope: Scan every outbound message through Rspamd BEFORE it is sent, to protect the pool's reputation from its own senders. `RspamdScanner.Scan(ctx, msg) (Verdict, error)` POSTs the raw message to a configured Rspamd `/checkv2` endpoint and maps the result to `Verdict{Action: pass|add_header|greylist|reject, Score, Symbols}`. Wire it into the pipeline (RELAY-04) as a pre-send gate: `reject` → Fail the message and feed a strong negative signal to the reputation policy; `add_header`/`greylist` → send but record a soft signal. This is OUTBOUND-only — it is NOT the inbound MX filter (that is `vulos-mail`). Rspamd endpoint is config; unset → scanner is a pass-through with a startup warning.
AC: [ ] Scan POSTs to Rspamd /checkv2 and maps the action [ ] reject verdict → message Failed + negative reputation signal [ ] soft verdict → sent + soft signal recorded [ ] Rspamd unset → pass-through + single warning (no crash) [ ] unit test mocks the Rspamd endpoint [ ] go test ./internal/sending/...

### [RELAY-12] Per-account reputation scoring + instant abuse suspension
`done` · P1 · L · dep: RELAY-03, RELAY-10 · parallel: no — internal/reputation/scoring.go, internal/reputation/capped.go
Scope: Extend the reputation policy with a real rolling per-account score computed from bounce rate, complaint/FBL counts (RELAY-07), Rspamd reject rate (RELAY-10), and provider spam rate. `Scorer.Score(account_id) float64` over a sliding window; `CheckSend` denies (ErrSuspended) once the score crosses the abuse threshold, and the suspension is INSTANT — a crossing event must also pull the account's not-yet-sent mail out of the active lease set (signal the pipeline to stop leasing for that account) rather than waiting for the next CheckSend. Provide an admin hook `Suspend(account_id, reason)` / `Reinstate(account_id)`. A suspended account's messages are deferred/dead-lettered per config, never silently dropped.
AC: [ ] score combines bounce + complaint + Rspamd + provider signals over a window [ ] threshold crossing → CheckSend returns ErrSuspended immediately [ ] suspension stops the pipeline from leasing more of that account's mail [ ] manual Suspend/Reinstate hooks work [ ] suspended mail deferred/dead-lettered, not dropped [ ] go test ./internal/reputation/...

### [RELAY-16] Open-relay-abuse prevention (submission authentication)
`done` · P0 · M · dep: RELAY-04 · parallel: no — internal/relay/auth.go, internal/relay/pipeline.go
Scope: The relay must NEVER forward mail for an unauthenticated or unknown sender. Define a `SubmissionAuthenticator` interface `Authenticate(ctx, msg) (account_id string, err error)` that the pipeline calls as the FIRST gate — before policy, routing, or sending — to bind every message to a known account; messages that fail authentication are rejected outright (dead-lettered with a reason, never delivered). Provide a reference impl that checks an injectable account registry. Also enforce envelope sanity: reject messages whose sender domain the account is not authorized to send for. This gate is mandatory and not bypassable by configuration.
AC: [ ] unauthenticated/unknown-account message rejected before any send attempt [ ] sender-domain authorization enforced per account [ ] gate runs first in the pipeline, ahead of policy/routing [ ] gate cannot be disabled by config [ ] go test ./internal/relay/...

---

## Area: Peering

_Prefix: `RELAY-*`_

> Versioned wire spec (security from cryptography, not secrecy; open federation a
> goal), the encrypted fabric/bucket transport, and clean SMTP fallback for
> non-Vulos recipients. Peering is one branch in the send pipeline.

### [RELAY-13] Peering wire protocol spec (versioned) in spec/
`done` · P2 · L · dep: RELAY-01 · parallel: yes — spec/PEERING.md, spec/VERSIONS.md
Scope: Write the versioned peering wire-protocol spec as documentation (no code). Cover: peer address resolution (how a recipient is determined to be a Vulos peer and how its endpoint/key is discovered), the encrypted envelope format, the cryptographic handshake and trust model (designed to be sound and safe to interoperate against — security from cryptography, NOT from the protocol being secret), replay protection (nonces/timestamps), open-relay-abuse prevention at the peer boundary, and explicit version negotiation. State the design intent that independent implementations can run Vulos-compatible nodes and peer (open federation). Maintain `spec/VERSIONS.md` declaring the current protocol version and the compatibility/version-bump rules. Cross-reference `vulos-mail` for the server side and the broader Vulos fabric.
AC: [ ] spec/PEERING.md documents resolution, envelope, handshake, replay protection, open-relay prevention, version negotiation [ ] trust model is explicitly cryptographic (no secrecy dependence) [ ] open-federation intent stated [ ] spec/VERSIONS.md declares the current version + version-bump rules [ ] cross-references vulos-mail

### [RELAY-14] Peering transport implementation
`done` · P2 · L · dep: RELAY-13, RELAY-04 · parallel: yes — internal/peering/transport.go, internal/peering/resolve.go
Scope: Implement the `Sender` for peer recipients per the RELAY-13 spec: resolve the peer endpoint/key, build the encrypted envelope, perform the handshake, hand the message off over an injectable fabric/bucket transport (`PeerTransport` interface — Vulos plugs in its bucket transport; the repo ships an in-memory/loopback reference for tests), apply replay protection, and classify the handoff into a `SendResult`. The transport is encrypted end to end and performs NO public DNS lookup and NO blocklist exposure. Peer identity verification and replay rejection are enforced here. Wire it as the peer branch of the pipeline (RELAY-04 `Router.IsPeer` → this sender).
AC: [ ] resolves peer + builds encrypted envelope per spec [ ] handoff over the PeerTransport interface (in-memory reference impl for tests) [ ] replay-protected: a replayed envelope is rejected [ ] no public DNS / blocklist path touched on the peer branch [ ] peer-branch result classified into SendResult [ ] go test ./internal/peering/...

### [RELAY-15] Peer detection + SMTP fallback in the router
`done` · P2 · M · dep: RELAY-14, RELAY-05 · parallel: no — internal/relay/router.go
Scope: Implement the real `Router.IsPeer(recipient)` using the peering resolver (RELAY-14): a recipient that resolves to a known Vulos peer takes the peering transport; everything else falls back to the standard SMTP sender (RELAY-05). The decision must be cheap (cache peer-resolution results with a TTL) and the fallback seamless — a non-peer or a peer-resolution failure routes to SMTP without dropping the message. A FAILED peer handoff must NOT silently downgrade onto public SMTP without explicit policy; default is retry/defer on the peer path. Per-recipient routing for multi-recipient messages (some peers, some not) splits correctly.
AC: [ ] peer recipient → peering transport; non-peer → SMTP [ ] peer-resolution result cached with a TTL [ ] mixed-recipient message splits peer vs SMTP correctly [ ] failed peer handoff defers/retries on the peer path (no silent SMTP downgrade) [ ] go test ./internal/relay/...

---

## Area: Future

### Federated peering reputation: ReputationAttestation message + signing/verify path
`todo` · P2 · L · dep: RELAY-14 · parallel: no — internal/peering/reputation.go (NOTE: check if spam agent is active here before touching)
Define the `ReputationAttestation` wire message: signed (Ed25519) JSON envelope declaring sender-identity reputation score, issuing relay, and TTL. Implement signing path (emit from local relay on outbound verdict) and verify path (validate chain from peering neighbour before storing score). Expose a `ReputationStore` interface so vulos-cloud can plug in its own store. Do not touch `internal/peering/reputation.go` if the spam agent has it checked out.
AC: [ ] attestation message encodes score, issuer, TTL, signature [ ] sign path: outbound relay signs after send verdict [ ] verify path: validates Ed25519 sig + issuer key + TTL expiry [ ] ReputationStore interface injectable [ ] go test ./internal/peering/...

### Submit listener per-IP rate cap
`todo` · P1 · S · dep: RELAY-16 · parallel: yes — cmd/relay/main.go, internal/relay/submit.go (or listener file)
Add per-IP rate cap to the HTTP submission listener (`RELAY_SUBMIT_ADDR`, default `:8025`). Configurable: `RELAY_SUBMIT_RATE_PER_IP` env var (default 60 req/min per source IP). Return HTTP 429 + `Retry-After` on cap breach. Log cap events to the abuse pipeline. Implement with a sliding-window token bucket per source IP.
AC: [ ] rate cap enforced per source IP [ ] HTTP 429 + Retry-After returned on cap breach [ ] cap events logged [ ] cap threshold configurable via env var [ ] go test ./internal/relay/... or similar

---

## Area: BYO Mail

_Spec: [`ROADMAP.md §BYO Mail support`](ROADMAP.md)_  ·  _Prefix: `RELAY-BYO-*`_
_Cross-repo: [`vulos-cloud`](https://github.com/vul-os/vulos-cloud) (BYO-CP-*) · [`vulos-mail`](https://github.com/vul-os/vulos-mail) (MAIL-BYO-*)_

> BYO outbound relay: the warm-up pool handles BYO and hosted customers identically. No
> distinction at the relay layer for sending reputation. BYO-specific work covers the
> encrypted queue delivery transport and health-check signal pass-through.

### [RELAY-BYO-01] BYO encrypted queue delivery transport
`in-progress` · P2 · M · dep: RELAY-14 · parallel: yes — internal/peering/byo_queue.go (new)
Scope: When a BYO vulos-mail instance polls for queued inbound mail, route the encrypted blob
transfer over the peering transport (RELAY-14) rather than plain HTTPS where the instance is
fabric-reachable. This improves delivery reliability for BYO instances behind NAT/CGNAT.
Fall back to direct HTTPS if peering is unavailable. The blobs are age-encrypted by the time
they reach the relay — the relay forwards opaque ciphertext, never plaintext.
AC: [ ] encrypted queue blobs routed via peering transport when instance is fabric-reachable [ ] fallback to HTTPS when peering unavailable [ ] relay never sees plaintext (ciphertext forwarded as-is) [ ] go build ./...

### [RELAY-BYO-02] BYO instance health-signal relay to cloud
`in-progress` · P3 · S · dep: RELAY-01 · parallel: yes — internal/relay/health.go (new)
Scope: The relay receives heartbeats from BYO instances over the peering/fabric connection.
Forward these as health signals to the cloud control plane's health-check endpoint so the
cloud health-check daemon (BYO-CP-04) can use peering-reachability as a "last seen" signal
in addition to direct HTTP pings.
AC: [ ] peering heartbeat from BYO instance forwarded to cloud health endpoint [ ] signal includes instance ULID + timestamp [ ] relay does not buffer or persist health signals [ ] go build ./...
