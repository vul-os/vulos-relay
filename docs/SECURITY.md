# Security Model

This chapter states the reverse tunnel's trust model plainly: what the relay operator
can and cannot see, how agents authenticate, what account linking adds, and which abuse
controls stand between the public internet and your box. The relay is designed to run
internet-facing and **fails closed** — no token store means it refuses to start, unknown
credentials are rejected, names cannot be hijacked, and every resource is bounded. But
it is a reverse **proxy**, not an end-to-end-encrypted pipe, and this chapter is honest
about what that means. (For the vulnerability-disclosure policy and the JS SDK's
peer-auth model, see the repo-level [SECURITY.md](../SECURITY.md).)

---

## What the relay can see

**The relay terminates TLS for tunneled traffic. There is no TLS passthrough to the
box.**

Follow a request through the code ([proxy.go](../tunnel/server/proxy.go),
[forward.go](../tunnel/agent/forward.go)): the relay (or its fronting edge) terminates
the public client's TLS, parses the request as plaintext HTTP, rewrites headers, and
writes it down a yamux stream. That stream is carried inside the agent's `wss://`
control connection — so it is encrypted **hop by hop** — but the relay process itself
handles every request and response in the clear.

| Leg | Encryption | Who sees plaintext |
|---|---|---|
| Public client → relay | TLS (relay's cert, or its edge/CDN's) | the relay (and its edge, if any) |
| Relay → agent | TLS (the agent's outbound `wss://`) | both ends: relay and agent |
| Agent → local app | plain TCP on loopback | the box only |
| Client → box via **verified direct endpoint** | TLS to the **box's own cert**, end to end | the box only — the relay never carries it |

Consequences, stated without varnish:

- A relay operator (or anyone who compromises the relay) can **read and modify all
  traffic that traverses the tunnel**: URLs, headers, cookies, bodies, WebSocket
  frames. This is identical to the trust you place in any reverse proxy, CDN, or
  `frp`/ngrok-style service.
- **Self-hosting the relay is the sovereignty story**: when you run `vulos-relayd`
  yourself, the "operator who can see everything" is you. That is the entire point of
  shipping it.
- Application-layer end-to-end encryption survives unchanged: payloads encrypted
  client-side (e.g. E2E-encrypted collaboration blobs) transit the relay as ciphertext
  inside bodies the relay could inspect but not decrypt.
- The **direct fast path bypasses the relay entirely** — TLS runs client↔box with the
  box's certificate. If relay-blindness matters for your workload, a verified direct
  endpoint gives it to you whenever the box is directly reachable.
- What the relay *records* is much narrower than what it can see: structured logs carry
  a bounded field set (`name`, `account`, `remote` IP, enum `reason`) and **never**
  tokens, secrets, request paths, query strings, headers, or bodies
  ([logging.go](../tunnel/server/logging.go) — the log helper has no field a token
  could even be passed in). Metrics labels are fixed enums; no attacker-controlled
  value ever becomes a series.

---

## Threat matrix

What each party can and cannot do, per the code:

| Adversary | Can | Cannot |
|---|---|---|
| **Malicious public visitor** | hit whatever the local app exposes; consume rate-limit budget | spoof its source IP to the box's app (XFF overwritten); reach the agent's LAN (loopback lock); learn why an auth attempt failed; hold a connection past the bounds |
| **Holder of a stolen agent token** | serve the granted name(s) from their own machine *once the real agent is offline* | displace a live session (first-come name hold); serve ungranted names; survive revocation/expiry (sweep cuts within ~20 s) |
| **Malicious/compromised box** | expose its own app; advertise endpoints *it actually controls* | advertise a victim's IP/hostname (nonce-echo ownership proof); make the relay probe internal targets (SSRF screen + auth-before-probe); notify or resolve SFUs across accounts (same-account guards) |
| **Compromised relay** | read/modify all tunneled traffic; refuse service | reach anything on the box except the one loopback port (agent-side SSRF guard, re-checked per stream); read direct-path traffic; extract tokens from logs/metrics |
| **Compromised control plane** | deny/revoke linked accounts; skew billing verdicts | affect unlinked/self-host grants (no CP involved); cut a live tunnel via a mere outage (mid-session fail-open — only definitive verdicts cut) |

---

## Agent authentication

Agents authenticate to the relay with a per-agent **bearer token**, presented in the
`Authorization: Bearer` header on the control dial and optionally echoed in the register
frame — if both are present they must agree
([control.go](../tunnel/server/control.go)).

The static token store ([auth.go](../tunnel/server/auth.go)) is deliberately paranoid:

- **Tokens are stored hashed** (SHA-256); the lookup map never holds raw secrets.
- **Constant-time matching**: the presented token's hash is compared against *every*
  stored hash with `subtle.ConstantTimeCompare`, so timing reveals neither a match nor
  which grant matched. The revoked-list does the same.
- **Fail-closed construction**: empty tokens, empty name lists, conflicting
  `account_id` or `expires_at` for the same token, and an entirely empty store are all
  startup errors — a misconfigured relay refuses to run rather than run open.
- **Non-leaky failures**: a rejected connect learns only `unauthorized`, never whether
  the token was unknown, the name ungranted, the grant expired, or the credential
  revoked.

### Name binding

A token authorizes **only the exact names in its grant** (normalized to a
DNS-label-safe subset: lowercase `a-z0-9-`, ≤63 chars, no edge hyphens). A live name is
held by exactly one session, first-come; a second claimant is refused with
`name unavailable`, never swapped in — an attacker who steals nothing cannot hijack
your subdomain, and even a *valid* second agent cannot displace a live one.

### Token lifecycle: TTL, rotation, revocation

- **Expiry** (`expires_at`, RFC 3339): after it, the grant's tokens stop authorizing
  (fail-closed), and the revocation sweep cuts a live tunnel whose token expires
  mid-session — a leaked long-lived token self-revokes.
- **Rotation** (`previous_token`): during a rotation window the old secret authorizes
  the same grant alongside the new one, so a fleet rolls tokens without a flag day;
  clear it when the roll is done. A `previous_token` equal to the current token, or
  already bound to a different grant, is a startup error.
- **Revocation** ([revocation.go](../tunnel/server/revocation.go)): three ways to kill
  a credential without editing the grants file and restarting:
  1. static revoked-list (`-revoked-file` or `VULOS_RELAY_REVOKED`, shape
     `{"tokens":[],"names":[],"accounts":[]}`),
  2. runtime API for embedders (`Server.RevokeToken` / `RevokeName` / `RevokeAccount`
     — sweeps immediately),
  3. for control-plane-linked installs, the CP answering `revoked:true` or `404` on
     the entitlement poll is a **definitive** revoke (and purges any cached-good
     mapping so a leaked credential cannot ride a stale cache).

  Revoked credentials are refused at connect, and a background sweep (default every
  20 s, `-revoke-sweep`) rechecks every live session and drops matches. Revocation
  latency is bounded, not instant: at most one sweep tick, plus (for the CP path) up
  to one entitlement-cache TTL (~30 s).

### Handling the token on the box

- Prefer the env vars (`VULOS_RELAY_TOKEN` etc.) over `-token` so the secret does not
  appear in process listings.
- The embedded agent's `Snapshot()` never includes the token; the agent's in-memory
  log never records it.
- The relay retains a live session's token in memory only (so the revocation sweep can
  recheck it) — it is never logged or sent anywhere.

---

## Account linking

Linking is **opt-in**; its security posture in one line: *the control plane decides who
may relay, the relay enforces it, and neither ever weakens the pure self-host path.*

- An **unlinked** grant (no `account_id`, or a relay with no
  `-cp-url`/`-cp-shared-secret`) is authorized purely by its name grant — no Vulos
  account, no gating, no metering.
- A **linked** credential — either a static grant carrying `account_id`, or (with
  `-cp-token-store`) a CP-minted *install credential* used directly as the agent token
  — is additionally gated on the account's relay entitlement.

The install credential comes from a headless device-code flow on the control plane
(`POST /api/link/device/{start,approve,poll}`): the approval step is done by a
signed-in human in a browser, `start` is rate-limited per IP, `approve` per account,
`poll` per device code (`428` while pending), and the credential is issued exactly once
(a second poll gets `410`). The relay validates install credentials by asking the CP
for that credential's entitlement (`GET /api/relay/entitlement` with the credential as
`Bearer`), which resolves it to an account in the same round trip — fail-closed on any
CP error at connect time, with a short (60 s) cache so reconnect storms don't hammer
the CP.

**Gate posture** ([gate.go](../tunnel/server/gate.go)) — worth internalizing because it
governs outages:

- **Connect: fail closed.** An account that is denied, over quota, revoked, *or simply
  un-vettable because the CP is unreachable* is refused.
- **Mid-session: fail open on blips.** A transient CP error never cuts a live tunnel;
  the last-known decision (or optimism) applies. Only a *definitive* verdict cuts:
  over-quota (`402` on the next request) or revoked (sweep drops the tunnel). A revoke
  is **sticky** — once observed, a later clean-looking read cannot un-revoke it.

Relay↔CP integrity: usage reports are HMAC-SHA256-signed over the exact body
(`X-Pop-Sig`, keyed by `CP_SHARED_SECRET`) with idempotent report IDs; entitlement
reads authenticate with the same shared secret (`X-Relay-Auth`) or the install
credential itself.

---

## Rate limits and abuse controls

Three memory-bounded token-bucket limiters, all returning `429` + `Retry-After: 1`
([ratelimit.go](../tunnel/server/ratelimit.go)); `0` keeps the default, a negative rate
disables that limiter:

| Limiter | Key | Default | Protects against |
|---|---|---|---|
| Control connections | source IP | 5/s, burst 20 | auth-guessing and CP-round-trip churn, *before* a WS upgrade is spent |
| Public requests | tunnel name | 50/s, burst 100 | one tunnel being flooded (or flooding) |
| Public requests | global | 500/s, burst 1000 | aggregate overload of the relay |

Buckets are lazily created, idle-evicted (10 m), and capped at 100k keys, so a flood of
distinct source IPs cannot grow memory; at the cap, *new* keys are refused rather than
tracked.

On top of the limiters, hard bounds keep every resource finite: 256 agents, 128
in-flight streams per agent, 64 KiB headers, 256 MiB request bodies (streamed, `413` on
overflow — never unbounded, a negative cap is refused at startup), 8 KiB control
messages, a 90 s idle/keepalive budget, and a 60 s time-to-response-headers deadline
that stops a half-dead agent from pinning all its stream slots. Accounts past their
billing cap are cut with `402`. Internal error details are never leaked to clients —
the public side sees only generic `4xx`/`5xx` bodies, and register failures are equally
terse.

### Header hygiene (no client-IP spoofing)

The relay is the ingress trust boundary, and what it forwards as `X-Forwarded-For` is
what your box's app will use for allowlists, rate limits, audit, and geo. Default
posture (`-trust-proxy-headers` off — directly internet-facing): any client-supplied
`X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto` is **discarded and overwritten**
with the observed peer, so a public client cannot forge its source IP. Behind a trusted
TLS-terminating edge (the `fly.toml` deployment), flip it on: the edge's XFF chain is
preserved and the edge appended, and the edge's `X-Forwarded-Proto` is honored.
Enabling it while directly exposed re-opens the spoof — it is the single most
consequential flag on the server. Hop-by-hop headers are stripped in both directions.

### What the relay does *not* authenticate

**Public visitors.** The relay authenticates *agents*, not the internet: whatever your
local app exposes on `-local` is exposed on the public URL, exactly as with `frp` or
ngrok. Authentication of end users is the app's job (VulOS surfaces bring their own
auth stack). The relay's contribution on the public side is rate limiting, size bounds,
and header hygiene — not access control.

Also unauthenticated by design, because they carry no user data and mutate nothing:

- `GET /_vulos-direct/resolve` — returns only a *verified* public endpoint (public
  routing info; knowing it grants no access — the box's own auth still gates every
  request there).
- `GET /_vulos-direct/probe` **on the box** — must be exempt from the box's auth
  stack, but serves only the relay's nonce echo and nothing else.
- `GET /api/meet/host/resolve?name=…` — scoped to the named tunnel's own
  registration; the SFU's own token gate still admits each joiner.

---

## Verified endpoints and cross-tenant seams

Everything the relay tells clients about *where else* to connect is verified, and
everything boxes can make the relay do is tenant-scoped:

- **Direct endpoints and SFU hosts are never trusted on the box's word.** Before
  advertising either, the relay probes the endpoint over the public internet with a
  fresh 256-bit nonce (`X-Vulos-Direct-Probe`) and requires the nonce echoed back —
  proof the advertiser actually serves that TLS endpoint, so a box cannot point
  clients (or the relay's probe) at a victim. The probe itself is SSRF-guarded in
  depth: https-only bare origins, parse-time public-IP screening, connect-time
  re-screening of every resolved IP (anti-DNS-rebind), NAT64/6to4/Teredo
  embedded-IPv4 unwrapping, no redirects, an 8 s bound. Verification runs only
  *after* auth + entitlement. ([directprobe.go](../tunnel/server/directprobe.go))
- **The agent-side SSRF guard** is the mirror image: the agent forwards only to its
  one configured loopback target, checked at startup and re-checked per stream — a
  malicious relay cannot steer an agent into the box's LAN or cloud metadata.
- **Cross-instance notify (`POST /api/s2s/notify`)** authenticates the sender's
  bearer against the *sender's own* tunnel name, then requires the **target tunnel to
  belong to the same account** — account A cannot inject notifications into account
  B's box on a shared relay (unbilled `""` is its own tenant). The relay never dials
  a caller-supplied URL here: it forwards only over the target's already-established
  tunnel, to a fixed path (`/api/notify/receive`).
  ([s2snotify.go](../tunnel/server/s2snotify.go))
- **SFU-host resolve is name-scoped** for the same reason: an unscoped "first live
  host" would hand one tenant's clients another tenant's media node.

---

## Admin surface

`/metrics`, `/healthz`, `/readyz` live on a **separate listener** (`-admin-addr`,
default `127.0.0.1:9090`) — never on the public tunnel port, because metrics leak
operational internals (agent counts, byte volumes, auth-failure rates). Access is
loopback-or-token: with no `-metrics-token`, only loopback may connect (fail closed);
binding the admin listener to a routable address without a token is refused at startup.
Token comparison is constant-time, and a refused request cannot tell whether a token is
even configured. The public listener keeps only the deliberately-lightweight
`GET /healthz` (`ok agents=N`).

---

## TLS deployment posture

- **Behind an edge/CDN** (recommended, and the Fly shape): the relay speaks plain HTTP
  on a private port; the edge terminates TLS. Never expose the plain-HTTP listener
  directly — the server logs a warning when running without `-cert`/`-key` for exactly
  this reason.
- **Self-terminating**: pass `-cert`/`-key`. Subdomain mode needs a wildcard cert for
  `*.relay.example.com`.
- **Agent dial**: verifies the relay's cert against system roots; pin a private CA via
  the library's `TLSConfig` for fully self-contained deployments. `-insecure`
  (`InsecureSkipVerify`) must never leave a test bench.

---

## Reporting a vulnerability

Report via GitHub Security Advisories (preferred) or `security@vulos.org` —
acknowledgement within 72 hours. See the repo-level [SECURITY.md](../SECURITY.md) for
the full policy and scope. For the tunnel subsystem, the areas we most want eyes on
are: agent-auth bypass, name-binding/hijack, SSRF-guard bypass (both directions),
entitlement/metering integrity, header-trust confusion, and cross-tenant leakage in the
notify/SFU/resolve surfaces.
