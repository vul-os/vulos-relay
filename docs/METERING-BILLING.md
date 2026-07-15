# Metering & Billing

This chapter explains how the relay measures transfer, how account tiers and quotas gate
it, exactly what happens when you hit a cap, and how to check your usage against the
control plane. The headline first: **billing is opt-in**. A self-hosted relay with no
control-plane wiring runs *unbilled* — tokens are authorized by their name grants and
nothing is measured, gated, or phoned home. Everything below applies only when a relay
is linked to Vulos Cloud (`-cp-url` + `-cp-shared-secret`) **and** the agent's
credential is bound to an account.

---

## Who is billed, who is not

| Setup | Gated? | Metered? |
|---|---|---|
| Relay with no `-cp-url`/`-cp-shared-secret` (pure self-host) | no | no |
| Linked relay, static grant **without** `account_id` | no | no |
| Linked relay, static grant **with** `account_id` | yes | yes |
| Linked relay with `-cp-token-store` (agent token = CP install credential) | yes | yes |
| Traffic over a **verified direct endpoint** (client dials the box directly) | n/a | **no — never touches the relay** |

That last row is worth designing around: the direct fast path is not just lower
latency, it is *unmetered by the relay by construction*, because the bytes go
client↔box without transiting the relay at all. A box with a public IP that advertises
`-direct` only consumes relay quota when clients actually fall back to the tunnel.
(See [TUNNEL-GUIDE.md](TUNNEL-GUIDE.md#direct-first-relay-fallback).)

---

## What is measured

Per account, the relay accumulates two counters
([metering.go](../tunnel/server/metering.go), [proxy.go](../tunnel/server/proxy.go)):

- **Bytes** — request-body bytes as they stream *into* the tunnel, response-body bytes
  as they stream *out*, and for WebSocket sessions the spliced bytes in **both**
  directions. HTTP header bytes are not counted — the meters wrap body and splice
  streams, not the raw socket. All three paths meter **incrementally, per read chunk**
  ([`meterReader`](../tunnel/server/metering.go)) — a byte is counted the moment it
  crosses the relay, **not** when the request/stream finally closes. This matters for
  the long-lived traffic a relay specializes in (SSE, large downloads, hours-long
  WebSockets): a stream open across a flush is already partly billed, and one killed by
  a drain/redeploy/crash before it closes has its transferred bytes captured by the
  next (or final shutdown) flush rather than being lost. Counting is mutex-guarded and
  race-clean under the two concurrent WebSocket splice directions.
- **Sessions** — one per proxied public request (each yamux stream opened into the
  agent counts one).

> **Planned, not current:** the meter today counts proxied **body bytes** as described
> here. A shift to an **egress-based** billing model is a future direction, not a shipped
> behavior — bill against, and reason about, the counters documented on this page.

Unbilled sessions (`accountID == ""`) skip per-account metering entirely; the
direction-bucketed Prometheus metric is updated regardless (see
[Observing metering locally](#observing-metering-locally) below), so even a pure
self-host relay can watch its own volume.

### How measurements reach the control plane

Metering never blocks the data path — proxy code only bumps in-memory counters. A
background loop flushes **deltas** to the CP:

- **Cadence:** every 45 s by default (`Config.MeterFlushPeriod`), plus a final flush on
  graceful shutdown. This is one reason `vulos-relayd` drains on SIGTERM rather than
  dying: the last deltas survive deploys.
- **Wire:** `POST {cp}/api/relay/usage` with an envelope
  `{pop_id, region, report_id, items:[{account_id, bytes, sessions}]}`,
  HMAC-SHA256-signed over the exact body in `X-Pop-Sig` (keyed by `CP_SHARED_SECRET`).
- **Per-region attribution:** the envelope stamps this relay's `region` (from
  `-region`, e.g. `eu-central`, `af-south`) so the CP's billing meter can price relay
  GB **per-region** directly from the report — relay egress is not uniform-cost
  (Hetzner EU ~€1/TB vs Fly Africa $0.12/GB, ~6× EU), so the same account's GB may
  bill differently by which PoP carried it. One relay node serves one region, so the
  tag is per-report (envelope-level), mirroring `pop_id`. It is `omitempty`: a
  self-host / single-region relay sends no region and the CP applies its own
  default/flat rate (or its own `pop_id`→region map). The `region` tag is advisory
  metadata for pricing — the authoritative bytes are the per-account `items`.
- **Idempotency:** each batch carries a stable `report_id`
  (`<pop>-<boot-nonce>-<seq>`). A failed flush is retried later **with the same id**,
  so a batch the CP applied but whose response was lost dedups to a no-op instead of
  double-billing. The per-process boot nonce prevents id collisions across relay
  restarts, which would otherwise make the CP's dedup silently drop post-restart
  batches (under-billing).
- **Outage behavior:** failed batches queue for retry, bounded at 1024 batches
  (~12 h at the default cadence); beyond that the *oldest* are shed, favoring fresher
  usage. Traffic is never blocked by a CP outage — `addBytes`/`addSession` are cheap
  in-memory operations no matter what the network is doing.
- The per-relay `-pop-id` (default derived from the domain, e.g.
  `relay-relay-example-com`) namespaces report ids, so multiple relays report
  independently and the CP dedups per PoP.

---

## Tiers and quotas

Quotas are decided by the **control plane**, not the relay: the relay asks and
enforces, the CP answers from the same billing source as the rest of the suite
(`GET /api/relay/entitlement`, backed by the CP's quota table joined with
current-month usage). The relay allowance is a **monthly byte budget** plus a
concurrency cap, per tier. As defined in the CP's quota table at the time of writing
(`vulos-cloud` `internal/billing/quota_table.go` — the CP's live values govern; check
your entitlement rather than trusting docs):

| Tier | Relay transfer / month | Relay concurrency |
|---|---|---|
| Free | 5 GiB | 5 |
| Personal | 15 GiB | 10 |
| Pro | 25 GiB | 20 |
| Team | 30 GiB | 20 |
| Enterprise | 60 GiB | 100 |

Notes on how the CP applies these:

- A cap of 0 GiB means "no relay allowance" and is treated as exceeded as soon as any
  usage exists.
- **TURN** (meeting media relay) sessions are a separate dimension (`turn_cap`) with
  its own per-tier session budget; *either* dimension being exceeded flips the account
  over-quota.
- Usage is compared against the **current month**; the window rolls automatically.
- The CP's read posture is deliberately asymmetric: a *metering read error* fails open
  (a transient usage-DB problem never hard-denies a paying tenant); only the
  *over-quota* path denies.

---

## What happens at the cap

The enforcement point is the relay's **entitlement gate**
([gate.go](../tunnel/server/gate.go)), fed two ways:

1. a cached `GET /api/relay/entitlement` poll (30 s TTL by default, `Config.GateTTL`),
   and
2. — faster — the over-quota account list the CP returns in its response to each usage
   report, which is pushed straight into the gate (`markOverQuota`) so an over-cap
   account is cut on its **next request** rather than after a TTL lapse.

Concretely, when an account goes over quota:

1. **In-flight requests finish.** Nothing is severed mid-body.
2. **Subsequent public requests get `402 Payment Required`** with the body
   `relay quota exceeded or not permitted for this account`. The tunnel session itself
   stays registered — only requests are refused — so recovery is instant once the
   account is back in budget.
3. **New connects are refused** (`relay not permitted for this account` in the
   register ack): the connect gate requires `relay_allowed` and not-over-quota,
   fail-closed.
4. **Recovery is automatic**: when the CP stops reporting the account over quota (new
   monthly period, tier upgrade), the next entitlement refresh clears the verdict — no
   relay restart, no agent action needed beyond its normal operation.

Distinguish over-quota from two neighbors:

- **Revocation** — over-quota refuses *requests* but leaves the tunnel up; a
  definitive revoke (CP `revoked:true`/`404`, or the static revoked-list) *drops the
  live tunnel* via the revocation sweep and refuses reconnects. A revoke is sticky;
  over-quota clears on the next clean entitlement read.
- **Transient CP failure** — mid-session the gate fails *open*: a billing blip never
  cuts a live tunnel. Connect-time still fails closed, since an account that cannot be
  vetted cannot be admitted.

A worked timeline at the defaults, for intuition:

```
t+0s    account crosses its byte cap mid-download (the download completes)
t≤45s   next usage flush posts the deltas; CP's response lists the account over_quota
t+ε     relay pushes the verdict into the gate → next request answers 402
        (worst case without the push path: one gate TTL, ~30s, after the flush)
later   new month / upgrade → next entitlement refresh (≤30s) clears the 402
```

Watch it happen in operator telemetry: `vulos_relay_over_quota_cuts_total`,
`vulos_relay_requests_total{outcome="over_quota"}`, and
`vulos_relay_tunnel_cuts_total{reason="over_quota"}` on `/metrics`, plus info-level
`account marked over quota` and `request cut: over quota / entitlement denied` lines in
the structured log.

---

## Checking your usage

`GET {cp}/api/relay/entitlement` is the single read that answers "what's my tier, cap,
and consumption right now". Two credential forms are accepted (both fail-closed):

1. **Your install credential** (the one minted by the device-link flow — see
   [GETTING-STARTED.md](GETTING-STARTED.md#path-b--vulos-hosted-relay-account-linked)):

   ```bash
   curl -H "Authorization: Bearer $INSTALL_CREDENTIAL" \
        https://cloud.vulos.dev/api/relay/entitlement
   ```

   The CP also accepts the credential in an `X-Install-Credential` header.

2. **Service credential** — for relay operators only:
   `X-Relay-Auth: $CP_SHARED_SECRET` plus an explicit `?account_id=` (or
   `X-Account-ID` header). This is how the relay itself reads entitlements on behalf
   of connected agents. A presented-but-invalid install credential never falls through
   to the service path.

Response shape:

```json
{
  "account_id":    "acct-42",
  "tier":          "pro",
  "relay_allowed": true,
  "over_quota":    false,
  "byte_cap":      26843545600,
  "turn_cap":      100,
  "used_bytes":    1073741824,
  "used_sessions": 12
}
```

- `byte_cap` / `used_bytes` — the monthly relay byte budget and current-month
  consumption, in bytes.
- `turn_cap` / `used_sessions` — the TURN session budget and consumption.
- `over_quota` — true when *either* dimension is exceeded; this is the same signal
  that produces `402` at the relay.
- `relay_allowed` — whether the tier grants relay at all (and is not over-quota).
- The response may also carry `revoked: true`, which is a definitive kill for the
  credential (see
  [SECURITY.md](SECURITY.md#token-lifecycle-ttl-rotation-revocation)).

There is deliberately **no usage-read endpoint on the relay itself** — the relay holds
only unflushed deltas (seconds of data); the CP is the ledger of record.

### Observing metering locally

Independent of billing, the relay's admin listener exposes the raw volume it proxies:

```bash
curl -s http://127.0.0.1:9090/metrics | grep proxied_bytes
# vulos_relay_proxied_bytes_total{direction="inbound"}  …   request bodies in
# vulos_relay_proxied_bytes_total{direction="outbound"} …   response bodies out
# vulos_relay_proxied_bytes_total{direction="duplex"}   …   spliced WS bytes
```

These counters are always maintained, billed or not, and are the fastest way to
sanity-check "how much is actually transiting this relay" against what the CP ledger
says. They are relay-wide, not per-account — per-account attribution exists only on
the billed path, and only account **ids** (never names/PII) leave the relay in usage
reports.

### Expected accounting slack

The honest error bars, all bounded and all in your favor or neutral:

- Up to one flush interval (45 s) of usage is always in flight; a hard-killed relay
  (not SIGTERM-drained) loses at most that window. Because egress is metered per-chunk
  (not at connection close), this bound holds even for a stream that has been open for
  hours — only the bytes since the last flush are ever at risk, not the whole stream.
- Under a prolonged CP outage (>~12 h at defaults) the oldest queued batches are shed
  — under-billing, never over-billing.
- Over-quota detection lags consumption by up to one flush + one gate refresh, so an
  account can overshoot its cap by roughly what it can transfer in that window; the
  push-on-usage-report path keeps this to seconds in practice.
- Header bytes and traffic on the direct path are not counted at all.
- The in-memory pending map is bounded (50,000 accounts); past that, *new* accounts'
  metering is dropped until a flush clears space — traffic itself is never blocked.

---

## Operator configuration recap

All billing wiring on `vulos-relayd` (see [TUNNEL.md](TUNNEL.md#flags--env) for the
full flag table):

| Flag | Env | Purpose |
|---|---|---|
| `-cp-url` | `VULOS_CP_URL` | Vulos Cloud base URL for entitlement + usage |
| `-cp-shared-secret` | `CP_SHARED_SECRET` | HMAC key for `X-Pop-Sig` + service auth for entitlement reads |
| `-pop-id` | `VULOS_RELAY_POP_ID` | This relay's PoP id (report-id namespace; default derived from the domain) |
| `-region` | `VULOS_RELAY_REGION` | This relay's geo tag, stamped on usage reports for per-region GB pricing (e.g. `eu-central`, `af-south`); also drives nearest-node routing |
| `-cp-token-store` | `VULOS_RELAY_CP_TOKENS=1` | Agent tokens are CP install credentials (requires both of the above) |

Both `-cp-url` and `-cp-shared-secret` are required to enable billing; with either
missing the relay logs `running UNBILLED (no -cp-url/-cp-shared-secret)` and serves
grants without gating or metering. `-cp-token-store` without them is a startup error.
Mixed mode works too: a static grants file where only some grants carry `account_id`
bills exactly those and serves the rest unbilled.

Library embedders reach the same knobs via `server.Config.CP` (a `*CPClient` with
`BaseURL`, `SharedSecret`, `PoPID`, and `Region` for per-region pricing),
`Config.GateTTL` (entitlement cache, default 30 s), and `Config.MeterFlushPeriod`
(default 45 s). `vulos-relayd` wires `CPClient.Region` from `-region` automatically.
