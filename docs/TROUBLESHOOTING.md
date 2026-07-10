# Troubleshooting

This chapter is a symptom-driven field guide for the reverse tunnel: where the logs
live, what each error string and status code actually means in the code, and the fix
for each. Statuses and messages quoted here are the literal ones emitted by
`vulos-relayd`, `vulos-relay-agent`, and the `tunnel/server` proxy path, so you can
grep for them verbatim.

---

## Where the logs are

**Relay server (`vulos-relayd`)** — structured `slog` output on **stderr**, JSON by
default:

- `VULOS_RELAY_LOG_LEVEL` = `debug` | `info` (default) | `warn` | `error`.
  Per-attempt noise (every auth failure, every rate-limit reject) is at `debug`;
  normal lifecycle (register/unregister, cuts) at `info`; server-side faults
  (usage-flush failure) at `warn`.
- `VULOS_RELAY_LOG_FORMAT=text` for human-readable output instead of JSON.
- Fields are bounded: `name`, `account`, `remote`, `reason` — tokens and request
  contents are never logged, so don't expect to find them.
- Where stderr lands depends on how you run it: `journalctl -u <unit>` under systemd,
  `docker logs` in a container, `fly logs -a vulos-relayd` on Fly.

Lifecycle lines to know (all `"component":"relay"`):

```
agent registered            name=box1 account=acct-42 remote=203.0.113.9
agent unregistered          name=box1 account=acct-42
connect refused: entitlement denied      name=box1 account=acct-42 reason=entitlement
connect refused: name unavailable        name=box1 reason=name_unavailable
revoking live tunnel        name=box1 reason=revocation
account marked over quota   account=acct-42 reason=over_quota
request cut: over quota / entitlement denied   name=box1 reason=over_quota
usage flush failed (will retry)          err=…        (warn — CP unreachable)
```

**Agent (`vulos-relay-agent`)** — plain log lines on **stderr**
(`vulos-relay-agent: …`, plus status transitions polled every 500 ms:
`status: starting`, `connected: <url>`, `error: <reason>`). An **embedded** agent
keeps the same lines in a bounded in-memory ring (last 200 entries) exposed as
`Snapshot().Log`, alongside `Status`, `LastError`, `PublicURL`, and the `Direct*`
verdict fields.

**Relay metrics** — `GET /metrics` on the admin listener (default `127.0.0.1:9090`,
loopback-only). The ones you will actually reach for:

| Metric | Tells you |
|---|---|
| `vulos_relay_active_agents` / `active_streams` | live sessions / in-flight requests |
| `vulos_relay_requests_total{outcome=…}` | `ok`, `no_tunnel`, `offline`, `rate_limited`, `over_quota`, `busy`, `bad_gateway`, `upgrade` |
| `vulos_relay_auth_failures_total{reason=…}` | `rate_limited`, `no_bearer`, `bad_register`, `unauthorized`, `entitlement`, `name_unavailable` |
| `vulos_relay_rate_limited_total{surface=…}` | which limiter fires: `control`, `per_tunnel`, `global` |
| `vulos_relay_tunnel_cuts_total{reason=…}` | `revocation` vs `over_quota` cuts |
| `vulos_relay_proxied_bytes_total{direction=…}` | volume: `inbound`, `outbound`, `duplex` |
| `vulos_relay_reconnects_total` | flapping agents |
| `vulos_relay_direct_verified_total` / `direct_rejected_total` | direct fast-path health |

---

## Tunnel won't connect

The agent's `error:` line carries the register ack's reason verbatim. Match it below.

### `dial: … connection refused / no such host / i/o timeout`

- **Cause:** wrong `-server`, DNS not pointing at the relay, relay down, or outbound
  443 blocked from the box.
- **Fix:** from the box, `curl https://<relay-domain>/healthz` — expect
  `ok agents=N`. Fix the URL/DNS/firewall accordingly. Only outbound 443 is needed;
  the box opens nothing inbound.

### `dial: … bad handshake / unexpected HTTP status`

- **Cause:** something in front of the relay is not passing WebSocket upgrades to
  `/_vulos-relay/control`, or you pointed the agent at the admin port.
- **Fix:** ensure your edge/CDN forwards WS upgrades; point `-server` at the
  **public** listener (`-addr`), never at `-admin-addr`.

### `register: unauthorized`

- **Cause:** the token is unknown, not granted this name, expired (`expires_at` in
  the past), or revoked. The relay deliberately does not say which.
- **Fix:** on the relay, check the grants (`-tokens-file` / `VULOS_RELAY_TOKENS`):
  token spelled exactly right, `-name` present in that grant's `names`, expiry not
  passed, token/name/account absent from the revoked-list. The relay logs
  `authorize failed` with the name and remote IP at `debug` level.

### `register: token mismatch`

- **Cause:** the token in the `Authorization` header differs from the one in the
  register frame. Only possible with a custom agent implementation.
- **Fix:** send the same token in both places (or header only).

### `register: invalid name`

- **Cause:** the name fails normalization — it must be lowercase `a-z0-9-`, at most
  63 chars, with no leading/trailing hyphen.
- **Fix:** rename. `Box_1` and `box1.` are invalid; `box-1` is fine.

### `register: name unavailable`

- **Cause:** another live session holds the name (names are first-come and cannot be
  hijacked), the previous session is dead-but-unreaped, or the relay is at
  `-max-agents` capacity.
- **Fix:** if it's your own restarted agent, wait ~10 s — the yamux keepalive miss
  frees the name and the agent's backoff loop will succeed on a later attempt.
  Otherwise pick another name, or raise `-max-agents`.

### `register: relay not permitted for this account`

- **Cause:** an account-linked token failed the entitlement gate: the tier denies
  relay, the account is over quota or revoked, **or the control plane was
  unreachable** — connect-time vetting fails closed.
- **Fix:** check your entitlement (see
  [Quota exceeded](#quota-exceeded)). If entitlement looks healthy, check relay↔CP
  connectivity (`-cp-url`, `CP_SHARED_SECRET`) and look for
  `usage flush failed (will retry)` in the relay log.

### `register: bad registration`

- **Cause:** malformed or oversized (>8 KiB) register frame — a custom agent bug.
- **Fix:** compare your frame against `tunnel/internal/wire`.

### `agent: LocalAddr "…" is not loopback (SSRF guard)` (at startup)

- **Cause:** `-local` is not `localhost` or a loopback IP.
- **Fix:** point `-local` at `127.0.0.1:<port>`. Forwarding to other hosts is refused
  by design; there is no override.

### Repeated `429 too many control-connection attempts`

- **Cause:** more than 5 connect attempts/s (burst 20) from one source IP — usually a
  crash-looping agent, or many agents sharing one NAT egress. Relay logs
  `control connection rate-limited` at `debug`.
- **Fix:** fix the crash loop first (its own `error:` line says why it keeps
  reconnecting). For large NATted fleets, raise `-ratelimit-control-rate` /
  `-ratelimit-control-burst`.

### Server refuses to start

Each startup refusal names its own fix; the ones you may hit:

- `-domain is required (or VULOS_RELAY_DOMAIN)`
- `no grants: set -tokens-file or VULOS_RELAY_TOKENS (refusing to run open)`
- `grant N: empty token` / `no names authorized` / `token bound to conflicting
  account_id` / `conflicting expires_at` / `previous_token equals token`
- `-cp-token-store requires -cp-url and -cp-shared-secret`
- `-max-request-bytes (VULOS_RELAY_MAX_REQUEST_BYTES) must be >= 0`
- `relay admin: refusing to serve /metrics on non-loopback "…" without a metrics
  token` — bind `-admin-addr` to loopback, or set `-metrics-token`.

---

## Public URL errors (what visitors see)

### `404 no such tunnel`

- **Cause:** the request didn't route to a name at all — the Host isn't
  `<name>.<relay-domain>` with exactly one label, or you used `/t/<name>/` without
  `-path-mode`.
- **Fix:** check DNS (`*.relay.example.com` must resolve to the relay) and that
  `-domain` matches the Host your edge forwards. Enable `-path-mode` if you rely on
  path routing.

### `502 tunnel offline`

- **Cause:** the name routed, but no live agent session holds it.
- **Fix:** start the agent / check its status; work through
  [Tunnel won't connect](#tunnel-wont-connect).

### `502 bad gateway` / `502 tunnel error`

- **Cause:** the stream to the agent failed, the agent's response was unreadable, or
  the 60 s time-to-headers deadline fired. When the agent itself answers 502, its log
  shows `local dial failed: …` — the local app is down or on the wrong port.
- **Fix:** check the **local app**: up, listening on `-local`, returning response
  headers within 60 s. Library embedders can raise `Config.RequestTimeout` for
  genuinely slow-to-headers apps.

### `403 forbidden` (from the agent)

- **Cause:** the agent's per-stream loopback re-check failed — your `-local`
  hostname now resolves off-loopback.
- **Fix:** use a literal `127.0.0.1:<port>`.

### `402 relay quota exceeded or not permitted for this account`

- See [Quota exceeded](#quota-exceeded).

### `429 too many requests for this tunnel` / `429 relay busy (rate limited)`

- **Cause:** the per-tunnel (50/s, burst 100) or global (500/s, burst 1000) request
  bucket is empty.
- **Fix:** clients should honor `Retry-After: 1`. Operators: raise
  `-ratelimit-req-rate/-burst` or `-ratelimit-global-rate/-burst`; a negative rate
  disables that limiter (trusted-edge/self-host).

### `503 tunnel busy`

- **Cause:** 128 concurrent in-flight streams for this agent — usually slow or hung
  local-app responses pinning slots, not raw traffic volume.
- **Fix:** fix the slow app; watch `active_streams`. Library embedders can raise
  `MaxStreamsPerAgent`.

### `413 request body too large (limit N bytes)`

- **Cause:** an upload exceeded `-max-request-bytes` (default 256 MiB).
- **Fix:** chunk the upload, or raise the cap (`VULOS_RELAY_MAX_REQUEST_BYTES`).
  Unbounded is deliberately not offered.

### Visitors' real IPs show up as the edge/relay IP in the box's app

- **Cause:** `X-Forwarded-For` posture mismatched to topology.
- **Fix:** directly exposed relay ⇒ leave `-trust-proxy-headers` **off**. Behind a
  trusted TLS-terminating edge (Fly) ⇒ set `VULOS_RELAY_TRUST_PROXY_HEADERS=1`.
  Never enable it while directly exposed — that re-opens client IP spoofing.

---

## TLS errors

### Agent: `x509: certificate signed by unknown authority`

- **Cause:** the relay serves a cert the box doesn't trust (private CA,
  self-signed).
- **Fix:** embed the agent and pin the CA via `agent.Options.TLSConfig`, or get a
  publicly-trusted cert (ACME). `-insecure` is for local testing **only**.

### Agent: `x509: certificate is valid for X, not relay.example.com`

- **Cause:** the cert doesn't cover the control-endpoint hostname.
- **Fix:** fix the SANs on whatever terminates TLS.

### Browser cert error on `https://box1.relay.example.com` but the apex works

- **Cause:** no **wildcard** cert for `*.relay.example.com`.
- **Fix:** issue one at your edge (`fly certs add "*.relay.example.com"` on Fly), or
  use `-path-mode` to avoid subdomains entirely.

### Relay logged `WARNING running plain HTTP — terminate TLS at your edge/CDN`

- **Cause:** started without `-cert`/`-key`. Fine behind an edge on a private port;
  dangerous if that listener is internet-reachable.
- **Fix:** keep the plain listener private, or add `-cert`/`-key`.

### Direct fast path rejected with `directError: not https`

- **Cause:** the `-direct` endpoint isn't a bare `https://` origin.
- **Fix:** advertise `https://host[:port]` with no path, query, or userinfo.

---

## Quota exceeded

Symptoms: public requests return `402`; reconnects fail with
`relay not permitted for this account`; relay log shows `account marked over quota`
then `request cut: over quota / entitlement denied`; `over_quota_cuts_total` climbs.

1. Confirm against the ledger of record:

   ```bash
   curl -H "Authorization: Bearer $INSTALL_CREDENTIAL" \
        https://cloud.vulos.dev/api/relay/entitlement
   ```

   Compare `used_bytes` vs `byte_cap` and `used_sessions` vs `turn_cap`; `over_quota`
   is the verdict the relay enforces.
2. Reduce what transits the relay: advertise a **direct endpoint** (`-direct`) —
   verified direct traffic bypasses the relay and is unmetered by it.
3. Upgrade the tier, or wait for the monthly window to roll. Recovery is automatic
   within one entitlement refresh (~30 s) once the CP verdict clears — the tunnel
   session was never torn down, so no agent action is needed.
4. If entitlement says you are **not** over quota but connects still fail: that is
   the connect-time fail-closed posture with an unreachable CP. Check the relay's
   `-cp-url`/secret and its log for `usage flush failed (will retry)`. Live tunnels
   stay up through a CP outage (mid-session fails open); only *new* connects are
   refused until the CP answers.

---

## High latency

- **Use the direct fast path.** Relay transit adds a full extra hop
  (client→relay→box). A box with a public IP should advertise `-direct`; verify with
  `curl https://<name>.<relay-domain>/_vulos-direct/resolve` → `"direct":true`.
  Clients using `tunnel/direct` then dial the box first automatically.
- **Direct advertised but `direct:false`?** Check the agent log:
  `direct endpoint not used (relay only): <reason>` (also `Snapshot().DirectError`).
  The reasons map to fixes:
  - `unreachable` — endpoint not publicly reachable, firewalled, or the probe took
    longer than 8 s.
  - `ownership proof failed` — the box isn't serving `/_vulos-direct/probe` with the
    nonce echo on the advertised listener; the path must be exempt from the box's
    auth stack.
  - `not https` / `endpoint must be a bare origin` / `userinfo not allowed` —
    malformed `-direct` value.
  - `non-public address` / `internal hostname` / `resolves to non-public address` —
    the SSRF screen: private/CGNAT/loopback/transition addresses are never probed.
  - `redirect not allowed` — the endpoint 30x's the probe; serve it directly.

  The relay counts rejections in `direct_rejected_total`.
- **Throttling reads as latency.** Bursty clients bouncing off the per-tunnel bucket
  see `429`s and retry delays; check `rate_limited_total{surface="per_tunnel"}` and
  raise the limits if it's legitimate traffic.
- **Distance to the relay.** One relay per region/cell is the model (no multi-relay
  session sharing); deploy the relay near the boxes or the users. On Fly, keep
  `auto_stop_machines = "off"` — tunnels are long-lived connections.
- **Slow first byte on one request** is usually the *local app*, not the tunnel: the
  relay's deadline only bounds time-to-headers (60 s) and streams bodies unbuffered
  in both directions.

---

## Connection drops

### Agent logs `session ended; reconnecting`, then reconnects within seconds

- **Cause:** normal — a relay restart/deploy (graceful drain) or a transient network
  blip. Reconnects use jittered exponential backoff (0.5 s → 30 s).
- **Fix:** nothing, unless frequent — then check `reconnects_total` on the relay and
  the network path between box and relay. During a relay deploy, agents reconnect to
  the replacement automatically.

### Tunnel session dropped, relay log says `revoking live tunnel`

- **Cause:** the revocation sweep: a static revoked-list match, a CP
  `revoked:true`/`404` verdict, or the grant's `expires_at` passed mid-session. Note
  that *over-quota* is not this — over-quota refuses requests (`402`) but keeps the
  session.
- **Fix:** rotate/re-issue the credential, remove it from the revoked-list, or extend
  the expiry. Reconnects stay refused until the revocation source clears.

### Name won't come back for ~10 s after a hard kill

- **Cause:** dead-peer detection — a hard-killed agent frees its name on the next
  yamux keepalive miss (~10 s server-side interval).
- **Fix:** expected; use `Stop()`/SIGTERM for instant release. The agent's own retry
  loop rides it out.

### Long-idle WebSocket/SSE dies around 90 s

- **Cause:** the relay's 90 s `IdleTimeout` is a keepalive budget, and yamux
  keepalives (10 s/20 s) normally keep the control connection alive — so a ~90 s cut
  usually points at a middlebox killing the *underlying* connection instead.
- **Fix:** check idle timeouts on any proxy/CDN between agent and relay, and between
  client and relay for the public leg.

### Everything drops at once; relay log: `shutting down (draining in-flight requests)`

- **Cause:** SIGTERM (deploy/restart). In-flight requests get up to 25 s to finish,
  the final usage flush runs, `/readyz` flips to 503.
- **Fix:** expected; agents reconnect. If requests are being cut, they exceeded the
  drain window.

### Streams hang, then the whole tunnel answers `503 tunnel busy`

- **Cause:** a half-dead local app pinning stream slots; the 60 s time-to-headers
  deadline is what eventually un-bricks each slot.
- **Fix:** fix the local app; watch `active_streams` against the 128/agent cap.

---

## Still stuck?

- Turn the relay to `VULOS_RELAY_LOG_LEVEL=debug` — every rejected connect and
  rate-limit event becomes visible with its bounded `reason`.
- Cross-reference the exact status/message with the code: proxy statuses in
  [`tunnel/server/proxy.go`](../tunnel/server/proxy.go), register acks in
  [`tunnel/server/control.go`](../tunnel/server/control.go), agent-side responses in
  [`tunnel/agent/forward.go`](../tunnel/agent/forward.go).
- The E2E tests are executable documentation of expected behavior:
  `go test -race ./tunnel/...` covers round-trips, WS, auth, SSRF, reconnect, rate
  limits, revocation, and billing.
- Conceptual background: [TUNNEL-GUIDE.md](TUNNEL-GUIDE.md) (behavior),
  [SECURITY.md](SECURITY.md) (why it refuses things),
  [METERING-BILLING.md](METERING-BILLING.md) (quota mechanics).
