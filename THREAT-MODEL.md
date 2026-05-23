# Threat Model — Vulos Relay

STRIDE pass. Last updated: 2026-05-23.

---

## Scope and Trust Boundaries

```
[Vulos Mail instances (submission)]
        |
        v (authenticated SMTP submission)
[Submission Listener]
        |
        v
[Queue (queue/)]
        |
        v
[Sending Pipeline (sending/)]
        |
        v (SMTP to destination MX)
[Internet / recipient MTAs]
              |
              v (peering / federation)
[Other Vulos Relay nodes (peering/)]
```

Trust boundaries:
- **Vulos Mail → Submission Listener**: authenticated via shared secret or mTLS. Considered semi-trusted (Vulos-controlled sender), but input is still validated.
- **Sending Pipeline → Internet**: untrusted external MTAs; STARTTLS/DANE enforced where available.
- **Relay ↔ Relay (peering)**: mutual TLS required; only known relay certificates accepted.
- **Queue store**: local filesystem; not externally accessible.

---

## Component 1: Submission Listener

### Trust boundaries
- Accepts SMTP submission from authenticated Vulos Mail instances.
- Authentication via shared API secret or mutual TLS certificate.
- Untrusted message content (headers, body) from the submitting user.

### Top 3 STRIDE threats

| # | Category | Threat |
|---|----------|--------|
| 1 | **Spoofing** | Attacker with network access to the submission port replays a captured authentication token to inject arbitrary mail. |
| 2 | **Tampering** | Maliciously crafted message headers (e.g. injected `Bcc:`, oversized header block) pass through submission and are delivered unmodified. |
| 3 | **Elevation of Privilege** | Submission endpoint exposed to the public internet by misconfiguration, allowing unauthenticated relay (open relay). |

### Mitigations in code
- Submission requires per-connection authentication; tokens are short-lived.
- Header size and count limits enforced at ingestion.
- Submission listener binds to loopback / internal interface by default; `config.yaml` must explicitly allow broader binding.

### Residual risks
- Token replay window exists between issue and expiry; no per-message nonce.
- Misconfigured deployments that expose port to internet are not detected automatically at startup.

---

## Component 2: Sending Pipeline

### Trust boundaries
- Reads from internal queue; dequeues one message at a time.
- Connects to external MX hosts; TLS negotiated per DANE / MTA-STS policy.
- External MX response (temp-fail, perm-fail, bounce) is untrusted input.

### Top 3 STRIDE threats

| # | Category | Threat |
|---|----------|--------|
| 1 | **Spoofing** | MX host presents a fraudulent TLS certificate; relay delivers mail to an attacker-controlled server. |
| 2 | **Denial of Service** | Delivery to a slow or unresponsive MX exhausts goroutine pool, blocking delivery to healthy destinations. |
| 3 | **Information Disclosure** | SMTP banner or error messages from external MX leak information about the relay's internal queue state or IP. |

### Mitigations in code
- DANE validation enforced where TLSA records exist; falls back to opportunistic TLS with CA verification.
- Per-destination delivery concurrency capped; stuck destinations time out independently.
- Error messages logged locally only; not forwarded to external senders.

### Residual risks
- DANE adoption is incomplete across the internet; many destinations use opportunistic TLS only (susceptible to active downgrade by a network attacker).
- Queue retry state is in local SQLite; no HA failover for the sending pipeline.

---

## Component 3: Peering / Federation

### Trust boundaries
- Relay nodes authenticate each other via mutual TLS.
- Peering connection list is configured statically; no automatic peer discovery.
- Each peer is a distinct trust boundary — a compromised peer can inject mail into the relay mesh.

### Top 3 STRIDE threats

| # | Category | Threat |
|---|----------|--------|
| 1 | **Spoofing** | Attacker presents a self-signed certificate matching a known peer CN to establish a fraudulent peering session. |
| 2 | **Tampering** | A compromised peer injects modified message headers during relay-to-relay forwarding. |
| 3 | **Repudiation** | No per-hop audit trail makes it impossible to determine which relay in the chain introduced a delivery failure or modification. |

### Mitigations in code
- Peer certificates pinned by public-key fingerprint in `config.yaml`; CN match alone is insufficient.
- Messages are passed verbatim between peers; headers are not re-written in the peering path.
- Each relay logs full SMTP transaction with message ID and peer identity.

### Residual risks
- Certificate rotation across a peering mesh requires coordinated config updates; lag creates a window of peering failure.
- Per-hop message integrity (e.g. DKIM over relay hops) is not implemented.

---

## Overall Residual Risks

1. Opportunistic TLS to external MTAs is downgrade-susceptible without DANE.
2. Peering certificate rotation has no automated coordination protocol.
3. No open-relay detection at startup for misconfigured deployments.
