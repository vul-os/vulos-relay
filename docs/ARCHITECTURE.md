# Vulos Relay – Architecture

## Overview

Vulos Relay is the outbound mail relay and Vulos-to-Vulos encrypted peering transport. It decouples mail submission from the mail server, providing:
- Warmed-IP SMTP relay (dedicated sending IP)
- Encrypted peer delivery path for Vulos-to-Vulos mail
- Pluggable queue + reputation policy seams

## Component Map

```
Submitter (vulos-mail)
   │ POST /submit
   ▼
┌──────────────────────┐
│  submit handler      │  internal/relay/submit.go
│  (auth gate RELAY-16)│
└──────────┬───────────┘
           │ Enqueue
    ┌──────▼───────┐
    │  Queue       │  internal/queue/
    │  (FS or Mem) │
    └──────┬───────┘
           │
    ┌──────▼───────────────────────────┐
    │  Pipeline (sending/pipeline.go)  │
    │  N workers, reputation policy    │
    └──────┬───────────────────────────┘
           │
    ┌──────▼────────────┐  ┌──────────────────┐
    │  RoutingSender    │→ │  PeerSender      │ Vulos-to-Vulos
    │  peering/routing  │  │  peering/sender  │ encrypted path
    └──────┬────────────┘  └──────────────────┘
           │ (fallback)
    ┌──────▼──────────┐
    │  SMTPSender     │ → Internet SMTP
    │  sending/smtp   │
    └─────────────────┘

Observability:
  internal/obs/ — vulos_relay_* metrics + OTel
  /metrics on submit listener (same port as /submit)
```

## Key Design Decisions

- **Open-relay prevention mandatory** (RELAY-16): `SharedSecretAuth` on every submission; cannot be bypassed.
- **Pluggable queue**: `FS` (persistent) or `Mem` (dev/test); set via `RELAY_QUEUE_BACKEND`.
- **Pluggable reputation**: `Permissive` (OSS default) or `Capped` (per-account daily cap + bounce threshold).
- **No CGO**: pure Go; builds with `CGO_ENABLED=0`.

## See Also

- Deployment: `docs/DEPLOY.md`
- Spec: `spec/`
