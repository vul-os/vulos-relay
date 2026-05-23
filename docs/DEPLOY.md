# Vulos Relay – Deployment Guide

## Self-Hosted

### Requirements
- Linux host with a static public IP (for warmed-IP SMTP)
- Port 25 for outbound SMTP; port 8025 for submit listener
- Go 1.21+ or Docker

### Build from Source

```sh
git clone https://github.com/vul-os/vulos-relay.git
cd vulos-relay
CGO_ENABLED=0 go build -trimpath -o vulos-relay ./cmd/relay/
./vulos-relay
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_QUEUE_BACKEND` | `fs` | `fs` or `mem` |
| `RELAY_QUEUE_DIR` | `/var/lib/vulos-relay/queue` | FSQueue directory |
| `RELAY_SUBMIT_ADDR` | `:8025` | Submit listener address |
| `RELAY_ACCOUNTS_SECRET` | _(empty)_ | Shared secret for the default account |
| `RELAY_WORKERS` | `4` | Concurrent delivery workers |
| `RELAY_SMTP_LOCAL_IP` | _(empty)_ | Source IP for outbound SMTP |
| `RELAY_SMTP_HELO` | _(empty)_ | EHLO hostname |
| `RELAY_POLICY` | `permissive` | `permissive` or `capped` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(empty)_ | OTel OTLP endpoint |

### Docker

```sh
docker run -d \
  --name vulos-relay \
  -p 8025:8025 \
  -v relay-queue:/var/lib/vulos-relay/queue \
  -e RELAY_ACCOUNTS_SECRET=<secret> \
  ghcr.io/vul-os/vulos-relay:latest
```

## Observability

- `GET /metrics` on the submit listener — Prometheus `vulos_relay_*` metrics.
- OTel traces when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.

## Upgrading

Stop, replace binary, restart. The FSQueue is forward-compatible; messages in the queue are not lost.
