# Vulos Relay – Documentation Index

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Relay architecture |
| [DEPLOY.md](DEPLOY.md) | Self-hosting / deployment guide |
| [RELEASING.md](RELEASING.md) | Release policy |
| [../SLOs.md](../SLOs.md) | Service level objectives |
| [../ROADMAP.md](../ROADMAP.md) | Roadmap |
| [../SECURITY.md](../SECURITY.md) | Security policy |

## Quick Links

- Submission API: `POST /submit` (see `internal/relay/submit.go`)
- Peering: `internal/peering/`
- Queue: `internal/queue/`
- Observability: `internal/obs/` + `/metrics` on submit listener
