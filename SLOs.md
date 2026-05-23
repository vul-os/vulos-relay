# Vulos Relay – Service Level Objectives

| # | Surface | Target | Measurement | Error budget (99.9% / month) | Rollback trigger |
|---|---------|--------|-------------|------------------------------|------------------|
| 1 | **Submission p99** | < 500 ms (POST /submit → queue) | `vulos_relay_request_duration_seconds` p99 | 43.2 min/month | p99 > 1 s for 5 min → halt deploy |
| 2 | **Outbound delivery p95** | < 60 s from queue to first delivery attempt | Trace span `sending.attempt` | 43.2 min/month | p95 > 180 s → alert |
| 3 | **Submission error rate** | < 1% | `vulos_relay_error_count_total / vulos_relay_request_count_total` | 26 min/month | Rate > 3% for 5 min → halt + alert |
| 4 | **Relay availability** | 99.9% | `/submit` reachable probe every 30 s | 43.2 min/month | 3 consecutive failures → restart + alert |
| 5 | **Queue depth** | < 500 pending messages under normal load | `vulos_relay_queue_depth` | Advisory | Depth > 2 000 sustained 5 min → alert; > 5 000 → halt |
| 6 | **Peering delivery p95** | < 10 s Vulos-to-Vulos peer path | Trace span `peering.deliver` | Advisory | p95 > 30 s → fallback to SMTP path |

## Notes

- Submission SLO covers time from TCP accept to queue enqueue returning.
- Error budget tracked per calendar month.
- Rollback trigger: CI/CD pipeline pause; human operator must approve revert.
