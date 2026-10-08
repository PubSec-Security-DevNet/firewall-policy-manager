# Production operations

Operate Firewall Policy Manager as a control plane with three distinct kinds of state: local durable intent, provider configuration, and device deployment. Health checks and audit evidence should tell operators which boundary is unhealthy without exposing secret values.

## Daily operator loop

1. Check edge/API readiness and worker/scheduler heartbeats.
2. Review failed or incomplete synchronization runs and current provider connection health.
3. Review pending approvals, staged ChangeSets, and deployments requiring reconciliation.
4. Inspect drift, missing resources, and provider-only resources rather than silently adopting them.
5. Watch queue depth, request/job errors, database/storage growth, and backup completion.
6. Review privileged audit activity and expiring credentials or certificates.

## Operational surfaces

| Need | Primary evidence | Safe response |
| --- | --- | --- |
| API availability | liveness/readiness, HTTP metrics, edge logs | Restore dependencies before restarting repeatedly |
| Background work | worker/scheduler health records, queue depth, job counters | Resolve dependency or lease state; reconcile uncertain jobs |
| Provider health | connection status, latest sync, capability evidence | Test read path; keep writes gated |
| Deployment | batch state, provider tasks, per-device results | Retry only known-safe failures; reconcile ambiguity first |
| Data protection | verified dump, off-host copy, escrowed application key | Run a non-destructive restore test |

Use `./scripts/production.sh status`, `logs`, and `validate` for the packaged first-line checks. Continue with [monitoring](./monitoring), [workers and scheduler](./workers), or [troubleshooting](./troubleshooting).
