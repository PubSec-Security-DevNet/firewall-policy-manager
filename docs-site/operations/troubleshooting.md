# Troubleshooting

Start with correlation IDs, service health, durable workflow state, and provider evidence. Do not weaken TLS, authorization, or protected gates to make a symptom disappear.

| Symptom | Likely cause | Inspect | Safe corrective action |
| --- | --- | --- | --- |
| OIDC provider absent or callback fails | Provider disabled, issuer/callback mismatch, discovery or certificate failure | Identity provider status, `APP_PUBLIC_URL`, safe auth events | Correct exact issuer/callback; test configuration again |
| Vault/secret resolution fails | Identity, policy, path, TLS, or unavailable Vault | Secret check, Vault audit/health, container identity | Restore Vault access; do not substitute plaintext in logs or Git |
| FMC connection fails | Certificate identity, CA, credential role, or endpoint | Connection test code, certificate chain, FMC account permissions | Install correct trust and least-privilege access; never disable TLS |
| SCC connection fails | Wrong region, expired token, insufficient access | Region, token lifecycle, test-connection evidence | Rotate dedicated token and retest with writes disabled |
| Sync stays failed/incomplete | Provider pagination, timeout, worker, or dependency failure | Sync run, worker log, provider health, queue | Resolve cause and run a fresh full sync; incomplete runs do not mark resources missing |
| ChangeSet validation fails | Revoked grant, stale revision, ownership, dependency, or IP-range denial | Structured validation results and current context | Refresh provider state and correct intent or grants; do not bypass preflight |
| Approval is unavailable | Wrong role/Group, self-approval policy, changed revision, rejected state | Approval policy, actor, audit trail | Use an independent authorized approver; resubmit only after correction |
| Deployment is partial/failed | Provider task or device-specific failure | Deployment detail, provider job IDs, per-device results | Correct known failure and retry eligible work; preserve successful results |
| Deployment is reconciliation-required | Worker lease expired or provider response was ambiguous | Durable lease, provider task, pending changes | Query provider outcome before any retry |
| Drift or missing resource appears | Out-of-band provider edit/delete | Latest complete sync, fingerprints, discrepancy detail | Accept provider state, restore/recreate through a ChangeSet, or resolve manually |
| Worker is unhealthy | Redis, PostgreSQL, image/config, or stuck lease | Heartbeat, queue, dependency readiness, logs | Restore dependencies, restart worker, reconcile expired work |
| Scheduler is unhealthy | PostgreSQL unavailable or advisory lock held | Scheduler heartbeat/logs and process count | Ensure one healthy scheduler and working PostgreSQL |
| SMTP delivery fails | DNS/TLS/auth or sender policy | Durable notification state and sanitized SMTP error | Correct server trust/credentials; retry notification without changing approval state |
| Backup cannot be restored | Incomplete archive, version mismatch, missing application key | Archive verification, PostgreSQL version, key custody | Use a verified off-host copy and correct key in an isolated restore |

If the safe next action is unclear, pause provider writes and preserve evidence before changing state.
