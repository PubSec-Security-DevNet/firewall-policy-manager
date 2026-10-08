# Deployment and recovery

Firewall Policy Manager keeps application intent, provider configuration, and firewall deployment separate:

```text
Approved ChangeSet
  → FMC/SCC configuration
  → provider pending changes
  → scheduled or authorized forced deployment
  → per-device result
```

A successful provider configuration transaction can become `STAGED` while it waits for deployment. It is not reported as deployed early.

## Deployment controls

- schedules are configured per provider connection;
- pause windows stop scheduled starts and can expire automatically;
- forced deployment requires current deployment authority and does not bypass approval or provider gates;
- batches retain included ChangeSets, target device IDs, provider jobs, friendly device names, and per-device results;
- partial, failed, unknown, and expired-lease outcomes remain explicit;
- ambiguous provider calls reconcile before retry.

## Compensating ChangeSet rollback

Rollback is safe recovery, not magic undo. Eligibility depends on retained snapshots, supported original operations, current revisions, and absence of incompatible dependent changes. When eligible, the application constructs a new compensating ChangeSet and sends it through validation, approval where required, provider execution, and a subsequent deployment.

Firewall Policy Manager does not claim a transactional firewall rollback. A provider-native deployment rollback, when supported and explicitly invoked, has its own task and per-device evidence; it does not replace compensating configuration recovery.

Deployment proceeds when current authority, target assignments and provider evidence satisfy the
[deployment safety contract](../installation/deployment-safety.md). Known unexplained pending
changes and unavailable evidence fail closed. An edit made directly in FMC/SCC after final preflight
is a documented provider boundary limitation.

The durable intent commit authorizes one provider request. Revocation after that boundary cannot
recall it. Replacement workers inspect recorded receipts and known targets without replaying the
write. Known deployment jobs resume monitoring; unknown job outcomes remain reconciliation-required.
Configuration recovery records per-intent desired-state evidence while retaining the ChangeSet for
review of ownership and remaining operations. Retry never blindly resends uncertain work.
