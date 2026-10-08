# Capabilities organized around operator goals

Firewall Policy Manager joins delegated administration, governed change, provider operations, and recovery in one model. Capabilities are exposed only when the current authorization context and observed provider evidence both support them.

## Delegate without losing control

Central administrators define Groups, Access Policy assignments, provider category mappings, rule capabilities, object and zone grants, authorized address ranges, and approval requirements. Delegated Users operate as one Active Group at a time; permissions from other memberships do not union.

[Explore delegated administration](./delegated-administration)

## Manage policy, not provider payloads

The normalized policy workspace covers ordered access rules, network and service objects, URLs, applications, zones, intrusion policy, file policy, and variable sets where the selected provider supports them. Ownership and use rights are evaluated for every element.

[Explore rules and objects](../guide/rules-objects)

## Govern every provider write

ChangeSets hold ordered intent, expected revisions, validation results, approval state, provider transactions, and audit evidence. Authority is checked again when the worker executes. Partial and ambiguous results remain explicit.

[Follow the ChangeSet lifecycle](../guide/changesets)

## Operate FMC and SCC through one workflow

Provider adapters normalize the workflow without claiming false parity. Connection- and version-specific evidence gates capabilities. Credentials stay server-side, TLS stays verified, and writes require explicit enablement.

[Compare provider integrations](../providers/)

## Know when reality changes

Manual and scheduled synchronization track complete inventory, provider revisions, drift, missing managed resources, and provider-only resources. Operators can accept provider state, restore or recreate through a ChangeSet, or resolve a conflict deliberately.

[Understand sync and reconciliation](../guide/sync-drift)

## Deploy and recover with evidence

Provider configuration and device deployment are distinct. Schedules, pause windows, authorized forced starts, provider jobs, friendly device names, and partial results are tracked. Eligible rollback produces a compensating ChangeSet; it is not a database rewind or guaranteed transactional undo.

[Explore deployment and recovery](./deployment-recovery)

## Authenticate and operate as an enterprise service

Entra ID, Duo SSO, and Generic OIDC feed explicit application identity mapping. Scoped API tokens, secure sessions, CSRF controls, Vault-backed secrets, audit, health, metrics, queues, worker/scheduler recovery, backups, and alerting support production operations.

[Review the security model](../security/) · [Run production operations](../operations/)
