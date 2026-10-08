# Provider operations

Provider operations are evidence-driven and default to read-only.

## Connect

Platform Admins create FMC or SCC connections in a disabled state, supply provider-specific credentials, and test the actual read path. The test validates authentication, identity/version, manager scope, policies, categories, rules, objects, and zones.

FMC uses short-lived REST tokens in memory. SCC uses an API-only bearer token and controlled region selection. Credentials are encrypted with AES-256-GCM and never returned in API responses or audit payloads.

## Synchronize

Manual and scheduled synchronization use a bounded worker path. Complete reads update normalized inventory, provider IDs, versions, fingerprints, revisions, capabilities, and missing/drifted state. Incomplete pagination does not mark unseen resources missing.

## Reconcile

When provider state diverges, Sync & drift records the discrepancy. Operators can review whether state was changed outside the control plane, whether the resource is missing, or whether a revision is stale. Reconciliation is explicit; provider names never silently adopt application ownership.

## Deployment boundary

Deployment schedules group active staged work by connector. Real-provider configuration writes and deployment polling require explicit connection write enablement, tested capability evidence, current authorization, approval, and successful preflight. Rollback uses a compensating ChangeSet only when stored snapshots and current provider revisions make it eligible. Run live compatibility probes only against approved non-production targets.

## Candidate deployment restriction

Native FMC/SCC deployment initiation is currently blocked: pending summaries cannot prove exact authorized change scope or atomic isolation from external edits. Empty pending observations never trigger a deployment POST. Staged configuration is not deployed configuration. This candidate is not ready for release.
