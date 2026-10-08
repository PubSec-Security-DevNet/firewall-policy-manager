# Sync, drift & reconciliation

Synchronization reads provider resources into normalized inventory: policies, categories, rules, objects, zones, dependencies, versions, and fingerprints. It does not infer application ownership from a provider name or silently adopt resources.

Drift can mean a changed revision, renamed resource, missing resource, category conflict, or incomplete dependency evidence. Reconciliation records the discrepancy and provides an explicit operator decision boundary.

| Observed condition | Meaning | Available safe direction |
| --- | --- | --- |
| Provider-only / unmanaged | The provider has a resource with no application ownership record | Leave unmanaged or explicitly accept provider state where supported |
| Drifted | A managed resource fingerprint or revision differs | Accept provider state or restore known state through a ChangeSet |
| Missing | A managed resource no longer exists at the provider | Recreate through a ChangeSet when dependencies and capability allow |
| Conflict | Current evidence cannot support an automatic decision | Resolve the underlying revision, ownership, or dependency conflict |

Accepting provider state is an audited ownership/state decision. Restore and recreate proposals enter the ordinary ChangeSet workflow; reconciliation does not write directly around authorization or approval.

Scheduled synchronization uses the worker queue and bounded batches. Incomplete reads retain the prior inventory and record failure evidence instead of marking unseen resources missing.

Upgrades quarantine legacy ownership and object grants. Platform Admins review individual assignments in Access grants; synchronization cannot clear this restriction.
