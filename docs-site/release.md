# Release candidate status

**Current status:** Release candidate

This release candidate presents the implemented FMC and SCC control-plane workflow: delegated authorization, policy/rule/object management, ChangeSets and approvals, synchronization and drift, deployment lifecycle, compensating ChangeSet recovery, enterprise OIDC, scoped API tokens, audit, and production operations.

Release-candidate status means operators should complete environment-specific acceptance before production enablement. In particular, validate the exact OIDC tenant, secret provider, provider versions and least-privilege accounts, trusted certificate paths, non-production mutations and deployments, alert delivery, backup restore, worker recovery, and rollback procedure.

Capability evidence is connection and provider-version specific. The application warns on an untested version family and keeps mutations behind explicit administrator-controlled gates.

- [Production installation](./installation/)
- [Production acceptance checklist](./installation/production#final-security-checklist)
- [Security reporting](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/security)
- [Releases](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/releases)
- [Issue tracker](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/issues)
