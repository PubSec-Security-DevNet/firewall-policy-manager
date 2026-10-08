# Cisco Secure Firewall Management Center

The FMC adapter uses verified TLS and short-lived REST authentication tokens held in memory. Administrators can use system trust or a private CA. The certificate must match the configured hostname or IP address; legacy hostname-mismatch fallback is not supported.

## Supported product workflow

- discover domains, devices, Access Control Policies, categories, rules, objects, zones, and applicable policy inventories;
- normalize paginated resources and record complete synchronization evidence;
- create, modify, delete, and order supported access rules through ChangeSets;
- create and mutate supported network, port-service, and URL objects through ChangeSets;
- inspect pending configuration and initiate authorized scheduled or forced deployment;
- poll deployment jobs and retain device-level success, partial, failure, or unknown results;
- detect out-of-band change, missing resources, and stale revisions for explicit reconciliation.

Provider-native capability varies by FMC version and configured account privilege. Firewall Policy Manager records evidence against the observed version and keeps unproven operations gated.

## Onboarding safely

Create a least-privilege FMC API account, establish trusted certificate identity, add the connection with writes disabled, run **Test connection**, complete a full synchronization, and inspect version/capability evidence. Validate mutations and deployment against an approved non-production target before enabling the write gate.

## Deployment boundary

See the [provider-specific deployment contract](../installation/deployment-safety.md). Deployment
uses current assignments, expanded pending evidence, recorded mutation results and durable intent.
The provider does not document atomic exclusion of direct edits after final preflight. Strict
exclusivity requires an operational change window.
