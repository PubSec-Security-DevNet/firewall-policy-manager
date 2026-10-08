# Provider integrations

FMC and SCC are first-class providers behind one normalized application contract. The common workflow covers inventory, authorization, ChangeSets, synchronization, discrepancies, and deployment while capability evidence prevents the application from pretending the providers are identical.

## Evidence before enablement

Connections begin disabled and read-only. **Test connection** exercises authentication, provider identity and version, manager scope, policies, categories, rules, objects, and zones. A successful test records connection-specific evidence; it does not globally certify every version or mutation.

Real writes require all applicable gates: enabled connection, explicit write enablement, supported capability evidence, current authorization, approval state, fresh provider revision, and a successful ChangeSet preflight.

| Shared workflow | Provider-specific handling |
| --- | --- |
| Normalized rule and object intent | API paths, authentication, pagination, and deployment APIs |
| Complete/incomplete synchronization semantics | FMC token lifecycle and SCC region selection |
| Version-scoped capability evidence | Differences in rule category, object, and deployment behavior |
| Drift and missing-resource records | Provider-specific revision and task identifiers |
| Per-device deployment results | Provider-specific pending-change and polling responses |

This is an independent open-source project and is not presented as an official Cisco product.
