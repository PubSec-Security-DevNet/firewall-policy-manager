# Feature: Milestone 3 ChangeSet drafts and mock execution

Status: Implemented
Owner/workstream: ChangeSets and safe provider mutation
Last updated: 2026-09-19

## Goal

Provide durable, Group-owned firewall rule and object drafts with exhaustive server-side
authorization, centralized object naming/equivalence resolution, stale-provider protection, and
independently tracked mock FMC/SCC transactions. Production FMC/SCC writes and deployment remain
disabled.

## ChangeSet model

`change_sets` now retains creator, immutable acting Group, primary and target policy IDs, metadata,
lifecycle state, optimistic revision, validated revision, provider revision snapshot, validation
results, execution results, failures, and audit metadata. `change_set_operations` stores ordered
provider-neutral operations with independent status, payload, expected resource revisions,
preflight decisions, naming resolution, execution result, and failure evidence.

Lifecycle states are `DRAFT`, `VALIDATION_FAILED`, `READY`, `EXECUTING`, `SUCCEEDED`, `FAILED`,
`PARTIALLY_SUCCEEDED`, `CONFLICT`, `RECONCILIATION_REQUIRED`, and `CANCELLED`. There is no
production deployment state.

## Operations and authorization

Supported mock operations are create/modify/delete/move rule and create object. Rule payloads use the
normalized model: zones, network/service/application/URL object references, manual networks and
ports, action, category, position, logging, and settings. Object drafts support network, port
service, URL, application, and application-filter types. Network, port-service, and URL creation
are fully enabled by mock capability evidence. Application/application-filter creation is
`PARTIAL`: normalization and conflict detection exist, but provider mutation remains blocked.

`ChangeSetService` calls the Milestone 2 `AuthorizationService` independently for the target
policy, target rule, mapped category, every zone, every referenced object, every manual network,
manual port syntax/capability, action, requested position, and object-create type. Denied provider
object identifiers are redacted in returned results. The complete preflight runs again immediately
before execution; current grants are never cached as permanent authority.

Every lookup is scoped by organization plus the explicit active Group. The stored ChangeSet Group
must equal the request Group, so membership or grants from another Group cannot contribute.

## Naming and equivalence

`ProviderObjectNamingService` is the only naming/equivalence implementation. It canonicalizes
network, service, URL, application, and filter values and returns exact reuse, equivalent reuse,
new object required, naming conflict, semantic conflict, or unsupported provider behavior. New
names use `<GROUP-SLUG>__<NAME>` and conservative FMC/SCC mock restrictions. Another Group's prefix
is rejected. Equivalent reuse still requires explicit object `USE` authorization.

## Revision and transaction strategy

Preflight snapshots provider versions, fingerprints, application revisions, and management state
for the policy, target rule, category, referenced objects, and zones. Object creation also snapshots
a digest of provider object inventory so a newly appearing equivalent/name conflict is stale state.
Refresh and execution compare current synchronized provider evidence to this snapshot and return
structured conflicts without rewriting the proposal.

Operations are grouped by manager and each manager receives an independent
`provider_transactions` record. The HTTP transaction adapter calls the stateful mock FMC/SCC
provider contract; successful operations change subsequent provider reads. The mock supports
success, provider failure, rate limiting, timeout before mutation, timeout after mutation, and partial
failure. Timeout after mutation becomes `RECONCILIATION_REQUIRED` and is never blindly retried.
Per-operation successes/failures are retained; the logical ChangeSet is explicitly non-atomic.
Stable transaction IDs make repeated delivery idempotent, and retained provider results support
explicit lookup of ambiguous outcomes.

An application-controlled `firewall_managers.is_mock` flag and a verified `mock` capability
evidence profile gate execution. Any non-mock target fails closed with
`PRODUCTION_PROVIDER_WRITE_DISABLED`. FMC/SCC production adapters remain read-only and no
deployment endpoint exists.

## REST API

- `POST/GET /api/v1/changesets`
- `GET/PATCH/DELETE /api/v1/changesets/{id}`
- `POST /api/v1/changesets/{id}/operations/rules`
- `POST /api/v1/changesets/{id}/operations/objects`
- `PUT/DELETE /api/v1/changesets/{id}/operations/{operation_id}`
- `POST /api/v1/changesets/{id}/preflight`
- `POST /api/v1/changesets/{id}/refresh`
- `POST /api/v1/changesets/{id}/execute`
- `GET /api/v1/changesets/{id}/transactions`
- `POST /api/v1/changesets/{id}/cancel`

All routes resolve the authenticated principal and explicit active Group, then reuse the same
application services. Errors use the canonical safe envelope with structured conflict details.

## Development UI and fixtures

The delegated workspace can create/select ChangeSets, add normalized rule operations using only
the active Group's categories/zones/objects, resolve permitted object drafts, inspect preflight and
transaction results, check revisions, and execute only when `READY`. A persistent warning states
that execution is mock-only and production deployment is disabled.

Fixtures include all existing roles, Alice's intentionally different Finance/Engineering access,
a single-Group approver, an administrator with no implicit delegated bypass, a Datacenter
view/use-only auditor, restricted Group address space/zones, equivalent and same-name/different-
value objects, and succeeded/failed/partial/ambiguous transaction examples.

## Verification

Automated coverage includes Group/ID substitution, unauthorized object injection and redaction,
zone/object/IP/category checks, execution-time revocation, active-Group mismatch, post-preflight
edits, stale revisions, naming/equivalence outcomes, production-write blocking, all defined roles,
success/failure/rate-limit/timeout/partial/ambiguous transactions, backend types/lint/tests,
frontend lint/types/tests/build, migration upgrade, Compose synchronization, and live REST mock
execution. Provider-contract tests independently cover FMC and SCC rule CRUD/order, stateful
network/port/URL creation, unsupported application creation, idempotency, and reconciliation.
Ordering tests cover within-category success, cross-Group/category and administrator-category
denial, cross-policy denial, and stale ordering evidence.

## Known limitations

- mock transactions mutate only the deterministic local mock provider and do not claim
  compatibility with a Cisco write API;
- successful provider writes require the existing synchronization path to refresh normalized
  inventory before a later ChangeSet can rely on the new provider revision;
- provider refresh compares current synchronized provider evidence; continuous provider polling
  and distributed execution workers remain future work;
- approval, deployment, rollback, production OIDC, MCP mutation tools, and real FMC/SCC writes are
  intentionally unavailable;
- the development editor exposes the normalized subset required for this milestone, not every
  provider-native rule feature.
