# Feature: Milestone 2 delegated authorization

Status: Implemented
Owner/workstream: delegated authorization
Last updated: 2026-09-19

## Goal

Establish the server-side boundary that decides whether an authenticated application User,
acting as exactly one explicitly selected Group, may perform an action in one Access Policy.
Provide administration and a small web experience that make Group isolation observable without
introducing provider writes.

## Non-goals

Real FMC/SCC mutation, deployment, production object/category creation, ChangeSet workflow,
provider-native RBAC, broad MCP mutation tools, and a final administration-console design.

## User flows

### Web

Users see their enabled memberships, select one active Group, and receive a freshly loaded
Group-scoped policy/rule/object/zone/address-space/capability view. Administrators can inspect and
manage Milestone 2 identities, memberships, delegations, grants, and category mappings.

### MCP

No MCP endpoint is added. The authorization service has no FastAPI dependency and requires the
same explicit context that future MCP tools must supply.

### API

`/api/v1/session` exposes eligible Groups. Delegated endpoints require `active_group_id` and
`policy_id`. Administration endpoints are under `/api/v1/admin` and require `manage_grants`.
Mutations use revisions and return the canonical safe error envelope.

## Authorization

- Authentication resolves by immutable issuer+subject; email/display name are attributes only.
- A current, enabled User and current, enabled membership are required.
- Membership grants eligibility only.
- Group and direct-User policy capabilities are combined only inside the exact same
  User+Group+Policy context.
- Object, zone, IP-network, and object-create checks are independent preflights.
- Provider existence does not grant USE. READ does not imply USE.
- The development bootstrap administrator role may manage grants; normal delegated users may not.
- All failures default deny with stable, non-enumerating decision codes.

## FMC / SCC compatibility

| Capability | FMC | SCC | Notes |
|---|---|---|---|
| Authorization preflight | application | application | Shared provider-neutral service |
| Inventory reads | mock read-only | mock read-only | Group-filtered from local inventory |
| Provider writes | not started | not started | Explicitly excluded |

## Domain/model changes

Add stable external identity, enabled/revision state, membership state, policy delegations,
same-context direct grants, object/zone/IP/object-create grants, audit events, and category mapping
expectation/sync metadata. Centralize Group provider-slug normalization and IP containment.

## ChangeSet / audit behavior

Existing ChangeSets retain immutable principal, acting Group, and policy references for delegated
work. Administrative grant changes and meaningful authorization decisions append audit events.
No provider transaction is created.

## Background work

None. Current authorization reads current database state on every protected request; no
distributed authorization cache is introduced.

## Failure modes

Disabled/missing users, Groups, memberships, or grants deny. Wrong-organization and identifier
substitution deny without disclosing cross-scope existence. Revocation takes effect on the next
request. Missing/drifted provider resources and unavailable provider capabilities deny safely.

## UI/presentation

Use existing semantic Mantine components. The active Group is prominent and policy/resource data
is reloaded when it changes. Loading, empty, error, disabled, validation, and confirmation states
remain keyboard accessible and target WCAG 2.2 AA.

## Security considerations

Primary threats are BOLA/IDOR, Group substitution, cross-Group or cross-policy union, direct-grant
ambiguity, stale client authorization, self-escalation, and provider metadata being mistaken for
authority. Database scope constraints plus one application authorization service mitigate these.

## Observability

Audit events retain actor, acting Group, policy, action, resource, decision/reason, interface, and
correlation ID without provider payloads or secrets.

## Configuration

No production secret or provider-write setting is added. Development authentication remains
explicitly environment-gated.

## Deployment/upgrade

One forward Alembic migration expands the Milestone 1 schema. Existing identities receive a
deterministic development issuer/subject backfill before non-null uniqueness is enforced.

## Tests

Unit/property-style parameterized authorization invariants, schema/migration checks, REST ID
substitution and administration checks, frontend active-Group tests, architecture checks, provider
capability gating, and canonical Compose smoke verification.

## Documentation updates

Update the product contract, authorization/interface/local-development docs, README, project
state, and handoff to reflect only behavior that is actually implemented.

## Acceptance criteria

Alice belongs to Finance and Engineering. With Finance selected, only Finance policy/resource
grants contribute; after switching to Engineering, only Engineering grants contribute. The
inverse/crossover cases are denied server-side and tested. Administration cannot be performed by
a delegated user. No real provider write occurs.

## Open questions

Production OIDC claims/issuer allowlists and finer-grained administrator delegation remain for a
future approved slice; the schema and immutable issuer+subject mapping are ready for it.
