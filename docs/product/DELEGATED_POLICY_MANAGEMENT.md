# Delegated Policy Management Product Requirements

## Purpose and status

The product provides delegated firewall-policy administration for FMC and SCC. This document is
the durable product contract for Group-scoped policy management across web, REST, MCP, workers,
authorization, audit, persistence, and provider integrations.

Milestone 3 implements the provider-neutral effective-delegation boundary, active-Group web flow,
administration surface, Group-filtered reads, durable ChangeSet drafts, exhaustive operation
preflight, centralized naming/equivalence, stale revision protection, deterministic mock-only
transactions, and audit evidence. Production provider writes, deployment, and production
authentication remain unimplemented.

## Authorization context

Every delegated policy operation executes with exactly this explicit context:

```text
Authenticated User + Active Group + Access Policy -> Effective delegated permissions
```

The server must validate that the user is a current member of the active Group and then evaluate
only grants scoped to that Group and Access Policy. It must never union grants from all of a user's
memberships or search memberships for a Group that would make an operation succeed.

Changing the active Group causes policy, rule, object, zone, IP-range, ordering, and permission
views to be re-evaluated. The UI will provide a prominent selector, but the selector is not an
authorization control; enforcement is server-side.

## Domain map

```text
Organization
  +-- User --< GroupMembership >-- Group(provider_slug)
  +-- FirewallManager -- Domain/Tenant -- AccessPolicy
                                          |
                   +----------------------+
                   |
                   +-- PolicyDelegation(Group/User, capabilities)        [future]
                   +-- GroupPolicyCategoryMapping -- Provider Category
                   +-- AccessRule(owner Group, creator/modifier User)
                   +-- ObjectUseGrant(Group/User -> FirewallObject)       [future]
                   +-- ZoneGrant(Group/User -> SecurityZone)              [future]
                   +-- IpRangeGrant(Group/User -> allowed network)        [future]
                   +-- ObjectCreateGrant(Group/User -> object classes)    [future]
                   +-- ChangeSet(principal, acting Group, AccessPolicy)
```

| Concept | Required behavior | Current state |
|---|---|---|
| User | Stable issuer+subject identity; enabled/revision state; zero or more memberships | Implemented |
| Group | Primary boundary with immutable normalized provider slug and enabled/revision state | Implemented |
| GroupMembership | Current eligibility only; never an automatic policy grant | Implemented |
| Active Group context | Exactly one Group plus one Access Policy per delegated operation | Server-enforced and exposed in web UI |
| PolicyDelegation | Explicit view/create/modify/delete/reorder/workflow-ready capabilities | Implemented; no provider mutation |
| Rule ownership | Exactly one owning Group for delegated rules, separate from creator/modifier | Enforced by delegated read/preflight and mock-only ChangeSet execution |
| Object use grants | Explicit READ/USE/MODIFY distinction | USE foundation and preflight implemented |
| Zone grants | Explicit source/destination/both use | Implemented |
| IP-range grants | Multiple canonical IPv4/IPv6 networks scoped to Group+policy | Implemented |
| Object-create grants | Limited classes plus provider capability and equivalence gating | Authorization representation/preflight implemented |
| Group/policy category mapping | Application-authoritative mapping to a provider category | Implemented; provider provisioning excluded |

## Membership and policy delegation

A User may belong to zero, one, or multiple Groups. Membership establishes eligibility to select a
Group; it grants no Access Policy or resource rights by itself. Policy delegation is explicit for
each Group/User and Access Policy. Access to one policy never implies access to another policy on
the same manager.

Initial policy capabilities are `view`, `create_rule`, `modify_rule`, `delete_rule`, and
`reorder_rule`. Workflow capabilities later include `submit`, `approve`, and `deploy`, preserving
the canonical distinction between read, use, modify, approval, and deployment.

Direct User grants may exist, but delegated rule operations still require an active Group and
Access Policy. There is no implicit personal Group.

## Rule ownership, visibility, and ordering

A delegated Access Rule has exactly one application Group owner. Ownership is independent of the
User who created or last modified it and remains stable when membership changes. Multiple Group
memberships never make a rule shared.

Within an active Group and Access Policy, delegated users primarily see/manage that Group's rules.
Administrative/global visibility requires separate permission. Ownership does not permit arbitrary
placement: create/reorder is constrained to the Group's mapped provider category and ordering
boundary. Cross-Group, administrator, protected, and provider-section moves are denied unless a
future explicit administrative capability allows them.

Provider category names do not establish ownership. The authoritative mapping is:

```text
Group + Access Policy -> GroupPolicyCategoryMapping -> Provider Rule Category
```

The category uses the Group's stable provider-facing slug/prefix. Creating a delegated rule places
it in that mapped category.

## Synchronized provider resources

Firewall objects, zones, policies, categories, and rules are synchronized into normalized local
inventory. UI selection uses that inventory rather than making a provider request per dropdown.
Each resource retains application identity, provider-native identity, version/fingerprint, sync
state, and drift/missing semantics. Synchronization never infers Group ownership from provider
names, categories, or native IDs.

Zone renames, deletion, or drift follow the same reconciliation states as other provider resources.
Rule references retain their element role so source/destination zones and networks, services,
applications, and URLs can be authorized independently.

## Object authorization and creation

Provider object existence does not grant use. Every referenced object requires server-side USE
authorization in the current User + active Group + Access Policy context. USE never implies MODIFY.

Delegated creation is initially limited to normalized classes:

- `NETWORK`;
- `PORT_SERVICE`;
- `URL`;
- `APPLICATION` and `APPLICATION_FILTER`.

Creation UI and APIs are available only when the current provider/version advertises tested
support. Provider-specific name character/length restrictions are supplied through the provider
boundary; application naming is centralized rather than reimplemented in pages/adapters.

Before creation, the application checks normalized equivalence across provider inventory. Network
and host comparisons use canonical address/network values; services use protocol plus port/range;
URLs and application/filter definitions use type-appropriate canonical forms. If an equivalent
object exists but is not authorized for USE, return an authorization/conflict result for
administrator resolution. Never silently grant access or create a duplicate.

Delegated-created objects belong to the active Group and use its immutable provider slug:

```text
<GROUP-SLUG>__<OBJECT-NAME>
```

Changing the Group display name does not change the slug or existing object identity.

## IP-range authorization

Groups/Users may receive multiple allowed IPv4 and eventually IPv6 ranges scoped to the active
Group and Access Policy. These ranges govern manual rule values and delegated network-object
creation. The complete requested address or network must be contained by an allowed network using
proper IP arithmetic, never string-prefix comparison. Ranges from other memberships do not
contribute.

## Rule-element authorization

Creation and modification independently authorize every applicable element:

- source and destination zones;
- source and destination network objects;
- manual source and destination address/network definitions;
- ports/services;
- applications/application filters;
- URLs.

The model remains extensible to future elements. A provider containing an element is not proof of
authorization.

## ChangeSets, cache, audit, and MCP

Every delegated ChangeSet records its principal, acting Group, and Access Policy. That context is
immutable for the ChangeSet: switching the UI Group does not transfer ownership, add permissions,
permit cross-Group resources, or change execution grants. Validation and execution re-authorize
using the stored context.

Authorization cache keys, if later introduced, include principal, active Group, Access Policy, and relevant
authorization/grant revision. No combined cross-Group entitlement cache is permitted.

Privileged audit records include actor, acting Group, Access Policy, ChangeSet/operation/provider,
action, decision, and outcome. Web and future MCP interfaces invoke the same services and
authorization. MCP never merges memberships,
selects a broader Group, or switches Groups to make a request succeed.

## Security invariants

1. A delegated operation executes under exactly one active Group.
2. Permissions from other Group memberships do not contribute.
3. Every delegated rule has exactly one owning Group.
4. Provider category placement does not establish ownership.
5. Existing provider objects require explicit USE permission.
6. Object USE does not imply MODIFY.
7. Created objects belong to the active Group and use its stable prefix.
8. IP/network values fit entirely within the active Group's authorized ranges.
9. Zones require explicit use authorization.
10. Every rule element is independently authorized.
11. Rule ownership does not imply arbitrary reorder placement.
12. A ChangeSet retains its acting Group context.
13. Switching Groups never changes an existing rule or ChangeSet context.
14. MCP and web use identical Group-context authorization.
15. Default deny.
