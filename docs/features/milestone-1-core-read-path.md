# Feature: Milestone 1 core domain and mock read path

Status: Implemented
Owner/workstream: milestone-1-core-read-path
Last updated: 2026-09-19

## Goal and user flow

Establish provider-neutral domain/persistence boundaries and prove that a developer can start the
canonical stack, synchronize deterministic FMC and SCC data, and browse the same normalized
manager/policy/rule/object path in REST and the web UI.

## Non-goals

Real Cisco connectivity, credentials, adoption, firewall mutation, approvals, deployment, MCP,
production scheduling, and final management UI.

## Authorization and data integrity

All inventory reads resolve the authenticated principal's organization in the application service;
provider IDs never authorize. Application UUIDs are primary identity. Initial discovery remains
unowned `OBSERVED` state. Organization, manager, policy, ownership, grant, ChangeSet, and sync
lookup paths are indexed; mutable resources have positive revisions; native metadata is sanitized.

The closing product-compatibility review added distinct User/Group/GroupMembership structure,
stable Group provider slugs, rule/object Group ownership fields, ChangeSet acting context,
Group+policy provider-category mappings, normalized zones, and typed rule-element references. It
did not implement effective delegated authorization.

## Provider and sync behavior

Both mocks satisfy one typed paginated contract. Capabilities are explicit and extensible. Native
IDs/versions/fingerprints remain provider attributes. A failed or incomplete page records an
incomplete run and never marks unseen resources missing. A complete run may mark unseen resources
`MISSING`; changed fingerprints become `DRIFTED` with a drift record.

Mocks also expose two Group-shaped provider categories, security zones, and representative
network, network-group, service, URL, application, and application-filter objects. Synchronization
does not infer application Group ownership from those provider observations.

## UI and API

Versioned, typed, bounded GET APIs expose managers, policies, rules, objects, and provider/sync
status with canonical errors and correlation IDs. The semantic UI layer renders manager status and
tabbed resource tables with loading, error, and empty states.

## Deployment and tests

Alembic revisions `20260919_0002_core_domain_sync` through
`_0005_delegated_group_foundations` extend the Milestone 0 schema. Compose runs migration, repeatable seed,
and mock synchronization as one-shots before the API. Tests cover shared provider contracts,
pagination faults, observed-first behavior, drift/missing/new resources, isolation, persistence
constraints, API pagination/errors/correlation IDs, and frontend states/accessibility.

## Limitations

Capability evidence covers deterministic mocks only. No `SUPPORTED` real-provider capability is
declared. The migration is forward-only from Milestone 0 because normalized provider data cannot be
losslessly collapsed into the old scaffold schema.
