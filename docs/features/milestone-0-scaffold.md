# Feature: Milestone 0 application scaffold

Status: Implemented
Owner/workstream: milestone-0-scaffold
Last updated: 2026-09-19

## Goal

Create the first executable application skeleton and one canonical, realistic local environment
for frontend, API, persistence, queue workers, scheduler, and deterministic FMC/SCC mocks.

## Non-goals

- Production authentication or deployment configuration.
- Real FMC/SCC credentials, mutation, deployment, or connector control channels.
- Final authorization, approval, ChangeSet, or database designs.
- MCP tools beyond reserving the architecture boundary.

## User flows

### Web

A developer starts the stack, sees that development authentication is active, and views seeded
organization and read-only provider inventory data.

### MCP

No MCP endpoint or tools are implemented in this milestone.

### API

Versioned health, development-session, and read-only overview endpoints are implemented.
Errors use the canonical envelope and correlation IDs.

## Authorization

Development authentication is allowed only in development/test and resolves a seeded user.
The overview service performs server-side read authorization. Unknown, inactive, and ungranted
users are denied. No approve or deploy action is exposed.

## FMC / SCC compatibility

Both local mocks implement deterministic health and read-only discovery through the same provider
contract. This does not establish compatibility with a real Cisco API version.

## Domain/model changes

The initial schema stores organizations, teams, users, manager records, policies, categories,
rules, network objects, ChangeSets, and drift records with deterministic seed IDs.

## ChangeSet / audit behavior

Seeded ChangeSets are display-only examples. No mutation state transitions or provider writes are
implemented. Audit tables and behavior remain future work.

## Background work

Redis-backed Dramatiq workers process an idempotent health task. A distinct scheduler enqueues
that task periodically. Critical workflow state is not stored in process memory.

## Failure modes

Readiness fails when PostgreSQL or Redis cannot be reached. Provider discovery reports a bounded,
safe unavailable status without leaking transport details. Production cannot enable dev auth.

## UI/presentation

Feature state lives in an overview hook; pages render through the initial semantic UI layer and
Mantine theme. Loading, error, and provider status have accessible text.

## Security considerations

Local provider URLs are centralized configuration, CORS is allowlisted, provider writes do not
exist, secrets use placeholders, containers run as non-root, and dev auth fails startup outside
development/test.

## Observability

Services emit structured logs. API responses preserve or create a correlation ID. Health endpoints
and Compose health checks cover all runtime dependencies.

## Configuration

`.env.example` contains safe local-only defaults. Real provider credentials are neither accepted nor
required by this scaffold.

## Deployment/upgrade

Alembic owns the schema. Migrations and seeding run as distinct one-shot Compose services before
the API starts.

## Tests

Backend unit/API/authorization/provider-contract/migration/worker tests and frontend component,
accessibility, lint, formatting, and type checks are required. The Compose smoke test verifies the
complete local stack.

## Documentation updates

Add the tracked root README and `.env.example`; update `PROJECT_STATE.md` and this workstream's
handoff.

## Acceptance criteria

- `docker compose up --build -d` starts a healthy mock-only environment.
- Seed and migration operations are repeatable.
- All formatter, linter, type, test, architecture, and CI configurations are executable.
- No production firewall write functionality exists.

## Open questions

Production identity, final role/grant schema, connector channel, and production queue operational
policy remain open beyond this milestone.
