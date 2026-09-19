# Firewall Manager

Firewall Manager is an early delegated control plane for Cisco Secure Firewall Management Center
(FMC) and Security Cloud Control (SCC). Milestone 3 adds Group-owned ChangeSet rule/object drafts,
authoritative Group+policy object ownership, safe category/object mutation, element-level
authorization, naming/equivalence resolution, stale-provider protection, mock-only transaction
execution, and audit evidence on top of delegated policy/resource authorization.

No production provider writes, approvals, deployments, MCP tools, or real-provider credentials are
implemented. The transaction path fails closed unless its target is explicitly a deterministic
mock.

## Quick start

Requirements: Docker Engine with Compose v2, `curl`, and `make`.

```sh
cp .env.example .env
make up
make smoke
```

Open <http://localhost:5173>. The local UI visibly uses the isolated development identity
`viewer@example.test` (Alice); she can switch between Finance and Engineering and observe isolated
entitlements. Set `VITE_DEV_AUTH_USER=admin@example.test` to use the authorization administration
UI. Development authentication is rejected at
startup in staging and production.

## Local services

The canonical Compose project starts the Vite frontend, FastAPI backend, PostgreSQL, Redis,
Dramatiq worker, scheduler, separate mock FMC/SCC services, and one-shot migration, seed, and
synchronization jobs. Migrations and seed data are repeatable. Startup discovers both mocks and
persists policies, categories, rules, objects, zones, dependencies, provider versions, and sync status as
`OBSERVED`; it never adopts or modifies provider resources.

Common commands:

```sh
make up                 # build and start the stack
make logs               # follow service logs
make migrate            # apply Alembic migrations
make seed               # safely reapply deterministic seed data
make sync               # run read-only synchronization for configured local managers
make test               # backend and frontend quality checks
make architecture       # import-boundary contracts
make security-check     # Python and npm dependency audits
make smoke              # full local integration smoke test
make docker-clean       # prune only stopped/dangling resources from this Compose project
make down               # stop containers, retain data
make reset CONFIRM=local  # remove this project's stack, volumes, and locally built images
```

Build and smoke commands automatically remove stopped containers, unused networks, and dangling
or obsolete tagged images labeled for the `firewall-manager-local` Compose project. Routine
cleanup never removes database/Redis volumes, current images, running containers, or resources
from another project. The confirmed reset is the only normal command that prunes project-labeled
local persistent data. Shared Docker builder cache is intentionally retained because Docker cannot
reliably scope it to one Compose project; use Docker's global cache controls manually only when
their cross-project impact is acceptable.

For host-side checks, create `backend/.venv` with Python 3.12+ and install
`pip install -e 'backend[dev]'`; run `npm ci` in `frontend/`. CI runs the same formatter, linter,
type, test, architecture, dependency, secret, SAST, container, migration, and Compose smoke gates.

## Architecture

Browser requests reach versioned FastAPI routes, which resolve a principal and call reusable
application services. Application services depend on repository and normalized provider ports;
concrete SQLAlchemy and FMC/SCC HTTP adapters remain outside the domain. Background jobs use the
same package and an external Redis broker. PostgreSQL and Redis hold all durable/shared state.

The API contract is available at <http://localhost:8000/docs> and health endpoints are under
`/api/v1/health`. Safe local configuration is documented inline in [.env.example](.env.example).
Delegated reads are `/api/v1/delegated/policies` and `/delegated/context`; both require an explicit
active Group and the context endpoint also requires an Access Policy. Administration endpoints are
under `/api/v1/admin`. Legacy organization-scoped inventory endpoints remain available to the
development administrator/read scaffold and use bounded cursor pagination.

Key source areas are:

- `backend/src/firewall_manager/domain`: normalized domain/provider DTOs and states;
- `backend/src/firewall_manager/application`: effective authorization, administration, delegated
  inventory, and shared sync services;
- `backend/src/firewall_manager/providers`: provider contract adapters, capability validation, and
  deterministic mocks;
- `backend/src/firewall_manager/persistence`: SQLAlchemy models/repositories;
- `frontend/src/features` and `frontend/src/ui`: view state and semantic presentation boundary;
- `config/provider-capabilities.yaml`: validated capability evidence.

The delegated-management product contract, including mandatory active-Group context, is in
[docs/product/DELEGATED_POLICY_MANAGEMENT.md](docs/product/DELEGATED_POLICY_MANAGEMENT.md). The
current read APIs are organization-scoped development inventory, not completed delegated views.

## Current limitations

- Authentication is development-only; stable issuer+subject mappings are stored, but production
  OIDC is not implemented.
- The bootstrap `admin` role is development-oriented; delegated access itself is evaluated from
  current membership, policy delegation, resource grants, and the exact active Group.
- Provider discovery and selected stateful writes are mock-backed. Real FMC/SCC compatibility is
  not claimed; real-provider capability evidence remains separate and unimplemented.
- ChangeSet drafts and deterministic mock rule/object transactions are implemented. Approval,
  deployment, and all production provider writes remain unavailable.
- Sync is a startup/manual one-shot; production scheduling, locking, and large-scale backpressure
  are not implemented.
- MCP and the private FMC connector are not implemented.

See [docs/PROJECT_STATE.md](docs/PROJECT_STATE.md) in development worktrees for the current
implementation snapshot and governing project guidance.
