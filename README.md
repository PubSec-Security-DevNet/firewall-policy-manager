# Firewall Manager

Firewall Manager is an early delegated control plane for Cisco Secure Firewall Management Center
(FMC) and Security Cloud Control (SCC). Milestone 4 adds administratively managed, unlimited real
FMC/SCC connections, encrypted write-only credentials, verified TLS/private-CA support, connection
testing, version-specific compatibility evidence, and scheduled read-only synchronization on top
of the Milestone 3 delegated ChangeSet and mock-transaction architecture.

Real-provider configuration writes, approvals, deployments, and MCP provider administration are
not implemented. The transaction path still fails closed unless its target is explicitly a
deterministic mock; every real connection reports `writable: false` regardless of credential role.

## Quick start

Requirements: Docker Engine with Compose v2, `curl`, and `make`.

```sh
cp .env.example .env
make up
make smoke
```

Open <http://localhost:5173>. Use the header selector to switch immediately among the deterministic
Admin, Firewall Admin, Group Admin, Alice, Bob, Carol, Viewer, Disabled User, and No Groups
identities. Selection is browser-session scoped and a switch reloads the application, clearing the
active Group and all user-specific UI state. Development authentication and its identity-list
endpoint are rejected/absent outside explicit development or test mode.

The mock-only stack does not require a secret-store key. Before creating a real connection,
generate a 32-byte base64 key with the command in `.env.example`, put it in the ignored local
`.env` as `APP_SECRET_KEY`, and restart the application processes. Production must inject this key
from an external secrets-management mechanism; it must never be committed or placed in an image.

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

## Real provider connections

Administration → Provider connections supports any number of independently credentialed FMC and
SCC connections. Connections start disabled, must pass the actual read path before they can be
enabled, retain separate health/sync/evidence/audit state, and may be disabled or retired without
deleting historical inventory. FMC uses a dedicated username/password to obtain short-lived REST
tokens in memory; SCC uses an API-only bearer token and a controlled Cisco region selector. FMC
requires HTTPS with system trust or an administrator-supplied CA bundle. There is no TLS bypass and
redirects are not followed.

Credentials are AES-256-GCM ciphertext in a dedicated secret table. Associated data binds each
ciphertext to its organization, connection purpose, secret UUID, and key version; connection rows
hold only the reference and safe metadata. Passwords, tokens, CA material, access/refresh tokens,
and authorization headers are excluded from API responses/audit and covered by logging-redaction
tests. The abstraction is deliberately replaceable with a KMS/Vault-backed store.

The UI includes capability-derived least-privilege setup guidance and links to Cisco's FMC 7.6/7.7
REST guides and SCC Firewall Manager API 1.20.0 documentation. Labels that Cisco does not verify
uniformly across FMC versions are explicitly shown as version-specific rather than guessed.

Live read-only probes are never part of ordinary CI. They require `RUN_REAL_FMC_TESTS=true` or
`RUN_REAL_SCC_TESTS=true`, the corresponding `REAL_*` credentials, and
`REAL_PROVIDER_NON_PRODUCTION_ACK=non-production-read-only`. Never point them at production. A
successful configured-connection test records evidence only for its discovered provider version;
the repository-wide real profiles remain `NOT_STARTED` until actual live compatibility evidence is
deliberately collected.

## Architecture

Browser requests reach versioned FastAPI routes, which resolve a principal and call reusable
application services. Application services depend on repository and normalized provider ports;
concrete SQLAlchemy and FMC/SCC HTTP adapters remain outside the domain. Background jobs use the
same package and an external Redis broker. PostgreSQL and Redis hold all durable/shared state.

The API contract is available at <http://localhost:8000/docs> and health endpoints are under
`/api/v1/health`. Safe local configuration is documented inline in [.env.example](.env.example).
Delegated reads are `/api/v1/delegated/policies` and `/delegated/context`; both require an explicit
active Group and the context endpoint also requires an Access Policy. Administration endpoints are
under `/api/v1/admin`; provider connections are under `/api/v1/admin/provider-connections` and are
restricted to the active platform `admin` role. Legacy organization-scoped inventory endpoints remain available to the
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
- Real FMC/SCC read adapters and connection management are implemented, but compatibility is not
  claimed for a version until a live, non-production read-only test succeeds for that connection.
  Repository-wide real capability baselines remain `NOT_STARTED`.
- ChangeSet drafts and deterministic mock rule/object transactions are implemented. Approval,
  deployment, and all production provider writes remain unavailable.
- Enabled real connections use one bounded scheduler batch and the existing worker queue. Advanced
  distributed claiming/locking and large-scale backpressure remain future work.
- MCP and the private FMC connector are not implemented.

See [docs/PROJECT_STATE.md](docs/PROJECT_STATE.md) in development worktrees for the current
implementation snapshot and governing project guidance.
