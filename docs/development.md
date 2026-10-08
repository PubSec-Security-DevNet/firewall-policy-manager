# Development environment — not for production

The root `compose.yaml` is the convenient local development topology. It intentionally contains
unsafe-for-production conveniences: deterministic mock FMC/SCC services, development identity
switching, seeded fixture users and organizations, Vite, API autoreload, source bind mounts, and
known local passwords.

Start it from the repository root:

```sh
cp .env.example .env
make up
make smoke
```

Open <http://localhost:5173>. API documentation is available at <http://localhost:8000/docs>.

Common commands:

```sh
make logs
make migrate
make seed
make sync
make test
make architecture
make security-check
make db-backup FILE=backups/local.dump
make db-restore-test FILE=backups/local.dump
make operational-smoke
make down
make reset CONFIRM=local
```

The mock-only stack can start without `APP_SECRET_KEY`. Before testing a real provider locally,
generate the base64-encoded 32-byte key described in `.env.example`, store it only in the ignored
`.env`, and restart the backend and worker. Never carry this development file, its passwords, its
mock URLs, or its authentication mode into production.

For a real installation, return to [the production installation guide](production-installation.md)
and use only `compose.production.yaml`.

The organization-wide overview and legacy inventory endpoints require a platform administrator. Delegated users select one Group and policy in the workspace; the dashboard does not aggregate permissions or inventory across memberships.
