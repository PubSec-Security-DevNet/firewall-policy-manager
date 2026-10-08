# Production release checklist

## Before deployment

- [ ] Approved non-production target and change window recorded.
- [ ] PostgreSQL backup completed and copied to encrypted, access-controlled storage.
- [ ] A restore rehearsal passed against the backup using the production installation procedure.
- [ ] Protected `app_secret_key` file or approved external secret provider is configured.
- [ ] `make secret-check` passed with the production key source.
- [ ] Current encryption key version and recovery material recorded separately from PostgreSQL.
- [ ] Current Entra, Duo, FMC, and SCC compatibility evidence reviewed.
- [ ] Dependency, SAST, secret, container, and SBOM checks passed.
- [ ] `make sbom` produced an SBOM that was retained with the release evidence.
- [ ] Prometheus scrape, alert rules, and Grafana dashboard are installed.
- [ ] Ingress TLS, authentication, rate limiting, and network policy are verified.

## Deployment

- [ ] Run migrations before application workers consume new queue payloads.
- [ ] Keep API, worker, scheduler, and migration jobs on the same secret/key version.
- [ ] Confirm `/api/v1/health/ready`, worker heartbeat, scheduler activity, and metrics scrape.
- [ ] Confirm interactive API docs are disabled outside development/test.
- [ ] Keep provider deployment paused during migration and smoke validation.
- [ ] Perform an authenticated read-only smoke test before resuming writes.
- [ ] Resume deployment only after provider status and reconciliation queues are reviewed.

## After deployment

- [ ] Test API token authentication and revocation.
- [ ] Test one scheduled sync and inspect its audit/correlation evidence.
- [ ] Verify no deployment is `UNKNOWN` or `RECONCILIATION_REQUIRED`.
- [ ] Exercise worker/scheduler restart and confirm heartbeat recovery.
- [ ] Confirm alerts are firing in a controlled test and then resolve.
- [ ] Record migration revision, image digests, backup ID, operator, and UTC completion time.

## Rollback and recovery

- [ ] Software rollback plan is approved separately from database rollback.
- [ ] Do not restore PostgreSQL to roll back firewall/provider state.
- [ ] After a database restore, run migrations, restore matching key material, perform read-only
      reconciliation, and inspect drift before enabling provider writes.
- [ ] Any uncertain provider deployment remains fenced until provider state is confirmed.
