# Backups and restore

The packaged backup command creates a timestamped custom-format PostgreSQL dump and verifies that PostgreSQL can read it:

```sh
./scripts/production.sh backup
```

Copy verified dumps to encrypted off-host storage. Escrow the stable application secret key separately; encrypted OIDC and provider credentials cannot be recovered from the database alone.

## Restore test

Perform restores into an isolated PostgreSQL instance. Verify the archive, restore schema and data, confirm the expected Alembic revision, run application readiness checks with a copy of the correct key, and inspect representative Users, provider connections, ChangeSets, audit records, and deployment history. Do not point the restored environment at production providers or enable workers until isolation is proven.

Document recovery point and recovery time evidence. A backup job exit code is not a restore test.

The production helper intentionally provides no one-command restore or volume deletion shortcut. Restoring production requires an explicit outage plan, verified target, retained pre-restore copy, migration decision, and post-restore provider reconciliation.
