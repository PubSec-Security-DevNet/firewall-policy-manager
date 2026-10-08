# Upgrade

Upgrade from an immutable reviewed release, not a moving branch.

1. Read the release notes and identify schema, configuration, provider-capability, and rollback considerations.
2. Create and verify a database backup; confirm separate custody of the application key.
3. Validate available disk space and the new production configuration.
4. Build or pull the release images.
5. Stop application traffic for the documented maintenance window.
6. Run `./scripts/production.sh migrate` once.
7. Start the full stack and wait for every health check.
8. Run `./scripts/production.sh validate` and inspect logs, worker/scheduler heartbeats, OIDC, provider reads, and metrics.
9. Keep provider writes paused until synchronization and version evidence are healthy.
10. Retain the prior images and backup until the validation window closes.

Database migrations are forward changes. A container image rollback does not reverse a schema change. If validation fails, follow the release-specific recovery procedure and restore only from a verified backup with a deliberate reconciliation plan.
