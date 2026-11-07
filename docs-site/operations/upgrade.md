# Upgrade

Use a maintenance window and a reviewed release tag or commit. Review the release's migration,
configuration, and recovery notes, pause provider schedules/writes, and reconcile active operations.
Confirm encrypted off-host backup storage and separate custody of the application key.

From the repository directory, replace the checkout placeholder before running:

```sh
./scripts/production.sh backup
./scripts/production.sh stop
git fetch --tags
git checkout --detach '<new-release-tag-or-commit>'
./scripts/production.sh setup
```

Setup preserves configuration, secrets, certificates, and database volumes. It builds the new
images, starts the database and queue, runs migrations while the application is stopped, starts
the application, and validates HTTPS. Resolve any failure before resuming service.

Verify login, provider reads and synchronization, worker/scheduler health, and monitoring before
resuming writes. If monitoring was previously enabled, run `./scripts/production.sh monitoring-start`
after setup. Retain the prior release and backup through the validation window.

An application rollback does not reverse database migrations or firewall changes. Follow the
release-specific recovery procedure and [backup and restore guidance](./backup-restore).
