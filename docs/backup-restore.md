# Production backup and recovery

Install and operate the stack through `scripts/production.sh`. This runbook covers recovery,
which is a separate maintenance procedure and has no script shortcut.

## Back up

From the repository directory:

```sh
./scripts/production.sh backup
```

Copy verified dumps to encrypted off-host storage. Escrow the stable application key separately.
A database dump without the matching key cannot decrypt stored application credentials.

## Rehearse recovery

Restore into an isolated PostgreSQL instance first. Verify schema revision, representative records,
and application readiness with the matching key. Keep the recovered environment isolated from
production providers and workers until the target and reconciliation plan are approved. Record
recovery point and recovery time evidence; archive verification alone is not a restore rehearsal.

## Restore production

Confirm the target environment, maintenance window, retained pre-restore backup, and matching
application key before executing this procedure. The restore replaces database contents. Replace
the example archive name, and adjust the environment-file path if using a custom runtime directory.
Run from the repository directory.

Restore during an approved maintenance window:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml stop edge frontend backend worker scheduler
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml --profile ops run --rm \
  -e CONFIRM_RESTORE=restore backup restore /backups/firewall-manager-YYYYMMDDTHHMMSSZ.dump
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml run --rm migrate
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml up -d backend worker scheduler frontend edge
```

Then run readiness checks, inspect pending/deploying ChangeSets, compare FMC/SCC actual state, mark
uncertain operations for reconciliation, and only then resume schedules/writes. A database restore
does **not** roll back FMC or SCC. Use a compensating ChangeSet/provider rollback procedure based
on observed provider state.

Never run `docker compose down -v` in production: `-v` destroys PostgreSQL, Redis, Prometheus, and
Grafana named volumes. Normal `docker compose down`, container recreation, image upgrade, and host
reboot preserve them. The separately mounted secret files are not Compose volumes and are not
removed by either command.
