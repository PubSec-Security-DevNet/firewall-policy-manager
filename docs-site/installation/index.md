# Production quick start

The supported single-host production topology runs Caddy, the built frontend, FastAPI, workers, the singleton scheduler, PostgreSQL, authenticated Redis, and optional Prometheus/Grafana as hardened containers. Only HTTPS is exposed publicly.

> This sequence is an orientation, not a substitute for the [complete production guide](./production). Read each linked section before operating the corresponding step.

## Installation sequence

<div class="lifecycle-grid"><div class="lifecycle-step"><b>01</b><strong>Prepare</strong><span>Current Docker Engine and Compose v2, DNS, storage, time sync, and outbound provider access.</span></div><div class="lifecycle-step"><b>02</b><strong>Configure</strong><span>Check out an immutable release and create the protected runtime layout.</span></div><div class="lifecycle-step"><b>03</b><strong>Secure</strong><span>Install TLS, create runtime secrets, and choose deployment injection or Vault.</span></div><div class="lifecycle-step"><b>04</b><strong>Start</strong><span>Start infrastructure, migrate PostgreSQL, then start API, workers, scheduler, frontend, and edge.</span></div></div>

1. [Prepare the host and release checkout](./production#host-and-network-prerequisites).
2. [Configure production environment and protected files](./production#production-configuration-and-runtime-secrets).
3. [Install the trusted certificate and private key](./tls).
4. Start the infrastructure services.
5. [Initialize the chosen secret provider](./secrets).
6. Apply the complete Alembic schema.
7. Start the application services and validate readiness.
8. [Configure and test OIDC](../security/authentication).
9. Bootstrap the first Platform Admin through the guarded first-run workflow.
10. Add [FMC](../providers/fmc) or [SCC](../providers/scc) with writes disabled.
11. Configure [backups](../operations/backup-restore) and [monitoring](../operations/monitoring) before production enablement.

## Guided setup

From an immutable release checkout:

```sh
cd /opt/firewall-manager/repository
./scripts/production.sh setup
```

The helper checks prerequisites, creates protected files, builds images, starts infrastructure, applies migrations, starts the stack, waits for health checks, and validates HTTPS. It preserves existing configuration and secrets.

After setup, open the configured HTTPS URL to complete OIDC and organization bootstrap. There is no default production username or password.

## Before enabling provider writes

- complete a full provider synchronization and review capability/version evidence;
- configure Groups, policy mappings, resource grants, authorized ranges, and approval requirements;
- validate backup restore, alerts, worker/scheduler recovery, deployment, and compensating rollback procedures;
- exercise real mutations only against an approved non-production FMC or SCC target;
- review the [production release checklist](./production#final-security-checklist).
