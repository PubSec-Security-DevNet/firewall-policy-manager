# Production installation and operations

This is the canonical single-host production deployment for Firewall Policy Manager. Follow it
from a clean Linux host. Every application runtime and infrastructure dependency runs in a
container: Caddy, the built React frontend, FastAPI, Dramatiq worker, singleton scheduler,
PostgreSQL, authenticated Redis, and optional Prometheus/Grafana. The host does not need Python,
Node.js, PostgreSQL clients, Redis, or a web server. The guided helper and readiness checks use
standard Linux utilities plus `curl`.

The preferred ingress identity is an administrator-provided trusted certificate. If neither PEM
file exists, a one-shot container automatically creates a hostname-correct self-signed certificate
so clean installations and reboots do not require certificate intervention.

`compose.yaml` is development-only. It contains mocks, development authentication, fixtures, hot
reload, source mounts, and known local passwords. Production uses only
`compose.production.yaml`.

## Optional guided helper

Administrators who prefer a guarded workflow can use one script instead of entering the Compose
commands individually:

```sh
cd /opt/firewall-manager/repository
./scripts/production.sh setup
```

The helper checks Docker, prompts for the public hostname and optional operator email, creates the
runtime directories, generates protected PostgreSQL/Redis/Grafana/application secrets without
printing them, builds the application images, starts infrastructure, applies migrations, starts the
complete stack, and validates HTTPS/API readiness. It requests `sudo` only while creating or
protecting host files. If the TLS directory is empty, the normal self-signed certificate initializer
runs automatically. The browser-based OIDC setup remains an intentional interactive step.

For automation, supply the prompts without placing secrets in the environment:

```sh
FM_PUBLIC_HOST=firewall.example.com \
FM_ADMIN_EMAIL=firewall-operations@example.com \
./scripts/production.sh setup
```

The operation commands and their effects are:

| Command | Purpose and effect |
| --- | --- |
| `setup` | First-time configuration: create protected files, build, migrate, start, and validate. Existing configuration and secrets are preserved. |
| `start` | Start or recreate the core stack and wait for health checks. Data and secrets remain unchanged. |
| `stop` | Stop containers so they can be restarted later. Containers, volumes, data, and secrets remain. |
| `restart` | Stop and start the core stack, then wait for health checks. Expect a short outage. |
| `down` | Remove production containers and networks. Named data volumes, backups, certificates, and secret files remain. |
| `status` | Show all production containers, including stopped containers and health state. |
| `logs [SERVICE ...]` | Follow the latest 200 log lines for everything or selected services; press Ctrl-C to exit. |
| `migrate` | Stop the API, worker and scheduler, apply pending migrations, and print the revision. Services stay stopped; review the upgrade result before `start`. |
| `backup` | Create a timestamped PostgreSQL dump and verify that PostgreSQL can read it. It does not copy the dump off-host. |
| `cert-refresh` | Generate a new 365-day self-signed certificate, restart the edge proxy, and validate HTTPS. It refuses to overwrite a CA-issued certificate. Clients must trust the new certificate. |
| `cert-reload` | Validate and reload the edge proxy after an administrator or PKI tool installs a renewed trusted PEM pair. No image rebuild is performed. |
| `monitoring-start` | Start the optional Prometheus and Grafana services and wait for health checks. |
| `monitoring-stop` | Stop Prometheus and Grafana while preserving their data. |
| `validate` | Render-check Compose, show service state, and test the HTTPS API readiness endpoint. |
| `config` | Open the non-secret production environment file in `$EDITOR` (default `vi`). Restart affected services afterward. |
| `help` | Print the command list and unattended-setup environment variables. |

For example:

```sh
./scripts/production.sh status
./scripts/production.sh logs backend worker scheduler
./scripts/production.sh backup
./scripts/production.sh cert-refresh
./scripts/production.sh monitoring-start
```

Run `./scripts/production.sh help` for the complete command list. The helper deliberately provides
no volume/secret deletion or restore shortcut. Restore, key rotation, upgrades, and decommissioning
remain explicit procedures later in this guide because they require operator judgment. The manual
sections below remain the authoritative explanation of every action performed by `setup`.

## 1. Architecture and security boundary

```text
browser -- HTTPS :443 --> Caddy -- edge network --> frontend:8080
                              |
                              +-------------------> backend:8000
                                                       |
                          data network (internal) -----+--> PostgreSQL
                              |                        +--> Redis
                              +--> worker / scheduler -+

backend / worker / scheduler -- egress network --> OIDC, SMTP, FMC, SCC
Prometheus / Grafana -------- monitoring network --> backend metrics
```

Only TCP 80 and 443 are published on all host interfaces. Port 80 exists only for HTTPS redirect;
close it if the redirect is not wanted. Grafana's optional admin network publishes only to
`127.0.0.1`. PostgreSQL,
Redis, Prometheus, API, frontend, worker, and scheduler have no public host bindings. The data and
monitoring networks are Docker-internal. The worker and scheduler are separate processes; the
scheduler also holds a PostgreSQL advisory lock so a second instance exits instead of running
duplicate schedules.

## 2. Host and network prerequisites

Use a supported 64-bit Linux distribution and a current Docker Engine/Compose plugin from the
[official Docker installation instructions](https://docs.docker.com/engine/install/). The commands
below assume Ubuntu 24.04 or a comparably maintained server, systemd, and an administrator who can
use `sudo`. Install Docker from Docker's repository—not an unmaintained distribution package—and
verify it:

```sh
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
sudo docker run --rm hello-world
git --version
curl --version
```

Use rootful Docker or protect membership in the `docker` group as root-equivalent access. Configure
the Docker daemon and host filesystem according to local hardening standards.

Baseline planning for a small installation is 4 CPU cores, 8 GiB RAM, 50 GiB fast persistent disk
plus backup capacity. This is starting guidance, not a capacity guarantee. Inventory size,
ChangeSet/audit retention, PostgreSQL, Prometheus retention, container logs, and database dumps
determine actual growth. Monitor them and resize before exhaustion; do not impose arbitrary limits
without workload measurements.

Prerequisites:

- one stable DNS name, for example `firewall.example.com`, resolving to the host or its load
  balancer;
- preferably, an administrator-provided server certificate whose SAN contains that exact name,
  its full intermediate chain, and the matching unencrypted PEM private key; otherwise the stack
  creates a self-signed certificate that clients must explicitly trust;
- inbound TCP 443, and optionally TCP 80 for redirect;
- outbound HTTPS from application containers to the OIDC discovery/token/JWKS endpoints and FMC/
  SCC APIs, plus the selected SMTP port;
- correct time synchronization and an organization-approved backup destination;
- an OIDC confidential client in Microsoft Entra ID, Cisco Duo SSO, or a standards-compliant OIDC
  provider.

Internal container traffic is API→PostgreSQL/Redis, worker and scheduler→PostgreSQL/Redis,
Prometheus→API metrics, and Grafana→Prometheus. Do not add host port mappings for those services.

## 3. Filesystem layout and release checkout

Use an immutable release tag or reviewed commit, never an unreviewed moving branch:

```sh
sudo install -d -m 0750 -o "$USER" -g "$USER" /opt/firewall-manager
cd /opt/firewall-manager
git clone https://github.com/PubSec-Security-DevNet/firewall-policy-manager.git repository
cd repository
git fetch --tags --force
git checkout --detach '<release-tag>'

sudo install -d -m 0750 -o "$USER" -g "$USER" \
  /opt/firewall-manager/runtime \
  /opt/firewall-manager/runtime/tls \
  /opt/firewall-manager/runtime/secrets \
  /opt/firewall-manager/backups
sudo chown root:root /opt/firewall-manager/runtime/tls
sudo chmod 0750 /opt/firewall-manager/runtime/tls
```

The `repository/` directory is Git-tracked code and non-secret policy/configuration.
`runtime/` contains the environment, Docker secret sources, and certificates. `backups/` contains
local staging copies of database dumps; copy them off-host. `production/runtime/`, PEM keys,
secrets, and backups are ignored by the repository, but `/opt/firewall-manager/runtime` is preferred
so an accidental `git add` cannot reach them.

## 4. Production configuration and runtime secrets

```sh
cd /opt/firewall-manager/repository
cp .env.production.example /opt/firewall-manager/runtime/.env.production
chmod 0600 /opt/firewall-manager/runtime/.env.production
```

Edit it and set `APP_PUBLIC_HOST`, `APP_PUBLIC_URL`, operator email, retention, and the two absolute
directory paths. It contains no passwords. Compose forces `APP_ENVIRONMENT=production`,
`DEV_AUTH_ENABLED=false`, file-mounted SecretStore key injection, HTTPS CORS, and non-mock default
provider URLs.

Generate unique secrets with container tools. The random values are never printed:

```sh
umask 027
docker run --rm alpine:3.22 sh -c 'head -c 48 /dev/urandom | base64' \
  > /opt/firewall-manager/runtime/secrets/postgres_password
docker run --rm alpine:3.22 sh -c 'head -c 48 /dev/urandom | base64' \
  > /opt/firewall-manager/runtime/secrets/redis_password
docker run --rm alpine:3.22 sh -c 'head -c 48 /dev/urandom | base64' \
  > /opt/firewall-manager/runtime/secrets/grafana_admin_password
docker run --rm alpine:3.22 sh -c 'head -c 32 /dev/urandom | base64' \
  > /opt/firewall-manager/runtime/secrets/app_secret_key
```

Grant the fixed application container group read access while keeping host access restricted:

```sh
sudo chown -R root:10001 /opt/firewall-manager/runtime/secrets
sudo chmod 0750 /opt/firewall-manager/runtime/secrets
sudo chmod 0640 /opt/firewall-manager/runtime/secrets/*
sudo chown root:10001 /opt/firewall-manager/backups
sudo chmod 0770 /opt/firewall-manager/backups
```

The PostgreSQL password bootstraps both PostgreSQL and the application connection. The Redis
password protects the private broker. The 32-byte base64 `app_secret_key` signs sessions and
encrypts application secrets; it must remain stable and must be escrowed separately from database
backups. The Grafana password is required only when the monitoring profile runs. OIDC is configured
later through the one-time setup screen; no OIDC secret file is needed. Never paste `docker compose
config` output from locally customized secret-bearing environment values into an issue.

## 5. Configure the HTTPS certificate

For a trusted production identity, copy the CA-issued files without committing or baking them into
an image:

```sh
sudo install -o root -g root -m 0644 /secure/source/fullchain.pem \
  /opt/firewall-manager/runtime/tls/fullchain.pem
sudo install -o root -g root -m 0600 /secure/source/privkey.pem \
  /opt/firewall-manager/runtime/tls/privkey.pem
```

`fullchain.pem` must contain the leaf server certificate followed by required intermediate
certificates. `privkey.pem` must match it and must not be password-encrypted because Caddy starts
unattended. The certificate SAN must contain `APP_PUBLIC_HOST`. With an enterprise CA, browsers and
managed clients must trust the issuing root/intermediates; that browser trust is separate from FMC
or SCC provider trust.

The primary path uses supplied PEM files and does not require public ACME. Certificate renewal is
an atomic file replacement followed by a proxy reload. After installing the replacement pair, the
helper performs the validation, reload, and readiness check:

```sh
sudo install -o root -g root -m 0644 /secure/source/fullchain.pem.new \
  /opt/firewall-manager/runtime/tls/fullchain.pem.new
sudo install -o root -g root -m 0600 /secure/source/privkey.pem.new \
  /opt/firewall-manager/runtime/tls/privkey.pem.new
sudo mv /opt/firewall-manager/runtime/tls/fullchain.pem.new \
  /opt/firewall-manager/runtime/tls/fullchain.pem
sudo mv /opt/firewall-manager/runtime/tls/privkey.pem.new \
  /opt/firewall-manager/runtime/tls/privkey.pem
./scripts/production.sh cert-reload
```

Verify the renewed expiry and chain with your enterprise TLS scanner or
`openssl s_client` from an approved administration workstation. No image rebuild is needed.

If both `fullchain.pem` and `privkey.pem` are absent, leave the TLS directory empty. When the edge
service starts, the `tls-init` one-shot container generates a P-256 self-signed certificate valid
for 365 days with `APP_PUBLIC_HOST` in its SAN. It writes the key with mode `0600`, then Caddy starts
normally. It never overwrites an existing pair. If only one PEM file exists, initialization fails
instead of replacing or mismatching administrator material.

A self-signed certificate encrypts traffic but does not establish a publicly trusted server
identity. Browsers will warn until administrators distribute `fullchain.pem` as an approved trust
anchor. Replace it with an enterprise/public CA certificate before broad user access. After placing
both replacement files, run `./scripts/production.sh cert-reload`; no application image rebuild is
required.

Run `./scripts/production.sh cert-refresh` to replace the generated self-signed certificate with a
new 365-day pair. The command validates that the existing certificate is self-signed, refuses a
CA-issued certificate, restarts only the edge proxy, and checks readiness. Because a newly generated
self-signed certificate is a new trust anchor, clients must explicitly trust the replacement. The
helper cannot renew a CA-issued certificate because issuance and authorization vary by PKI; automate
your approved PKI client to install both PEM files atomically and then invoke `cert-reload`.

## 6. Render, build, and start infrastructure

Use this exact Compose prefix for all remaining commands:

```sh
cd /opt/firewall-manager/repository
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml config --quiet
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml build backend frontend
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml up -d db redis
```

PostgreSQL and Redis must become healthy. The Compose render contains secret file *paths*, not
their values. Treat rendered output as operational configuration anyway; inspect it locally and do
not attach it blindly to tickets.

The `tls-init` service runs automatically when `edge` is requested. Inspect its result with:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml logs tls-init
```

Verify the master-key file can be loaded without printing it:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml run --rm --no-deps backend python -c \
  'from firewall_manager.config import get_settings; assert get_settings().secret_store_master_key; print("Application secret key: ok")'
```

The key remains a plaintext host file protected by ownership and filesystem permissions. Docker
Compose bind-mounts it read-only only into application containers that need it. It is not stored in
an environment variable, image, Compose interpolation output, or database. Host root and Docker
administrators can read it, so restrict that access and use full-disk encryption where required.
Keep a separately encrypted escrow copy: losing this key makes encrypted OIDC, provider, and SMTP
credentials unrecoverable even when the PostgreSQL backup is intact.

## 7. Migrate and start the application

Migrations are an explicit administrator step; the API never races another replica to migrate:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml run --rm migrate
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml run --rm migrate alembic current
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml up -d backend worker scheduler frontend edge
```

An Alembic failure exits nonzero; do not start or upgrade application containers until it is
resolved. `alembic upgrade head` is idempotent. Production images contain Alembic and Python, so
the host does not.

## 8. Complete first-time OIDC setup

There is no default account, password login, development identity header, or file-based bootstrap
provider. On a genuinely empty database, the login page presents a one-time setup screen. Before
opening it, create a confidential OIDC client in Entra, Duo, or the generic provider and allow the
production application URL. The screen generates the provider ID from its display name; register
this exact redirect URI after entering the display name and before selecting **Test configuration**:

```text
https://firewall.example.com/api/v1/auth/<generated-provider-id>/callback
```

Then browse to `APP_PUBLIC_URL` and:

1. Enter the organization name and the first administrator's display name and email.
2. Select Entra, Duo, or Generic OIDC and enter the display name, exact HTTPS issuer URL, client ID,
   and client secret.
3. Confirm the generated provider ID matches the registered callback URI.
4. Select **Test configuration** and complete the real provider sign-in as that administrator.
5. After the callback reports success, select **Complete initial setup**.
6. Sign in normally and verify the Platform Admin surfaces and external identity mapping.

The test callback obtains the authenticated identity's immutable `sub`; email alone never grants or
links access. Completion atomically creates the organization, Platform Admin, external identity,
and database-managed OIDC provider. The client secret is encrypted in PostgreSQL using the
file-mounted application key. The setup screen stops being available once any organization, User,
or OIDC provider exists. If an incomplete or existing deployment loses all providers, use the guarded
operator recovery process in the
[authentication runbook](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/blob/main/docs/AUTHENTICATION.md#existing-deployment-recovery);
do not make the public first-run screen available again.

Provider requirements:

- Entra: tenant-specific issuer/discovery, confidential web client, exact redirect URI, and
  `openid profile email` scopes;
- Duo SSO: Duo's exact OIDC issuer/client values and exact redirect URI;
- generic: standards-compliant discovery, RS256 JWKS validation, Authorization Code flow, and an
  immutable subject claim.

Issuer + subject controls identity mapping. Email/display-name claims are metadata and do not
authorize or auto-link users.

## 9. SMTP and application secrets

The production secret model is:

| Secret | Location | Backup requirement |
| --- | --- | --- |
| PostgreSQL password | protected Docker secret source file | credential escrow |
| Redis password | protected Docker secret source file | rotate/recreate if lost |
| application/session encryption key | protected Docker secret source file | separate encrypted escrow is mandatory |
| OIDC/provider/SMTP credentials | AES-256-GCM ciphertext in PostgreSQL | DB plus application key required |
| Grafana admin password | protected Docker secret source file | rotate if lost |
| public TLS private key | protected runtime certificate path | enterprise PKI process |

Configure SMTP after login through the administration UI whenever possible. Set host, port, sender,
STARTTLS or implicit TLS, username/password, and an optional custom SMTP CA. The password is
write-only encrypted storage. If SMTP is unavailable, notifications retry through the worker;
in-application approval queues remain authoritative and usable. Do not bundle a mail server.

## 10. FMC onboarding

FMC and SCC trust are unrelated to the browser certificate. A container may not trust an internal
FMC CA by default. For FMC, choose `CUSTOM_CA` and paste the PEM CA chain into the connection form;
it is encrypted with the credentials and reused by API, worker, and scheduler after every restart.
Never disable verification or use `verify=False`.

As Platform Admin:

1. Confirm container DNS/routing reaches the FMC HTTPS endpoint.
2. Create a dedicated FMC account using the least privilege its tested API/version permits.
3. Create an FMC connection with exact HTTPS base endpoint, username/password, writes disabled,
   and system trust or the custom CA bundle.
4. Select **Test Connection** and verify the recorded product/version/certificate evidence.
5. Run a full inventory sync and inspect policies, rules, objects, zones, and capability evidence.
6. Configure Users, Groups, memberships, policy delegation, object/zone grants, IP ranges, and
   approval requirements.
7. Exercise ChangeSet approval against a non-production policy.
8. Enable the per-connection write gate only when the credential permissions, discovered version,
   backups, rollback plan, deployment schedule, and monitoring are approved.

FMC obtains short-lived REST tokens in memory. Credential privileges alone never open the
application write gate. Cisco role names and permissions vary by FMC release; validate the smallest
working read set first, then add only the exact configuration/deployment permissions proven by the
target version.

## 11. SCC onboarding

SCC uses a selected Cisco region and an API bearer token rather than an FMC URL and username/
password. As Platform Admin:

1. Confirm outbound HTTPS to the selected SCC regional API and Cisco identity endpoints.
2. Create a dedicated API client/token with the narrowest inventory scope first.
3. Create the SCC connection with the correct region and token, writes disabled.
4. Test the connection; review tenant, version/API evidence, capabilities, and any rate-limit result.
5. Run inventory sync and inspect SCC-normalized policies, objects, rules, zones, and drift.
6. Configure delegation/grants and test approvals in a non-production tenant.
7. Add only proven mutation/deployment scopes and enable the independent write gate when ready.

Do not paste an FMC CA into SCC or copy FMC permission labels to SCC; SCC uses Cisco-managed regional
TLS and token scopes.

## 12. Initial application checklist

Complete in order after the first login:

- [ ] first-run OIDC test completed and DB-managed identity provider verified
- [ ] Platform Admin identity and external issuer/subject mapping verified
- [ ] FMC and/or SCC connection tested read-only
- [ ] full provider sync and version/capability evidence reviewed
- [ ] Users, Groups, and memberships created
- [ ] policy delegation, object grants, zone grants, and IP ranges configured
- [ ] approval rules and approvers tested
- [ ] SMTP and in-app approval behavior tested
- [ ] deployment schedule reviewed; write gates remain closed until approved
- [ ] monitoring alerts loaded
- [ ] database backup created, copied off-host, and restore-tested

## 13. Monitoring and logging

Monitoring is optional because Prometheus/Grafana consume additional memory and disk:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml --profile monitoring up -d prometheus grafana
```

Prometheus has no host port. Grafana binds only to `127.0.0.1:${GRAFANA_PORT}` and disallows
anonymous access/sign-up; reach it through an SSH tunnel or approved authenticated reverse proxy.
Use the generated admin password, then rotate it according to policy. The provisioned datasource
and dashboard load automatically. Alerts cover API availability, errors/rate limits, worker
heartbeat, and reconciliation state.

Application logs are structured JSON with correlation IDs and redaction filters:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml logs --since=30m backend worker scheduler edge
```

Compose uses Docker's `json-file` driver with five 10 MiB files per container to prevent unbounded
local growth. Forward logs to the enterprise aggregation platform with access controls and
retention; never enable permanent DEBUG logging or collect cookies, authorization headers, OIDC
codes, provider payloads, or secret-bearing request bodies.

## 14. Readiness verification

`docker ps` is insufficient. Run all relevant checks:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml ps
curl --fail --silent https://firewall.example.com/healthz
curl --fail --silent https://firewall.example.com/api/v1/health/live
curl --fail --silent https://firewall.example.com/api/v1/health/ready
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  https://firewall.example.com/api/v1/metrics)" = 404

docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml exec db sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml exec redis sh -c \
  'redis-cli --no-auth-warning -a "$(cat /run/secrets/redis_password)" ping'
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml exec worker python -m firewall_manager.worker.health
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml exec scheduler python -m firewall_manager.scheduler_health
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml run --rm migrate alembic current
```

Also verify browser login, secure/HttpOnly session cookies, CSRF rejection, HSTS/security headers,
the certificate hostname/chain/expiry, one provider test, one full sync, one in-app approval, and
monitoring targets/alerts when enabled.

For the generated self-signed certificate, add
`--cacert /opt/firewall-manager/runtime/tls/fullchain.pem` to the host-side `curl` commands. Do not
use `--insecure`; client trust should remain explicit.

## 15. Back up and restore through containers

Create and validate a PostgreSQL custom-format dump without host PostgreSQL tools:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml --profile ops run --rm backup backup
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml --profile ops run --rm backup \
  verify /backups/firewall-manager-YYYYMMDDTHHMMSSZ.dump
```

Copy verified dumps off-host, encrypt them in transit/at rest, enforce retention, and record restore
tests. Local dumps are not disaster recovery. Escrow `app_secret_key` separately under equivalent
or stronger protection; do not place it beside the database dump. A PostgreSQL dump without that
key cannot decrypt stored credentials.

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

## 16. Host restart and persistence test

During commissioning, record a maintenance window and test:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml down
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml up -d
```

No operator action is required after Docker starts: every required secret is available from its
protected host file and services start under `restart: unless-stopped`. Confirm the same users and
provider records exist, Redis AOF state is accepted, the worker heartbeat returns, only one
scheduler owns its advisory lock, queued work resumes, and provider state is reconciled before
writes. During commissioning, also perform a real host reboot and repeat these checks.

## 17. Upgrade and rollback

There is no claimed zero-downtime upgrade for this single-host reference architecture.

1. Pause deployment schedules and leave provider write gates closed where practical.
2. Review release notes and Compose/image changes.
3. Create and verify a PostgreSQL dump; confirm separate encrypted custody of `app_secret_key`.
4. Fetch and detach at the new immutable tag.
5. Render Compose locally and build/pull images.
6. Stop edge/API/worker/scheduler, run the explicit migration, then recreate them.
7. Run all readiness, login, provider connectivity, sync, queue, and monitoring checks.
8. Reconcile any operation that was active at shutdown, then resume schedules/write gates.

Example:

```sh
git fetch --tags --force
git checkout --detach '<new-release-tag>'
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml config --quiet
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml build backend frontend
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml stop edge backend worker scheduler
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml run --rm migrate
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml up -d backend worker scheduler frontend edge
```

Application image rollback, Alembic downgrade, database restore, compensating ChangeSet, and FMC/
SCC deployment rollback are five different operations. Never imply that recreating an older Docker
image reverses a provider configuration. Prefer a forward fix; use an Alembic downgrade only when
the specific migration documents and tests it.

## 18. Decommission

Pause schedules and writes, finish/reconcile active deployments, export required audit evidence,
take final PostgreSQL and application-key backups, and record retention ownership. Stop the stack
without volumes. Revoke the OIDC client, FMC/SCC credentials, SMTP credential, and operator access.
Remove DNS and certificates when the retention window permits. Only after an
authorized owner confirms recoverability/retention may you remove named volumes and securely
destroy backups and host keys. Volume removal is destructive and normally unrecoverable.

## 19. Final production security checklist

- [ ] `compose.production.yaml` is used; development Compose, mocks, fixtures, and dev auth are absent
- [ ] only TCP 443 (and optional redirect port 80) is externally reachable
- [ ] valid hostname certificate/full chain installed; private key is outside Git/images
- [ ] generated self-signed certificate is explicitly trusted only by intended clients or replaced
      with an enterprise/public CA certificate
- [ ] PostgreSQL, Redis, Prometheus, API, worker, and scheduler have no host/public ports
- [ ] PostgreSQL and Redis passwords are unique file-mounted secrets
- [ ] `app_secret_key` is a unique 32-byte key, outside Git/images/environment variables
- [ ] runtime secret files are root-owned, mode `0640` or tighter, and host/Docker access is restricted
- [ ] the application key has a separately encrypted escrow copy and is excluded from database backups
- [ ] an unattended real host reboot was tested successfully
- [ ] OIDC is active and Platform Admin issuer/subject mapping is verified
- [ ] secure cookies, CSRF, HSTS/security headers, and rate limiting were exercised
- [ ] FMC/SCC TLS validation remains enabled; private FMC CA bundle is configured where needed
- [ ] real connections began read-only; provider versions/capabilities and write gates were reviewed
- [ ] SMTP failure leaves in-app approvals usable
- [ ] backups are encrypted/off-host and a containerized restore was tested
- [ ] monitoring and finite Docker log rotation are active
- [ ] `docker compose down -v` is prohibited by the operations runbook

## 20. External managed substitutions

Advanced installations may replace the reference PostgreSQL, Redis, ingress, or file-mounted key
with managed services or an external KMS-backed secret manager if they preserve the same driver/API
behavior, TLS, persistence, least privilege, and availability assumptions. That is not the primary
walkthrough and requires a deployment-specific Compose override and validation. Do not weaken
production defaults merely to make a managed service fit.

## Deployment safety and existing installations

Automated FMC/SCC deployment is device-wide because the native provider APIs cannot isolate a
specific application's pending items. FPM records pending changes outside the application as
warnings and deploys them with the managed batch; it still refuses malformed or incomplete
provider evidence and known managed mutations with explicit errors. Do not treat a staged
ChangeSet as deployed, or retry an uncertain provider operation.

Provider names, prefixes, and categories do not grant ownership during synchronization. Upgrades
quarantine legacy assignments for individual administrator review, invalidate active approvals,
and disable writes for affected organizations. Stop all API/worker/scheduler processes before
migration. See [Legacy ownership review](legacy-ownership.md) and
[Deployment safety contracts](deployment-safety.md). The `migrate` helper leaves writers stopped;
run `start` after a successful migration. Native deployment remains blocked in this candidate.

Creating and editing a Changeset requires the corresponding policy operation grant; submission is
automatic in the application workflow and does not require a separate grant. Delegated approvers
require the Approve ChangeSets grant as well as the approver role; self-approval is refused. Edits
and revalidation invalidate approval, and execution rechecks the approver's current authority.

The shipped stack injects a file-backed encryption key and does not deploy Vault. External Vault
AppRole support is an alternative integration requiring operator-managed TLS, credentials, policy,
availability, and recovery validation. It is not part of the bundled installation.

The canonical application version is `backend/src/firewall_manager/version.py`. Python package
metadata and the API derive their version from it. `/api/v1/health/live` also exposes a build SHA;
pass `--build-arg APP_GIT_SHA=$(git rev-parse --short HEAD)` when building the backend to populate it.

## Deployment authorization and change windows

Read the [deployment safety contract](deployment-safety.md) before enabling provider writes.
FPM cannot exclude direct provider edits before or after its final preflight; those edits can be
included in the same native device deployment. Prevent concurrent direct edits when your
organization requires strict isolation.
A durable intent authorizes one request; revocations after its commit cannot recall that request.
Preserve database intent evidence during recovery and inspect reconciliation-required jobs before
planning further changes.
