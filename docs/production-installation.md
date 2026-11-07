# Production installation and operations

Install Firewall Policy Manager with `./scripts/production.sh setup`. This is the single
installation workflow for the supported Linux host deployment. The script creates protected
configuration and secrets, builds the images, runs database migrations, starts the services,
and validates HTTPS. You do not need to run Compose commands or generate secrets manually.

Caddy, the production frontend, API, worker, scheduler, PostgreSQL, Redis, and optional monitoring
run in containers. Python, Node.js, database clients, and a web server are not required on the host.
The development environment is for contributors and tests only.

## Host and network prerequisites

Prepare the host before running setup:

- A supported 64-bit Linux distribution with Docker Engine and the Compose v2 plugin installed
  using the [Docker installation guide](https://docs.docker.com/engine/install/).
- Git, Bash, `curl`, standard Linux utilities, Docker daemon access, and root or `sudo` access
  to create protected host files. Treat Docker administration as root-equivalent access.
- A stable hostname such as `firewall.example.com`, resolving to this server from both the host
  and client browsers. Use a persistent public IP/DNS arrangement for cloud deployments.
- Inbound TCP 443 for HTTPS and optionally TCP 80 for redirects. Keep database, queue, and
  application container ports private.
- Outbound access for image/package downloads, OIDC, FMC/SCC, and your SMTP service, plus
  working DNS and time synchronization.
- An OIDC confidential client in Entra ID, Duo SSO, or a compatible provider, and an approved
  destination for encrypted off-host backups.

For a small production installation, plan for **4 CPU cores, 8 GiB RAM, and 50 GiB of fast
persistent disk**, plus backup capacity. These are planning figures, not a capacity guarantee.
The frontend build has exhausted a 1 GiB host with no swap; use at least 4 GiB RAM for build
headroom. Monitor actual usage and allow additional capacity for inventories, audit retention,
backups, and optional monitoring.

Check the host:

```sh
docker version
docker compose version
git --version
curl --version
free -h
df -h
```

## Check out the release and run setup

Clone the repository into your chosen code directory and select a reviewed release tag or commit.
Replace `<release-tag-or-commit>` before running the checkout command:

```sh
git clone https://github.com/PubSec-Security-DevNet/firewall-policy-manager.git
cd firewall-policy-manager
git checkout --detach '<release-tag-or-commit>'
./scripts/production.sh setup
```

Run subsequent script commands from this repository directory. When prompted, enter:

1. **Public hostname:** the exact hostname you will open in the browser, without `https://`,
   a port, or a path.
2. **Operator contact email:** optional contact information; it does not create an administrator.

Setup creates the runtime and backup directories automatically. It generates PostgreSQL, Redis,
Grafana, and application encryption secrets without printing their values. When no certificate
pair exists, it also creates a self-signed certificate for the configured hostname.

The image build is followed by database startup, migrations, application startup, health checks,
and HTTPS validation. **Build completion is not setup completion.** A successful run prints:

```text
Production validation passed: https://your-configured-hostname
Open the configured HTTPS URL to complete the one-time OIDC setup.
```

Setup then returns to the shell prompt. If it fails, correct the reported issue and rerun `setup`.
Existing configuration, secrets, certificates, and database volumes are preserved. If setup is
already running, use a second terminal for `status` rather than starting another setup process.

For unattended setup, provide the same non-secret answers:

```sh
FM_PUBLIC_HOST=firewall.example.com \
FM_ADMIN_EMAIL=firewall-operations@example.com \
./scripts/production.sh setup
```

These variables initialize a new configuration; they do not overwrite an existing one.

## HTTPS and configuration

Open the exact URL printed by setup. A generated self-signed certificate requires explicit client
trust. Install a certificate issued by your organization's CA or a public CA before broad user
access. Browser certificate trust is separate from FMC/SCC provider trust.

Default locations created by setup:

| Location                                        | Contents                                                          |
| ----------------------------------------------- | ----------------------------------------------------------------- |
| `/opt/firewall-manager/runtime/.env.production` | Non-secret application settings and public hostname               |
| `/opt/firewall-manager/runtime/secrets/`        | Protected service passwords and stable application encryption key |
| `/opt/firewall-manager/runtime/tls/`            | `fullchain.pem` and matching `privkey.pem`                        |
| `/opt/firewall-manager/backups/`                | Local database backup staging directory                           |

If you use `FM_RUNTIME_DIR` or `FM_BACKUP_DIR`, supply the same values on subsequent script calls.
Keep these paths outside the repository. Back up the application key separately from the database;
losing it makes stored OIDC, provider, and SMTP credentials unrecoverable.

Edit non-secret settings with:

```sh
./scripts/production.sh config
./scripts/production.sh start
./scripts/production.sh validate
```

`start` applies environment changes by recreating affected services. Routine setup does not
regenerate existing secrets or certificates. Do not change the application key as a configuration edit.

### Install or renew a trusted certificate

After setup has created the runtime directories, install your matching PEM files and reload HTTPS:

```sh
sudo install -o root -g root -m 0644 /secure/source/fullchain.pem \
  /opt/firewall-manager/runtime/tls/fullchain.pem
sudo install -o root -g root -m 0600 /secure/source/privkey.pem \
  /opt/firewall-manager/runtime/tls/privkey.pem
./scripts/production.sh cert-reload
```

The full chain must include the server certificate and required intermediates. The unencrypted
private key must match, and the certificate SAN must cover `APP_PUBLIC_HOST`. Coordinate replacement
of both files so no proxy restart occurs between them. A partial pair fails initialization.

To renew the setup-generated self-signed pair instead:

```sh
./scripts/production.sh cert-refresh
```

This command refuses to replace a CA-issued certificate. Clients must trust the new self-signed
certificate. Neither certificate command rebuilds the application images.

### If the public hostname changes

Rerunning setup keeps the old hostname and certificate. Use `config` to update both `APP_PUBLIC_HOST`
and `APP_PUBLIC_URL`. For a setup-generated self-signed certificate, then run:

```sh
./scripts/production.sh cert-refresh
./scripts/production.sh start
./scripts/production.sh validate
```

For a CA-issued certificate, install a replacement covering the new hostname and use `cert-reload`
in place of `cert-refresh`. Update the OIDC client's registered callback URLs to the new hostname.

## Complete first-time OIDC setup

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

## Connect FMC or SCC

### FMC onboarding

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

### SCC onboarding

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

### Before enabling provider writes

Configure SMTP through the administrator UI if notifications are required. SMTP credentials are
encrypted with the application key; in-app approval queues remain available if delivery fails.

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

## Routine operations

All commands below use `./scripts/production.sh COMMAND` from the repository directory.

| Command              | Purpose and effect                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `setup`              | First-time configuration: create protected files, build, migrate, start, and validate. Existing configuration and secrets are preserved.                                             |
| `start`              | Start or recreate the core stack and wait for health checks. Data and secrets remain unchanged.                                                                                      |
| `stop`               | Stop containers so they can be restarted later. Containers, volumes, data, and secrets remain.                                                                                       |
| `restart`            | Stop and start the core stack, then wait for health checks. Expect a short outage.                                                                                                   |
| `down`               | Remove production containers and networks. Named data volumes, backups, certificates, and secret files remain.                                                                       |
| `status`             | Show all production containers, including stopped containers and health state.                                                                                                       |
| `logs [SERVICE ...]` | Follow the latest 200 log lines for everything or selected services; press Ctrl-C to exit.                                                                                           |
| `migrate`            | Stop the API, worker and scheduler, apply pending migrations, and print the revision. Services stay stopped; review the upgrade result before `start`.                               |
| `backup`             | Create a timestamped PostgreSQL dump and verify that PostgreSQL can read it. It does not copy the dump off-host.                                                                     |
| `cert-refresh`       | Generate a new 365-day self-signed certificate, restart the edge proxy, and validate HTTPS. It refuses to overwrite a CA-issued certificate. Clients must trust the new certificate. |
| `cert-reload`        | Validate and reload the edge proxy after an administrator or PKI tool installs a renewed trusted PEM pair. No image rebuild is performed.                                            |
| `monitoring-start`   | Start the optional Prometheus and Grafana services and wait for health checks.                                                                                                       |
| `monitoring-stop`    | Stop Prometheus and Grafana while preserving their data.                                                                                                                             |
| `validate`           | Render-check Compose, show service state, and test the HTTPS API readiness endpoint.                                                                                                 |
| `config`             | Open the non-secret production environment file in `$EDITOR` (default `vi`). Run `start` to apply environment changes.                                                               |
| `help`               | Print the command list and unattended-setup environment variables.                                                                                                                   |

`logs` intentionally follows output until you press Ctrl+C; this exits log viewing without stopping
services. `setup`, `start`, and `validate` should complete and return to the prompt.

Start optional monitoring and inspect service health with:

```sh
./scripts/production.sh monitoring-start
./scripts/production.sh status
./scripts/production.sh validate
./scripts/production.sh logs backend worker scheduler edge
```

Prometheus remains private. Grafana binds to host loopback; use an approved SSH tunnel or
administrative ingress. Keep alerts, finite log retention, and off-host backups operational.

## Backups and recovery

```sh
./scripts/production.sh backup
```

This creates a timestamped PostgreSQL dump and checks that PostgreSQL can read it. Copy the dump to
encrypted off-host storage and retain the matching application key separately. Archive verification
does not replace an isolated restore test. A database restore does not roll back firewall state.

The script has no restore or volume-deletion command. Restore requires an explicit maintenance plan
and provider reconciliation; follow the
[backup and recovery runbook](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/blob/main/docs/backup-restore.md).

## Upgrade and rollback

Use a maintenance window. Pause provider schedules/writes and reconcile active operations. Review
release-specific migration and recovery instructions, take a backup, and confirm key custody.
Then stop services before switching to the reviewed release and rerun setup:

```sh
./scripts/production.sh backup
./scripts/production.sh stop
git fetch --tags
git checkout --detach '<new-release-tag-or-commit>'
./scripts/production.sh setup
```

Setup rebuilds the images, starts the database and queue, migrates, starts the application, and
validates HTTPS while retaining configuration and data. If it fails, resolve the error before
resuming service. Verify login, provider reads, full synchronization, worker/scheduler health,
and monitoring before reopening write gates. If monitoring was enabled, run `monitoring-start`
after setup to bring that optional stack up as well.

An older application image does not reverse database migrations or firewall changes. Use the
release-specific recovery procedure; prefer a forward fix unless a tested rollback is documented.

## Restart and persistence verification

During commissioning, test `restart` and a planned host reboot. Verify that Users, provider records,
worker/scheduler heartbeats, and queued work survive. Reconcile provider state before resuming writes.
Docker must start at boot; services use `restart: unless-stopped`. Services explicitly stopped with
`stop` require `start` to resume.

## Installation troubleshooting

| Symptom                                              | Check and next action                                                                                                                                                                 |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `./scripts/production.sh: No such file or directory` | Change into the cloned `firewall-policy-manager` directory.                                                                                                                           |
| Build stalls at `tsc -b` or exits unexpectedly       | Check `free -h` and kernel OOM logs. Increase host memory if the kernel killed build processes, then rerun setup.                                                                     |
| Images finish building but setup has not returned    | Run `status` in another terminal and inspect `logs backend worker scheduler edge tls-init`. Setup still has migrations, health checks, and HTTPS validation to complete.              |
| Services are healthy but setup/validate waits        | Check configured hostname, DNS, routing, and TCP 443 from the host. The current final HTTPS check has no explicit timeout.                                                            |
| Browser reports `ERR_SSL_PROTOCOL_ERROR`             | Compare the browser hostname with `APP_PUBLIC_HOST`, `APP_PUBLIC_URL`, and the certificate SAN; inspect `logs edge tls-init`. Use the hostname-change procedure above if they differ. |
| Browser reports an untrusted certificate             | Trust the generated certificate through your approved process or install a CA-issued pair; do not disable certificate verification.                                                   |
| Logs never return to the prompt                      | `logs` follows output by design. Press Ctrl+C to stop viewing.                                                                                                                        |

Setup retains the original hostname and certificate even if the server's public address changes.
Prefer a stable hostname and IP arrangement to avoid repeated certificate and OIDC callback changes.

## Final security checklist

- [ ] `scripts/production.sh setup` completed successfully; development Compose, mocks, fixtures, and dev auth are absent
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

## Deployment authorization and change windows

Read the [deployment safety contract](deployment-safety.md) before enabling provider writes.
FPM cannot exclude direct provider edits before or after its final preflight; those edits can be
included in the same native device deployment. Prevent concurrent direct edits when your
organization requires strict isolation.
A durable intent authorizes one request; revocations after its commit cannot recall that request.
Preserve database intent evidence during recovery and inspect reconciliation-required jobs before
planning further changes.
