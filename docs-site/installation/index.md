# Install Firewall Policy Manager

Use `./scripts/production.sh setup` for the supported single-host installation. The script creates
protected configuration and secrets, builds the images, migrates the database, starts services,
and validates HTTPS.

## Prepare the host

Use Linux with Docker Engine, Compose v2, Git, `curl`, and root or `sudo` access. Choose a stable
hostname that resolves to the server and allow inbound TCP 443. Plan for 4 CPU cores, 8 GiB RAM,
and 50 GiB persistent disk for a small production deployment. A 1 GiB host can run out of memory
during the frontend build.

See [host and network prerequisites](./production#host-and-network-prerequisites) before starting.

## Run setup

Replace `<release-tag-or-commit>` with a reviewed release tag or commit:

```sh
git clone https://github.com/PubSec-Security-DevNet/firewall-policy-manager.git
cd firewall-policy-manager
git checkout --detach '<release-tag-or-commit>'
./scripts/production.sh setup
```

Enter the exact browser hostname when prompted, without `https://` or a path. Setup creates
runtime files automatically; you do not need to generate passwords or run Compose manually.

Wait for `Production validation passed` and the final instruction to open the HTTPS URL. Setup
then returns to the prompt. A completed image build is only part of setup. If it fails, correct
the reported problem and rerun it; existing configuration, secrets, and data are preserved.

## Complete browser setup

Open the configured HTTPS URL. The generated self-signed certificate requires client trust;
[install a trusted certificate](./tls) before broad user access. Complete the one-time OIDC setup
to create the organization and first Platform Admin. There is no default production password.

Connect [FMC](../providers/fmc) or [SCC](../providers/scc) with writes disabled. Complete provider
synchronization, authorization, approvals, [backups](../operations/backup-restore), and
[monitoring](../operations/monitoring) before enabling provider writes.

## Manage the installation

Run these commands from the repository directory:

```sh
./scripts/production.sh status
./scripts/production.sh logs backend worker scheduler edge
./scripts/production.sh help
```

`logs` follows output until Ctrl+C; it does not stop services. Continue with the
[setup and command reference](./production), [troubleshooting](./production#installation-troubleshooting),
and [final security checklist](./production#final-security-checklist).
