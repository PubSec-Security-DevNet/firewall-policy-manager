# Runtime secrets

`./scripts/production.sh setup` generates the PostgreSQL, Redis, Grafana, and application encryption
secrets automatically. No separate secrets service or manual password-generation step is required.
Rerunning setup preserves existing values.

The default secret directory is `/opt/firewall-manager/runtime/secrets/`. Files are root-owned,
restricted to the required container group, and mounted read-only into the services that need them.
The non-secret settings file is separate; edit it with `./scripts/production.sh config`.

## Protect recovery material

- Escrow the stable application encryption key separately from database backups. Both are needed
  to recover encrypted OIDC, provider, and SMTP credentials.
- Protect PostgreSQL, Redis, and optional Grafana credentials under your credential-custody policy.
- Keep TLS private keys under your certificate-management policy.
- Never put secret contents in Git, images, logs, screenshots, shell transcripts, or issues.

Configure OIDC during browser setup and provider/SMTP credentials in the administrator UI. These
credentials are encrypted in PostgreSQL using the file-mounted application key.

Changing the application key file alone makes existing encrypted records unreadable. Key rotation
requires a planned migration and recovery procedure; it is not part of routine installation.
See [backups and restore](../operations/backup-restore) for recovery requirements.
