# Vault and secrets

Production secrets must not appear in Git, container images, Compose output pasted into issues, logs, or shell history. The application supports protected deployment injection and HashiCorp Vault KV v2 through the same secret-provider boundary.

## What requires custody

- the application secret key used for sessions and encrypted application records;
- PostgreSQL and Redis credentials;
- the optional Grafana administrator credential;
- OIDC client secrets;
- FMC credentials and SCC API tokens;
- public and private-CA private key material.

The application key must remain stable across API, worker, and scheduler containers. Escrow it separately from PostgreSQL backups: a database dump without the key cannot decrypt stored provider or OIDC credentials.

## Validate and rotate

Use the packaged secret check to prove that configured references can be resolved and encrypted records can be decrypted without printing values. Rotation is a transactional operator procedure: take a verified backup, retain the old key for the recovery window, rotate, validate every service, and only then retire the old material.

For Vault, use a narrowly scoped workload identity and policy granting only required KV v2 paths. Protect Vault's own TLS identity and availability; readiness should fail visibly when required secrets cannot be resolved.

See the [full production guide](./production#production-configuration-and-runtime-secrets) for exact file ownership and commands.
