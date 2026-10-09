# Firewall Policy Manager

Firewall Policy Manager is a delegated control plane for Cisco Secure Firewall Management Center
(FMC) and Security Cloud Control (SCC). It provides OIDC authentication, scoped administration,
inventory synchronization, approval-backed ChangeSets, provider deployment controls, audit
evidence, and reconciliation workflows.

[![Quality gate](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/actions/workflows/quality.yml)
[![Documentation](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/actions/workflows/docs-pages.yml/badge.svg?branch=main)](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/actions/workflows/docs-pages.yml)
[![License](https://img.shields.io/github/license/PubSec-Security-DevNet/firewall-policy-manager)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/PubSec-Security-DevNet/firewall-policy-manager?sort=semver)](https://github.com/PubSec-Security-DevNet/firewall-policy-manager/releases)

## Why Firewall Policy Manager

Many organizations need application teams, business units, or regional operators to manage their
own firewall rules while continuing to share centrally operated FMC or SCC infrastructure. Separate
firewall or management instances can provide strong isolation, but they may not be supported by the
deployed platform, fit the network topology, or be operationally and economically practical. The
usual alternatives—routing every change through a central ticket queue or granting broad provider
access—either slow delivery or weaken administrative boundaries.

Firewall Policy Manager provides a governed middle path. Central teams retain ownership of the
shared infrastructure and define each Group's policy, rule category, objects, zones, address ranges,
approval requirements, and deployment authority. Delegated teams can then perform authorized rule
and object work inside those boundaries, with validation, audit, synchronization, and reconciliation
applied consistently.

This delegated model complements rather than replaces separate instances. Where regulatory,
failure-domain, or network-isolation requirements demand a hard infrastructure boundary, use the
appropriate provider and platform isolation controls.

## Production deployment

**For every real installation, use the production container stack.** It runs the reverse proxy,
production frontend, API, worker, singleton scheduler, PostgreSQL, authenticated Redis, and optional
Prometheus/Grafana entirely in containers. The host needs Docker Engine, Docker Compose, Git, DNS,
and network access—not Python, Node.js, PostgreSQL, Redis, or a web server. A trusted certificate is
recommended; the stack creates a self-signed certificate when no PEM pair is supplied.

The canonical command is:

```sh
docker compose --env-file /opt/firewall-manager/runtime/.env.production \
  -f compose.production.yaml up -d
```

For a guided installation and day-two commands, use the optional production helper:

```sh
./scripts/production.sh setup
./scripts/production.sh status
./scripts/production.sh stop
./scripts/production.sh start
./scripts/production.sh cert-refresh
```

It prompts for the public hostname and operator email, creates protected configuration and secret
files, builds images, migrates the database, starts the stack, and validates HTTPS. It never has a
command that deletes production volumes or secret files. `cert-refresh` safely replaces only a
self-signed certificate; use `cert-reload` after installing a renewed CA-issued PEM pair. The
production guide includes a table explaining the effect and persistence behavior of every command.

Use the helper, or complete the guide's configuration, secret, TLS, and migration sequence before
treating the raw Compose command as a production start. Complete OIDC setup in the browser after
the services are healthy. Use the copy/paste production sequence in the
[full production installation guide](docs/production-installation.md).

Production quick start:

1. Provision Linux with Docker Engine, the Compose plugin, Git, DNS, and TCP 443.
2. Check out an immutable release and create protected runtime, certificate, secret, and backup
   directories outside the repository.
3. Copy [.env.production.example](.env.production.example), generate the PostgreSQL, Redis,
   Grafana, and protected application-key secret files, and optionally install a trusted HTTPS
   certificate.
4. Build the application images and start PostgreSQL and Redis.
5. Run the containerized Alembic migration and start the API, worker, singleton scheduler,
   production frontend, and Caddy edge.
6. Use the one-time setup screen to test OIDC and create the first organization, provider, and
   Platform Admin; the client secret is stored through the encrypted application SecretStore.
7. Onboard FMC/SCC read-only, validate sync and capabilities, then configure authorization,
   approvals, backups, monitoring, and write gates.
8. Complete the guide's health, HTTPS, persistence, restart, restore, and security checks.

The production stack publishes only TCP 80/443. Grafana is optional and binds to host loopback;
PostgreSQL, Redis, Prometheus, API, worker, and scheduler have no public host bindings.

> `compose.yaml` is not a production shortcut. It deliberately enables mock FMC/SCC providers,
> development authentication, fixture users/data, Vite, source mounts, and API reload mode.

## Development setup — not for production

Requirements: Docker Engine with Compose v2, `curl`, and `make`.

```sh
cp .env.example .env
make up
make smoke
```

Open <http://localhost:5173>. The header identity selector, mock providers, local-only passwords,
seeded organizations, hot reload, and source bind mounts exist solely for development and tests.
See [docs/development.md](docs/development.md) for the service layout and common commands.

## Documentation

- [Production installation and operations](docs/production-installation.md)
- [Development environment](docs/development.md)
- [Authentication and OIDC](docs/AUTHENTICATION.md)
- [Monitoring](docs/MONITORING.md)
- [Ingress security](docs/INGRESS_SECURITY.md)
- [Delegated policy model](docs/product/DELEGATED_POLICY_MANAGEMENT.md)
- [SBOM workflow](docs/SBOM.md)
- [Production release checklist](docs/PRODUCTION_RELEASE_CHECKLIST.md)

## Security

Provider and application credentials are write-only encrypted records in PostgreSQL. The canonical
deployment mounts the AES-256-GCM master key read-only from a protected host file into only the
application containers that require it. Real provider connections begin disabled and read-only.
TLS verification cannot be disabled; FMC private trust is supplied as an explicit CA bundle.

Do not report secrets, `docker compose config` output from a secret-bearing customization,
application keys, private keys, database dumps, or provider payloads in an issue.

## Contributing

Run `make license-check`, `make test`, `make architecture`, `make security-check`, and
`git diff --check` for application changes. Production packaging changes must also render
`compose.production.yaml`, build both application images, and complete the production smoke and
persistence procedure in the production guide.

## License

Copyright 2026 Cisco Systems, Inc.

Firewall Policy Manager is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE) for details.
