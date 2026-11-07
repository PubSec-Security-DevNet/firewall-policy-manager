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

## Installation

Use the production setup script for every real installation. It runs the frontend, API, worker,
scheduler, PostgreSQL, Redis, and HTTPS proxy in containers. Prepare a Linux host with Docker
Engine, Compose v2, Git, `curl`, a stable hostname, and inbound HTTPS access. Plan for 4 CPU cores,
8 GiB RAM, and 50 GiB persistent disk for a small production deployment; a 1 GiB host is too small
for the frontend build.

```sh
git clone https://github.com/PubSec-Security-DevNet/firewall-policy-manager.git
cd firewall-policy-manager
git checkout --detach '<release-tag-or-commit>'
./scripts/production.sh setup
```

Replace the checkout placeholder with a reviewed release tag or commit. Setup prompts for the
public hostname and optional operator email, creates protected configuration and secrets, builds
images, migrates the database, starts services, and validates HTTPS. It preserves existing data
and configuration when rerun. When setup returns successfully, open the printed HTTPS URL to
complete OIDC and create the first Platform Admin. There is no default production password.

Setup creates a self-signed certificate if no certificate pair exists. Clients must trust it;
install a CA-issued certificate before broad user access. See the
[installation guide](docs/production-installation.md) for prerequisites, certificate management,
setup troubleshooting, and the script command reference.

For routine operations, run from the repository directory:

```sh
./scripts/production.sh status
./scripts/production.sh stop
./scripts/production.sh start
./scripts/production.sh backup
./scripts/production.sh help
```

The script manages the production Compose configuration. The separate development environment
below is for contributors and tests.

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
