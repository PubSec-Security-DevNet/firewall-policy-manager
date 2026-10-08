# Security reporting

Report suspected vulnerabilities privately to the repository maintainers using their published
private contact channel. If GitHub private vulnerability reporting is enabled for this repository,
use **Security → Report a vulnerability**. Do not post credentials, tenant data, or exploit details
in public issues. Include the affected version, reproduction steps using sanitized fixtures,
expected authorization boundary, and observed impact.

This repository currently targets `1.0.0-rc1`, a prerelease candidate. It is not a claim of production
readiness. Deployment uses provider-specific preflight and durable dispatch intents;
see [deployment safety](docs/deployment-safety.md) for guarantees and provider boundary limitations. Follow the
[production installation guide](docs/production-installation.md) for Docker secrets, TLS, backups,
and upgrade procedures, and [legacy ownership review](docs/legacy-ownership.md) when upgrading.

Never include runtime secrets, browser sessions, private keys, or provider credentials in a report
attachment. Rotate exposed credentials through the documented operational procedure.
