# Health and monitoring

The production deployment exposes liveness, readiness, and Prometheus metrics through the controlled API boundary. The repository includes alert rules, a Grafana dashboard, and provisioning for the optional monitoring profile.

## What to alert on

- API readiness failure or elevated 5xx/error rate;
- worker or scheduler heartbeat expiry;
- queued work that remains unclaimed or grows unexpectedly;
- failed, partial, ambiguous, or reconciliation-required ChangeSets and deployments;
- provider connection failure or incomplete synchronization;
- new drift and missing managed resources;
- PostgreSQL, Redis, filesystem, certificate, and backup health;
- repeated authentication failure or privileged administrative activity.

Start the optional stack with `./scripts/production.sh monitoring-start`. Prometheus remains on the internal monitoring network. Grafana's administrative binding is loopback-only by default; expose it through an approved authenticated ingress if remote access is required.

Application logs carry correlation identifiers and structured failure codes. They must not contain credentials, tokens, OIDC claims beyond safe identifiers, or raw provider payloads. Preserve enough retention to connect user intent, worker execution, provider response, and deployment result.
