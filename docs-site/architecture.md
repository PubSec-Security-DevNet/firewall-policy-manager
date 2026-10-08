# Architecture

Firewall Policy Manager is an API-centered control plane. Browser, REST automation, background workers, and scheduler paths converge on shared application services; only provider adapters communicate with FMC or SCC.

## Runtime topology

<div class="architecture-map">
  <div class="architecture-column"><div class="architecture-node"><strong>Browser</strong><span>React application</span></div><div class="architecture-node"><strong>REST / API tokens</strong><span>Scoped automation</span></div><div class="architecture-node"><strong>OIDC</strong><span>Entra · Duo · Generic</span></div></div>
  <div class="architecture-column architecture-column--core"><div class="architecture-label">CONTROL PLANE</div><div class="architecture-node"><strong>FastAPI + application services</strong><span>Authorization, ChangeSets, inventory, deployment</span></div><div class="architecture-node"><strong>PostgreSQL</strong><span>Durable state, revisions, audit, leases</span></div><div class="architecture-node"><strong>Redis + workers + scheduler</strong><span>Queued provider work and recovery</span></div></div>
  <div class="architecture-column"><div class="architecture-node"><strong>Provider adapters</strong><span>Normalized typed contract</span></div><div class="architecture-node"><strong>Cisco FMC</strong><span>Verified TLS + REST auth</span></div><div class="architecture-node"><strong>Cisco SCC</strong><span>Region + API token</span></div></div>
</div>

The default production deployment supplies the application's master encryption key through a Docker secret. Custom deployments can use HashiCorp Vault KV v2 instead. The application also supports SMTP delivery for ChangeSet approval notifications and optional Prometheus/Grafana monitoring.

## Write path

```text
Browser / REST
  → application service authorization
  → durable ChangeSet and ordered operations
  → validation + approval boundary
  → queued worker claim and execution-time reauthorization
  → provider adapter transaction
  → pending configuration / deployment plan
  → provider task polling and per-device result
  → synchronization and reconciliation evidence
```

The frontend never calls providers. Provider credentials are decrypted only inside trusted server processes. Ambiguous mutation timeouts reconcile before retry, and stale provider state conflicts rather than being overwritten.

## Read and synchronization path

Provider connections discover paginated inventory through typed adapters. A complete run updates resources, fingerprints, revisions, capability/version evidence, and missing-resource state. An incomplete run records its failure but does not classify unseen resources as missing.

Observed provider state is separate from application ownership. Names and categories do not silently grant ownership. Discrepancies become durable operator decisions.

## Production boundary

Caddy is the only public container and routes HTTPS to the static frontend and API. PostgreSQL, Redis, Prometheus, API, worker, and scheduler have no public host binding. Internal data and monitoring networks are isolated; application processes use a separate egress path for OIDC, SMTP, FMC, and SCC.

The scheduler holds a PostgreSQL advisory lock. Workers use durable leases and heartbeats. Expired uncertain work becomes reconciliation-required instead of being duplicated.

See the [security model](./security/) and [production installation](./installation/production) for boundary details.
