# Security model

Firewall Policy Manager treats delegation as a security boundary, not a UI convenience. Authentication establishes identity. The application then resolves one explicit Active Group, one Access Policy, and the exact grants needed for each resource and action. Enforcement happens server-side on every read and mutation path.

## Boundary at a glance

<div class="architecture-map">
  <div class="architecture-column"><div class="architecture-node"><strong>OIDC identity</strong><span>Issuer + subject</span></div><div class="architecture-node"><strong>Scoped API token</strong><span>Hash-only, expiring, revocable</span></div></div>
  <div class="architecture-column architecture-column--core"><div class="architecture-label">FIREWALL POLICY MANAGER</div><div class="architecture-node"><strong>Active Group authorization</strong><span>Membership + policy delegation + explicit resource grants</span></div><div class="architecture-node"><strong>ChangeSet boundary</strong><span>Validate, approve, reauthorize, execute, audit</span></div><div class="architecture-node"><strong>Revision and drift checks</strong><span>Conflict rather than silently overwrite</span></div></div>
  <div class="architecture-column"><div class="architecture-node"><strong>FMC</strong><span>Verified TLS + least privilege</span></div><div class="architecture-node"><strong>SCC</strong><span>Controlled region + API token</span></div></div>
</div>

## Core controls

| Control | What it means in practice |
| --- | --- |
| Default deny | Missing membership, delegation, grant, capability evidence, or current revision closes the operation. |
| Server-side authorization | Browser affordances improve usability; they never provide authority. REST, workers, and scheduled execution reuse application services. |
| No permission union | Only the Active Group contributes rights. Other Group memberships add nothing to the current request. |
| ChangeSet-only provider writes | The browser never calls Cisco providers directly. Mutations are durable, reviewable, and reauthorized before execution. |
| Stale-state protection | Expected revisions and synchronized provider fingerprints prevent silent overwrites. |
| Deployment separation | A successful configuration write is not reported as a successful firewall deployment. |
| Auditable privilege | Administrative, approval, provider, deployment, token, and reconciliation activity produces audit evidence. |

## Platform protections

- Microsoft Entra ID, Cisco Duo SSO, and standards-compliant Generic OIDC use server-side Authorization Code flows.
- Opaque sessions are bounded, revocable, `HttpOnly`, `Secure` in production, and protected by CSRF controls.
- API tokens are shown once, stored as hashes, scoped, expiring, and evaluated as their target User.
- Provider TLS verification stays enabled. Private CAs extend trust without disabling certificate-chain or hostname verification.
- Provider and OIDC secrets are encrypted at rest; production can use deployment-injected keys or HashiCorp Vault KV v2.
- Rate limiting, secure response headers, disabled production API docs, readiness checks, metrics, and audit retention support operations.

Continue with [Active Group authorization](./authorization), [authentication](./authentication), or the [production security checklist](../installation/production#final-security-checklist).
