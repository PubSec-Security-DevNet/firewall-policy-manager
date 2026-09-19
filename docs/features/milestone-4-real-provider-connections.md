# Milestone 4 — Real Provider Connections

## Outcome

Milestone 4 adds unlimited, persistent FMC and SCC connections while retaining a hard
configuration-read-only boundary for every real provider. Each connection owns an application UUID,
encrypted credential reference, safe routing/TLS configuration, provider manager namespace,
version-specific capability evidence, scopes, health, schedule, revision, and audit history.

Mock managers remain independent and retain their Milestone 3 write evidence. Mock evidence cannot
promote a real manager, and a provider credential with write privileges cannot make a real adapter
writable.

## Administrative lifecycle

Only an active platform `admin` may list or change connections. `firewall_admin`, `group_admin`, and
delegated roles are denied through the same current-user authorization service. Connections are
created `DISABLED` and `NEVER_TESTED`; connection testing runs authentication, identity/version,
domain/tenant, device, policy, category, rule, object, and zone reads through the runtime adapter.
Only a `CONNECTED` connection may become `ACTIVE`. Credential or routing/TLS changes disable the
connection and require retesting. Retirement is irreversible through the current API and preserves
historical records.

Manual sync writes a durable queue state before dispatch. A single scheduler actor claims bounded
due batches; stale work for a disabled/retired connection exits without restarting it. The existing
provider-independent synchronization service preserves observed ownership, pagination completeness,
drift, provider IDs/fingerprints/revisions, and connection-specific manager namespaces.

## Provider behavior

FMC endpoints must be HTTPS origins without embedded credentials, paths, queries, or fragments.
Known metadata, loopback, link-local, multicast, reserved, and unspecified targets are rejected,
while legitimate RFC1918 FMC addresses are permitted. DNS is validated before authentication.
System TLS verification or an explicit PEM CA bundle is mandatory; redirects are not followed.
FMC source credentials obtain short-lived `X-auth` tokens, kept only in adapter memory, with one
bounded re-authentication attempt on a rejected read token.

SCC endpoints are constructed only from Cisco's supported US, EU, APJ, AU, IN, UAE, FedRAMP, and
IL5 region map. An API-only bearer token discovers token/tenant information, then the normalized
cdFMC read surface. Both providers use bounded timeouts, pagination, retries, and rate-limit
handling. The transport permits GET plus the one FMC authentication POST; normalized real adapters
expose no configuration-mutation operation.

## Restricted secrets

The `SecretStore` port separates connection state from secret storage. The local/container adapter
uses AES-256-GCM with a random 96-bit nonce and associated data containing organization ID, secret
UUID, immutable purpose, and key version. The root key remains outside PostgreSQL. REST responses
expose only credential type/presence, non-secret FMC username, and update time. Rotation is
write-only and audit records contain only action metadata. Structured-log redaction covers common
password, token, API-key, and authorization fields.

The current encrypted-database adapter is replaceable by an external KMS/Vault implementation.
Production requires `APP_SECRET_KEY` from a secret-management mechanism. Database contents and the
master key must be protected independently.

## Evidence and test boundary

Successful live reads create evidence rows keyed by connection, actual provider version, and
capability. Only exercised reads become `READ_ONLY`/`TESTED`; real mutations remain `NOT_STARTED`.
Fixture tests validate parsing/error/safety behavior but do not constitute live Cisco compatibility
evidence.

Live probes are explicitly gated by `RUN_REAL_FMC_TESTS` / `RUN_REAL_SCC_TESTS` plus
`REAL_PROVIDER_NON_PRODUCTION_ACK=non-production-read-only`. They issue read-only discovery calls
and must never target production. No create/delete test is allowed against a real provider.

## Development identities

The development-only `/api/v1/dev/users` catalog and header selector switch among deterministic
seeded users per browser session. Each request resolves the selected database User; there is no
authorization bypass. A full navigation on change clears active Group and React/query state.
Startup rejects development authentication in staging/production, and the catalog route is not
registered when the adapter is disabled.

## Authoritative Cisco references

- [Secure Firewall Management Center REST API Quick Start Guide 7.6](https://www.cisco.com/c/en/us/td/docs/security/firepower/760/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_760.html)
- [Secure Firewall Management Center REST API Quick Start Guide 7.7](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770.html)
- [SCC Firewall Manager API authentication and roles (API 1.20.0)](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/authentication/)
- [SCC Firewall Manager API regions and endpoints](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/getting-started/)

Exact FMC RBAC labels that are not stable/verified in these sources are intentionally not invented;
administrators are directed to the target-version API Explorer and the connection test identifies
the specific failed read capability.
