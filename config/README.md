# Machine-Readable Governance Data

These files are validated governance inputs consumed by code and tests. The capability file uses
JSON syntax, which is valid YAML 1.2, so the standard library can parse it without another runtime
parser dependency.

## provider-capabilities.yaml

The capability status drives the deterministic mocks and is validated by contract/config tests:
- provider contract tests;
- compatibility documentation;
- feature availability.

Every capability has separate `mock` and `real` FMC/SCC evidence. `SUPPORTED` must not be set
without successful provider-contract and application-path tests. Mock evidence can never promote
the real-provider profile; synchronization rejects a manager/evidence-profile mismatch.

Configured real connections begin from the `real` `NOT_STARTED` baseline. A successful connection
test may persist `TESTED` read-only evidence only for that connection and discovered provider
version. This runtime evidence does not rewrite this repository-wide capability document and never
promotes any real mutation capability.

The validated vocabulary includes category and security-zone reads, rule ordering, category
mutation, and class-specific object creation/mutation capabilities for network, port-service, URL,
and application objects. A `NOT_STARTED` or `PARTIAL` mutation capability remains unavailable to
delegated execution; only `SUPPORTED` enables the operation. Category ensure and network,
port-service, and URL mutation are `SUPPORTED` only for the deterministic mock profiles. All real
write declarations and mock application-object mutation remain `NOT_STARTED`.

## permissions.yaml

Defines canonical action terminology/invariants.

The runtime authorization implementation may use database IDs/models, but it should map to a
stable canonical vocabulary instead of inventing synonyms per feature.
`manage_providers` is a separate platform-administration boundary; Group Admin and Firewall Admin
do not inherit it.

## Provider connection secrets

`APP_SECRET_KEY` is a base64-encoded 32-byte master key for the current encrypted-database
SecretStore. It is intentionally absent from these files and may be empty only when no real
connections are created in local development. `SECRET_STORE_KEY_VERSION` is stored with each
ciphertext to support controlled rotation/migration. Production must supply key material through a
secret manager or equivalent runtime injection, independently of PostgreSQL and source control.

## Drift prevention

Once code generation/rendering is installed, CI should verify machine-readable governance data
and rendered Markdown/API documentation remain consistent.
