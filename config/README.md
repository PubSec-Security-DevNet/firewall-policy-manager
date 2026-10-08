# Machine-Readable Governance Data

The capability file is a validated governance input consumed by code and tests. It uses JSON
syntax, which is valid YAML 1.2, so the standard library can parse it without another runtime parser
dependency.

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

The validated vocabulary includes category and security-zone reads, rule ordering, deployment,
category mutation, and class-specific object creation/mutation capabilities for network,
port-service, URL, and application objects. A `NOT_STARTED`, `PARTIAL`, or `UNSUPPORTED` mutation
capability remains unavailable to delegated execution; only `SUPPORTED` enables the operation.
Static capability declarations and connection-specific runtime evidence are both required for real
provider execution.

## Provider connection secrets

`APP_SECRET_KEY` is a base64-encoded 32-byte master key for the current encrypted-database
SecretStore. It is intentionally absent from these files and may be empty only when no real
connections are created in local development. `SECRET_STORE_KEY_VERSION` is stored with each
ciphertext to support controlled rotation/migration. Production must supply key material through a
secret manager or equivalent runtime injection, independently of PostgreSQL and source control.
