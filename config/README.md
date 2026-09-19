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

The validated vocabulary includes category and security-zone reads, rule ordering, and the
initial provider-gated object-creation classes. A `NOT_STARTED` or `PARTIAL` mutation capability
remains unavailable to delegated execution; only `SUPPORTED` enables the operation.

## permissions.yaml

Defines canonical action terminology/invariants.

The runtime authorization implementation may use database IDs/models, but it should map to a
stable canonical vocabulary instead of inventing synonyms per feature.

## Drift prevention

Once code generation/rendering is installed, CI should verify machine-readable governance data
and rendered Markdown/API documentation remain consistent.
