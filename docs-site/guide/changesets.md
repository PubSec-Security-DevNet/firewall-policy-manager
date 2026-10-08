# ChangeSets

ChangeSets are the durable boundary between an operator’s intent and provider state. A draft can contain multiple rule and object operations, but it retains the exact principal, Group, policy, expected resources, revisions, and provider snapshots used to validate it.

## Lifecycle

```text
DRAFT → READY → SUBMITTED → APPROVED → QUEUED → EXECUTING → SUCCEEDED → STAGED
   ↘ VALIDATION_FAILED / REJECTED / FAILED / PARTIALLY_SUCCEEDED
                           ↘ CONFLICT / RECONCILIATION_REQUIRED
```

The available transitions depend on authorization, provider capability, connection write gates, and the approval policy. A ChangeSet can also become stale when a provider fingerprint, application revision, category, zone, or dependency changes.

## Preflight

Before execution, the server checks:

- current membership and the immutable stored Active Group;
- Access Policy capabilities and object-use grants;
- rule ownership and mapped category boundaries;
- provider capability/version evidence;
- object naming and canonical equivalence;
- source/destination zone and IP-range containment;
- dependency and cross-Group/cross-policy impact;
- current provider/application revisions and fingerprints.

The complete preflight runs again immediately before execution. Denied provider identifiers are redacted from returned failure details.

## Transactions and failure

Each provider manager receives an independently tracked transaction. Provider execution preserves success, failure, rate limiting, timeout-before-mutation, timeout-after-mutation, partial success, and idempotent redelivery evidence. An ambiguous timeout is reconciled before retry. Real FMC/SCC writes remain disabled until the connection and capability gates are explicitly satisfied.

`SUCCEEDED` means provider configuration was accepted. When the provider reports pending changes, the ChangeSet becomes `STAGED` and follows the separate deployment lifecycle. Approval is conditional; policies that do not require it do not invent an approval step.

## Recovery

An eligible rollback uses stored before/after snapshots to construct a new compensating ChangeSet. Eligibility checks current revisions, supported operation types, and dependent changes. The compensating work is validated, approved when required, executed, and deployed like any other change. It is not a transactional rollback of firewall state.
