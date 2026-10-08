# Workflow states

The product intentionally separates configuration, intent, approval, provider execution, and reconciliation. This supports safe review and makes rollback an auditable new operation.

| Boundary | Current states | Meaning |
| --- | --- | --- |
| Synchronized resource | `OBSERVED`, `UNMANAGED`, `DRIFTED`, `MISSING`, `CONFLICT` | What the latest complete provider read establishes. |
| ChangeSet drafting | `DRAFT`, `VALIDATION_FAILED`, `READY` | Intent is editable or has completed preflight. |
| Governance | `SUBMITTED`, `APPROVED`, `REJECTED` | Approval policy is being or has been resolved. |
| Provider execution | `QUEUED`, `EXECUTING`, `SUCCEEDED`, `FAILED`, `PARTIALLY_SUCCEEDED`, `CONFLICT`, `RECONCILIATION_REQUIRED` | Configuration work and its provider transaction result. |
| Pending deployment | `STAGED`, `READY`, `APPROVAL_REQUIRED`, `SCHEDULED` | Configuration is waiting for a device deployment boundary. |
| Deployment | `DEPLOYING`, `DEPLOYED`, `PARTIAL`, `FAILED`, `UNKNOWN`, `RECONCILIATION_REQUIRED` | Provider task and per-device outcome. |
| Recovery | `ROLLING_BACK`, `ROLLED_BACK` | An eligible recovery operation is in progress or confirmed. |

Real provider writes require connection-level write enablement, tested capability evidence, current
authorization, approval when configured, successful preflight, and reconciliation after execution.
Configuration success and device deployment success are never treated as the same state.
