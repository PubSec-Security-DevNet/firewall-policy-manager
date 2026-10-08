# A governed layer for shared firewall policy

Firewall Policy Manager is for security platform teams that operate shared Cisco Secure Firewall infrastructure but need product teams, business units, or regional administrators to manage their own policy slice. Direct FMC or SCC access is often too broad for that operating model: provider roles do not express the full combination of application Group, policy assignment, object use, ownership, zone direction, network range, approval, and deployment boundary.

The product sits between delegated operators and provider infrastructure. It does not hide FMC or SCC behind another generic editor. It adds the context, governance, and reconciliation needed to delegate safely.

## Why a delegated layer instead of another instance?

Separate firewall or management instances can be the right answer when an organization needs a hard infrastructure boundary. They are not always available or feasible, however: the deployed platform may not support the required instance model, the network topology may depend on shared enforcement points, or the additional licensing, capacity, upgrades, monitoring, and operational ownership may be disproportionate to the policy boundary being created.

Without a delegated layer, shared environments commonly fall back to one of two poor choices: every rule change becomes a central-team ticket, or teams receive provider access broader than the work they actually own. Firewall Policy Manager provides a governed middle path. Teams manage only their assigned policy slice and authorized resources, while the platform team retains control of shared infrastructure, approval policy, provider credentials, deployment authority, and audit evidence.

This model does not turn shared infrastructure into separate fault, regulatory, or network-isolation domains. When those hard boundaries are required, use the appropriate provider and platform isolation controls.

## The product contract

```text
Person
  → authenticated User
  → one Active Group
  → one assigned Access Policy
  → explicit action and resource grants
  → ChangeSet
  → provider transaction
  → deployment and observed result
```

Every boundary is enforced by the API and shared application services. The browser communicates intent; it is not trusted to establish authorization.

## What makes it different

### Context is explicit

A User with several Group memberships operates as exactly one Active Group. Rights from other memberships are not combined. This makes the current ownership, policy section, resource grants, and address boundary explainable to both the operator and the audit trail.

### References and ownership are separate

Teams can be allowed to use centrally maintained objects without being able to modify them. Application-managed objects carry authoritative Group and policy ownership; provider-only resources remain unmanaged until an explicit decision.

### Changes have a lifecycle

Rule and object edits become ordered ChangeSet operations. Preflight checks provider capability, names, dependencies, grants, IP containment, and synchronized revisions. Approval is applied where policy requires it, and authority is checked again at execution.

### Provider reality is first-class

Firewall Policy Manager assumes administrators and other systems may also touch FMC or SCC. Complete synchronization finds drift, missing managed resources, and provider-only resources. Operators can accept provider state, restore or recreate through a ChangeSet, or resolve a conflict deliberately.

### Configuration is not deployment

Provider configuration success can leave pending changes. Scheduled or authorized forced deployment is tracked separately through provider jobs and per-device results. Partial and uncertain outcomes remain visible for recovery.

## Strongest capabilities

- delegated Access Policy administration with one Active Group and no permission union;
- rule ownership and Group-controlled provider categories;
- object USE versus modify/delete ownership, with authorized IPv4/IPv6 ranges;
- durable ChangeSets, approvals, execution-time reauthorization, and provider transactions;
- normalized FMC and SCC workflows with version-specific capability evidence;
- scheduled synchronization, drift detection, missing/provider-only resources, and reconciliation;
- pending-change inspection, scheduled/forced deployment, and device-level results;
- compensating ChangeSet recovery with snapshot, revision, and dependency checks;
- Entra ID, Duo SSO, Generic OIDC, scoped API tokens, and secure server-side sessions;
- audit, Vault-backed secrets, metrics, health, queues, worker/scheduler recovery, and backups.

Next: [take the product tour](./tour) or [explore capabilities](./features/).
