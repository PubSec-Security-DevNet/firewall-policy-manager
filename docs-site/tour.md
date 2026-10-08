# Product tour

Follow one governed change from delegated scope to provider reality. The screenshots are captures of the running application using non-production data. Session identity and the visual development banner were omitted during capture; no security control was changed.

## 1. Start with operational context

The dashboard summarizes synchronized providers, accessible policies, normalized objects, open ChangeSets, and conditions that need attention. The persistent working context shows the Active Group and selected Access Policy.

<AppScreenshot src="/screenshots/dashboard.png" alt="Security posture dashboard with synchronized FMC and SCC provider inventory" label="Security posture" caption="Provider health, accessible policy inventory, and active work in one operational scan." />

## 2. Select the delegated boundary

An administrator maps a Group to an Access Policy and provider category, then grants only the required rule actions, objects, zones, address ranges, and object classes. A delegated User selects one available Group and policy. The server clears and recomputes the previous context rather than combining permissions.

<AppScreenshot src="/screenshots/groups.png" alt="Groups administration showing governed team contexts" label="Groups" caption="Membership makes a context available; policy and resource grants establish what that context can do." />

<AppScreenshot src="/screenshots/access-grants.png" alt="Access grants administration for policy and resource delegation" label="Access grants" caption="Policy, object, zone, IP range, creation, and category boundaries are administered explicitly." />

## 3. Build policy from allowed resources

The Rules workspace shows ordered rules owned by the Active Group. Rule editors offer only authorized zones, network and service objects, applications, URLs, intrusion policy, file policy, and variable sets supported for the selected provider context.

<AppScreenshot src="/screenshots/rules.png" alt="Delegated Rules workspace with owned policy rules" label="Rules" caption="The team works in its own mapped policy section; every referenced element is authorized independently." />

The Objects workspace distinguishes resources the Group may use from application-managed resources it owns. Network values are checked against authorized ranges, and dependency checks protect referenced objects.

<AppScreenshot src="/screenshots/objects.png" alt="Object inventory showing ownership and use rights" label="Objects" caption="Use, ownership, modification, deletion, provider support, and synchronization state stay visible." />

## 4. Govern and execute the ChangeSet

Edits become an ordered durable ChangeSet. Validation checks current membership, policy capabilities, grants, ownership, naming, dependencies, provider capability, expected revisions, and drift. Submission enters approval when required. Provider execution reauthorizes and revalidates before it writes.

<AppScreenshot src="/screenshots/changesets.png" alt="ChangeSets workspace showing approval, success, validation failure, rejection, and retry states" label="ChangeSets" caption="Intent, state, provider transaction evidence, failures, and recovery remain inspectable." />

## 5. Deploy, observe, and reconcile

Successful provider configuration becomes staged or pending deployment—not deployed. A schedule or authorized forced action creates a deployment batch, starts provider jobs, and polls device results. Partial, failed, or unknown outcomes remain explicit.

Later synchronization compares provider revisions and fingerprints with managed inventory. Out-of-band changes become drift records. Missing resources can be recreated through a ChangeSet, known drift can be restored through a ChangeSet, and provider state can be accepted as an explicit audited decision.

Eligible rollback also creates a compensating ChangeSet. It requires usable snapshots, current revisions, and compatible dependencies, then follows the same approval, execution, and deployment lifecycle.

Continue with [ChangeSets](./guide/changesets), [deployment and recovery](./features/deployment-recovery), or [Sync & drift](./guide/sync-drift).
