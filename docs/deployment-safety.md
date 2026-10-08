# Deployment safety and durable dispatch

Firewall Policy Manager separates configuration changes from deployment. Successful configuration
writes do not mean that a firewall has deployed them. Normal deployment is permitted when the
provider evidence and current authorization satisfy the checks below. Unexplained, unavailable or
malformed evidence stops deployment before its mutation intent is committed.

## FMC contract

**Documented provider behavior.** The deployable-device API supplies target readiness, policy status
and a deployment version. Expanded per-device pending changes identify entities and, where
available, field/reference differences. The deployment API accepts explicit device IDs and selected
policy types. FPM selects `PG.FIREWALL.NGFWAccessControlPolicy`, with `forceDeploy` and
`ignoreWarning` true. If that policy is mandatory, Cisco adds it implicitly and FPM excludes it
from the selector as required by the API. Mandatory additional policy types are refused. Versions are trigger timestamps, not documented compare-and-swap conditions.
Policy locks cover individual policies; the documented API does not establish an exclusive lock
covering every device setting and referenced object through deployment.

**FPM checks.** FPM derives devices from current policy assignments, validates original actors,
delegations, approvals, connector state and revisions, then inspects complete deployable and
expanded pending collections. Native deployment is provider-wide for the selected device, so
pending entities that are not attributable to FPM are recorded as evidence and warnings rather
than blocking dispatch; direct FMC/SCC edits therefore deploy with the managed changes. Known FPM
mutations still require the expected action and cannot report an explicit provider error. Provider
generated display/default fields and aggregate parent records are tolerated. Current resource
configuration and available revisions must still match recorded results. Unknown assignments,
unapproved policy types, dirty dependencies, mandatory additional policies, incomplete collections
and detectable version changes cause refusal. FPM re-reads selected deployable metadata, including
group dependencies and device members, immediately before dispatch authorization. An empty, valid
pending collection is acceptable; it no longer disables deployment.

This deliberately supports a conservative subset of provider responses. Unsupported versions,
missing entity details or response shapes that cannot establish this contract fail closed. Older
summary-only pending APIs are insufficient. Controlled tests are not certification of every FMC
release; validate the connection and a safe target on the installed version.

Sources: [expanded pending changes](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/get-pending-changes/),
[deployable devices](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/get-deployable-device/),
[deployment request](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/create-deployment-request/),
[policy locks](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/create-policy-lock/),
[FMC REST resources](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770/Objects_In_The_REST_API.html).

## SCC contract

**Documented provider behavior.** SCC inventory identifies devices by SCC UID and exposes
`uidOnFmc` for cdFMC-managed devices. SCC's multi-FTD deployment endpoint accepts `deviceUids`; it
does not document a policy-type selector. Its pending-change endpoint can return an empty list
when no baseline is available, so emptiness there cannot establish a clean candidate. Change Request
IDs are not documented immutable deployment snapshots or mutation-set idempotency keys.

**FPM checks.** FPM requires an unambiguous mapping of every selected SCC UID to a cdFMC-managed
FTD and its FMC ID. It uses the documented **cdFMC selective deployment API**, expanded pending
information and task status API, applying the FMC evidence checks to those mapped IDs. It does not
use an undocumented `selectedPolicyTypes` SCC payload, silently discard unsupported device types,
or expand a requested target list. New job identities are stored as domain/task IDs. Historical SCC
deployment-run IDs remain readable through the SCC status API. The SCC inventory pending endpoint
is not used as clean-state proof.

Sources: [SCC multi-device deployment](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/cdfmc-managed-ftds-only-deploy-changes-to-multiple-ftd-devices/),
[SCC pending changes](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/get-pending-changes-on-a-cdfmc-managed-ftd/),
[Change Requests](https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/get-change-requests/),
and the cdFMC schemas linked above.

## Provider boundary and operational change windows

The reviewed Cisco APIs do not document an immutable candidate, exact mutation-set deployment,
transaction-bound deployment, or revision condition that excludes concurrent edits. FPM does not
claim these guarantees. Its successive inspection reads are not a transactional snapshot. An out-of-band change made **after final preflight** may enter the provider's
subsequent deployment semantics. A local database lock cannot prevent an administrator from editing
FMC or SCC. Device selection and policy-type selection narrow the request; neither proves exclusive
ownership of the configuration deployed.

Organizations requiring strict exclusivity must prevent direct provider edits throughout the
configuration/deployment window through their operational access and change procedures. This is an
operational assumption, not a provider lock implemented by FPM. No extra acknowledgment workflow
can create the missing atomic primitive.

FPM stores observed preflight evidence with the durable intent, polls returned jobs and queues a
fresh provider synchronization after completion. Synchronization compares managed desired state
with observations and surfaces detectable differences as drift. It cannot reconstruct every
transient external edit or prove the absence of unrelated changes outside managed inventory.

## Durable intent is the dispatch authorization boundary

Before each mutating provider request, the worker validates its database generation and lease,
current actor/grants, approval and revision, connector write authority and exact target scope.
Short-lived database locks serialize existing authority revocations with this check. A unique
intent records the job, operation, generation, actor, scope, native request, revision context,
creation time and deployment preflight evidence. **The intent commit authorizes that one external
request.** Database locks are released before HTTP transmission.

A revocation or lease loss before that commit prevents authorization. A later revocation cannot
recall the committed request, including one paused immediately before its socket write. A returning
stale worker cannot commit workflow results, enqueue downstream work or authorize another request.
New operations require current authority. This is effectively-once operation handling through
unique intent, fencing and reconciliation, not mathematically exactly-once network delivery.

An expired worker's replacement treats an intent as potentially successful and never blindly
resends it. Known deployment receipts restore read-only job monitoring. A missing deployment job
receipt leaves the outcome uncertain. Configuration recovery reads known target IDs and records
`DESIRED_STATE_PRESENT` or `UNKNOWN` for each intent. A create without a provider receipt remains
unknown; a same-name object is not proof of ownership. The ChangeSet remains reconciliation-required
for review of ownership and any operations that were not completed. Recovery does not automatically
adopt objects, replay the transaction or authorize its remaining mutations. Retry stays unavailable
while the external outcome is uncertain.

The integrated sequence is: claim → current authority and targets → provider preflight → guarded
intent commit → one HTTP request → fenced receipt → job monitoring/recovery → synchronization.
A crash at any point after intent commit preserves that intent for inspection.
