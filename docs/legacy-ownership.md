# Reviewing ownership after upgrade

Stop the API, workers and scheduler before migrating. The production helper's `migrate` command
stops them and leaves them stopped; use `start` only after migration succeeds. Never run old workers
alongside the upgraded schema. Take a verified backup first.

Migration `20261007_0045` preserves existing rule/object ownership, category mappings and object
USE/MODIFY grants in individual `REVIEW_REQUIRED` records. Old schemas do not contain complete,
unambiguous assignment provenance. Names, creator metadata and successful transactions alone
cannot prove every persisted assignment was explicitly authorized.

Assignments remain stored but cannot authorize mutation or object USE until their Group/policy's
pending records have been individually reviewed. The dashboard never combines Groups. Provider
synchronization, drift acceptance, a familiar name, and editing an ordinary grant cannot clear the
review records. The migration disables provider writes and pauses deployment for affected
organizations, invalidates active ChangeSets/approvals, and marks active deployments for
reconciliation. This is deliberately conservative and may include legitimate old assignments.

A Platform Admin opens **Access grants → Legacy ownership review**, checks the displayed resource,
Group and policy against independent evidence, then confirms one assignment with a written reason.
The server requires the exact scope and current resource revision and records the administrator,
reason, resource and scope in Audit. There is no bulk confirmation. Unassigned or deleted resources
cannot be confirmed; leave them quarantined until their intended authority can be resolved.

Confirmation does not enable provider writes, revive approvals, erase drift, or start deployment.
Every pending assignment in the scope must be reviewed before its authority becomes usable. Use
fresh validation/approval for new ChangeSets. Native deployment is still subject to the limitations
in [Deployment safety contracts](deployment-safety.md).

Fresh installs have no legacy records. Resources explicitly created after migration do not require
legacy review. Re-running `alembic upgrade head` does not create duplicate reviews. These security
migrations cannot be downgraded to silently restore unsafe authority; restore the verified backup
with matching application images if an upgrade must be rolled back.
