# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Database claim generations, durable mutation intent, and fenced unit-of-work commits."""

import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import event, select
from sqlalchemy.orm import Session

from firewall_manager.application.errors import ApplicationError
from firewall_manager.application.mutation_guard import current_mutation_guard, mutation_context
from firewall_manager.persistence.models import (
    AccessPolicy,
    AccessRule,
    AuditEvent,
    ChangeSet,
    Deployment,
    Device,
    FirewallManager,
    FirewallObject,
    Group,
    GroupMembership,
    GroupPolicyCategoryMapping,
    IpRangeGrant,
    ObjectCreateGrant,
    ObjectUseGrant,
    PolicyDelegation,
    ProviderConnection,
    ProviderDomain,
    ProviderTransaction,
    User,
    ZoneGrant,
)


class ExecutionFenceLostError(ApplicationError):
    code = "EXECUTION_FENCE_LOST"
    status_code = 409
    safe_message = "Execution ownership expired. Reconciliation is required before retry."


class ExecutionFence:
    def __init__(  # noqa: PLR0913, PLR0917 -- durable claim identity
        self,
        session: Session,
        model: type[ChangeSet] | type[Deployment],
        job_id: UUID,
        epoch: int,
        owner: str,
        authorize: Callable[[], None] | None = None,
    ) -> None:
        self.session, self.model, self.job_id = session, model, job_id
        self.epoch, self.owner, self.authorize = epoch, owner, authorize
        self._checking = False
        session.info["execution_fence"] = self

    def check(self) -> None:
        if self._checking:
            return
        self._checking = True
        try:
            table = self.model.__table__
            owner = "execution_owner" if self.model is ChangeSet else "lease_owner"
            lease = "execution_lease_until" if self.model is ChangeSet else "lease_until"
            with self.session.no_autoflush:
                row = self.session.execute(
                    select(table.c.execution_epoch, table.c[owner], table.c[lease])
                    .where(table.c.id == self.job_id)
                    .with_for_update()
                ).one_or_none()
            if (
                row is None
                or row[0] != self.epoch
                or row[1] != self.owner
                or row[2] is None
                or row[2] <= datetime.now(UTC)
            ):
                raise ExecutionFenceLostError
        finally:
            self._checking = False

    def before_mutation(self, method: str, path: str, payload: object = None) -> None:
        self.check()
        row = self.session.get(self.model, self.job_id)
        if row is None:
            raise ExecutionFenceLostError
        # SHARE locks serialize authority revocations with this short commit boundary.
        # No lock is held during provider preflight or HTTP. Existing affirmative authority
        # cannot disappear between its final check and the intent commit.
        if isinstance(row, Deployment):
            self.session.execute(
                select(ChangeSet.id)
                .where(ChangeSet.id.in_([UUID(str(i)) for i in row.included_change_set_ids]))
                .order_by(ChangeSet.id)
                .with_for_update(read=True)
            ).all()
        for model in (
            User,
            Group,
            GroupMembership,
            PolicyDelegation,
            ObjectUseGrant,
            IpRangeGrant,
            ZoneGrant,
            ObjectCreateGrant,
            ProviderConnection,
            Device,
            FirewallManager,
            ProviderDomain,
            AccessPolicy,
            AccessRule,
            FirewallObject,
            GroupPolicyCategoryMapping,
        ):
            self.session.execute(
                select(model.id)
                .where(model.organization_id == row.organization_id)
                .order_by(model.id)
                .with_for_update(read=True)
            ).all()
        if self.authorize is not None:
            self.authorize()
        previous = row.mutation_intent or {}
        if (
            previous
            and previous.get("epoch") != self.epoch
            and previous.get("state") != "COMPLETED"
        ):
            raise ExecutionFenceLostError
        context = dict(mutation_context.get() or {})
        digest = hashlib.sha256(
            json.dumps(
                [
                    context.get("operation_id"),
                    method,
                    path,
                    context.get("request_parameters"),
                    payload,
                ],
                sort_keys=True,
                default=str,
            ).encode()
        ).hexdigest()
        entries = list(previous.get("entries", []))
        if entries and entries[-1].get("state") == "OUTCOME_UNCERTAIN":
            raise ExecutionFenceLostError(details={"code": "PREVIOUS_INTENT_UNCERTAIN"})
        retry_of: str | None = None
        matching = [
            item
            for item in entries
            if item.get("context", {}).get("operation_id") == context.get("operation_id")
            and item.get("method") == method
            and item.get("path") == path
        ]
        if matching:
            prior = matching[-1]
            prior_response = prior.get("response")
            # FMC can reject an expired access token before it evaluates the request. This is
            # a definitive non-mutating result, so the provider adapter may reauthenticate and
            # deliver one fenced retry. Any other duplicate remains forbidden: its outcome may
            # already be unknown and must be reconciled instead of resent.
            if not isinstance(prior_response, dict) or prior_response.get("status") != 401:
                raise ExecutionFenceLostError(details={"code": "INTENT_ALREADY_COMMITTED"})
            retry_of = str(prior.get("id"))
        actor = row.principal_id if isinstance(row, ChangeSet) else row.requested_by_user_id
        if actor is None and isinstance(row, Deployment):
            transaction = self.session.get(ProviderTransaction, row.provider_transaction_id)
            change = self.session.get(ChangeSet, transaction.change_set_id) if transaction else None
            actor = change.principal_id if change else None
        intent = {
            "id": str(uuid4()),
            "job_id": str(row.id),
            "epoch": self.epoch,
            "sequence": len(entries) + 1,
            "method": method,
            "path": path,
            "request_hash": digest,
            "request": payload,
            "context": context,
            "actor_id": str(actor) if actor else None,
            "group_id": str(row.acting_group_id) if isinstance(row, ChangeSet) else None,
            "policy_id": str(row.access_policy_id) if isinstance(row, ChangeSet) else None,
            "authorization_revision": row.revision,
            "created_at": datetime.now(UTC).isoformat(),
            "state": "OUTCOME_UNCERTAIN",
        }
        if retry_of is not None:
            intent["retry_of"] = retry_of
        row.mutation_intent = {**intent, "entries": [*entries, intent]}
        self.session.add(
            AuditEvent(
                organization_id=row.organization_id,
                actor_user_id=actor,
                action="external_dispatch_authorized",
                resource_type=self.model.__tablename__,
                resource_id=row.id,
                decision="ALLOW",
                reason_code="DURABLE_INTENT_COMMITTED",
                details=intent,
            )
        )
        # Linearization point: exactly this request is now authorized and potentially in
        # flight, even if this worker pauses before its socket write. Recovery must not resend.
        self.session.commit()

    def after_mutation(self, result: object = None) -> None:
        self.check()
        row = self.session.get(self.model, self.job_id)
        if row is None:
            raise ExecutionFenceLostError
        value = dict(row.mutation_intent)
        entries = list(value.get("entries", []))
        if entries:
            entries[-1] = {**entries[-1], "response": result, "state": "RESPONSE_RECEIVED"}
            row.mutation_intent = {**value, "entries": entries}
        # Result evidence becomes durable before another mutation; unknown outcomes never
        # authorize the next request. The claim is rechecked again by the commit hook.
        self.session.commit()

    def close(self) -> None:
        self.session.info.pop("execution_fence", None)


def _guard(session: Session, *args: object) -> None:
    fence = session.info.get("execution_fence")
    if isinstance(fence, ExecutionFence):
        fence.check()
        row = session.get(fence.model, fence.job_id)
        if (
            row is not None
            and (
                row.state == "SUCCEEDED"
                or (
                    isinstance(row, Deployment)
                    and row.state == "DEPLOYED"
                    and row.rollback_state in {None, "ROLLED_BACK"}
                )
            )
            and row.mutation_intent
        ):
            row.mutation_intent = {**row.mutation_intent, "state": "COMPLETED"}


# Every local result flush/commit is fenced, including exceptional paths and poll results.
event.listen(Session, "before_flush", _guard)
event.listen(Session, "before_commit", _guard)


class SessionMutationGuard:
    def __init__(self, session: Session) -> None:
        self.session = session

    def before_mutation(self, method: str, path: str, payload: object = None) -> None:
        fence = self.session.info.get("execution_fence")
        if not isinstance(fence, ExecutionFence):
            raise ExecutionFenceLostError
        fence.before_mutation(method, path, payload)

    def after_mutation(self, result: object = None) -> None:
        fence = self.session.info.get("execution_fence")
        if not isinstance(fence, ExecutionFence):
            raise ExecutionFenceLostError
        fence.after_mutation(result)


@contextmanager
def mutation_scope(session: Session) -> Iterator[None]:
    token = current_mutation_guard.set(SessionMutationGuard(session))
    try:
        yield
    finally:
        current_mutation_guard.reset(token)
        session.info.pop("execution_fence", None)
