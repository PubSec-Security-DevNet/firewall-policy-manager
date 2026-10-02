"""Durable deployment planning and approval; execution remains provider-job based."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from firewall_manager.application.authorization import require_action
from firewall_manager.application.errors import InvalidChangeSetStateError, ResourceOutOfScopeError
from firewall_manager.domain.models import Action, DeploymentState, Principal
from firewall_manager.persistence.models import (
    AccessRule,
    AuditEvent,
    ChangeSet,
    ChangeSetOperation,
    Deployment,
    Device,
    FirewallManager,
    FirewallObject,
    ProviderConnection,
    ProviderTransaction,
)


class DeploymentService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def plan(
        self, principal: Principal, change_set_id: UUID, device_ids: list[str]
    ) -> dict[str, object]:
        require_action(principal, Action.DEPLOY)
        change_set = self._session.scalar(
            select(ChangeSet).where(
                ChangeSet.id == change_set_id,
                ChangeSet.organization_id == principal.organization_id,
            )
        )
        if change_set is None:
            raise ResourceOutOfScopeError
        transaction = self._session.scalar(
            select(ProviderTransaction)
            .where(
                ProviderTransaction.change_set_id == change_set_id,
                ProviderTransaction.state.in_(("SUCCEEDED", "PARTIALLY_SUCCEEDED")),
            )
            .order_by(ProviderTransaction.created_at.desc())
        )
        if transaction is None:
            raise InvalidChangeSetStateError(details={"code": "PROVIDER_CONFIGURATION_NOT_STAGED"})
        existing = self._session.scalar(
            select(Deployment).where(Deployment.provider_transaction_id == transaction.id)
        )
        if existing is not None:
            return self._view(existing)
        pending = {
            "warnings": [
                item.get("warnings", [])
                for item in transaction.operation_results
                if isinstance(item, dict) and item.get("warnings")
            ],
            "scope_known": True,
        }
        row = Deployment(
            id=uuid4(),
            organization_id=principal.organization_id,
            provider_transaction_id=transaction.id,
            provider_connection_id=self._connection_for_manager(transaction.manager_id),
            manager_id=transaction.manager_id,
            state=DeploymentState.APPROVAL_REQUIRED.value,
            requested_by_user_id=principal.user_id,
            target_device_ids=device_ids,
            included_change_set_ids=[str(change_set_id)],
            plan_snapshot={
                "change_set_id": str(change_set_id),
                "manager_id": str(transaction.manager_id),
                "expected_scope": "provider policy/device deployment",
            },
            pending_change_evidence=pending,
        )
        self._session.add(row)
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                active_group_id=change_set.acting_group_id,
                policy_id=change_set.access_policy_id,
                action="deployment_plan_created",
                resource_type="deployment",
                resource_id=row.id,
                decision="ALLOW",
                reason_code="DEPLOYMENT_APPROVAL_REQUIRED",
                details=pending,
            )
        )
        self._session.flush()
        return self._view(row)

    def queue_connector(
        self, principal: Principal, connection_id: UUID, force: bool = False
    ) -> dict[str, object]:
        """Create one batch for all staged changes not already in an active deployment."""
        if principal.role != "admin":
            raise ResourceOutOfScopeError
        connection = self._session.scalar(
            select(ProviderConnection)
            .where(
                ProviderConnection.id == connection_id,
                ProviderConnection.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        manager = self._session.scalar(
            select(FirewallManager).where(
                FirewallManager.provider_connection_id == connection_id,
                FirewallManager.organization_id == principal.organization_id,
            )
        )
        if (
            connection is None
            or manager is None
            or connection.lifecycle != "ACTIVE"
            or not connection.write_enabled
        ):
            raise ResourceOutOfScopeError
        if connection.deployment_paused:
            raise InvalidChangeSetStateError(details={"code": "DEPLOYMENT_MAINTENANCE_PAUSED"})
        if not force and not connection.deployment_schedule_enabled:
            raise InvalidChangeSetStateError(details={"code": "DEPLOYMENT_SCHEDULE_DISABLED"})
        pending = self._pending_transactions(principal.organization_id, manager.id, connection_id)
        scheduled = self._session.scalar(
            select(Deployment)
            .where(
                Deployment.provider_connection_id == connection_id,
                Deployment.state == DeploymentState.SCHEDULED.value,
            )
            .order_by(Deployment.created_at.desc())
        )
        if scheduled is not None:
            if pending:
                scheduled.included_change_set_ids = list(
                    dict.fromkeys(
                        [
                            *scheduled.included_change_set_ids,
                            *[str(item.change_set_id) for item in pending],
                        ]
                    )
                )
                scheduled.pending_change_evidence = {"transaction_count": len(pending)}
            if (
                force
                or connection.deployment_next_at is None
                or connection.deployment_next_at <= datetime.now(UTC)
            ):
                scheduled.state = DeploymentState.READY.value
            connection.deployment_status = "QUEUED"
            self._session.flush()
            return self._view(scheduled)
        if not pending:
            return {"status": "NO_PENDING_CHANGES", "connection_id": connection_id}
        row = Deployment(
            id=uuid4(),
            organization_id=principal.organization_id,
            provider_connection_id=connection_id,
            manager_id=manager.id,
            provider_transaction_id=pending[0].id,
            state=DeploymentState.READY.value,
            requested_by_user_id=principal.user_id if force else None,
            target_device_ids=[],
            included_change_set_ids=[str(item.change_set_id) for item in pending],
            plan_snapshot={"connector_id": str(connection_id), "automatic": not force},
            pending_change_evidence={"transaction_count": len(pending)},
        )
        self._session.add(row)
        connection.deployment_status = "QUEUED"
        self._session.flush()
        return self._view(row)

    def pause_connector(
        self, principal: Principal, connection_id: UUID, reason: str, until: datetime | None
    ) -> dict[str, object]:
        """Durably pause automatic and manual deployment starts for one connector."""
        if principal.role != "admin":
            raise ResourceOutOfScopeError
        connection = self._session.scalar(
            select(ProviderConnection)
            .where(
                ProviderConnection.id == connection_id,
                ProviderConnection.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        if connection is None:
            raise ResourceOutOfScopeError
        connection.deployment_paused = True
        connection.deployment_pause_reason = reason
        connection.deployment_paused_at = datetime.now(UTC)
        connection.deployment_pause_until = until
        connection.deployment_paused_by_user_id = principal.user_id
        connection.deployment_status = "PAUSED"
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                action="deployment_paused",
                resource_type="provider_connection",
                resource_id=connection_id,
                decision="ALLOW",
                reason_code="MAINTENANCE_WINDOW",
                details={"reason": reason, "until": until.isoformat() if until else None},
            )
        )
        self._session.flush()
        return {"connection_id": connection_id, "paused": True, "until": until}

    def resume_connector(self, principal: Principal, connection_id: UUID) -> dict[str, object]:
        """Resume deployment starts after an explicit maintenance pause."""
        if principal.role != "admin":
            raise ResourceOutOfScopeError
        connection = self._session.scalar(
            select(ProviderConnection)
            .where(
                ProviderConnection.id == connection_id,
                ProviderConnection.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        if connection is None:
            raise ResourceOutOfScopeError
        connection.deployment_paused = False
        connection.deployment_pause_reason = None
        connection.deployment_paused_at = None
        connection.deployment_pause_until = None
        connection.deployment_paused_by_user_id = None
        connection.deployment_status = None
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                action="deployment_resumed",
                resource_type="provider_connection",
                resource_id=connection_id,
                decision="ALLOW",
                reason_code="MAINTENANCE_WINDOW_ENDED",
                details={},
            )
        )
        self._session.flush()
        return {"connection_id": connection_id, "paused": False}

    def schedule_connector(self, principal: Principal, connection_id: UUID) -> dict[str, object]:
        """Expose newly staged changes immediately without starting deployment early."""
        connection = self._session.scalar(
            select(ProviderConnection)
            .where(
                ProviderConnection.id == connection_id,
                ProviderConnection.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        manager = self._session.scalar(
            select(FirewallManager).where(
                FirewallManager.provider_connection_id == connection_id,
                FirewallManager.organization_id == principal.organization_id,
            )
        )
        if (
            connection is None
            or manager is None
            or connection.lifecycle != "ACTIVE"
            or not connection.write_enabled
        ):
            return {"status": "DEPLOYMENT_NOT_AVAILABLE", "connection_id": connection_id}
        pending = self._pending_transactions(principal.organization_id, manager.id, connection_id)
        if not pending:
            return {"status": "NO_PENDING_CHANGES", "connection_id": connection_id}
        scheduled = self._session.scalar(
            select(Deployment)
            .where(
                Deployment.provider_connection_id == connection_id,
                Deployment.state == DeploymentState.SCHEDULED.value,
            )
            .order_by(Deployment.created_at.desc())
        )
        if scheduled is None:
            scheduled = Deployment(
                id=uuid4(),
                organization_id=principal.organization_id,
                provider_connection_id=connection_id,
                manager_id=manager.id,
                provider_transaction_id=pending[0].id,
                state=DeploymentState.SCHEDULED.value,
                target_device_ids=[],
                included_change_set_ids=[str(item.change_set_id) for item in pending],
                plan_snapshot={
                    "connector_id": str(connection_id),
                    "automatic": True,
                    "scheduled_for": (
                        connection.deployment_next_at.isoformat()
                        if connection.deployment_next_at is not None
                        else None
                    ),
                },
                pending_change_evidence={"transaction_count": len(pending)},
            )
            self._session.add(scheduled)
        else:
            scheduled.included_change_set_ids = list(
                dict.fromkeys(
                    [
                        *scheduled.included_change_set_ids,
                        *[str(item.change_set_id) for item in pending],
                    ]
                )
            )
            scheduled.pending_change_evidence = {"transaction_count": len(pending)}
        connection.deployment_status = "QUEUED"
        if connection.deployment_next_at is None:
            connection.deployment_next_at = datetime.now(UTC)
        self._session.flush()
        return self._view(scheduled)

    def _pending_transactions(
        self, organization_id: UUID, manager_id: UUID, connection_id: UUID
    ) -> list[ProviderTransaction]:
        active_ids = {
            item
            for values in self._session.scalars(
                select(Deployment.included_change_set_ids).where(
                    Deployment.provider_connection_id == connection_id,
                )
            )
            for item in (values or [])
        }
        transactions = list(
            self._session.scalars(
                select(ProviderTransaction)
                .join(ChangeSet, ChangeSet.id == ProviderTransaction.change_set_id)
                .where(
                    ProviderTransaction.organization_id == organization_id,
                    ProviderTransaction.manager_id == manager_id,
                    ProviderTransaction.state.in_(("SUCCEEDED", "PARTIALLY_SUCCEEDED")),
                    ChangeSet.state.in_(("SUCCEEDED", "PARTIALLY_SUCCEEDED")),
                )
                .order_by(ProviderTransaction.created_at)
            )
        )
        return [item for item in transactions if str(item.change_set_id) not in active_ids]

    def list(self, principal: Principal) -> list[dict[str, object]]:
        require_action(principal, Action.APPROVE)
        rows = self._session.scalars(
            select(Deployment)
            .where(
                Deployment.organization_id == principal.organization_id,
            )
            .order_by(Deployment.updated_at.desc())
        ).all()
        views = [self._view(row) for row in rows]
        for index, view in enumerate(views):
            if not view["rollback_eligible"]:
                continue
            devices = self._device_ids(rows[index])
            if not devices:
                continue
            for newer_row in rows[:index]:
                if newer_row.state != DeploymentState.DEPLOYED.value:
                    continue
                if devices & self._device_ids(newer_row):
                    view["rollback_eligible"] = False
                    view["rollback_unavailable_reason"] = (
                        "A newer deployment affects one or more of the same devices."
                    )
                    break
        return views

    def retry(self, principal: Principal, deployment_id: UUID) -> dict[str, object]:
        """Queue a fresh connector batch for a failed deployment."""
        if principal.role != "admin":
            raise ResourceOutOfScopeError
        failed = self._session.scalar(
            select(Deployment).where(
                Deployment.id == deployment_id,
                Deployment.organization_id == principal.organization_id,
            )
        )
        if failed is None or failed.state not in (
            DeploymentState.FAILED.value,
            DeploymentState.UNKNOWN.value,
            DeploymentState.RECONCILIATION_REQUIRED.value,
        ):
            raise InvalidChangeSetStateError(details={"code": "DEPLOYMENT_NOT_RETRYABLE"})
        if failed.provider_connection_id is None:
            raise InvalidChangeSetStateError(details={"code": "DEPLOYMENT_CONNECTOR_MISSING"})
        connection = self._session.get(ProviderConnection, failed.provider_connection_id)
        if connection is None or connection.lifecycle != "ACTIVE" or not connection.write_enabled:
            raise ResourceOutOfScopeError
        failed.state = DeploymentState.READY.value
        failed.external_operation_id = None
        failed.failure_info = {}
        failed.device_results = []
        failed.plan_snapshot = {**failed.plan_snapshot, "retry": True}
        connection.deployment_status = "QUEUED"
        self._session.flush()
        return self._view(failed)

    def rollback(self, principal: Principal, deployment_id: UUID) -> dict[str, object]:
        """Queue a provider-native rollback of the completed deployment batch."""
        if principal.role != "admin":
            raise ResourceOutOfScopeError
        row = self._session.scalar(
            select(Deployment).where(
                Deployment.id == deployment_id,
                Deployment.organization_id == principal.organization_id,
            )
        )
        if row is None:
            raise ResourceOutOfScopeError
        if row.state != DeploymentState.DEPLOYED.value:
            raise InvalidChangeSetStateError(details={"code": "DEPLOYMENT_NOT_ROLLBACKABLE"})
        if row.rollback_state:
            raise InvalidChangeSetStateError(details={"code": "ROLLBACK_ALREADY_IN_PROGRESS"})
        if row.provider_connection_id is None or not row.external_operation_id:
            raise InvalidChangeSetStateError(details={"code": "DEPLOYMENT_PROVIDER_TASK_MISSING"})
        connection = self._session.get(ProviderConnection, row.provider_connection_id)
        if connection is None or connection.lifecycle != "ACTIVE" or not connection.write_enabled:
            raise ResourceOutOfScopeError
        row.rollback_state = "READY"
        row.rollback_requested_by_user_id = principal.user_id
        row.rollback_external_operation_id = None
        row.rollback_device_results = []
        row.rollback_failure_info = {}
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                action="deployment_rollback_requested",
                resource_type="deployment",
                resource_id=row.id,
                decision="ALLOW",
                reason_code="DEPLOYMENT_ROLLBACK_REQUESTED",
                details={"external_operation_id": row.external_operation_id},
            )
        )
        connection.deployment_status = "ROLLING_BACK"
        self._session.flush()
        return self._view(row)

    def approve(self, principal: Principal, deployment_id: UUID) -> dict[str, object]:
        require_action(principal, Action.APPROVE)
        row = self._session.scalar(
            select(Deployment).where(
                Deployment.id == deployment_id,
                Deployment.organization_id == principal.organization_id,
            )
        )
        if row is None:
            raise ResourceOutOfScopeError
        if row.requested_by_user_id == principal.user_id:
            raise InvalidChangeSetStateError(details={"code": "SEPARATION_OF_DUTY"})
        if row.state != DeploymentState.APPROVAL_REQUIRED.value:
            raise InvalidChangeSetStateError
        row.approved_by_user_id = principal.user_id
        row.state = DeploymentState.READY.value
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                action="deployment_approved",
                resource_type="deployment",
                resource_id=row.id,
                decision="ALLOW",
                reason_code="DEPLOYMENT_APPROVED",
                details={"plan_revision": row.revision},
            )
        )
        self._session.flush()
        return self._view(row)

    def _view(self, row: Deployment) -> dict[str, object]:
        rollback_eligible, rollback_reason = self._rollback_eligibility(row)
        device_ids = self._device_ids(row)
        device_names = dict(
            self._session.execute(
                select(Device.native_id, Device.name).where(Device.native_id.in_(device_ids))
            ).all()
        )
        return {
            "id": row.id,
            "organization_id": row.organization_id,
            "provider_transaction_id": row.provider_transaction_id,
            "provider_connection_id": row.provider_connection_id,
            "manager_id": row.manager_id,
            "state": row.state,
            "external_operation_id": row.external_operation_id,
            "rollback_state": row.rollback_state,
            "rollback_external_operation_id": row.rollback_external_operation_id,
            "rollback_requested_by_user_id": row.rollback_requested_by_user_id,
            "rollback_device_results": row.rollback_device_results,
            "rollback_failure_info": row.rollback_failure_info,
            "rollback_eligible": rollback_eligible,
            "rollback_unavailable_reason": rollback_reason,
            "requested_by_user_id": row.requested_by_user_id,
            "approved_by_user_id": row.approved_by_user_id,
            "target_device_ids": row.target_device_ids,
            "device_names": device_names,
            "included_change_set_ids": row.included_change_set_ids,
            "plan_snapshot": row.plan_snapshot,
            "pending_change_evidence": row.pending_change_evidence,
            "device_results": row.device_results,
            "failure_info": row.failure_info,
            "lease_until": row.lease_until,
            "heartbeat_at": row.heartbeat_at,
            "revision": row.revision,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def _rollback_eligibility(self, row: Deployment) -> tuple[bool, str | None]:
        if row.state != DeploymentState.DEPLOYED.value:
            return False, "Deployment is not complete."
        operations = self._session.scalars(
            select(ChangeSetOperation).where(
                ChangeSetOperation.change_set_id.in_(
                    [UUID(value) for value in row.included_change_set_ids]
                )
            )
        ).all()
        for operation in operations:
            if operation.kind == "ENSURE_RULE_CATEGORY":
                continue
            snapshot = operation.rollback_snapshot or {}
            if operation.kind in {
                "MODIFY_RULE",
                "MOVE_RULE",
                "DELETE_RULE",
                "MODIFY_OBJECT",
                "DELETE_OBJECT",
            }:
                resource_id = snapshot.get("resource_id")
                expected = snapshot.get("revision")
                if not resource_id or expected is None:
                    return False, "Rollback history is unavailable for one or more changes."
                model = AccessRule if operation.kind.endswith("RULE") else FirewallObject
                revision = self._session.scalar(
                    select(model.revision).where(model.id == UUID(str(resource_id)))
                )
                if (
                    revision != int(expected) + 1
                    and getattr(
                        self._session.get(model, UUID(str(resource_id))), "management_state", None
                    )
                    != "MANAGED"
                ):
                    return False, "The affected rule or object changed after deployment."
            elif operation.kind in {"CREATE_RULE", "CREATE_OBJECT"}:
                result = operation.execution_result or {}
                if not result.get("provider_resource_id"):
                    return False, "The created provider resource could not be identified."
            else:
                return False, "This deployment contains an unsupported rollback operation."
        return True, None

    @staticmethod
    def _device_ids(row: Deployment) -> set[str]:
        if row.target_device_ids:
            return set(row.target_device_ids)
        return {
            str(item.get("uid") or item.get("device_id"))
            for item in row.device_results
            if item.get("uid") or item.get("device_id")
        } or {
            str(device_id)
            for job in row.plan_snapshot.get("provider_jobs", [])
            for device_id in job.get("provider", {}).get("deviceList", [])
        }

    def _connection_for_manager(self, manager_id: UUID) -> UUID | None:
        return self._session.scalar(
            select(ProviderConnection.id)
            .join(FirewallManager, FirewallManager.provider_connection_id == ProviderConnection.id)
            .where(FirewallManager.id == manager_id)
        )
