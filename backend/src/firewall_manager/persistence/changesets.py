"""SQL persistence adapter for durable Milestone 3 ChangeSets."""

# ruff: noqa: PLR0913, PLR0917 -- writes retain explicit actor and scope arguments.

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from firewall_manager.application.errors import (
    InvalidChangeSetStateError,
    InvalidInputError,
    ResourceOutOfScopeError,
    StaleWriteError,
)
from firewall_manager.domain.models import ChangeSetState, OperationStatus, Principal
from firewall_manager.persistence.models import (
    AccessPolicy,
    AccessRule,
    AuditEvent,
    ChangeSet,
    ChangeSetOperation,
    FirewallManager,
    FirewallObject,
    Group,
    GroupPolicyCategoryMapping,
    ProviderTransaction,
    RuleCategory,
    SecurityZone,
)

_EDITABLE_STATES = {
    ChangeSetState.DRAFT.value,
    ChangeSetState.VALIDATION_FAILED.value,
    ChangeSetState.READY.value,
}


def _as_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise InvalidInputError
    return cast("dict[str, object]", value)


def _as_dict_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise InvalidInputError
    return cast("list[dict[str, object]]", value)


def _as_str_dict(value: object) -> dict[str, str]:
    result = _as_dict(value)
    if not all(isinstance(item, str) for item in result.values()):
        raise InvalidInputError
    return cast("dict[str, str]", result)


def _json_safe(value: object) -> object:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        mapping = cast("dict[object, object]", value)
        result: dict[str, object] = {}
        for key, item in mapping.items():
            if not isinstance(key, str):
                raise InvalidInputError
            result[key] = _json_safe(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in cast("list[object] | tuple[object, ...]", value)]
    return value


class SqlChangeSetRepository:
    """Organization- and Group-scoped ChangeSet persistence with optimistic revisions."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create_change_set(
        self,
        principal: Principal,
        group_id: UUID,
        policy_id: UUID,
        title: str,
        description: str,
        audit_metadata: dict[str, object],
    ) -> dict[str, object]:
        policy = self._session.scalar(
            select(AccessPolicy).where(
                AccessPolicy.id == policy_id,
                AccessPolicy.organization_id == principal.organization_id,
            )
        )
        if policy is None:
            raise ResourceOutOfScopeError
        row = ChangeSet(
            organization_id=principal.organization_id,
            principal_id=principal.user_id,
            acting_group_id=group_id,
            access_policy_id=policy_id,
            target_policy_ids=[str(policy_id)],
            title=title,
            description=description,
            summary=description,
            state=ChangeSetState.DRAFT.value,
            audit_metadata=audit_metadata,
        )
        self._session.add(row)
        self._session.flush()
        return self._change_set_dict(row)

    def list_change_sets(self, principal: Principal, group_id: UUID) -> list[dict[str, object]]:
        rows = list(
            self._session.scalars(
                select(ChangeSet)
                .where(
                    ChangeSet.organization_id == principal.organization_id,
                    ChangeSet.acting_group_id == group_id,
                )
                .order_by(ChangeSet.updated_at.desc(), ChangeSet.id)
            )
        )
        return [self._change_set_dict(row) for row in rows]

    def get_change_set(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> dict[str, object] | None:
        row = self._owned_row(principal, group_id, change_set_id)
        return self._change_set_dict(row) if row else None

    def update_change_set_metadata(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        title: str,
        description: str,
        expected_revision: int,
    ) -> dict[str, object]:
        row = self._require_editable(principal, group_id, change_set_id)
        if row.revision != expected_revision:
            raise StaleWriteError
        row.title = title
        row.description = description
        row.summary = description
        self._invalidate(row)
        self._session.flush()
        return self._change_set_dict(row)

    def add_operation(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        kind: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        change_set = self._require_editable(principal, group_id, change_set_id)
        policy_id = UUID(str(payload.get("policy_id") or change_set.access_policy_id))
        policy = self._session.scalar(
            select(AccessPolicy).where(
                AccessPolicy.id == policy_id,
                AccessPolicy.organization_id == principal.organization_id,
            )
        )
        if policy is None:
            raise ResourceOutOfScopeError
        sequence = (
            int(
                self._session.scalar(
                    select(func.coalesce(func.max(ChangeSetOperation.sequence), 0)).where(
                        ChangeSetOperation.change_set_id == change_set_id
                    )
                )
                or 0
            )
            + 1
        )
        row = ChangeSetOperation(
            organization_id=principal.organization_id,
            change_set_id=change_set_id,
            manager_id=policy.manager_id,
            access_policy_id=policy_id,
            sequence=sequence,
            kind=kind,
            payload=payload,
            status=OperationStatus.DRAFT.value,
        )
        target_ids = set(change_set.target_policy_ids)
        target_ids.add(str(policy_id))
        change_set.target_policy_ids = sorted(target_ids)
        self._invalidate(change_set)
        self._session.add(row)
        self._session.flush()
        return self._operation_dict(row)

    def update_operation(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        operation_id: UUID,
        payload: dict[str, object],
        expected_revision: int,
    ) -> dict[str, object]:
        change_set = self._require_editable(principal, group_id, change_set_id)
        row = self._session.scalar(
            select(ChangeSetOperation).where(
                ChangeSetOperation.id == operation_id,
                ChangeSetOperation.change_set_id == change_set_id,
                ChangeSetOperation.organization_id == principal.organization_id,
            )
        )
        if row is None:
            raise ResourceOutOfScopeError
        if row.revision != expected_revision:
            raise StaleWriteError
        row.payload = payload
        row.validation_results = []
        row.resolution = {}
        row.expected_revisions = {}
        row.status = OperationStatus.DRAFT.value
        row.revision += 1
        self._invalidate(change_set)
        self._session.flush()
        return self._operation_dict(row)

    def remove_operation(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        operation_id: UUID,
    ) -> None:
        change_set = self._require_editable(principal, group_id, change_set_id)
        row = self._session.scalar(
            select(ChangeSetOperation).where(
                ChangeSetOperation.id == operation_id,
                ChangeSetOperation.change_set_id == change_set_id,
                ChangeSetOperation.organization_id == principal.organization_id,
            )
        )
        if row is None:
            raise ResourceOutOfScopeError
        self._session.delete(row)
        self._invalidate(change_set)
        self._session.flush()

    def save_preflight(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        operation_results: list[dict[str, object]],
        state: str,
        provider_snapshot: dict[str, object],
    ) -> dict[str, object]:
        row = self._require_editable(principal, group_id, change_set_id)
        by_id = {UUID(str(item["operation_id"])): item for item in operation_results}
        operations = list(
            self._session.scalars(
                select(ChangeSetOperation).where(
                    ChangeSetOperation.change_set_id == change_set_id,
                    ChangeSetOperation.organization_id == principal.organization_id,
                )
            )
        )
        for operation in operations:
            result = by_id.get(operation.id)
            if result is None:
                continue
            operation.validation_results = _as_dict_list(result.get("checks", []))
            operation.resolution = _as_dict(result.get("resolution", {}))
            operation.expected_revisions = _as_str_dict(result.get("expected_revisions", {}))
            operation.status = str(result.get("status", OperationStatus.INVALID.value))
            operation.revision += 1
        row.validation_results = operation_results
        row.provider_revision_snapshot = provider_snapshot
        row.failure_info = {}
        row.state = state
        row.revision += 1
        row.validated_revision = row.revision
        self._session.flush()
        return self._change_set_dict(row)

    def current_revision_snapshot(
        self, operation: dict[str, object], organization_id: UUID
    ) -> dict[str, str]:
        payload = _as_dict(operation["payload"])
        policy_id = UUID(str(operation["access_policy_id"]))
        policy = self._session.scalar(
            select(AccessPolicy).where(
                AccessPolicy.id == policy_id,
                AccessPolicy.organization_id == organization_id,
            )
        )
        if policy is None:
            return {"policy": "MISSING"}
        snapshot = {"policy": self._resource_token(policy)}
        references: tuple[tuple[str, type[Any], str], ...] = (
            ("rule_id", AccessRule, "rule"),
            ("category_id", RuleCategory, "category"),
        )
        for key, model, label in references:
            if payload.get(key):
                item = self._session.scalar(
                    select(model).where(
                        model.id == UUID(str(payload[key])),
                        model.organization_id == organization_id,
                    )
                )
                snapshot[f"{label}:{payload[key]}"] = (
                    self._resource_token(item) if item is not None else "MISSING"
                )
        for key, model, label in (
            ("source_zone_ids", SecurityZone, "zone"),
            ("destination_zone_ids", SecurityZone, "zone"),
            ("source_object_ids", FirewallObject, "object"),
            ("destination_object_ids", FirewallObject, "object"),
            ("port_object_ids", FirewallObject, "object"),
            ("application_object_ids", FirewallObject, "object"),
            ("url_object_ids", FirewallObject, "object"),
        ):
            raw_values = payload.get(key, [])
            values = cast("list[object]", raw_values) if isinstance(raw_values, list) else []
            for value in values:
                item = self._session.scalar(
                    select(model).where(
                        model.id == UUID(str(value)), model.organization_id == organization_id
                    )
                )
                snapshot[f"{label}:{value}"] = (
                    self._resource_token(item) if item is not None else "MISSING"
                )
        if operation["kind"] == "CREATE_OBJECT":
            objects = list(
                self._session.execute(
                    select(
                        FirewallObject.id,
                        FirewallObject.name,
                        FirewallObject.object_type,
                        FirewallObject.normalized_value,
                        FirewallObject.provider_fingerprint,
                    ).where(
                        FirewallObject.manager_id == operation["manager_id"],
                        FirewallObject.organization_id == organization_id,
                        FirewallObject.management_state != "MISSING",
                    )
                )
            )
            snapshot["object_inventory"] = hashlib.sha256(
                json.dumps([tuple(map(str, item)) for item in objects], sort_keys=True).encode()
            ).hexdigest()
        if operation["kind"] == "MOVE_RULE" or (
            operation["kind"] == "CREATE_RULE" and payload.get("position") is not None
        ):
            ordering = list(
                self._session.execute(
                    select(
                        AccessRule.id,
                        AccessRule.category_id,
                        AccessRule.position,
                        AccessRule.provider_version,
                        AccessRule.provider_fingerprint,
                    ).where(
                        AccessRule.policy_id == policy_id,
                        AccessRule.organization_id == organization_id,
                        AccessRule.management_state != "MISSING",
                    )
                )
            )
            snapshot["rule_ordering"] = hashlib.sha256(
                json.dumps([tuple(map(str, item)) for item in ordering], sort_keys=True).encode()
            ).hexdigest()
        return snapshot

    def naming_context(
        self, policy_id: UUID, group_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None:
        row = self._session.execute(
            select(AccessPolicy, FirewallManager, Group)
            .join(FirewallManager, FirewallManager.id == AccessPolicy.manager_id)
            .join(
                Group,
                (Group.id == group_id) & (Group.organization_id == AccessPolicy.organization_id),
            )
            .where(
                AccessPolicy.id == policy_id,
                AccessPolicy.organization_id == organization_id,
            )
        ).one_or_none()
        if row is None:
            return None
        policy, manager, group = row
        objects = list(
            self._session.scalars(
                select(FirewallObject).where(
                    FirewallObject.manager_id == manager.id,
                    FirewallObject.organization_id == organization_id,
                    FirewallObject.management_state.notin_(("MISSING", "CONFLICT")),
                )
            )
        )
        return {
            "manager_id": manager.id,
            "provider": manager.provider,
            "is_mock": manager.is_mock,
            "group_slug": group.provider_slug,
            "objects": [
                {
                    "object_id": item.id,
                    "name": item.name,
                    "object_type": item.object_type,
                    "normalized_value": item.normalized_value,
                }
                for item in objects
            ],
            "policy_revision": self._resource_token(policy),
        }

    def set_execution_state(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        state: str,
        execution_results: dict[str, object],
        failure_info: dict[str, object],
    ) -> dict[str, object]:
        row = self._owned_row(principal, group_id, change_set_id)
        if row is None:
            raise ResourceOutOfScopeError
        row.state = state
        row.execution_results = cast("dict[str, object]", _json_safe(execution_results))
        row.failure_info = cast("dict[str, object]", _json_safe(failure_info))
        row.revision += 1
        transactions = _as_dict_list(execution_results.get("transactions", []))
        operation_results: dict[UUID, dict[str, object]] = {}
        for transaction in transactions:
            for item in _as_dict_list(transaction.get("operation_results", [])):
                operation_results[UUID(str(item["operation_id"]))] = item
        for operation in self._operations(change_set_id):
            result = operation_results.get(operation.id)
            if result:
                operation.status = str(result["status"])
                operation.execution_result = result
                operation.failure_info = _as_dict(result.get("failure", {}))
                operation.revision += 1
        self._session.flush()
        return self._change_set_dict(row)

    def upsert_provider_transaction(
        self,
        change_set: dict[str, object],
        manager_id: UUID,
        state: str,
        operation_results: list[dict[str, object]],
        failure_info: dict[str, object],
        reconciliation_required: bool,
        external_operation_id: str | None,
    ) -> dict[str, object]:
        change_set_id = UUID(str(change_set["id"]))
        row = self._session.scalar(
            select(ProviderTransaction).where(
                ProviderTransaction.change_set_id == change_set_id,
                ProviderTransaction.manager_id == manager_id,
            )
        )
        if row is None:
            row = ProviderTransaction(
                organization_id=UUID(str(change_set["organization_id"])),
                change_set_id=change_set_id,
                manager_id=manager_id,
                state=state,
            )
            self._session.add(row)
        else:
            row.revision += 1
        row.state = state
        row.operation_results = operation_results
        row.failure_info = failure_info
        row.reconciliation_required = reconciliation_required
        row.external_operation_id = external_operation_id
        self._session.flush()
        return self._transaction_dict(row)

    def manager_execution_target(
        self, manager_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None:
        row = self._session.scalar(
            select(FirewallManager).where(
                FirewallManager.id == manager_id,
                FirewallManager.organization_id == organization_id,
            )
        )
        if row is None:
            return None
        return {
            "id": row.id,
            "provider": row.provider,
            "native_id": row.native_id,
            "base_url": row.base_url,
            "is_mock": row.is_mock,
            "read_only": row.read_only,
        }

    def provider_capability_state(
        self, manager_id: UUID, capability: str, organization_id: UUID
    ) -> str | None:
        capabilities = self._session.scalar(
            select(FirewallManager.capabilities).where(
                FirewallManager.id == manager_id,
                FirewallManager.organization_id == organization_id,
            )
        )
        if not isinstance(capabilities, dict):
            return None
        value = capabilities.get(capability)
        return str(value) if value is not None else None

    def rule_ordering_bounds(
        self,
        group_id: UUID,
        policy_id: UUID,
        category_id: UUID,
        organization_id: UUID,
    ) -> tuple[int, int] | None:
        category = self._session.scalar(
            select(RuleCategory)
            .join(
                GroupPolicyCategoryMapping,
                GroupPolicyCategoryMapping.category_id == RuleCategory.id,
            )
            .where(
                RuleCategory.id == category_id,
                RuleCategory.policy_id == policy_id,
                RuleCategory.organization_id == organization_id,
                GroupPolicyCategoryMapping.group_id == group_id,
                GroupPolicyCategoryMapping.policy_id == policy_id,
                GroupPolicyCategoryMapping.organization_id == organization_id,
                GroupPolicyCategoryMapping.sync_state == "SYNCED",
            )
        )
        if category is None:
            return None
        next_position = self._session.scalar(
            select(func.min(RuleCategory.position)).where(
                RuleCategory.policy_id == policy_id,
                RuleCategory.organization_id == organization_id,
                RuleCategory.position > category.position,
                RuleCategory.management_state != "MISSING",
            )
        )
        upper = int(next_position) - 1 if next_position is not None else 2**31 - 1
        return int(category.position), upper

    def prepare_provider_operations(
        self, operations: list[dict[str, object]], organization_id: UUID
    ) -> list[dict[str, object]]:
        """Resolve application UUIDs to normalized provider identities at the adapter edge."""
        prepared: list[dict[str, object]] = []
        for operation in operations:
            payload = dict(_as_dict(operation["payload"]))
            policy = self._session.scalar(
                select(AccessPolicy).where(
                    AccessPolicy.id == UUID(str(operation["access_policy_id"])),
                    AccessPolicy.organization_id == organization_id,
                )
            )
            if policy is None:
                raise ResourceOutOfScopeError
            provider_payload = dict(payload)
            provider_payload["policy_native_id"] = policy.native_id
            provider_payload["expected_policy_version"] = policy.provider_version
            if payload.get("category_id"):
                category = self._native_resource(
                    RuleCategory, UUID(str(payload["category_id"])), organization_id
                )
                provider_payload["category_native_id"] = category.native_id
            if payload.get("rule_id"):
                rule = self._native_resource(
                    AccessRule, UUID(str(payload["rule_id"])), organization_id
                )
                provider_payload["rule_native_id"] = rule.native_id
                provider_payload["expected_rule_version"] = rule.provider_version
            for source, target, model in (
                ("source_zone_ids", "source_zone_native_ids", SecurityZone),
                ("destination_zone_ids", "destination_zone_native_ids", SecurityZone),
                ("source_object_ids", "source_object_native_ids", FirewallObject),
                ("destination_object_ids", "destination_object_native_ids", FirewallObject),
                ("port_object_ids", "port_object_native_ids", FirewallObject),
                ("application_object_ids", "application_object_native_ids", FirewallObject),
                ("url_object_ids", "url_object_native_ids", FirewallObject),
            ):
                values = payload.get(source, [])
                if isinstance(values, list):
                    provider_payload[target] = [
                        self._native_resource(model, UUID(str(value)), organization_id).native_id
                        for value in cast("list[object]", values)
                    ]
            resolution = dict(_as_dict(operation.get("resolution", {})))
            if str(operation["kind"]) == "CREATE_OBJECT":
                provider_payload["provider_name"] = resolution.get("provider_name")
                provider_payload["normalized_value"] = resolution.get("normalized_value")
                existing_id = resolution.get("existing_object_id")
                if existing_id:
                    resolution["existing_object_native_id"] = self._native_resource(
                        FirewallObject, UUID(str(existing_id)), organization_id
                    ).native_id
                provider_payload["resolution"] = resolution
            prepared.append(
                {
                    "id": str(operation["id"]),
                    "kind": str(operation["kind"]),
                    "provider_payload": provider_payload,
                }
            )
        return prepared

    def group_provider_slug(self, group_id: UUID, organization_id: UUID) -> str | None:
        return self._session.scalar(
            select(Group.provider_slug).where(
                Group.id == group_id, Group.organization_id == organization_id
            )
        )

    def _native_resource(self, model: type[Any], resource_id: UUID, organization_id: UUID) -> Any:
        row = self._session.scalar(
            select(model).where(
                model.id == resource_id,
                model.organization_id == organization_id,
                model.management_state != "MISSING",
            )
        )
        if row is None:
            raise ResourceOutOfScopeError
        return row

    def cancel_change_set(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        row = self._require_editable(principal, group_id, change_set_id)
        row.state = ChangeSetState.CANCELLED.value
        row.revision += 1
        self._session.flush()
        return self._change_set_dict(row)

    def delete_change_set(self, principal: Principal, group_id: UUID, change_set_id: UUID) -> None:
        row = self._require_editable(principal, group_id, change_set_id)
        self._session.execute(
            delete(ChangeSetOperation).where(ChangeSetOperation.change_set_id == row.id)
        )
        self._session.delete(row)
        self._session.flush()

    def record_change_event(
        self,
        principal: Principal,
        group_id: UUID,
        policy_id: UUID,
        change_set_id: UUID,
        action: str,
        result: str,
        details: dict[str, object],
    ) -> None:
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.user_id,
                active_group_id=group_id,
                policy_id=policy_id,
                action=action,
                resource_type="change_set",
                resource_id=change_set_id,
                decision="ALLOW" if result in {"ALLOW", "SUCCEEDED", "READY"} else "DENY",
                reason_code=result,
                interface="application",
                details=details,
                occurred_at=datetime.now(UTC),
            )
        )

    def _owned_row(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> ChangeSet | None:
        return self._session.scalar(
            select(ChangeSet).where(
                ChangeSet.id == change_set_id,
                ChangeSet.organization_id == principal.organization_id,
                ChangeSet.acting_group_id == group_id,
            )
        )

    def _require_editable(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> ChangeSet:
        row = self._owned_row(principal, group_id, change_set_id)
        if row is None:
            raise ResourceOutOfScopeError
        if row.state not in _EDITABLE_STATES:
            raise InvalidChangeSetStateError
        return row

    def _invalidate(self, row: ChangeSet) -> None:
        row.state = ChangeSetState.DRAFT.value
        row.validation_results = []
        row.provider_revision_snapshot = {}
        row.validated_revision = None
        row.revision += 1

    def _operations(self, change_set_id: UUID) -> list[ChangeSetOperation]:
        return list(
            self._session.scalars(
                select(ChangeSetOperation)
                .where(ChangeSetOperation.change_set_id == change_set_id)
                .order_by(ChangeSetOperation.sequence, ChangeSetOperation.id)
            )
        )

    def _change_set_dict(self, row: ChangeSet) -> dict[str, object]:
        return {
            "id": row.id,
            "organization_id": row.organization_id,
            "creator_id": row.principal_id,
            "active_group_id": row.acting_group_id,
            "access_policy_id": row.access_policy_id,
            "target_policy_ids": row.target_policy_ids,
            "title": row.title,
            "description": row.description,
            "state": row.state,
            "revision": row.revision,
            "validated_revision": row.validated_revision,
            "provider_revision_snapshot": row.provider_revision_snapshot,
            "validation_results": row.validation_results,
            "execution_results": row.execution_results,
            "failure_info": row.failure_info,
            "audit_metadata": row.audit_metadata,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "operations": [self._operation_dict(item) for item in self._operations(row.id)],
            "transactions": [
                self._transaction_dict(item)
                for item in self._session.scalars(
                    select(ProviderTransaction)
                    .where(ProviderTransaction.change_set_id == row.id)
                    .order_by(ProviderTransaction.created_at, ProviderTransaction.id)
                )
            ],
        }

    @staticmethod
    def _operation_dict(row: ChangeSetOperation) -> dict[str, object]:
        return {
            "id": row.id,
            "change_set_id": row.change_set_id,
            "manager_id": row.manager_id,
            "access_policy_id": row.access_policy_id,
            "sequence": row.sequence,
            "kind": row.kind,
            "payload": row.payload,
            "expected_revisions": row.expected_revisions,
            "status": row.status,
            "validation_results": row.validation_results,
            "resolution": row.resolution,
            "execution_result": row.execution_result,
            "failure_info": row.failure_info,
            "revision": row.revision,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    @staticmethod
    def _transaction_dict(row: ProviderTransaction) -> dict[str, object]:
        return {
            "id": row.id,
            "manager_id": row.manager_id,
            "state": row.state,
            "operation_results": row.operation_results,
            "failure_info": row.failure_info,
            "reconciliation_required": row.reconciliation_required,
            "external_operation_id": row.external_operation_id,
            "revision": row.revision,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    @staticmethod
    def _resource_token(row: Any) -> str:
        return (
            f"{row.provider_version or ''}:{row.provider_fingerprint}:"
            f"{row.revision}:{row.management_state}"
        )
