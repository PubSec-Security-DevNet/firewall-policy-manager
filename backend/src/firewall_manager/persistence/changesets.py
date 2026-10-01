"""SQL persistence adapter for durable Milestone 3 ChangeSets."""

# ruff: noqa: PLR0913, PLR0917 -- writes retain explicit actor and scope arguments.

import hashlib
import ipaddress
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import CursorResult
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
    EmailNotification,
    FilePolicy,
    FirewallManager,
    FirewallObject,
    Group,
    GroupMembership,
    GroupPolicyCategoryMapping,
    IntrusionPolicy,
    ObjectReference,
    ObjectUseGrant,
    ProviderCapabilityEvidence,
    ProviderConnection,
    ProviderDomain,
    ProviderTransaction,
    RuleCategory,
    RuleZoneReference,
    SecurityZone,
    User,
    VariableSet,
)
from firewall_manager.providers.capabilities import (
    VALIDATION_WRITE_CAPABILITIES,
    effective_write_capabilities,
)

_WRITE_CAPABILITY_BY_OPERATION = {
    "CREATE_RULE": "access_rule_create",
    "MODIFY_RULE": "access_rule_update",
    "DELETE_RULE": "access_rule_delete",
    "MOVE_RULE": "rule_ordering",
    "ENSURE_RULE_CATEGORY": "rule_category_mutation",
}

_OBJECT_CAPABILITY_BY_OPERATION = {
    ("CREATE_OBJECT", "NETWORK"): "network_object_create",
    ("CREATE_OBJECT", "NETWORK_GROUP"): "network_object_create",
    ("CREATE_OBJECT", "PORT_SERVICE"): "port_service_object_create",
    ("CREATE_OBJECT", "PORT_SERVICE_GROUP"): "port_service_object_create",
    ("CREATE_OBJECT", "URL"): "url_object_create",
    ("CREATE_OBJECT", "URL_GROUP"): "url_object_create",
    ("MODIFY_OBJECT", "NETWORK"): "network_object_mutation",
    ("MODIFY_OBJECT", "NETWORK_GROUP"): "network_object_mutation",
    ("MODIFY_OBJECT", "PORT_SERVICE"): "port_service_object_mutation",
    ("MODIFY_OBJECT", "PORT_SERVICE_GROUP"): "port_service_object_mutation",
    ("MODIFY_OBJECT", "URL"): "url_object_mutation",
    ("MODIFY_OBJECT", "URL_GROUP"): "url_object_mutation",
    ("DELETE_OBJECT", "NETWORK"): "network_object_mutation",
    ("DELETE_OBJECT", "NETWORK_GROUP"): "network_object_mutation",
    ("DELETE_OBJECT", "PORT_SERVICE"): "port_service_object_mutation",
    ("DELETE_OBJECT", "PORT_SERVICE_GROUP"): "port_service_object_mutation",
    ("DELETE_OBJECT", "URL"): "url_object_mutation",
    ("DELETE_OBJECT", "URL_GROUP"): "url_object_mutation",
}

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

    def _rule_application_snapshot(self, rule: AccessRule) -> dict[str, object]:
        """Capture the complete application-managed rule intent for reconciliation."""
        values: dict[str, object] = {
            "name": rule.name,
            "action": rule.action,
            "enabled": rule.enabled,
            "logging": "BEGIN" if rule.log_begin else "END" if rule.log_end else "NONE",
            "position": rule.position,
            "category_id": str(rule.category_id) if rule.category_id else None,
            "intrusion_policy_id": str(rule.intrusion_policy_id)
            if rule.intrusion_policy_id
            else None,
            "variable_set_id": str(rule.variable_set_id) if rule.variable_set_id else None,
            "file_policy_id": str(rule.file_policy_id) if rule.file_policy_id else None,
        }
        object_keys = {
            "SOURCE_NETWORK": "source_object_ids",
            "DESTINATION_NETWORK": "destination_object_ids",
            "SOURCE_PORT": "source_port_object_ids",
            "DESTINATION_PORT": "destination_port_object_ids",
            "PORT_SERVICE": "destination_port_object_ids",
            "APPLICATION": "application_object_ids",
            "URL": "url_object_ids",
        }
        for key in set(object_keys.values()):
            values[key] = []
        for target_id, element_type in self._session.execute(
            select(ObjectReference.target_object_id, ObjectReference.element_type).where(
                ObjectReference.source_rule_id == rule.id
            )
        ):
            key = object_keys.get(str(element_type))
            if key:
                cast("list[str]", values[key]).append(str(target_id))
        values["source_zone_ids"] = []
        values["destination_zone_ids"] = []
        for zone_id, element_type in self._session.execute(
            select(RuleZoneReference.zone_id, RuleZoneReference.element_type).where(
                RuleZoneReference.rule_id == rule.id
            )
        ):
            key = "source_zone_ids" if str(element_type) == "SOURCE" else "destination_zone_ids"
            cast("list[str]", values[key]).append(str(zone_id))
        return values

    def _object_application_snapshot(self, row: FirewallObject) -> dict[str, object]:
        values: dict[str, object] = {
            "name": row.name,
            "object_type": row.object_type,
            "normalized_value": row.normalized_value,
        }
        if str(row.object_type).endswith("_GROUP"):
            values["member_object_ids"] = [
                str(target_id)
                for (target_id,) in self._session.execute(
                    select(ObjectReference.target_object_id).where(
                        ObjectReference.source_object_id == row.id,
                        ObjectReference.element_type == "MEMBER",
                    )
                )
            ]
        return values

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

    def list_pending_approvals(self, principal: Principal) -> list[dict[str, object]]:
        rows = list(
            self._session.scalars(
                select(ChangeSet)
                .join(Group, Group.id == ChangeSet.acting_group_id)
                .join(
                    GroupMembership,
                    (GroupMembership.group_id == Group.id)
                    & (GroupMembership.organization_id == Group.organization_id),
                )
                .where(
                    ChangeSet.organization_id == principal.organization_id,
                    ChangeSet.state == ChangeSetState.READY.value,
                    ChangeSet.principal_id != principal.user_id,
                    Group.approval_required.is_(True),
                    Group.is_active.is_(True),
                    GroupMembership.user_id == principal.user_id,
                    GroupMembership.status == "ACTIVE",
                )
                .order_by(ChangeSet.updated_at.asc(), ChangeSet.id),
            )
        )
        return [self._change_set_dict(row) for row in rows]

    def list_all_change_sets(self, principal: Principal) -> list[dict[str, object]]:
        rows = list(
            self._session.scalars(
                select(ChangeSet)
                .where(ChangeSet.organization_id == principal.organization_id)
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

    def rule_id_by_native(
        self, manager_id: UUID, native_id: str, organization_id: UUID
    ) -> UUID | None:
        return self._session.scalar(
            select(AccessRule.id).where(
                AccessRule.manager_id == manager_id,
                AccessRule.native_id == native_id,
                AccessRule.organization_id == organization_id,
            )
        )

    def object_id_by_native(
        self, manager_id: UUID, native_id: str, organization_id: UUID
    ) -> UUID | None:
        return self._session.scalar(
            select(FirewallObject.id).where(
                FirewallObject.manager_id == manager_id,
                FirewallObject.native_id == native_id,
                FirewallObject.organization_id == organization_id,
            )
        )

    def rule_revision(self, rule_id: UUID, organization_id: UUID) -> int | None:
        row = self._session.scalar(
            select(AccessRule.revision).where(
                AccessRule.id == rule_id,
                AccessRule.organization_id == organization_id,
            )
        )
        return int(row) if row is not None else None

    def object_revision(self, object_id: UUID, organization_id: UUID) -> int | None:
        row = self._session.scalar(
            select(FirewallObject.revision).where(
                FirewallObject.id == object_id,
                FirewallObject.organization_id == organization_id,
            )
        )
        return int(row) if row is not None else None

    def rule_management_state(self, rule_id: UUID, organization_id: UUID) -> str | None:
        return self._session.scalar(
            select(AccessRule.management_state).where(
                AccessRule.id == rule_id,
                AccessRule.organization_id == organization_id,
            )
        )

    def object_management_state(self, object_id: UUID, organization_id: UUID) -> str | None:
        return self._session.scalar(
            select(FirewallObject.management_state).where(
                FirewallObject.id == object_id,
                FirewallObject.organization_id == organization_id,
            )
        )

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
            operation.rollback_snapshot = self._rollback_snapshot(operation)
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
        if state == ChangeSetState.READY.value:
            group = self._session.scalar(
                select(Group).where(
                    Group.id == group_id, Group.organization_id == principal.organization_id
                )
            )
            if group is not None and group.approval_required:
                approvers = self._session.scalars(
                    select(User)
                    .join(GroupMembership, GroupMembership.user_id == User.id)
                    .where(
                        GroupMembership.organization_id == principal.organization_id,
                        GroupMembership.group_id == group_id,
                        GroupMembership.status == "ACTIVE",
                        User.organization_id == principal.organization_id,
                        User.is_active.is_(True),
                        User.role.in_(("approver", "firewall_admin", "admin")),
                        User.id != principal.user_id,
                    )
                ).all()
                dedupe_key = f"changeset-approval:{row.id}:{row.revision}"
                for approver in approvers:
                    exists = self._session.scalar(
                        select(EmailNotification.id).where(
                            EmailNotification.organization_id == principal.organization_id,
                            EmailNotification.recipient_user_id == approver.id,
                            EmailNotification.dedupe_key == dedupe_key,
                        )
                    )
                    if exists is None:
                        self._session.add(
                            EmailNotification(
                                organization_id=principal.organization_id,
                                recipient_user_id=approver.id,
                                recipient_email=approver.email,
                                kind="CHANGESET_APPROVAL_REQUIRED",
                                dedupe_key=dedupe_key,
                                subject=f"Approval required: {row.title}"[:255],
                                body=(
                                    f"A ChangeSet is waiting for your approval.\n\n"
                                    f"Title: {row.title}\n"
                                    f"Group: {group.name}\n"
                                    f"Submitted by: {principal.email}\n"
                                    f"Revision: {row.revision}\n\n"
                                    "Open the Approvals page in Firewall Manager to review it."
                                ),
                            )
                        )
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
            ("object_id", FirewallObject, "object"),
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
            ("source_port_object_ids", FirewallObject, "object"),
            ("destination_port_object_ids", FirewallObject, "object"),
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
        if operation["kind"] == "ENSURE_RULE_CATEGORY":
            categories = list(
                self._session.execute(
                    select(
                        RuleCategory.id,
                        RuleCategory.native_id,
                        RuleCategory.name,
                        RuleCategory.provider_version,
                        RuleCategory.provider_fingerprint,
                        RuleCategory.management_state,
                    ).where(
                        RuleCategory.policy_id == policy_id,
                        RuleCategory.organization_id == organization_id,
                    )
                )
            )
            snapshot["category_inventory"] = hashlib.sha256(
                json.dumps([tuple(map(str, item)) for item in categories], sort_keys=True).encode()
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

    def object_mutation_context(
        self, object_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None:
        row = self._session.execute(
            select(FirewallObject, AccessPolicy)
            .join(AccessPolicy, AccessPolicy.manager_id == FirewallObject.manager_id)
            .where(
                FirewallObject.id == object_id,
                FirewallObject.organization_id == organization_id,
                AccessPolicy.id == policy_id,
                AccessPolicy.organization_id == organization_id,
            )
        ).one_or_none()
        if row is None:
            return None
        item, policy = row
        return {
            "object_id": item.id,
            "manager_id": item.manager_id,
            "object_type": item.object_type,
            "name": item.name,
            "expected_provider_name": item.expected_provider_name,
            "normalized_value": item.normalized_value,
            "provider_version": item.provider_version,
            "provider_fingerprint": item.provider_fingerprint,
            "management_state": item.management_state,
            "policy_id": policy.id,
        }

    def object_equivalent_id(
        self,
        manager_id: UUID,
        object_type: str,
        normalized_value: str,
        excluded_object_id: UUID,
        organization_id: UUID,
    ) -> UUID | None:
        return self._session.scalar(
            select(FirewallObject.id).where(
                FirewallObject.organization_id == organization_id,
                FirewallObject.manager_id == manager_id,
                FirewallObject.object_type == object_type,
                FirewallObject.normalized_value == normalized_value,
                FirewallObject.id != excluded_object_id,
                FirewallObject.management_state.notin_(("MISSING", "CONFLICT")),
            )
        )

    def category_ensure_context(
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
        _policy, manager, group = row
        mapping = self._session.scalar(
            select(GroupPolicyCategoryMapping).where(
                GroupPolicyCategoryMapping.organization_id == organization_id,
                GroupPolicyCategoryMapping.group_id == group_id,
                GroupPolicyCategoryMapping.policy_id == policy_id,
            )
        )
        categories = list(
            self._session.scalars(
                select(RuleCategory).where(
                    RuleCategory.organization_id == organization_id,
                    RuleCategory.policy_id == policy_id,
                    RuleCategory.management_state != "MISSING",
                )
            )
        )
        return {
            "provider": manager.provider,
            "group_slug": group.provider_slug,
            "mapping": (
                {
                    "id": mapping.id,
                    "category_id": mapping.category_id,
                    "expected_category_name": mapping.expected_category_name,
                    "sync_state": mapping.sync_state,
                    "revision": mapping.revision,
                }
                if mapping
                else None
            ),
            "categories": [
                {
                    "id": item.id,
                    "native_id": item.native_id,
                    "name": item.name,
                    "provider_version": item.provider_version,
                    "management_state": item.management_state,
                    "position": item.position,
                }
                for item in categories
            ],
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

    def commit_provider_transaction_intent(self) -> None:
        """Durably record a real transaction before any external mutation can occur."""
        self._session.commit()

    def queue_execution(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        """Claim a validated ChangeSet once before publishing its worker message."""
        row = self._owned_row(principal, group_id, change_set_id)
        if (
            row is None
            or row.state
            not in (
                {ChangeSetState.APPROVED.value}
                if bool(self._change_set_dict(row).get("approval_required"))
                else {ChangeSetState.READY.value, ChangeSetState.APPROVED.value}
            )
            or row.validated_revision != row.revision
        ):
            raise InvalidChangeSetStateError
        row.state = ChangeSetState.QUEUED.value
        row.submitted_at = datetime.now(UTC)
        row.submitted_by_user_id = principal.user_id
        row.revision += 1
        row.validated_revision = row.revision
        self._session.flush()
        return self._change_set_dict(row)

    def approve_change_set(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        row = self._owned_row(principal, group_id, change_set_id)
        if row is None or row.state != ChangeSetState.READY.value:
            raise InvalidChangeSetStateError
        member = self._session.scalar(
            select(GroupMembership).where(
                GroupMembership.organization_id == principal.organization_id,
                GroupMembership.group_id == group_id,
                GroupMembership.user_id == principal.user_id,
                GroupMembership.status == "ACTIVE",
            )
        )
        if member is None:
            raise ResourceOutOfScopeError
        if row.principal_id == principal.user_id:
            raise InvalidChangeSetStateError(details={"code": "SEPARATION_OF_DUTY"})
        row.state = ChangeSetState.APPROVED.value
        row.approved_at = datetime.now(UTC)
        row.approved_by_user_id = principal.user_id
        row.approved_revision = row.revision
        row.revision += 1
        row.validated_revision = row.revision
        self._session.flush()
        return self._change_set_dict(row)

    def recover_expired_execution_leases(self, *, now: datetime | None = None) -> list[UUID]:
        current = now or datetime.now(UTC)
        rows = list(
            self._session.scalars(
                select(ChangeSet)
                .where(
                    ChangeSet.state == ChangeSetState.EXECUTING.value,
                    ChangeSet.execution_lease_until.is_not(None),
                    ChangeSet.execution_lease_until < current,
                )
                .with_for_update(skip_locked=True)
            )
        )
        recovered: list[UUID] = []
        for row in rows:
            transactions = list(
                self._session.scalars(
                    select(ProviderTransaction).where(
                        ProviderTransaction.change_set_id == row.id,
                        ProviderTransaction.state.in_(("EXECUTING", "AMBIGUOUS")),
                    )
                )
            )
            row.execution_owner = None
            row.execution_lease_until = None
            row.execution_heartbeat_at = current
            if transactions:
                row.failure_info = {
                    "code": "EXECUTION_LEASE_EXPIRED",
                    "recovery": "RECONCILIATION_REQUIRED",
                    "transaction_ids": [str(item.id) for item in transactions],
                }
                row.state = ChangeSetState.RECONCILIATION_REQUIRED.value
                for transaction in transactions:
                    transaction.state = "RECONCILIATION_REQUIRED"
                    transaction.reconciliation_required = True
                    transaction.failure_info = {"code": "EXECUTION_LEASE_EXPIRED"}
                    transaction.revision += 1
            else:
                row.failure_info = {"code": "EXECUTION_LEASE_EXPIRED", "recovery": "ELIGIBLE"}
                row.state = ChangeSetState.QUEUED.value
            row.revision += 1
            if row.state == ChangeSetState.QUEUED.value:
                recovered.append(row.id)
        self._session.flush()
        return recovered

    def acquire_execution_lease(
        self, change_set_id: UUID, owner: str, *, lease_seconds: int = 120
    ) -> bool:
        now = datetime.now(UTC)
        result = self._session.execute(
            update(ChangeSet)
            .where(
                ChangeSet.id == change_set_id,
                ChangeSet.state == ChangeSetState.EXECUTING.value,
                (
                    ChangeSet.execution_lease_until.is_(None)
                    | (ChangeSet.execution_lease_until < now)
                ),
            )
            .values(
                execution_owner=owner,
                execution_lease_until=now + timedelta(seconds=lease_seconds),
                execution_heartbeat_at=now,
            )
        )
        self._session.flush()
        return bool(cast("CursorResult[Any]", result).rowcount)

    def heartbeat_execution_lease(
        self, change_set_id: UUID, owner: str, *, lease_seconds: int = 120
    ) -> bool:
        now = datetime.now(UTC)
        result = self._session.execute(
            update(ChangeSet)
            .where(
                ChangeSet.id == change_set_id,
                ChangeSet.execution_owner == owner,
            )
            .values(
                execution_lease_until=now + timedelta(seconds=lease_seconds),
                execution_heartbeat_at=now,
            )
        )
        self._session.flush()
        return bool(cast("CursorResult[Any]", result).rowcount)

    def commit_change_set_queue(self) -> None:
        """Commit the unique queue claim before a fast worker can consume it."""
        self._session.commit()

    def claim_queued_execution(
        self, principal: Principal, group_id: UUID, change_set_id: UUID, owner: str | None = None
    ) -> bool:
        """Atomically allow only one worker delivery to execute provider writes."""
        claimed = self._session.execute(
            update(ChangeSet)
            .where(
                ChangeSet.id == change_set_id,
                ChangeSet.organization_id == principal.organization_id,
                ChangeSet.acting_group_id == group_id,
                ChangeSet.principal_id == principal.user_id,
                ChangeSet.state == ChangeSetState.QUEUED.value,
            )
            .values(
                state=ChangeSetState.EXECUTING.value,
                updated_at=datetime.now(UTC),
                execution_owner=owner,
                execution_lease_until=(datetime.now(UTC) + timedelta(seconds=120))
                if owner
                else None,
                execution_heartbeat_at=datetime.now(UTC) if owner else None,
            )
            .execution_options(synchronize_session=False)
        )
        self._session.commit()
        # The worker preloads the ChangeSet for scope validation. Refresh that
        # identity-map entry so subsequent reads see the atomically claimed state.
        self._session.expire_all()
        return bool(cast("CursorResult[Any]", claimed).rowcount)

    def manager_execution_target(
        self, manager_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None:
        manager = self._session.scalar(
            select(FirewallManager)
            .where(
                FirewallManager.id == manager_id,
                FirewallManager.organization_id == organization_id,
            )
            .with_for_update()
        )
        if manager is None:
            return None
        connection = None
        if manager.provider_connection_id is not None:
            connection = self._session.scalar(
                select(ProviderConnection)
                .where(
                    ProviderConnection.id == manager.provider_connection_id,
                    ProviderConnection.organization_id == organization_id,
                )
                .with_for_update()
            )
        return {
            "id": manager.id,
            "organization_id": manager.organization_id,
            "provider": manager.provider,
            "native_id": manager.native_id,
            "base_url": manager.base_url,
            "is_mock": manager.is_mock,
            "read_only": manager.read_only,
            "provider_type": connection.provider_type if connection else manager.provider,
            "provider_connection_id": connection.id if connection else None,
            "credential_reference": connection.credential_reference if connection else None,
            "display_name": connection.display_name if connection else manager.display_name,
            "region": connection.region if connection else None,
            "base_endpoint": connection.base_endpoint if connection else manager.base_url,
            "write_enabled": connection.write_enabled if connection else manager.is_mock,
            "lifecycle": connection.lifecycle if connection else "ACTIVE",
            "connection_status": connection.connection_status if connection else "CONNECTED",
            "provider_version": (
                connection.provider_version if connection else manager.provider_version
            ),
            "capabilities": effective_write_capabilities(
                dict(manager.capabilities),
                validation_writes_enabled=bool(
                    connection and connection.write_enabled and not manager.is_mock
                ),
            ),
        }

    def provider_capability_state(
        self, manager_id: UUID, capability: str, organization_id: UUID
    ) -> str | None:
        row = self._session.execute(
            select(FirewallManager, ProviderConnection)
            .outerjoin(
                ProviderConnection,
                ProviderConnection.id == FirewallManager.provider_connection_id,
            )
            .where(
                FirewallManager.id == manager_id,
                FirewallManager.organization_id == organization_id,
            )
        ).one_or_none()
        if row is None:
            return None
        manager, connection = row
        capabilities = effective_write_capabilities(
            dict(manager.capabilities),
            validation_writes_enabled=bool(
                connection and connection.write_enabled and not manager.is_mock
            ),
        )
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
        bounds = self._session.execute(
            select(func.min(AccessRule.position), func.max(AccessRule.position)).where(
                AccessRule.policy_id == policy_id,
                AccessRule.category_id == category.id,
                AccessRule.organization_id == organization_id,
                AccessRule.management_state != "MISSING",
            )
        ).one()
        if bounds[0] is None or bounds[1] is None:
            return None
        return int(bounds[0]), int(bounds[1])

    def prepare_provider_operations(  # noqa: PLR0912, PLR0915 -- explicit adapter-edge mapping
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
            domain = self._native_resource(ProviderDomain, policy.domain_id, organization_id)
            provider_payload["domain_native_id"] = domain.native_id
            provider_payload["expected_revisions"] = dict(
                _as_str_dict(operation.get("expected_revisions", {}))
            )
            if payload.get("category_id"):
                category = self._native_resource(
                    RuleCategory, UUID(str(payload["category_id"])), organization_id
                )
                provider_payload["category_native_id"] = category.native_id
                provider_payload["expected_category_name"] = category.name
                if category.provider_version:
                    provider_payload["expected_category_version"] = category.provider_version
            for source, target, model in (
                ("intrusion_policy_id", "intrusion_policy_native_id", IntrusionPolicy),
                ("variable_set_id", "variable_set_native_id", VariableSet),
                ("file_policy_id", "file_policy_native_id", FilePolicy),
            ):
                if payload.get(source):
                    resource = self._native_resource(
                        model, UUID(str(payload[source])), organization_id
                    )
                    if (
                        resource.manager_id != policy.manager_id
                        or resource.domain_id != policy.domain_id
                    ):
                        raise ResourceOutOfScopeError
                    provider_payload[target] = resource.native_id
            if payload.get("rule_id"):
                rule = self._native_resource(
                    AccessRule, UUID(str(payload["rule_id"])), organization_id
                )
                provider_payload["rule_native_id"] = rule.native_id
                provider_payload["expected_rule_name"] = rule.name
                provider_payload["expected_rule_action"] = rule.action
                if rule.provider_version:
                    provider_payload["expected_rule_version"] = rule.provider_version
            if payload.get("anchor_rule_id"):
                anchor_rule = self._native_resource(
                    AccessRule, UUID(str(payload["anchor_rule_id"])), organization_id
                )
                provider_payload["anchor_rule_native_id"] = anchor_rule.native_id
            if payload.get("object_id"):
                item = self._native_resource(
                    FirewallObject, UUID(str(payload["object_id"])), organization_id
                )
                provider_payload["object_native_id"] = item.native_id
                if item.provider_version:
                    provider_payload["expected_object_version"] = item.provider_version
                provider_payload["expected_provider_name"] = item.expected_provider_name
            for source, target, model in (
                ("source_zone_ids", "source_zone_native_ids", SecurityZone),
                ("destination_zone_ids", "destination_zone_native_ids", SecurityZone),
                ("source_object_ids", "source_object_native_ids", FirewallObject),
                ("destination_object_ids", "destination_object_native_ids", FirewallObject),
                ("port_object_ids", "port_object_native_ids", FirewallObject),
                ("source_port_object_ids", "source_port_object_native_ids", FirewallObject),
                (
                    "destination_port_object_ids",
                    "destination_port_object_native_ids",
                    FirewallObject,
                ),
                ("application_object_ids", "application_object_native_ids", FirewallObject),
                ("url_object_ids", "url_object_native_ids", FirewallObject),
            ):
                values = payload.get(source, [])
                if isinstance(values, list):
                    provider_payload[target] = [
                        self._provider_reference(
                            self._native_resource(model, UUID(str(value)), organization_id)
                        )
                        for value in cast("list[object]", values)
                    ]
            if payload.get("intrusion_policy_id") and bool(payload.get("enabled", True)):
                intrusion = self._native_resource(
                    IntrusionPolicy, UUID(str(payload["intrusion_policy_id"])), organization_id
                )
                if not payload.get("variable_set_id") and intrusion.default_variable_set_native_id:
                    provider_payload["variable_set_native_id"] = (
                        intrusion.default_variable_set_native_id
                    )
            resolution = dict(_as_dict(operation.get("resolution", {})))
            if str(operation["kind"]) == "CREATE_OBJECT":
                provider_payload["provider_name"] = resolution.get("provider_name")
                provider_payload["normalized_value"] = resolution.get("normalized_value")
                member_ids = resolution.get(
                    "member_object_ids", payload.get("member_object_ids", [])
                )
                if isinstance(member_ids, list):
                    provider_payload["member_object_native_ids"] = [
                        self._native_resource(
                            FirewallObject, UUID(str(value)), organization_id
                        ).native_id
                        for value in member_ids
                    ]
                    provider_payload["member_object_references"] = [
                        self._provider_reference(
                            self._native_resource(FirewallObject, UUID(str(value)), organization_id)
                        )
                        for value in member_ids
                    ]
                existing_id = resolution.get("existing_object_id")
                if existing_id:
                    resolution["existing_object_native_id"] = self._native_resource(
                        FirewallObject, UUID(str(existing_id)), organization_id
                    ).native_id
                provider_payload["resolution"] = resolution
            elif str(operation["kind"]) == "MODIFY_OBJECT":
                provider_payload["normalized_value"] = resolution.get("normalized_value")
            elif str(operation["kind"]) == "ENSURE_RULE_CATEGORY":
                provider_payload["provider_name"] = resolution.get("provider_name")
                category_id = resolution.get("category_id")
                if category_id:
                    category = self._native_resource(
                        RuleCategory, UUID(str(category_id)), organization_id
                    )
                    provider_payload["category_native_id"] = category.native_id
                    if category.provider_version:
                        provider_payload["expected_category_version"] = category.provider_version
            elif str(operation["kind"]) == "CREATE_RULE":
                provider_payload["name"] = resolution.get("provider_name", payload.get("name"))
                provider_payload["category_provider_name"] = resolution.get(
                    "category_provider_name"
                )
                category_id = resolution.get("category_id")
                if category_id:
                    category = self._native_resource(
                        RuleCategory, UUID(str(category_id)), organization_id
                    )
                    provider_payload["category_native_id"] = category.native_id
            prepared.append(
                {
                    "id": str(operation["id"]),
                    "kind": str(operation["kind"]),
                    "provider_payload": provider_payload,
                }
            )
        return prepared

    @staticmethod
    def _provider_reference(row: Any) -> dict[str, str]:
        """Build the typed object reference required by FMC/cdFMC rule payloads."""
        if isinstance(row, SecurityZone):
            provider_type = "SecurityZone"
        elif isinstance(row, FirewallObject):
            provider_type = {
                "NETWORK_GROUP": "NetworkGroup",
                "PORT_SERVICE": "ProtocolPortObject",
                "PORT_SERVICE_GROUP": "PortObjectGroup",
                "URL": "Url",
                "URL_GROUP": "UrlGroup",
                "APPLICATION": "Application",
                "APPLICATION_FILTER": "ApplicationFilter",
            }.get(row.object_type, "Network")
            if row.object_type == "NETWORK" and row.normalized_value:
                if row.normalized_value.count("-") == 1:
                    provider_type = "Range"
                else:
                    parsed = ipaddress.ip_network(row.normalized_value, strict=False)
                    provider_type = (
                        "Host" if parsed.prefixlen == parsed.max_prefixlen else "Network"
                    )
        else:
            provider_type = type(row).__name__
        reference = {"id": str(row.native_id), "name": str(row.name), "type": provider_type}
        if isinstance(row, FirewallObject) and row.object_type == "APPLICATION_FILTER":
            reference["object_type"] = str(row.object_type)
            if row.normalized_value:
                reference["normalized_value"] = str(row.normalized_value)
        return reference

    def reconcile_successful_operations(  # noqa: PLR0912, PLR0915 -- typed operation reducer
        self,
        change_set: dict[str, object],
        principal: Principal,
        group_id: UUID,
        operations: list[dict[str, object]],
        operation_results: list[dict[str, object]],
    ) -> None:
        """Persist ownership and provider state only after unambiguous provider success."""
        del change_set  # Scope is carried by the immutable operation and principal records.
        by_id = {str(item.get("operation_id")): item for item in operation_results}
        for operation in operations:
            result = by_id.get(str(operation["id"]))
            if result is None or result.get("status") != OperationStatus.SUCCEEDED.value:
                continue
            payload = _as_dict(operation["payload"])
            resolution = _as_dict(operation.get("resolution", {}))
            kind = str(operation["kind"])
            policy = self._session.scalar(
                select(AccessPolicy).where(
                    AccessPolicy.id == UUID(str(operation["access_policy_id"])),
                    AccessPolicy.organization_id == principal.organization_id,
                )
            )
            if policy is None:
                raise ResourceOutOfScopeError
            provider_resource = _as_dict(result.get("provider_resource", {}))
            if kind == "CREATE_OBJECT" and result.get("mutated") is True:
                native_id = str(result["provider_resource_id"])
                row = self._session.scalar(
                    select(FirewallObject).where(
                        FirewallObject.manager_id == policy.manager_id,
                        FirewallObject.native_id == native_id,
                    )
                )
                if row is None:
                    row = FirewallObject(
                        id=uuid4(),
                        organization_id=principal.organization_id,
                        manager_id=policy.manager_id,
                        domain_id=policy.domain_id,
                        native_id=native_id,
                        name=str(resolution["provider_name"]),
                        expected_provider_name=str(resolution["provider_name"]),
                        provider_version=str(provider_resource.get("native_version", "1")),
                        provider_fingerprint=str(provider_resource["fingerprint"]),
                        native_metadata={},
                        management_state="MANAGED",
                        revision=1,
                        owner_group_id=group_id,
                        owner_policy_id=policy.id,
                        created_by_user_id=principal.user_id,
                        modified_by_user_id=principal.user_id,
                        object_type=str(payload["object_type"]),
                        normalized_value=str(resolution["normalized_value"]),
                        sharing_mode="private",
                    )
                    self._session.add(row)
                    self._session.flush()
                    for permission in ("read", "use"):
                        self._session.add(
                            ObjectUseGrant(
                                organization_id=principal.organization_id,
                                group_id=group_id,
                                policy_id=policy.id,
                                object_id=row.id,
                                permission=permission,
                            )
                        )
                member_ids = payload.get("member_object_ids", [])
                if str(payload.get("object_type", "")).endswith("_GROUP") and isinstance(
                    member_ids, list
                ):
                    self._replace_object_group_references(row, payload, principal.organization_id)
                row.application_snapshot = self._object_application_snapshot(row)
            elif kind == "MODIFY_OBJECT":
                row = self._native_resource(
                    FirewallObject, UUID(str(payload["object_id"])), principal.organization_id
                )
                row.normalized_value = str(resolution["normalized_value"])
                row.provider_version = str(provider_resource["native_version"])
                row.provider_fingerprint = str(provider_resource["fingerprint"])
                row.modified_by_user_id = principal.user_id
                row.management_state = "MANAGED"
                row.revision += 1
                row.application_snapshot = self._object_application_snapshot(row)
            elif kind == "DELETE_OBJECT":
                row = self._native_resource(
                    FirewallObject, UUID(str(payload["object_id"])), principal.organization_id
                )
                row.management_state = "MISSING"
                row.modified_by_user_id = principal.user_id
                row.revision += 1
            elif kind == "ENSURE_RULE_CATEGORY" and result.get("mutated") is True:
                category = RuleCategory(
                    organization_id=principal.organization_id,
                    manager_id=policy.manager_id,
                    policy_id=policy.id,
                    native_id=str(result["provider_resource_id"]),
                    name=str(resolution["provider_name"]),
                    provider_version=str(provider_resource.get("native_version", "1")),
                    provider_fingerprint=str(provider_resource["fingerprint"]),
                    native_metadata={},
                    management_state="MANAGED",
                    revision=1,
                    position=int(str(provider_resource["position"])),
                )
                self._session.add(category)
                self._session.flush()
                self._session.add(
                    GroupPolicyCategoryMapping(
                        organization_id=principal.organization_id,
                        group_id=group_id,
                        policy_id=policy.id,
                        category_id=category.id,
                        expected_category_name=str(resolution["provider_name"]),
                        sync_state="SYNCED",
                        revision=1,
                    )
                )
            elif kind == "CREATE_RULE":
                category = None
                category_id = payload.get("category_id") or resolution.get("category_id")
                if category_id:
                    category = self._native_resource(
                        RuleCategory, UUID(str(category_id)), principal.organization_id
                    )
                if category is None:
                    mapping = self._session.scalar(
                        select(GroupPolicyCategoryMapping).where(
                            GroupPolicyCategoryMapping.organization_id == principal.organization_id,
                            GroupPolicyCategoryMapping.group_id == group_id,
                            GroupPolicyCategoryMapping.policy_id == policy.id,
                            GroupPolicyCategoryMapping.sync_state == "SYNCED",
                        )
                    )
                    if mapping is not None:
                        category = self._native_resource(
                            RuleCategory, mapping.category_id, principal.organization_id
                        )
                native_id = str(result["provider_resource_id"])
                provider_name = str(resolution.get("provider_name", payload["name"]))
                rule = self._session.scalar(
                    select(AccessRule).where(
                        AccessRule.organization_id == principal.organization_id,
                        AccessRule.policy_id == policy.id,
                        AccessRule.native_id == native_id,
                    )
                )
                if rule is not None and (
                    rule.owner_group_id != group_id or rule.name != provider_name
                ):
                    raise StaleWriteError
                if rule is None:
                    rule = AccessRule(
                        organization_id=principal.organization_id,
                        manager_id=policy.manager_id,
                        policy_id=policy.id,
                        native_id=native_id,
                        name=provider_name,
                        native_metadata={},
                        revision=1,
                        created_by_user_id=principal.user_id,
                    )
                    self._session.add(rule)
                rule.category_id = category.id if category else None
                rule.provider_version = str(provider_resource.get("native_version", ""))
                rule.provider_fingerprint = str(provider_resource["fingerprint"])
                rule.management_state = "MANAGED"
                rule.owner_group_id = group_id
                rule.modified_by_user_id = principal.user_id
                rule.action = str(payload["action"])
                rule.enabled = bool(payload.get("enabled", True))
                logging_mode = str(payload.get("logging", "NONE")).upper()
                rule.log_begin = logging_mode == "BEGIN"
                rule.log_end = logging_mode == "END"
                rule.intrusion_policy_id = self._native_resource_id_from_payload(
                    IntrusionPolicy, payload.get("intrusion_policy_id"), principal.organization_id
                )
                rule.variable_set_id = self._rule_variable_set_id(
                    payload, principal.organization_id, rule.manager_id, rule.enabled
                )
                rule.file_policy_id = self._native_resource_id_from_payload(
                    FilePolicy, payload.get("file_policy_id"), principal.organization_id
                )
                rule.position = int(
                    str(payload.get("position", provider_resource.get("position", 0)))
                )
                self._session.flush()
                self._replace_rule_references(rule, payload, principal.organization_id)
                rule.application_snapshot = self._rule_application_snapshot(rule)
            elif kind in {"MODIFY_RULE", "MOVE_RULE"}:
                rule = self._native_resource(
                    AccessRule, UUID(str(payload["rule_id"])), principal.organization_id
                )
                if payload.get("category_id"):
                    category = self._native_resource(
                        RuleCategory,
                        UUID(str(payload["category_id"])),
                        principal.organization_id,
                    )
                    rule.category_id = category.id
                if kind == "MODIFY_RULE":
                    rule.name = str(payload.get("name", rule.name))
                    rule.action = str(payload.get("action", rule.action))
                    rule.enabled = bool(payload.get("enabled", rule.enabled))
                    logging_mode = str(payload.get("logging", "NONE")).upper()
                    rule.log_begin = logging_mode == "BEGIN"
                    rule.log_end = logging_mode == "END"
                    rule.intrusion_policy_id = self._native_resource_id_from_payload(
                        IntrusionPolicy,
                        payload.get("intrusion_policy_id"),
                        principal.organization_id,
                    )
                    rule.variable_set_id = self._rule_variable_set_id(
                        payload, principal.organization_id, rule.manager_id, rule.enabled
                    )
                    rule.file_policy_id = self._native_resource_id_from_payload(
                        FilePolicy, payload.get("file_policy_id"), principal.organization_id
                    )
                    self._replace_rule_references(rule, payload, principal.organization_id)
                if kind == "MOVE_RULE" and result.get("provider_resource_id"):
                    rule.native_id = str(result["provider_resource_id"])
                if payload.get("position") is not None:
                    rule.position = int(str(payload["position"]))
                rule.provider_version = str(provider_resource.get("native_version", ""))
                rule.provider_fingerprint = str(provider_resource["fingerprint"])
                rule.modified_by_user_id = principal.user_id
                rule.management_state = "MANAGED"
                rule.revision += 1
                rule.application_snapshot = self._rule_application_snapshot(rule)
            elif kind == "DELETE_RULE":
                rule = self._native_resource(
                    AccessRule, UUID(str(payload["rule_id"])), principal.organization_id
                )
                self._session.execute(
                    delete(ObjectReference).where(ObjectReference.source_rule_id == rule.id)
                )
                self._session.execute(
                    delete(RuleZoneReference).where(RuleZoneReference.rule_id == rule.id)
                )
                # This is an application-initiated deletion that completed at the
                # provider.  It is not a provider-side disappearance.  Retaining
                # the row as MISSING turns a successful delete into a false
                # reconciliation discrepancy on the next sync.  Change-set and
                # transaction history retain the audit trail, so remove the
                # normalized resource from the active inventory instead.
                self._session.delete(rule)
        self._session.flush()

    def record_successful_write_evidence(
        self,
        change_set: dict[str, object],
        principal: Principal,
        manager_id: UUID,
        operations: list[dict[str, object]],
        operation_results: list[dict[str, object]],
    ) -> set[str]:
        """Promote only capabilities proven by successful live provider mutations."""
        manager = self._session.scalar(
            select(FirewallManager)
            .where(
                FirewallManager.id == manager_id,
                FirewallManager.organization_id == principal.organization_id,
                FirewallManager.is_mock.is_(False),
            )
            .with_for_update()
        )
        if manager is None or manager.provider_connection_id is None:
            return set()
        connection = self._session.scalar(
            select(ProviderConnection)
            .where(
                ProviderConnection.id == manager.provider_connection_id,
                ProviderConnection.organization_id == principal.organization_id,
            )
            .with_for_update()
        )
        if connection is None or not connection.provider_version:
            return set()

        results = {str(item.get("operation_id")): item for item in operation_results}
        proven = {
            "pending_change_inspection"
            for result in results.values()
            if result.get("status") == OperationStatus.SUCCEEDED.value
        }
        for operation in operations:
            result = results.get(str(operation["id"]))
            if (
                result is None
                or result.get("status") != OperationStatus.SUCCEEDED.value
                or result.get("mutated") is not True
            ):
                continue
            kind = str(operation["kind"])
            capability = _WRITE_CAPABILITY_BY_OPERATION.get(kind)
            if capability is None:
                payload = _as_dict(operation.get("payload", {}))
                object_type = str(payload.get("object_type", ""))
                if not object_type and payload.get("object_id"):
                    owned_object = self._session.get(
                        FirewallObject, UUID(str(payload["object_id"]))
                    )
                    object_type = owned_object.object_type if owned_object is not None else ""
                capability = _OBJECT_CAPABILITY_BY_OPERATION.get((kind, object_type))
            if capability in VALIDATION_WRITE_CAPABILITIES:
                proven.add(capability)

        now = datetime.now(UTC)
        promoted: set[str] = set()
        for capability in proven:
            evidence = self._session.scalar(
                select(ProviderCapabilityEvidence).where(
                    ProviderCapabilityEvidence.connection_id == connection.id,
                    ProviderCapabilityEvidence.provider_version == connection.provider_version,
                    ProviderCapabilityEvidence.capability == capability,
                )
            )
            if evidence is None:
                evidence = ProviderCapabilityEvidence(
                    organization_id=principal.organization_id,
                    connection_id=connection.id,
                    provider_version=connection.provider_version,
                    capability=capability,
                )
                self._session.add(evidence)
            if evidence.status == "SUPPORTED" and evidence.evidence_level == "TESTED":
                continue
            evidence.status = "SUPPORTED"
            evidence.evidence_level = "TESTED"
            evidence.evidence_summary = (
                f"Live provider operation succeeded in ChangeSet {change_set['id']}."
            )
            evidence.tested_at = now
            promoted.add(capability)

        if promoted:
            manager.capabilities = {
                **manager.capabilities,
                **dict.fromkeys(promoted, "SUPPORTED"),
            }
            manager.revision += 1
            self._session.add(
                AuditEvent(
                    organization_id=principal.organization_id,
                    actor_user_id=principal.user_id,
                    action="manage_providers",
                    resource_type="provider_connection",
                    resource_id=connection.id,
                    decision="SUCCESS",
                    reason_code="live_write_capabilities_tested",
                    interface="worker",
                    details={
                        "provider": connection.provider_type,
                        "provider_version": connection.provider_version,
                        "change_set_id": str(change_set["id"]),
                        "capabilities": sorted(promoted),
                    },
                )
            )
            self._session.flush()
        return promoted

    def _replace_rule_references(
        self, rule: AccessRule, payload: dict[str, object], organization_id: UUID
    ) -> None:
        """Replace normalized rule elements only after an unambiguous provider success."""
        self._session.execute(
            delete(ObjectReference).where(ObjectReference.source_rule_id == rule.id)
        )
        self._session.execute(delete(RuleZoneReference).where(RuleZoneReference.rule_id == rule.id))
        for key, element in (
            ("source_object_ids", "SOURCE_NETWORK"),
            ("destination_object_ids", "DESTINATION_NETWORK"),
            ("port_object_ids", "PORT_SERVICE"),
            ("source_port_object_ids", "SOURCE_PORT"),
            ("destination_port_object_ids", "DESTINATION_PORT"),
            ("application_object_ids", "APPLICATION"),
            ("url_object_ids", "URL"),
        ):
            values = payload.get(key, [])
            if isinstance(values, list):
                for value in cast("list[object]", values):
                    item = self._native_resource(FirewallObject, UUID(str(value)), organization_id)
                    self._session.add(
                        ObjectReference(
                            organization_id=organization_id,
                            manager_id=rule.manager_id,
                            source_rule_id=rule.id,
                            target_object_id=item.id,
                            element_type=element,
                        )
                    )
        for key, element in (
            ("source_zone_ids", "SOURCE"),
            ("destination_zone_ids", "DESTINATION"),
        ):
            values = payload.get(key, [])
            if isinstance(values, list):
                for value in cast("list[object]", values):
                    zone = self._native_resource(SecurityZone, UUID(str(value)), organization_id)
                    self._session.add(
                        RuleZoneReference(
                            organization_id=organization_id,
                            manager_id=rule.manager_id,
                            rule_id=rule.id,
                            zone_id=zone.id,
                            element_type=element,
                        )
                    )

    def _replace_object_group_references(
        self,
        source_object: FirewallObject,
        payload: dict[str, object],
        organization_id: UUID,
    ) -> None:
        """Persist group membership after the provider confirms group creation."""
        self._session.execute(
            delete(ObjectReference).where(ObjectReference.source_object_id == source_object.id)
        )
        values = payload.get("member_object_ids", [])
        if not isinstance(values, list):
            return
        for value in cast("list[object]", values):
            member = self._native_resource(FirewallObject, UUID(str(value)), organization_id)
            self._session.add(
                ObjectReference(
                    organization_id=organization_id,
                    manager_id=source_object.manager_id,
                    source_object_id=source_object.id,
                    target_object_id=member.id,
                    element_type="MEMBER",
                )
            )

    def group_provider_slug(self, group_id: UUID, organization_id: UUID) -> str | None:
        return self._session.scalar(
            select(Group.provider_slug).where(
                Group.id == group_id, Group.organization_id == organization_id
            )
        )

    def _native_resource_id_from_payload(
        self, model: type[Any], value: object, organization_id: UUID
    ) -> UUID | None:
        if not value:
            return None
        return self._native_resource(model, UUID(str(value)), organization_id).id

    def _rule_variable_set_id(
        self, payload: dict[str, object], organization_id: UUID, manager_id: UUID, enabled: bool
    ) -> UUID | None:
        selected = self._native_resource_id_from_payload(
            VariableSet, payload.get("variable_set_id"), organization_id
        )
        if selected is not None or not enabled or not payload.get("intrusion_policy_id"):
            return selected
        intrusion = self._native_resource(
            IntrusionPolicy, UUID(str(payload["intrusion_policy_id"])), organization_id
        )
        if not intrusion.default_variable_set_native_id:
            return None
        return self._session.scalar(
            select(VariableSet.id).where(
                VariableSet.manager_id == manager_id,
                VariableSet.native_id == intrusion.default_variable_set_native_id,
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

    def delete_admin_change_set(self, principal: Principal, change_set_id: UUID) -> None:
        row = self._session.scalar(
            select(ChangeSet).where(
                ChangeSet.id == change_set_id,
                ChangeSet.organization_id == principal.organization_id,
            )
        )
        if row is None:
            raise ResourceOutOfScopeError
        if row.state not in _EDITABLE_STATES:
            raise InvalidChangeSetStateError
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
                decision=(
                    "ALLOW"
                    if result
                    in {
                        "ALLOW",
                        "SUCCEEDED",
                        "READY",
                        "QUEUED",
                        "EXECUTING",
                        "PARTIALLY_SUCCEEDED",
                        "RECONCILIATION_REQUIRED",
                    }
                    else "DENY"
                ),
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
        creator = self._session.scalar(
            select(User).where(
                User.id == row.principal_id,
                User.organization_id == row.organization_id,
            )
        )
        group = self._session.get(Group, row.acting_group_id) if row.acting_group_id else None
        return {
            "id": row.id,
            "organization_id": row.organization_id,
            "creator_id": row.principal_id,
            "creator_display_name": creator.display_name if creator else None,
            "creator_email": creator.email if creator else None,
            "active_group_id": row.acting_group_id,
            "approval_required": bool(group.approval_required) if group else False,
            "access_policy_id": row.access_policy_id,
            "target_policy_ids": row.target_policy_ids,
            "title": row.title,
            "description": row.description,
            "state": row.state,
            "revision": row.revision,
            "validated_revision": row.validated_revision,
            "submitted_at": row.submitted_at,
            "submitted_by_user_id": row.submitted_by_user_id,
            "approved_at": row.approved_at,
            "approved_by_user_id": row.approved_by_user_id,
            "approved_revision": row.approved_revision,
            "approval_invalidated_at": row.approval_invalidated_at,
            "execution_owner": row.execution_owner,
            "execution_lease_until": row.execution_lease_until,
            "execution_heartbeat_at": row.execution_heartbeat_at,
            "execution_operation": row.execution_operation,
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
            "rollback_snapshot": row.rollback_snapshot,
            "execution_result": row.execution_result,
            "failure_info": row.failure_info,
            "revision": row.revision,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def _rollback_snapshot(self, operation: ChangeSetOperation) -> dict[str, object]:
        """Capture the normalized state immediately before a ChangeSet is validated."""
        payload = operation.payload
        kind = operation.kind
        if kind in {"MODIFY_RULE", "DELETE_RULE", "MOVE_RULE"} and payload.get("rule_id"):
            rule = self._session.get(AccessRule, UUID(str(payload["rule_id"])))
            if rule is not None:
                return {
                    "resource_type": "rule",
                    "resource_id": str(rule.id),
                    "provider_native_id": rule.native_id,
                    "revision": rule.revision,
                    "fingerprint": rule.provider_fingerprint,
                    "state": self._rule_application_snapshot(rule),
                }
        if kind in {"MODIFY_OBJECT", "DELETE_OBJECT"} and payload.get("object_id"):
            item = self._session.get(FirewallObject, UUID(str(payload["object_id"])))
            if item is not None:
                return {
                    "resource_type": "object",
                    "resource_id": str(item.id),
                    "provider_native_id": item.native_id,
                    "revision": item.revision,
                    "fingerprint": item.provider_fingerprint,
                    "state": self._object_application_snapshot(item),
                }
        return {"resource_type": "none"}

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
            "lease_owner": row.lease_owner,
            "lease_until": row.lease_until,
            "heartbeat_at": row.heartbeat_at,
            "last_probe_at": row.last_probe_at,
            "provider_metadata": row.provider_metadata,
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
