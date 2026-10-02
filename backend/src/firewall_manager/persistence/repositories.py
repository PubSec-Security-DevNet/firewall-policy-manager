"""SQLAlchemy implementations of application repository ports."""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import UUID

from sqlalchemy import ColumnElement, and_, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from firewall_manager.application.errors import (
    InvalidInputError,
    ProviderContractError,
    ResourceOutOfScopeError,
    StaleWriteError,
)
from firewall_manager.domain.models import (
    AuthorizationDecision,
    CapabilityStatus,
    ChangeSetState,
    DiscoveredCategory,
    DiscoveredDevice,
    DiscoveredDomain,
    DiscoveredFilePolicy,
    DiscoveredIntrusionPolicy,
    DiscoveredObject,
    DiscoveredObjectReference,
    DiscoveredPolicy,
    DiscoveredRule,
    DiscoveredVariableSet,
    DiscoveredZone,
    DiscoveredZoneReference,
    FirewallObjectType,
    NativeResource,
    Principal,
    ProviderEvidenceProfile,
    ProviderInfo,
    ProviderKind,
    ResourceState,
    SyncResult,
    SyncStatus,
)
from firewall_manager.domain.networks import network_is_contained
from firewall_manager.persistence.models import (
    AccessPolicy,
    AccessRule,
    AuditEvent,
    AuthenticationEvent,
    ChangeSet,
    ChangeSetOperation,
    Deployment,
    Device,
    DirectUserPolicyGrant,
    DriftRecord,
    ExternalIdentity,
    FilePolicy,
    FirewallManager,
    FirewallObject,
    Group,
    GroupMembership,
    GroupPolicyCategoryMapping,
    IntrusionPolicy,
    IpRangeGrant,
    ObjectCreateGrant,
    ObjectReference,
    ObjectUseGrant,
    Organization,
    PolicyDelegation,
    ProviderConnection,
    ProviderDomain,
    RuleCategory,
    RuleZoneReference,
    SecurityZone,
    SyncRun,
    User,
    VariableSet,
    ZoneGrant,
)
from firewall_manager.providers.capabilities import (
    CapabilityEvidenceMismatchError,
    default_capability_path,
    effective_write_capabilities,
    load_capabilities,
    verify_capability_evidence,
)

SyncedModel = TypeVar(
    "SyncedModel",
    ProviderDomain,
    Device,
    AccessPolicy,
    IntrusionPolicy,
    FilePolicy,
    RuleCategory,
    AccessRule,
    FirewallObject,
    SecurityZone,
    VariableSet,
)
_SENSITIVE_METADATA_PARTS = ("secret", "password", "token", "authorization", "private_key")
_USABLE_STATES = ("OBSERVED", "UNMANAGED", "MANAGED")
_CONTEXT_RESOURCE_STATES = (
    "OBSERVED",
    "UNMANAGED",
    "MANAGED",
    "PENDING_ADOPTION",
    "DRIFTED",
    "MISSING",
    "CONFLICT",
)
_OBJECT_CREATE_CAPABILITY_NAMES = {
    "NETWORK": "network_object_create",
    "NETWORK_GROUP": "network_object_create",
    "PORT_SERVICE": "port_service_object_create",
    "PORT_SERVICE_GROUP": "port_service_object_create",
    "URL": "url_object_create",
    "URL_GROUP": "url_object_create",
    "APPLICATION": "application_object_create",
    "APPLICATION_FILTER": "application_object_create",
}
_PROVIDER_SHARED_OBJECT_TYPES = (
    FirewallObjectType.APPLICATION.value,
    FirewallObjectType.APPLICATION_FILTER.value,
)


def sanitize_provider_metadata(metadata: dict[str, str]) -> dict[str, str]:
    """Drop keys that could cause credentials to persist in provider metadata."""
    return {
        key: value
        for key, value in metadata.items()
        if not any(part in key.casefold() for part in _SENSITIVE_METADATA_PARTS)
    }


class SqlOverviewRepository:
    """Organization-scoped read queries used by API application services."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def principal_by_email(self, email: str) -> Principal | None:
        user = self._session.scalar(
            select(User).where(User.email == email, User.is_active.is_(True))
        )
        if user is None:
            return None
        return Principal(
            user.id,
            user.organization_id,
            user.email,
            user.role,
            user.identity_issuer,
            user.identity_subject,
        )

    def organization_name(self, organization_id: UUID) -> str | None:
        return self._session.scalar(
            select(Organization.name).where(Organization.id == organization_id)
        )

    def development_identities(self) -> list[dict[str, object]]:
        """List deterministic identities only for the conditionally mounted dev-auth route."""
        rows = list(
            self._session.scalars(
                select(User)
                .where(User.identity_issuer == "urn:firewall-manager:development")
                .order_by(User.display_name, User.id)
            )
        )
        return [
            {
                "email": row.email,
                "display_name": row.display_name,
                "role": row.role,
                "enabled": row.is_active,
            }
            for row in rows
        ]

    def counts(self, organization_id: UUID) -> dict[str, int]:
        real_manager_ids = select(FirewallManager.id).where(
            FirewallManager.organization_id == organization_id,
            FirewallManager.is_mock.is_(False),
        )
        real_policy_ids = select(AccessPolicy.id).where(
            AccessPolicy.organization_id == organization_id,
            AccessPolicy.manager_id.in_(real_manager_ids),
        )
        return {
            "managers": self._count(
                FirewallManager,
                FirewallManager.organization_id == organization_id,
                FirewallManager.is_mock.is_(False),
            ),
            "policies": self._count(
                AccessPolicy,
                AccessPolicy.organization_id == organization_id,
                AccessPolicy.manager_id.in_(real_manager_ids),
            ),
            "rules": self._count(
                AccessRule,
                AccessRule.organization_id == organization_id,
                AccessRule.policy_id.in_(real_policy_ids),
            ),
            "objects": self._count(
                FirewallObject,
                FirewallObject.organization_id == organization_id,
                FirewallObject.manager_id.in_(real_manager_ids),
            ),
            "change_sets": self._count(
                ChangeSet,
                ChangeSet.organization_id == organization_id,
                ChangeSet.state.in_(
                    (
                        ChangeSetState.READY.value,
                        ChangeSetState.QUEUED.value,
                        ChangeSetState.EXECUTING.value,
                    )
                ),
            ),
        }

    def provider_summaries(self, organization_id: UUID) -> list[dict[str, object]]:
        """Return real normalized providers represented in the application inventory."""
        managers = list(
            self._session.scalars(
                select(FirewallManager)
                .where(
                    FirewallManager.organization_id == organization_id,
                    FirewallManager.is_mock.is_(False),
                )
                .order_by(FirewallManager.display_name, FirewallManager.id)
            )
        )
        summaries: list[dict[str, object]] = []
        for manager in managers:
            policy_count = self._session.scalar(
                select(func.count())
                .select_from(AccessPolicy)
                .where(
                    AccessPolicy.organization_id == organization_id,
                    AccessPolicy.manager_id == manager.id,
                )
            )
            object_count = self._session.scalar(
                select(func.count())
                .select_from(FirewallObject)
                .where(
                    FirewallObject.organization_id == organization_id,
                    FirewallObject.manager_id == manager.id,
                )
            )
            rule_count = self._session.scalar(
                select(func.count())
                .select_from(AccessRule)
                .join(AccessPolicy, AccessPolicy.id == AccessRule.policy_id)
                .where(
                    AccessRule.organization_id == organization_id,
                    AccessPolicy.manager_id == manager.id,
                )
            )
            summaries.append(
                {
                    "provider": manager.provider,
                    "display_name": manager.display_name,
                    "provider_version": manager.provider_version or "Unknown",
                    "policy_count": int(policy_count or 0),
                    "rule_count": int(rule_count or 0),
                    "object_count": int(object_count or 0),
                    "writable": not manager.read_only,
                }
            )
        return summaries

    def _count(self, model: type[Any], *where: ColumnElement[bool]) -> int:
        value = self._session.scalar(select(func.count()).select_from(model).where(*where))
        return int(value or 0)

    def _page(
        self,
        model: type[Any],
        where: Sequence[ColumnElement[bool]],
        offset: int,
        limit: int,
        order_by: Any | None = None,
    ) -> tuple[list[Any], int]:
        total = int(
            self._session.scalar(select(func.count()).select_from(model).where(*where)) or 0
        )
        rows = list(
            self._session.scalars(
                select(model)
                .where(*where)
                .order_by(order_by if order_by is not None else model.name, model.id)
                .offset(offset)
                .limit(limit)
            )
        )
        return rows, total

    def list_managers(
        self, organization_id: UUID, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        rows, total = self._page(
            FirewallManager,
            [
                FirewallManager.organization_id == organization_id,
                FirewallManager.is_mock.is_(False),
            ],
            offset,
            limit,
            FirewallManager.display_name,
        )
        return [
            {
                "id": row.id,
                "provider": row.provider,
                "display_name": row.display_name,
                "read_only": row.read_only,
                "provider_version": row.provider_version,
                "revision": row.revision,
            }
            for row in rows
        ], total

    def list_policies(
        self, organization_id: UUID, manager_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        real_manager_ids = select(FirewallManager.id).where(
            FirewallManager.organization_id == organization_id,
            FirewallManager.is_mock.is_(False),
        )
        where = [
            AccessPolicy.organization_id == organization_id,
            AccessPolicy.manager_id.in_(real_manager_ids),
        ]
        if manager_id is not None:
            where.append(AccessPolicy.manager_id == manager_id)
        rows, total = self._page(AccessPolicy, where, offset, limit)
        return [self._resource_dict(row) for row in rows], total

    def list_rules(
        self, organization_id: UUID, policy_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        real_policy_ids = select(AccessPolicy.id).where(
            AccessPolicy.organization_id == organization_id,
            AccessPolicy.manager_id.in_(
                select(FirewallManager.id).where(
                    FirewallManager.organization_id == organization_id,
                    FirewallManager.is_mock.is_(False),
                )
            ),
        )
        where = [
            AccessRule.organization_id == organization_id,
            AccessRule.policy_id.in_(real_policy_ids),
        ]
        if policy_id is not None:
            where.append(AccessRule.policy_id == policy_id)
        rows, total = self._page(AccessRule, where, offset, limit)
        return [
            {
                **self._resource_dict(row),
                "policy_id": row.policy_id,
                "category_id": row.category_id,
                "action": row.action,
                "enabled": row.enabled,
                "logging": "BEGIN" if row.log_begin else "END" if row.log_end else "NONE",
                "position": row.position,
            }
            for row in rows
        ], total

    def list_objects(
        self, organization_id: UUID, manager_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        real_manager_ids = select(FirewallManager.id).where(
            FirewallManager.organization_id == organization_id,
            FirewallManager.is_mock.is_(False),
        )
        where = [
            FirewallObject.organization_id == organization_id,
            FirewallObject.manager_id.in_(real_manager_ids),
        ]
        if manager_id is not None:
            where.append(FirewallObject.manager_id == manager_id)
        where.append(~FirewallObject.object_type.in_(_PROVIDER_SHARED_OBJECT_TYPES))
        rows, total = self._page(FirewallObject, where, offset, limit)
        return [
            {
                **self._resource_dict(row),
                "object_type": row.object_type,
                "value": row.normalized_value,
                "sharing_mode": row.sharing_mode,
            }
            for row in rows
        ], total

    @staticmethod
    def _resource_dict(row: Any) -> dict[str, object]:
        return {
            "id": row.id,
            "manager_id": row.manager_id,
            "name": row.name,
            "management_state": row.management_state,
            "revision": row.revision,
            "provider_version": row.provider_version,
        }

    def provider_status(self, organization_id: UUID) -> list[dict[str, object]]:
        connections = {
            row.id: row
            for row in self._session.scalars(
                select(ProviderConnection).where(
                    ProviderConnection.organization_id == organization_id
                )
            )
        }
        managers = list(
            self._session.scalars(
                select(FirewallManager)
                .where(FirewallManager.organization_id == organization_id)
                .where(FirewallManager.is_mock.is_(False))
                .order_by(FirewallManager.display_name)
            )
        )
        result: list[dict[str, object]] = []
        for manager in managers:
            connection = (
                connections.get(manager.provider_connection_id)
                if manager.provider_connection_id is not None
                else None
            )
            latest = self._session.scalar(
                select(SyncRun)
                .where(
                    SyncRun.organization_id == organization_id,
                    SyncRun.manager_id == manager.id,
                )
                .order_by(SyncRun.started_at.desc())
                .limit(1)
            )
            current_status = connection.sync_status if connection is not None else None
            is_active_sync = current_status in {"QUEUED", "RUNNING"}
            capabilities = dict(manager.capabilities)
            # Keep the historical keys for API compatibility, while exposing the
            # discovery/mutation split explicitly. Group CRUD is governed by the
            # corresponding object-mutation capability.
            capabilities.update(
                {
                    "network_group_discovery": capabilities.get("network_groups", "UNKNOWN"),
                    "network_group_mutation": capabilities.get(
                        "network_object_mutation", "UNKNOWN"
                    ),
                    "port_object_group_discovery": capabilities.get(
                        "port_objects_groups", "UNKNOWN"
                    ),
                    "port_object_group_mutation": capabilities.get(
                        "port_service_object_mutation", "UNKNOWN"
                    ),
                    "url_group_discovery": capabilities.get("url_groups", "UNKNOWN"),
                    "url_group_mutation": capabilities.get("url_object_mutation", "UNKNOWN"),
                    "rollback_changeset": "SUPPORTED",
                    "provider_native_rollback": "UNSUPPORTED",
                }
            )
            for legacy_name in ("network_groups", "port_objects_groups", "url_groups", "rollback"):
                capabilities.pop(legacy_name, None)
            result.append(
                {
                    "manager_id": manager.id,
                    "connection_id": manager.provider_connection_id,
                    "provider": manager.provider,
                    "display_name": manager.display_name,
                    "provider_version": manager.provider_version,
                    "capabilities": capabilities,
                    "evidence_profile": (
                        ProviderEvidenceProfile.MOCK.value
                        if manager.is_mock
                        else ProviderEvidenceProfile.REAL.value
                    ),
                    "writable": not manager.read_only,
                    "sync_status": current_status or (latest.status if latest else None),
                    "sync_complete": False
                    if is_active_sync
                    else (latest.complete if latest else False),
                    "resources_seen": latest.resources_seen if latest else 0,
                    "last_sync_at": (
                        connection.last_sync
                        if connection is not None and connection.last_sync is not None
                        else latest.completed_at
                        if latest
                        else None
                    ),
                    "error_code": (
                        connection.last_error_code
                        if connection is not None and not is_active_sync
                        else latest.error_code
                        if latest
                        else None
                    ),
                }
            )
        return result

    def synchronization_discrepancies(  # noqa: PLR0912, PLR0913, PLR0917 -- explicit state reducer
        self,
        organization_id: UUID,
        manager_id: UUID | None = None,
        policy_id: UUID | None = None,
        resource_type: str | None = None,
        state: str | None = None,
        connection_id: UUID | None = None,
    ) -> list[dict[str, object]]:
        """Return bounded, organization-scoped drift evidence without provider payload leaks."""
        query = (
            select(DriftRecord)
            .join(FirewallManager, FirewallManager.id == DriftRecord.manager_id)
            .where(
                DriftRecord.organization_id == organization_id,
                FirewallManager.is_mock.is_(False),
            )
        )
        if manager_id is not None:
            query = query.where(DriftRecord.manager_id == manager_id)
        if resource_type is not None:
            query = query.where(DriftRecord.resource_type == resource_type)
        if state is not None:
            query = query.where(DriftRecord.status == state)
        if connection_id is not None:
            query = query.join(FirewallManager, FirewallManager.id == DriftRecord.manager_id).where(
                FirewallManager.provider_connection_id == connection_id
            )
        rows = list(self._session.scalars(query.order_by(DriftRecord.created_at.desc()).limit(500)))
        result: dict[tuple[str, UUID], dict[str, object]] = {}
        for row in rows:
            if row.resource_type == "firewall_objects":
                object_row = self._session.get(FirewallObject, row.resource_id)
                if (
                    object_row is not None
                    and object_row.object_type in _PROVIDER_SHARED_OBJECT_TYPES
                ):
                    continue
            item = self._drift_response(row, policy_id)
            if item is not None:
                result[(row.resource_type, row.resource_id)] = item
        # Missing and provider-only resources do not necessarily have a DriftRecord. Include
        # them from the authoritative normalized inventory without changing ownership state.
        resource_models: tuple[tuple[str, type[Any]], ...] = (
            ("provider_domains", ProviderDomain),
            ("devices", Device),
            ("access_policies", AccessPolicy),
            ("intrusion_policies", IntrusionPolicy),
            ("variable_sets", VariableSet),
            ("file_policies", FilePolicy),
            ("rule_categories", RuleCategory),
            ("access_rules", AccessRule),
            ("firewall_objects", FirewallObject),
            ("security_zones", SecurityZone),
        )
        managers = select(
            FirewallManager.id, FirewallManager.provider, FirewallManager.provider_connection_id
        ).where(FirewallManager.is_mock.is_(False))
        manager_rows = {
            manager_id_value: (provider, provider_connection_id)
            for manager_id_value, provider, provider_connection_id in self._session.execute(
                managers
            )
            if manager_id is None or manager_id_value == manager_id
            if connection_id is None or provider_connection_id == connection_id
        }
        for table_name, model in resource_models:
            inventory_query = select(model).where(
                model.organization_id == organization_id,
                model.manager_id.in_(manager_rows),
            )
            if table_name == "firewall_objects":
                inventory_query = inventory_query.where(
                    ~FirewallObject.object_type.in_(_PROVIDER_SHARED_OBJECT_TYPES)
                )
            for resource in self._session.scalars(inventory_query):
                if resource.management_state in {"OBSERVED", "UNMANAGED"}:
                    display_state = "OBSERVED"
                    provider_only = True
                elif resource.management_state not in {"DRIFTED", "MISSING", "CONFLICT"}:
                    continue
                else:
                    display_state = resource.management_state
                    provider_only = False
                resource_policy_id = getattr(resource, "policy_id", None)
                if policy_id is not None and resource_policy_id != policy_id:
                    continue
                if resource_type is not None and resource_type != table_name:
                    continue
                if state is not None and state != display_state:
                    continue
                provider, provider_connection_id = manager_rows[resource.manager_id]
                key = (table_name, resource.id)
                result.setdefault(
                    key,
                    {
                        "id": resource.id,
                        "manager_id": resource.manager_id,
                        "connection_id": provider_connection_id,
                        "provider": provider,
                        "resource_type": table_name,
                        "resource_id": resource.id,
                        "name": resource.name,
                        "policy_id": resource_policy_id,
                        "state": display_state,
                        "provider_only": provider_only,
                        "previous_fingerprint": None,
                        "observed_fingerprint": resource.provider_fingerprint,
                        "previous_snapshot": resource.application_snapshot or {},
                        "observed_snapshot": self._resource_snapshot(resource),
                        "details": {
                            "summary": (
                                "Provider resource is not known to application ownership"
                                if provider_only
                                else f"Resource is {display_state.lower()}"
                            )
                        },
                        "created_at": resource.updated_at,
                    },
                )
        return list(result.values())

    def _drift_response(self, row: DriftRecord, policy_id: UUID | None) -> dict[str, object] | None:
        resource_models: dict[str, type[Any]] = {
            "provider_domains": ProviderDomain,
            "devices": Device,
            "access_policies": AccessPolicy,
            "intrusion_policies": IntrusionPolicy,
            "variable_sets": VariableSet,
            "file_policies": FilePolicy,
            "rule_categories": RuleCategory,
            "access_rules": AccessRule,
            "firewall_objects": FirewallObject,
            "security_zones": SecurityZone,
        }
        model = resource_models.get(row.resource_type)
        resource = self._session.get(model, row.resource_id) if model else None
        if (
            resource is None
            or resource.management_state != row.status
            or resource.last_seen_sync_run_id != row.sync_run_id
        ):
            return None
        resource_policy_id = getattr(resource, "policy_id", None)
        if policy_id is not None and resource_policy_id != policy_id:
            return None
        manager = self._session.get(FirewallManager, row.manager_id)
        if manager is None:
            return None
        return {
            "id": row.id,
            "manager_id": row.manager_id,
            "connection_id": manager.provider_connection_id,
            "provider": manager.provider,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "name": str(
                (row.observed_snapshot or {}).get("name")
                or getattr(resource, "name", row.resource_id)
            ),
            "policy_id": resource_policy_id,
            "state": row.status,
            "provider_only": False,
            "previous_fingerprint": row.previous_fingerprint,
            "observed_fingerprint": row.observed_fingerprint,
            "previous_snapshot": row.previous_snapshot or {},
            "observed_snapshot": row.observed_snapshot or {},
            "details": row.details,
            "created_at": row.created_at,
        }

    def _resource_snapshot(self, resource: Any) -> dict[str, object]:
        values = {"name": resource.name, "fingerprint": resource.provider_fingerprint}
        for key in (
            "action",
            "enabled",
            "position",
            "category_id",
            "object_type",
            "normalized_value",
            "zone_type",
            "model",
        ):
            value = getattr(resource, key, None)
            if value is not None:
                values[key] = str(value) if isinstance(value, UUID) else value
        if isinstance(resource, AccessRule):
            object_keys = {
                "SOURCE_NETWORK": "source_object_ids",
                "DESTINATION_NETWORK": "destination_object_ids",
                "SOURCE_PORT": "source_port_object_ids",
                "DESTINATION_PORT": "destination_port_object_ids",
                "PORT_SERVICE": "destination_port_object_ids",
                "APPLICATION": "application_object_ids",
                "URL": "url_object_ids",
            }
            object_values: dict[str, list[str]] = {key: [] for key in object_keys.values()}
            for target_id, element_type in self._session.execute(
                select(ObjectReference.target_object_id, ObjectReference.element_type).where(
                    ObjectReference.source_rule_id == resource.id
                )
            ):
                key = object_keys.get(str(element_type))
                if key:
                    object_values[key].append(str(target_id))
            zone_keys = {"SOURCE": "source_zone_ids", "DESTINATION": "destination_zone_ids"}
            zone_values: dict[str, list[str]] = {key: [] for key in zone_keys.values()}
            for zone_id, element_type in self._session.execute(
                select(RuleZoneReference.zone_id, RuleZoneReference.element_type).where(
                    RuleZoneReference.rule_id == resource.id
                )
            ):
                key = zone_keys.get(str(element_type))
                if key:
                    zone_values[key].append(str(zone_id))
            values.update(object_values)
            values.update(zone_values)
            values["logging"] = (
                "BEGIN" if resource.log_begin else "END" if resource.log_end else "NONE"
            )
            values["intrusion_policy_id"] = (
                str(resource.intrusion_policy_id) if resource.intrusion_policy_id else None
            )
            values["variable_set_id"] = (
                str(resource.variable_set_id) if resource.variable_set_id else None
            )
            values["file_policy_id"] = (
                str(resource.file_policy_id) if resource.file_policy_id else None
            )
        elif isinstance(resource, FirewallObject):
            values["member_object_ids"] = [
                str(target_id)
                for (target_id,) in self._session.execute(
                    select(ObjectReference.target_object_id).where(
                        ObjectReference.source_object_id == resource.id,
                        ObjectReference.element_type == "MEMBER",
                    )
                )
            ]
        return values

    def _drift_belongs_to_policy(self, row: DriftRecord, policy_id: UUID) -> bool:
        tables = {"access_rules": AccessRule, "rule_categories": RuleCategory}
        model = tables.get(row.resource_type)
        if model is None:
            return True
        return (
            self._session.scalar(
                select(model.id).where(model.id == row.resource_id, model.policy_id == policy_id)
            )
            is not None
        )

    def accept_provider_state(
        self, organization_id: UUID, drift_id: UUID, actor_user_id: UUID
    ) -> dict[str, object] | None:
        """Accept only the already-synchronized observation; never infer ownership."""
        row = self._session.scalar(
            select(DriftRecord).where(
                DriftRecord.id == drift_id, DriftRecord.organization_id == organization_id
            )
        )
        if row is None:
            return None
        resource_models: dict[str, type[Any]] = {
            "provider_domains": ProviderDomain,
            "devices": Device,
            "access_policies": AccessPolicy,
            "intrusion_policies": IntrusionPolicy,
            "variable_sets": VariableSet,
            "file_policies": FilePolicy,
            "rule_categories": RuleCategory,
            "access_rules": AccessRule,
            "firewall_objects": FirewallObject,
            "security_zones": SecurityZone,
        }
        model = resource_models.get(row.resource_type)
        resource = self._session.get(model, row.resource_id) if model else None
        if resource is None or resource.manager_id != row.manager_id:
            return None
        latest_sync = self._session.scalar(
            select(SyncRun)
            .where(
                SyncRun.organization_id == organization_id,
                SyncRun.manager_id == row.manager_id,
            )
            .order_by(SyncRun.started_at.desc())
            .limit(1)
        )
        if (
            latest_sync is None
            or latest_sync.complete is not True
            or row.status not in {"DRIFTED", "CONFLICT", "MISSING"}
            or (row.status != "MISSING" and resource.last_seen_sync_run_id != latest_sync.id)
        ):
            return None
        # Provider-only resources remain OBSERVED/UNMANAGED; accepting state never adopts them.
        resource.application_snapshot = self._resource_snapshot(resource)
        if getattr(resource, "owner_group_id", None) is None:
            resource.management_state = ResourceState.OBSERVED
        else:
            resource.management_state = ResourceState.MANAGED
        resource.revision += 1
        row.status = "ACCEPTED"
        row.details = {**row.details, "accepted_by_user_id": str(actor_user_id)}
        self._session.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="accept_provider_state",
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                decision="SUCCESS",
                reason_code="PROVIDER_STATE_ACCEPTED",
                interface="rest",
                details={"drift_id": str(row.id), "manager_id": str(row.manager_id)},
            )
        )
        self._session.commit()
        return {"id": row.id, "state": resource.management_state}

    def reconciliation_proposal(
        self, organization_id: UUID, drift_id: UUID
    ) -> dict[str, object] | None:
        row = self._session.scalar(
            select(DriftRecord).where(
                DriftRecord.id == drift_id,
                DriftRecord.organization_id == organization_id,
                DriftRecord.status.in_(("DRIFTED", "CONFLICT", "MISSING")),
            )
        )
        if row is None:
            return None
        resource_models: dict[str, type[Any]] = {
            "access_rules": AccessRule,
            "firewall_objects": FirewallObject,
        }
        model = resource_models.get(row.resource_type)
        resource = self._session.get(model, row.resource_id) if model else None
        if resource is None:
            return None
        owner_group_id = getattr(resource, "owner_group_id", None)
        policy_id = getattr(resource, "owner_policy_id", None) or getattr(
            resource, "policy_id", None
        )
        if owner_group_id is None or policy_id is None:
            return None
        desired = (row.previous_snapshot or {}).get("application_snapshot")
        if not isinstance(desired, dict):
            desired = row.previous_snapshot or {}
        if not desired:
            return None
        return {
            "drift_id": row.id,
            "resource_type": row.resource_type,
            "resource_id": resource.id,
            "resource_name": resource.name,
            "owner_group_id": owner_group_id,
            "policy_id": policy_id,
            "status": row.status,
            "desired": desired,
        }


class SqlAuthorizationRepository:
    """Current-state authorization reads with organization and context scope in every query."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def user_state(self, user_id: UUID, organization_id: UUID) -> tuple[bool, int] | None:
        row = self._session.execute(
            select(User.is_active, User.revision).where(
                User.id == user_id, User.organization_id == organization_id
            )
        ).one_or_none()
        return (bool(row[0]), int(row[1])) if row else None

    def membership_state(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> tuple[bool, int] | None:
        row = self._session.execute(
            select(
                GroupMembership.status, GroupMembership.revision, Group.is_active, Group.revision
            )
            .join(
                Group,
                (Group.id == GroupMembership.group_id)
                & (Group.organization_id == GroupMembership.organization_id),
            )
            .where(
                GroupMembership.user_id == user_id,
                GroupMembership.group_id == group_id,
                GroupMembership.organization_id == organization_id,
            )
        ).one_or_none()
        if row is None:
            return None
        return row[0] == "ACTIVE" and bool(row[2]), max(int(row[1]), int(row[3]))

    def policy_state(self, policy_id: UUID, organization_id: UUID) -> tuple[UUID, str, int] | None:
        row = self._session.execute(
            select(
                AccessPolicy.manager_id, AccessPolicy.management_state, AccessPolicy.revision
            ).where(
                AccessPolicy.id == policy_id,
                AccessPolicy.organization_id == organization_id,
            )
        ).one_or_none()
        return (row[0], str(row[1]), int(row[2])) if row else None

    def policy_capabilities(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[set[str], int, bool]:
        capabilities: set[str] = set()
        revision = 0
        group_grant = self._session.execute(
            select(PolicyDelegation.capabilities, PolicyDelegation.revision).where(
                PolicyDelegation.organization_id == organization_id,
                PolicyDelegation.group_id == group_id,
                PolicyDelegation.policy_id == policy_id,
                PolicyDelegation.is_active.is_(True),
            )
        ).one_or_none()
        if group_grant:
            capabilities.update(group_grant[0])
            revision = max(revision, int(group_grant[1]))
        direct_grant = self._session.execute(
            select(DirectUserPolicyGrant.capabilities, DirectUserPolicyGrant.revision).where(
                DirectUserPolicyGrant.organization_id == organization_id,
                DirectUserPolicyGrant.user_id == user_id,
                DirectUserPolicyGrant.group_id == group_id,
                DirectUserPolicyGrant.policy_id == policy_id,
                DirectUserPolicyGrant.is_active.is_(True),
            )
        ).one_or_none()
        if direct_grant:
            capabilities.update(direct_grant[0])
            revision = max(revision, int(direct_grant[1]))
        return capabilities, revision, group_grant is not None

    def object_grant_state(
        self, group_id: UUID, policy_id: UUID, object_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, set[str], int] | None:
        rows = list(
            self._session.execute(
                select(
                    FirewallObject.manager_id,
                    FirewallObject.management_state,
                    ObjectUseGrant.permission,
                    ObjectUseGrant.revision,
                )
                .join(
                    ObjectUseGrant,
                    (ObjectUseGrant.object_id == FirewallObject.id)
                    & (ObjectUseGrant.organization_id == FirewallObject.organization_id),
                )
                .where(
                    FirewallObject.id == object_id,
                    FirewallObject.organization_id == organization_id,
                    ObjectUseGrant.group_id == group_id,
                    ObjectUseGrant.policy_id == policy_id,
                )
            )
        )
        if not rows:
            return None
        return (
            rows[0][0],
            str(rows[0][1]),
            {str(row[2]) for row in rows},
            max(int(row[3]) for row in rows),
        )

    def object_mutation_state(
        self, group_id: UUID, policy_id: UUID, object_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None:
        """Return authoritative ownership and conservative dependency scope for mutation."""
        row = self._session.execute(
            select(FirewallObject, AccessPolicy.manager_id)
            .join(
                AccessPolicy,
                (AccessPolicy.id == policy_id)
                & (AccessPolicy.organization_id == FirewallObject.organization_id),
            )
            .where(
                FirewallObject.id == object_id,
                FirewallObject.organization_id == organization_id,
                FirewallObject.manager_id == AccessPolicy.manager_id,
            )
        ).one_or_none()
        if row is None:
            return None
        item, manager_id = row
        latest_sync_complete = self._session.scalar(
            select(SyncRun.complete)
            .where(
                SyncRun.organization_id == organization_id,
                SyncRun.manager_id == item.manager_id,
            )
            .order_by(SyncRun.started_at.desc())
            .limit(1)
        )
        references = list(
            self._session.scalars(
                select(ObjectReference).where(
                    ObjectReference.organization_id == organization_id,
                    ObjectReference.target_object_id == object_id,
                )
            )
        )
        if latest_sync_complete is not True:
            dependency_state = "INCOMPLETE"
        elif not references:
            dependency_state = "UNREFERENCED"
        else:
            within_scope = True
            for reference in references:
                if reference.source_rule_id is None:
                    within_scope = False
                    break
                rule = self._session.get(AccessRule, reference.source_rule_id)
                if (
                    rule is None
                    or rule.owner_group_id != group_id
                    or rule.policy_id != policy_id
                    or rule.management_state not in _USABLE_STATES
                ):
                    within_scope = False
                    break
            dependency_state = "WITHIN_SCOPE" if within_scope else "CROSS_SCOPE"
        return {
            "manager_id": manager_id,
            "management_state": str(item.management_state),
            "owner_group_id": item.owner_group_id,
            "owner_policy_id": item.owner_policy_id,
            "object_type": item.object_type,
            "provider_name": item.name,
            "expected_provider_name": item.expected_provider_name,
            "provider_name_matches": bool(
                item.expected_provider_name and item.name == item.expected_provider_name
            ),
            "dependency_state": dependency_state,
            "reference_count": len(references),
            "revision": int(item.revision),
        }

    def zone_grant_state(
        self, group_id: UUID, policy_id: UUID, zone_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, set[str], int] | None:
        rows = list(
            self._session.execute(
                select(
                    SecurityZone.manager_id,
                    SecurityZone.management_state,
                    ZoneGrant.direction,
                    ZoneGrant.revision,
                )
                .join(
                    ZoneGrant,
                    (ZoneGrant.zone_id == SecurityZone.id)
                    & (ZoneGrant.organization_id == SecurityZone.organization_id),
                )
                .where(
                    SecurityZone.id == zone_id,
                    SecurityZone.organization_id == organization_id,
                    ZoneGrant.group_id == group_id,
                    ZoneGrant.policy_id == policy_id,
                )
            )
        )
        if not rows:
            return None
        return (
            rows[0][0],
            str(rows[0][1]),
            {str(row[2]) for row in rows},
            max(int(row[3]) for row in rows),
        )

    def ip_range_grants(
        self, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[list[str], int]:
        rows = list(
            self._session.execute(
                select(IpRangeGrant.network, IpRangeGrant.revision).where(
                    IpRangeGrant.organization_id == organization_id,
                    IpRangeGrant.group_id == group_id,
                    IpRangeGrant.policy_id == policy_id,
                )
            )
        )
        return [str(row[0]) for row in rows], max((int(row[1]) for row in rows), default=0)

    def object_create_grant_state(
        self, group_id: UUID, policy_id: UUID, object_type: str, organization_id: UUID
    ) -> tuple[UUID, dict[str, str], int] | None:
        grant_type = {
            "NETWORK_GROUP": "NETWORK",
            "PORT_SERVICE_GROUP": "PORT_SERVICE",
            "URL_GROUP": "URL",
        }.get(object_type, object_type)
        row = self._session.execute(
            select(
                AccessPolicy.manager_id,
                FirewallManager.capabilities,
                FirewallManager.is_mock,
                ObjectCreateGrant.revision,
                ProviderConnection.write_enabled,
            )
            .join(
                ObjectCreateGrant,
                (ObjectCreateGrant.policy_id == AccessPolicy.id)
                & (ObjectCreateGrant.organization_id == AccessPolicy.organization_id),
            )
            .join(FirewallManager, FirewallManager.id == AccessPolicy.manager_id)
            .outerjoin(
                ProviderConnection,
                ProviderConnection.id == FirewallManager.provider_connection_id,
            )
            .where(
                ObjectCreateGrant.organization_id == organization_id,
                ObjectCreateGrant.group_id == group_id,
                ObjectCreateGrant.policy_id == policy_id,
                ObjectCreateGrant.object_type == grant_type,
            )
        ).one_or_none()
        if row is None:
            return None
        return (
            row[0],
            effective_write_capabilities(
                dict(row[1]),
                validation_writes_enabled=bool(row[4]) and not bool(row[2]),
            ),
            int(row[3]),
        )

    def equivalent_object_id(
        self, manager_id: UUID, object_type: str, normalized_value: str, organization_id: UUID
    ) -> UUID | None:
        return self._session.scalar(
            select(FirewallObject.id).where(
                FirewallObject.organization_id == organization_id,
                FirewallObject.manager_id == manager_id,
                FirewallObject.object_type == object_type,
                FirewallObject.normalized_value == normalized_value,
                FirewallObject.management_state.notin_(("MISSING", "CONFLICT")),
            )
        )

    def rule_owner_state(
        self, rule_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[UUID | None, str, int] | None:
        row = self._session.execute(
            select(
                AccessRule.owner_group_id, AccessRule.management_state, AccessRule.revision
            ).where(
                AccessRule.id == rule_id,
                AccessRule.policy_id == policy_id,
                AccessRule.organization_id == organization_id,
            )
        ).one_or_none()
        return (row[0], str(row[1]), int(row[2])) if row else None

    def category_mapping_state(
        self, group_id: UUID, policy_id: UUID, category_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, int] | None:
        row = self._session.execute(
            select(
                RuleCategory.manager_id,
                RuleCategory.management_state,
                GroupPolicyCategoryMapping.revision,
            )
            .join(
                GroupPolicyCategoryMapping,
                (GroupPolicyCategoryMapping.category_id == RuleCategory.id)
                & (GroupPolicyCategoryMapping.organization_id == RuleCategory.organization_id),
            )
            .where(
                RuleCategory.id == category_id,
                RuleCategory.policy_id == policy_id,
                RuleCategory.organization_id == organization_id,
                GroupPolicyCategoryMapping.group_id == group_id,
                GroupPolicyCategoryMapping.policy_id == policy_id,
                GroupPolicyCategoryMapping.sync_state == "SYNCED",
            )
        ).one_or_none()
        return (row[0], str(row[1]), int(row[2])) if row else None

    def record_authorization_decision(
        self, decision: AuthorizationDecision, *, interface: str, correlation_id: str | None
    ) -> None:
        # Denials and privileged administration are security evidence. Routine successful reads
        # remain out of the audit stream to avoid drowning meaningful activity.
        if decision.allowed and decision.action.value not in {"manage_grants", "manage_providers"}:
            return
        # A denied request causes the delivery transaction to roll back. Persist decision evidence
        # independently so the rollback cannot erase the event it is meant to explain.
        with Session(bind=self._session.get_bind()) as audit_session, audit_session.begin():
            actor_user_id = decision.principal_id
            raw_actor_user_id = self._session.info.get("auth_actor_user_id")
            if isinstance(raw_actor_user_id, str):
                actor_user_id = UUID(raw_actor_user_id)
            active_group_id = (
                audit_session.scalar(
                    select(Group.id).where(
                        Group.id == decision.active_group_id,
                        Group.organization_id == decision.organization_id,
                    )
                )
                if decision.active_group_id
                else None
            )
            policy_id = (
                audit_session.scalar(
                    select(AccessPolicy.id).where(
                        AccessPolicy.id == decision.access_policy_id,
                        AccessPolicy.organization_id == decision.organization_id,
                    )
                )
                if decision.access_policy_id
                else None
            )
            audit_session.add(
                AuditEvent(
                    organization_id=decision.organization_id,
                    actor_user_id=actor_user_id,
                    active_group_id=active_group_id,
                    policy_id=policy_id,
                    action=decision.action.value,
                    resource_type=decision.resource_type.value,
                    resource_id=decision.resource_id,
                    decision="ALLOW" if decision.allowed else "DENY",
                    reason_code=decision.reason.value,
                    interface=interface,
                    correlation_id=correlation_id,
                    details={
                        "authorization_revision": decision.authorization_revision,
                        "effective_user_id": str(decision.principal_id),
                    },
                )
            )

    def active_groups_for_user(
        self, user_id: UUID, organization_id: UUID
    ) -> list[dict[str, object]]:
        rows = self._session.execute(
            select(Group.id, Group.name, Group.provider_slug, Group.revision)
            .join(
                GroupMembership,
                (GroupMembership.group_id == Group.id)
                & (GroupMembership.organization_id == Group.organization_id),
            )
            .where(
                GroupMembership.user_id == user_id,
                GroupMembership.organization_id == organization_id,
                GroupMembership.status == "ACTIVE",
                Group.is_active.is_(True),
            )
            .order_by(Group.name, Group.id)
        )
        return [
            {"id": row[0], "name": row[1], "provider_slug": row[2], "revision": row[3]}
            for row in rows
        ]

    def default_context_for_user(
        self, user_id: UUID, organization_id: UUID
    ) -> tuple[UUID | None, UUID | None]:
        row = self._session.execute(
            select(User.default_group_id, User.default_policy_id).where(
                User.id == user_id, User.organization_id == organization_id
            )
        ).one_or_none()
        return (row[0], row[1]) if row else (None, None)

    def set_default_context_for_user(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> bool:
        membership = self.membership_state(user_id, group_id, organization_id)
        if membership is None or not membership[0]:
            return False
        delegated = any(
            item["id"] == policy_id
            for item in self.delegated_policies(user_id, group_id, organization_id)
        )
        if not delegated:
            return False
        user = self._session.scalar(
            select(User).where(User.id == user_id, User.organization_id == organization_id)
        )
        if user is None:
            return False
        user.default_group_id = group_id
        user.default_policy_id = policy_id
        user.revision += 1
        return True

    def _firewall_resource_states(  # noqa: PLR0912 -- explicit resource/deployment state mapping
        self,
        manager_id: UUID,
        policy_id: UUID,
        rules: list[AccessRule],
        object_rows: list[tuple[object, ...]],
        deployment_supported: bool,
    ) -> dict[UUID, str]:
        """Return provider/device state separately from application management state."""
        states: dict[UUID, str] = {
            row.id: (
                "NOT_PRESENT"
                if row.management_state == "MISSING"
                else "UNDEPLOYED"
                if deployment_supported and row.management_state == "MANAGED"
                else "UNKNOWN"
            )
            for row in rules
        }
        states.update(
            {
                row[0]: (
                    "NOT_PRESENT"
                    if row[4] == "MISSING"
                    else "UNDEPLOYED"
                    if deployment_supported and row[4] == "MANAGED"
                    else "UNKNOWN"
                )
                for row in object_rows
            }
        )
        if not deployment_supported:
            return states
        deployments = list(
            self._session.scalars(
                select(Deployment)
                .where(Deployment.manager_id == manager_id)
                .order_by(Deployment.updated_at.desc())
            )
        )
        change_set_ids = [
            change_set_id
            for deployment in deployments
            for change_set_id in deployment.included_change_set_ids
        ]
        if not change_set_ids:
            return states
        operations = list(
            self._session.scalars(
                select(ChangeSetOperation).where(
                    ChangeSetOperation.manager_id == manager_id,
                    ChangeSetOperation.access_policy_id == policy_id,
                    ChangeSetOperation.change_set_id.in_(change_set_ids),
                )
            )
        )
        operations_by_change_set: dict[str, list[ChangeSetOperation]] = {}
        for operation in operations:
            operations_by_change_set.setdefault(str(operation.change_set_id), []).append(operation)
        rules_by_name = {row.name: row.id for row in rules}
        objects_by_name = {(row[1], row[2]): row[0] for row in object_rows}
        for deployment in deployments:
            deployment_state = str(deployment.state)
            if deployment_state == "DEPLOYED":
                provider_state = "DEPLOYED"
            elif deployment_state in {
                "SCHEDULED",
                "READY",
                "DEPLOYING",
                "FAILED",
                "UNKNOWN",
                "RECONCILIATION_REQUIRED",
            }:
                provider_state = "UNDEPLOYED"
            else:
                continue
            for change_set_id in deployment.included_change_set_ids:
                for operation in operations_by_change_set.get(str(change_set_id), []):
                    payload = operation.payload
                    resource_id = None
                    if operation.kind in {"CREATE_RULE", "MODIFY_RULE", "DELETE_RULE"}:
                        resource_id = payload.get("rule_id") or rules_by_name.get(
                            str(payload.get("name") or "")
                        )
                    elif operation.kind in {"CREATE_OBJECT", "MODIFY_OBJECT", "DELETE_OBJECT"}:
                        resource_id = payload.get("object_id") or objects_by_name.get(
                            (str(payload.get("name") or ""), str(payload.get("object_type") or ""))
                        )
                    if resource_id is None:
                        continue
                    resource_uuid = UUID(str(resource_id))
                    if operation.kind.startswith("DELETE_") and provider_state == "DEPLOYED":
                        states[resource_uuid] = "NOT_PRESENT"
                    elif resource_uuid in states:
                        states[resource_uuid] = provider_state
        return states

    def delegated_context_view(  # noqa: PLR0913, PLR0917 -- explicit context filters
        self,
        user_id: UUID,
        group_id: UUID,
        policy_id: UUID,
        organization_id: UUID,
        include_applications: bool = True,
        include_rules: bool = True,
    ) -> dict[str, object] | None:
        policy = self._session.scalar(
            select(AccessPolicy).where(
                AccessPolicy.id == policy_id, AccessPolicy.organization_id == organization_id
            )
        )
        if policy is None:
            return None
        capabilities, _revision, _delegated = self.policy_capabilities(
            user_id, group_id, policy_id, organization_id
        )
        rules = (
            list(
                self._session.scalars(
                    select(AccessRule)
                    .where(
                        AccessRule.organization_id == organization_id,
                        AccessRule.policy_id == policy_id,
                        AccessRule.owner_group_id == group_id,
                        AccessRule.management_state.in_(_CONTEXT_RESOURCE_STATES),
                    )
                    .order_by(AccessRule.position, AccessRule.id)
                )
            )
            if include_rules
            else []
        )
        rule_ids = [row.id for row in rules]
        rule_elements: dict[UUID, dict[str, list[str]]] = {
            rule_id: {
                "source_zones": [],
                "destination_zones": [],
                "source_networks": [],
                "destination_networks": [],
                "source_services": [],
                "destination_services": [],
                "applications": [],
                "urls": [],
            }
            for rule_id in rule_ids
        }
        if rule_ids and include_rules:
            zone_references = self._session.execute(
                select(RuleZoneReference.rule_id, SecurityZone.name, RuleZoneReference.element_type)
                .join(SecurityZone, SecurityZone.id == RuleZoneReference.zone_id)
                .where(
                    RuleZoneReference.organization_id == organization_id,
                    RuleZoneReference.rule_id.in_(rule_ids),
                )
                .order_by(SecurityZone.name)
            )
            for rule_id, zone_name, element_type in zone_references:
                key = "source_zones" if element_type == "SOURCE" else "destination_zones"
                rule_elements[rule_id][key].append(str(zone_name))
            object_references = self._session.execute(
                select(
                    ObjectReference.source_rule_id,
                    FirewallObject.name,
                    ObjectReference.element_type,
                )
                .join(FirewallObject, FirewallObject.id == ObjectReference.target_object_id)
                .where(
                    ObjectReference.organization_id == organization_id,
                    ObjectReference.source_rule_id.in_(rule_ids),
                )
                .order_by(FirewallObject.name)
            )
            element_keys = {
                "SOURCE_NETWORK": "source_networks",
                "DESTINATION_NETWORK": "destination_networks",
                "PORT_SERVICE": "destination_services",
                "SOURCE_PORT": "source_services",
                "DESTINATION_PORT": "destination_services",
                "APPLICATION": "applications",
                "URL": "urls",
            }
            for rule_id, object_name, element_type in object_references:
                key = element_keys.get(str(element_type))
                if rule_id is not None and key is not None:
                    rule_elements[rule_id][key].append(str(object_name))
        object_type_filter = (
            True
            if include_applications
            else ~FirewallObject.object_type.in_(_PROVIDER_SHARED_OBJECT_TYPES)
        )
        object_rows = list(
            self._session.execute(
                select(
                    FirewallObject.id,
                    FirewallObject.name,
                    FirewallObject.object_type,
                    FirewallObject.normalized_value,
                    FirewallObject.management_state,
                    FirewallObject.owner_group_id,
                    FirewallObject.owner_policy_id,
                    FirewallObject.created_by_user_id,
                )
                .outerjoin(
                    ObjectUseGrant,
                    (ObjectUseGrant.object_id == FirewallObject.id)
                    & (ObjectUseGrant.organization_id == FirewallObject.organization_id),
                )
                .where(
                    FirewallObject.organization_id == organization_id,
                    FirewallObject.manager_id == policy.manager_id,
                    FirewallObject.management_state.in_(_CONTEXT_RESOURCE_STATES),
                    object_type_filter,
                    or_(
                        FirewallObject.object_type.in_(_PROVIDER_SHARED_OBJECT_TYPES),
                        and_(
                            ObjectUseGrant.group_id == group_id,
                            ObjectUseGrant.policy_id == policy_id,
                            ObjectUseGrant.permission == "use",
                        ),
                    ),
                )
                .distinct()
                .order_by(FirewallObject.name, FirewallObject.id)
            )
        )
        object_ids = [row[0] for row in object_rows]
        member_ids_by_object: dict[UUID, list[UUID]] = {}
        if object_ids:
            for source_id, target_id in self._session.execute(
                select(ObjectReference.source_object_id, ObjectReference.target_object_id).where(
                    ObjectReference.organization_id == organization_id,
                    ObjectReference.source_object_id.in_(object_ids),
                    ObjectReference.element_type == "MEMBER",
                )
            ):
                if source_id is not None:
                    member_ids_by_object.setdefault(source_id, []).append(target_id)
        objects = [
            {
                "id": row[0],
                "name": row[1],
                "object_type": row[2],
                "normalized_value": row[3],
                "management_state": row[4],
                "owner_type": "GROUP" if row[5] is not None else "PROVIDER",
                "owner_group_id": row[5],
                "owner_policy_id": row[6],
                "created_by_user_id": row[7],
                "member_object_ids": member_ids_by_object.get(row[0], []),
            }
            for row in object_rows
        ]
        zones = list(
            self._session.execute(
                select(SecurityZone.id, SecurityZone.name, ZoneGrant.direction)
                .join(
                    ZoneGrant,
                    (ZoneGrant.zone_id == SecurityZone.id)
                    & (ZoneGrant.organization_id == SecurityZone.organization_id),
                )
                .where(
                    SecurityZone.organization_id == organization_id,
                    SecurityZone.manager_id == policy.manager_id,
                    SecurityZone.management_state.in_(_USABLE_STATES),
                    ZoneGrant.group_id == group_id,
                    ZoneGrant.policy_id == policy_id,
                )
                .order_by(SecurityZone.name, SecurityZone.id)
            )
        )
        ranges, _range_revision = self.ip_range_grants(group_id, policy_id, organization_id)
        create_types = list(
            self._session.scalars(
                select(ObjectCreateGrant.object_type)
                .where(
                    ObjectCreateGrant.organization_id == organization_id,
                    ObjectCreateGrant.group_id == group_id,
                    ObjectCreateGrant.policy_id == policy_id,
                )
                .order_by(ObjectCreateGrant.object_type)
            )
        )
        group_types = {
            "NETWORK": "NETWORK_GROUP",
            "PORT_SERVICE": "PORT_SERVICE_GROUP",
            "URL": "URL_GROUP",
        }
        create_types.extend(group_types[item] for item in create_types if item in group_types)
        manager = self._session.get(FirewallManager, policy.manager_id)
        if manager is None:
            return None
        connection = (
            self._session.get(ProviderConnection, manager.provider_connection_id)
            if manager.provider_connection_id is not None
            else None
        )
        provider_capabilities = effective_write_capabilities(
            dict(manager.capabilities),
            validation_writes_enabled=bool(
                connection and connection.write_enabled and not manager.is_mock
            ),
        )
        firewall_states = self._firewall_resource_states(
            policy.manager_id,
            policy_id,
            rules,
            object_rows,
            provider_capabilities.get("deployment_status") == "SUPPORTED",
        )
        for item in objects:
            item["firewall_state"] = firewall_states.get(item["id"], "UNKNOWN")
        categories = list(
            self._session.execute(
                select(RuleCategory.id, RuleCategory.name)
                .join(
                    GroupPolicyCategoryMapping,
                    GroupPolicyCategoryMapping.category_id == RuleCategory.id,
                )
                .where(
                    RuleCategory.organization_id == organization_id,
                    RuleCategory.policy_id == policy_id,
                    RuleCategory.management_state.in_(_USABLE_STATES),
                    GroupPolicyCategoryMapping.group_id == group_id,
                    GroupPolicyCategoryMapping.policy_id == policy_id,
                    GroupPolicyCategoryMapping.sync_state == "SYNCED",
                )
            )
        )
        intrusion_policies = list(
            self._session.scalars(
                select(IntrusionPolicy)
                .where(
                    IntrusionPolicy.organization_id == organization_id,
                    IntrusionPolicy.manager_id == policy.manager_id,
                    IntrusionPolicy.domain_id == policy.domain_id,
                    (
                        IntrusionPolicy.management_state.in_(_USABLE_STATES)
                        | IntrusionPolicy.id.in_(
                            select(AccessRule.intrusion_policy_id).where(
                                AccessRule.policy_id == policy_id,
                                AccessRule.intrusion_policy_id.is_not(None),
                            )
                        )
                    ),
                )
                .order_by(IntrusionPolicy.name, IntrusionPolicy.id)
            )
        )
        variable_sets = list(
            self._session.scalars(
                select(VariableSet)
                .where(
                    VariableSet.organization_id == organization_id,
                    VariableSet.manager_id == policy.manager_id,
                    VariableSet.domain_id == policy.domain_id,
                    (
                        VariableSet.management_state.in_(_USABLE_STATES)
                        | VariableSet.id.in_(
                            select(AccessRule.variable_set_id).where(
                                AccessRule.policy_id == policy_id,
                                AccessRule.variable_set_id.is_not(None),
                            )
                        )
                    ),
                )
                .order_by(VariableSet.name, VariableSet.id)
            )
        )
        file_policies = list(
            self._session.scalars(
                select(FilePolicy)
                .where(
                    FilePolicy.organization_id == organization_id,
                    FilePolicy.manager_id == policy.manager_id,
                    FilePolicy.domain_id == policy.domain_id,
                    (
                        FilePolicy.management_state.in_(_USABLE_STATES)
                        | FilePolicy.id.in_(
                            select(AccessRule.file_policy_id).where(
                                AccessRule.policy_id == policy_id,
                                AccessRule.file_policy_id.is_not(None),
                            )
                        )
                    ),
                )
                .order_by(FilePolicy.name, FilePolicy.id)
            )
        )
        return {
            "policy": {
                "id": policy.id,
                "manager_id": policy.manager_id,
                "name": policy.name,
                "management_state": policy.management_state,
                "revision": policy.revision,
            },
            "provider_writable": bool(manager) and not manager.read_only,
            "firewall_deployment_status": (
                "SUPPORTED"
                if provider_capabilities.get("deployment_status") == "SUPPORTED"
                else "NOT_AVAILABLE"
            ),
            "provider_type": manager.provider,
            "provider_name": manager.display_name,
            "provider_is_mock": manager.is_mock,
            "capabilities": sorted(capabilities),
            "rules": [
                {
                    "id": row.id,
                    "name": row.name,
                    "action": row.action,
                    "enabled": row.enabled,
                    "logging": "BEGIN" if row.log_begin else "END" if row.log_end else "NONE",
                    "position": row.position,
                    "management_state": row.management_state,
                    "revision": row.revision,
                    "category_id": row.category_id,
                    "intrusion_policy_id": row.intrusion_policy_id,
                    "variable_set_id": row.variable_set_id,
                    "file_policy_id": row.file_policy_id,
                    "firewall_state": firewall_states.get(row.id, "UNKNOWN"),
                    **rule_elements[row.id],
                }
                for row in rules
            ],
            "objects": objects,
            "zones": [{"id": row[0], "name": row[1], "direction": row[2]} for row in zones],
            "categories": [{"id": row[0], "name": row[1]} for row in categories],
            "intrusion_policies": [
                {
                    "id": row.id,
                    "name": row.name,
                    "default_variable_set_id": next(
                        (
                            variable.id
                            for variable in variable_sets
                            if variable.native_id == row.default_variable_set_native_id
                        ),
                        None,
                    ),
                }
                for row in intrusion_policies
            ],
            "variable_sets": [
                {"id": row.id, "name": row.name, "is_default": row.is_default}
                for row in variable_sets
            ],
            "file_policies": [{"id": row.id, "name": row.name} for row in file_policies],
            "ip_ranges": ranges,
            "object_create": [
                {
                    "object_type": object_type,
                    "provider_supported": bool(manager)
                    and provider_capabilities.get(
                        _OBJECT_CREATE_CAPABILITY_NAMES.get(object_type, "")
                    )
                    == "SUPPORTED",
                }
                for object_type in create_types
            ],
        }

    def delegated_policies(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> list[dict[str, object]]:
        group_policy_ids = select(PolicyDelegation.policy_id).where(
            PolicyDelegation.organization_id == organization_id,
            PolicyDelegation.group_id == group_id,
            PolicyDelegation.is_active.is_(True),
            PolicyDelegation.capabilities.contains(["view"]),
        )
        direct_policy_ids = select(DirectUserPolicyGrant.policy_id).where(
            DirectUserPolicyGrant.organization_id == organization_id,
            DirectUserPolicyGrant.user_id == user_id,
            DirectUserPolicyGrant.group_id == group_id,
            DirectUserPolicyGrant.is_active.is_(True),
            DirectUserPolicyGrant.capabilities.contains(["view"]),
        )
        policies = list(
            self._session.scalars(
                select(AccessPolicy)
                .where(
                    AccessPolicy.organization_id == organization_id,
                    AccessPolicy.id.in_(group_policy_ids.union(direct_policy_ids)),
                    AccessPolicy.management_state.notin_(("MISSING", "CONFLICT")),
                )
                .order_by(AccessPolicy.name, AccessPolicy.id)
            )
        )
        return [
            {
                "id": policy.id,
                "manager_id": policy.manager_id,
                "name": policy.name,
                "management_state": policy.management_state,
                "revision": policy.revision,
            }
            for policy in policies
        ]


class SqlAdministrationRepository:
    """Bounded administration writes with optimistic concurrency and scope validation."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def authorization_snapshot(self, organization_id: UUID) -> dict[str, object]:
        users = list(
            self._session.scalars(
                select(User)
                .where(User.organization_id == organization_id)
                .order_by(User.display_name)
            )
        )
        groups = list(
            self._session.scalars(
                select(Group).where(Group.organization_id == organization_id).order_by(Group.name)
            )
        )
        audit_events = self._session.execute(
            select(AuditEvent, User.display_name, Group.name, AccessPolicy.name)
            .join(
                User,
                (User.id == AuditEvent.actor_user_id)
                & (User.organization_id == AuditEvent.organization_id),
            )
            .outerjoin(
                Group,
                (Group.id == AuditEvent.active_group_id)
                & (Group.organization_id == AuditEvent.organization_id),
            )
            .outerjoin(
                AccessPolicy,
                (AccessPolicy.id == AuditEvent.policy_id)
                & (AccessPolicy.organization_id == AuditEvent.organization_id),
            )
            .where(AuditEvent.organization_id == organization_id)
            .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
            .limit(200)
        ).all()
        authentication_events = self._session.execute(
            select(AuthenticationEvent, User.display_name)
            .outerjoin(User, User.id == AuthenticationEvent.user_id)
            .where(AuthenticationEvent.organization_id == organization_id)
            .order_by(AuthenticationEvent.occurred_at.desc(), AuthenticationEvent.id.desc())
            .limit(200)
        ).all()
        return {
            "users": [self._user_dict(row) for row in users],
            "groups": [self._group_dict(row) for row in groups],
            "policies": self._rows(
                AccessPolicy, organization_id, (AccessPolicy.name, AccessPolicy.id)
            ),
            "objects": self._rows(
                FirewallObject, organization_id, (FirewallObject.name, FirewallObject.id)
            ),
            "zones": self._rows(
                SecurityZone, organization_id, (SecurityZone.name, SecurityZone.id)
            ),
            "categories": self._rows(
                RuleCategory, organization_id, (RuleCategory.name, RuleCategory.id)
            ),
            "memberships": self._rows(
                GroupMembership,
                organization_id,
                (GroupMembership.user_id, GroupMembership.group_id),
            ),
            "policy_delegations": self._rows(
                PolicyDelegation,
                organization_id,
                (PolicyDelegation.group_id, PolicyDelegation.policy_id),
            ),
            "direct_user_policy_grants": self._rows(
                DirectUserPolicyGrant,
                organization_id,
                (DirectUserPolicyGrant.user_id, DirectUserPolicyGrant.group_id),
            ),
            "object_use_grants": self._rows(
                ObjectUseGrant, organization_id, (ObjectUseGrant.group_id, ObjectUseGrant.object_id)
            ),
            "zone_grants": self._rows(
                ZoneGrant, organization_id, (ZoneGrant.group_id, ZoneGrant.zone_id)
            ),
            "ip_range_grants": self._rows(
                IpRangeGrant, organization_id, (IpRangeGrant.group_id, IpRangeGrant.network)
            ),
            "object_create_grants": self._rows(
                ObjectCreateGrant,
                organization_id,
                (ObjectCreateGrant.group_id, ObjectCreateGrant.object_type),
            ),
            "category_mappings": self._rows(
                GroupPolicyCategoryMapping,
                organization_id,
                (GroupPolicyCategoryMapping.group_id, GroupPolicyCategoryMapping.policy_id),
            ),
            "audit_events": [
                {
                    "id": event.id,
                    "actor": actor_name,
                    "acting_group": group_name,
                    "policy": policy_name,
                    "action": event.action,
                    "resource_type": event.resource_type,
                    "decision": event.decision,
                    "reason_code": event.reason_code,
                    "interface": event.interface,
                    "correlation_id": event.correlation_id,
                    "details": {
                        key: event.details[key]
                        for key in (
                            "authorization_revision",
                            "status",
                            "error_code",
                            "operation",
                            "provider",
                            "effective_user_id",
                            "effective_user_email",
                            "reason",
                        )
                        if key in event.details
                    },
                    "occurred_at": event.occurred_at,
                }
                for event, actor_name, group_name, policy_name in audit_events
            ]
            + [
                {
                    "id": event.id,
                    "actor": actor_name or "Unmapped identity",
                    "acting_group": None,
                    "policy": None,
                    "action": event.event,
                    "resource_type": "authentication",
                    "decision": event.outcome,
                    "reason_code": event.details.get("reason", "AUTHENTICATION"),
                    "interface": "oidc",
                    "correlation_id": event.correlation_id,
                    "details": {
                        key: event.details[key]
                        for key in ("reason", "issuer")
                        if key in event.details
                    },
                    "occurred_at": event.occurred_at,
                }
                for event, actor_name in authentication_events
            ],
        }

    def create_user(
        self, organization_id: UUID, actor_user_id: UUID, values: dict[str, object]
    ) -> dict[str, object]:
        row = User(
            organization_id=organization_id,
            identity_issuer=str(values["identity_issuer"]),
            identity_subject=str(values["identity_subject"]),
            email=str(values["email"]),
            display_name=str(values["display_name"]),
            role=str(values.get("role", "viewer")),
            is_active=True,
            revision=1,
        )
        self._session.add(row)
        self._session.flush()
        self._session.add(
            ExternalIdentity(
                organization_id=organization_id,
                user_id=row.id,
                provider_id="manual",
                issuer=row.identity_issuer,
                subject=row.identity_subject,
                email_claim=row.email,
                display_name_claim=row.display_name,
            )
        )
        self._save(row)
        self._audit_change(organization_id, actor_user_id, row.id, "user")
        return self._user_dict(row)

    def create_group(
        self, organization_id: UUID, actor_user_id: UUID, values: dict[str, object]
    ) -> dict[str, object]:
        row = Group(
            organization_id=organization_id,
            name=str(values["name"]),
            provider_slug=str(values["provider_slug"]),
            is_active=True,
            approval_required=bool(values.get("approval_required", False)),
            revision=1,
        )
        self._session.add(row)
        self._save(row)
        self._audit_change(organization_id, actor_user_id, row.id, "group")
        return self._group_dict(row)

    def update_enabled(  # noqa: PLR0913, PLR0917 -- explicit audit/write context
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        resource: str,
        resource_id: UUID,
        enabled: bool,
        expected_revision: int,
    ) -> dict[str, object]:
        model: type[User] | type[Group] = User if resource == "users" else Group
        row = self._session.scalar(
            select(model).where(model.id == resource_id, model.organization_id == organization_id)
        )
        if row is None:
            raise ResourceOutOfScopeError
        if row.revision != expected_revision:
            raise StaleWriteError
        row.is_active = enabled
        row.revision += 1
        self._session.flush()
        self._audit_change(organization_id, actor_user_id, row.id, resource)
        return self._user_dict(row) if isinstance(row, User) else self._group_dict(row)

    def update_group_approval(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        group_id: UUID,
        approval_required: bool,
        expected_revision: int,
    ) -> dict[str, object]:
        row = self._session.scalar(
            select(Group).where(Group.id == group_id, Group.organization_id == organization_id)
        )
        if row is None:
            raise ResourceOutOfScopeError
        if row.revision != expected_revision:
            raise StaleWriteError
        row.approval_required = approval_required
        row.revision += 1
        self._audit_change(organization_id, actor_user_id, row.id, "group_approval_policy")
        self._session.flush()
        return self._group_dict(row)

    def update_user_role(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        user_id: UUID,
        role: str,
        expected_revision: int,
    ) -> dict[str, object]:
        row = self._session.scalar(
            select(User).where(User.id == user_id, User.organization_id == organization_id)
        )
        if row is None:
            raise ResourceOutOfScopeError
        if row.revision != expected_revision:
            raise StaleWriteError
        row.role = role
        row.revision += 1
        self._session.flush()
        self._audit_change(organization_id, actor_user_id, row.id, "users")
        return self._user_dict(row)

    def upsert_authorization_resource(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        resource: str,
        values: dict[str, object],
        expected_revision: int | None,
    ) -> dict[str, object]:
        self._validate_scope(organization_id, resource, values)
        model, keys = self._resource_model_and_keys(resource)
        conditions = [model.organization_id == organization_id]
        conditions.extend(getattr(model, key) == values[key] for key in keys)
        row = self._session.scalar(select(model).where(*conditions))
        if row is not None:
            if expected_revision is None or row.revision != expected_revision:
                raise StaleWriteError
            self._apply_mutable_values(resource, row, values)
            row.revision += 1
        else:
            if expected_revision is not None:
                raise StaleWriteError
            row = model(organization_id=organization_id, revision=1, **values)
            self._session.add(row)
        self._save(row)
        self._audit_change(organization_id, actor_user_id, row.id, resource)
        return self._model_dict(row)

    def revoke_authorization_resource(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        resource: str,
        resource_id: UUID,
        expected_revision: int,
    ) -> None:
        """Delete an explicit grant while retaining append-only audit evidence."""
        model, _ = self._resource_model_and_keys(resource)
        row = self._session.scalar(
            select(model).where(model.id == resource_id, model.organization_id == organization_id)
        )
        if row is None:
            raise ResourceOutOfScopeError
        if row.revision != expected_revision:
            raise StaleWriteError
        self._session.delete(row)
        self._session.flush()
        self._audit_change(organization_id, actor_user_id, resource_id, f"{resource}:revoked")

    def _validate_scope(
        self, organization_id: UUID, resource: str, values: dict[str, object]
    ) -> None:
        checks: list[tuple[type[Any], str]] = []
        if "user_id" in values:
            checks.append((User, "user_id"))
        if "group_id" in values:
            checks.append((Group, "group_id"))
        if "policy_id" in values:
            checks.append((AccessPolicy, "policy_id"))
        if "object_id" in values:
            checks.append((FirewallObject, "object_id"))
        if "zone_id" in values:
            checks.append((SecurityZone, "zone_id"))
        if "category_id" in values:
            checks.append((RuleCategory, "category_id"))
        for model, key in checks:
            value = values.get(key)
            if (
                not isinstance(value, UUID)
                or self._session.scalar(
                    select(model.id).where(
                        model.id == value, model.organization_id == organization_id
                    )
                )
                is None
            ):
                raise ResourceOutOfScopeError
        if resource == "category-mappings":
            policy = self._session.get(AccessPolicy, values["policy_id"])
            category = self._session.get(RuleCategory, values["category_id"])
            if policy is None or category is None or category.policy_id != policy.id:
                raise ResourceOutOfScopeError
        if resource in {"object-use-grants", "zone-grants"}:
            self._validate_provider_resource_manager(organization_id, resource, values)
        if resource == "object-use-grants":
            self._validate_network_object_grant(organization_id, values)

    def _validate_network_object_grant(
        self, organization_id: UUID, values: dict[str, object]
    ) -> None:
        """Require every assigned network object to fit a Group's authorized ranges."""
        object_value, object_type = self._session.execute(
            select(FirewallObject.normalized_value, FirewallObject.object_type).where(
                FirewallObject.id == values.get("object_id"),
                FirewallObject.organization_id == organization_id,
            )
        ).one_or_none() or (None, None)
        if object_type != "NETWORK" or not object_value:
            return
        ranges, _revision = self.ip_range_grants(
            UUID(str(values["group_id"])),
            UUID(str(values["policy_id"])),
            organization_id,
        )
        contained = any(network_is_contained(str(object_value), grant) for grant in ranges)
        if not ranges or not contained:
            raise InvalidInputError(details={"code": "NETWORK_OBJECT_OUTSIDE_ASSIGNED_IP_RANGES"})

    def _validate_provider_resource_manager(
        self, organization_id: UUID, resource: str, values: dict[str, object]
    ) -> None:
        """Require grants to reference inventory on the selected policy's provider manager."""
        policy_manager_id = self._session.scalar(
            select(AccessPolicy.manager_id).where(
                AccessPolicy.id == values.get("policy_id"),
                AccessPolicy.organization_id == organization_id,
            )
        )
        model, key = (
            (FirewallObject, "object_id")
            if resource == "object-use-grants"
            else (SecurityZone, "zone_id")
        )
        resource_manager_id = self._session.scalar(
            select(model.manager_id).where(
                model.id == values.get(key),
                model.organization_id == organization_id,
            )
        )
        if policy_manager_id is None or resource_manager_id != policy_manager_id:
            raise ResourceOutOfScopeError

    @staticmethod
    def _resource_model_and_keys(resource: str) -> tuple[type[Any], tuple[str, ...]]:
        resources: dict[str, tuple[type[Any], tuple[str, ...]]] = {
            "memberships": (GroupMembership, ("user_id", "group_id")),
            "policy-delegations": (PolicyDelegation, ("group_id", "policy_id")),
            "direct-user-policy-grants": (
                DirectUserPolicyGrant,
                ("user_id", "group_id", "policy_id"),
            ),
            "object-use-grants": (
                ObjectUseGrant,
                ("group_id", "policy_id", "object_id", "permission"),
            ),
            "zone-grants": (ZoneGrant, ("group_id", "policy_id", "zone_id", "direction")),
            "ip-range-grants": (IpRangeGrant, ("group_id", "policy_id", "network")),
            "object-create-grants": (
                ObjectCreateGrant,
                ("group_id", "policy_id", "object_type"),
            ),
            "category-mappings": (
                GroupPolicyCategoryMapping,
                ("group_id", "policy_id"),
            ),
        }
        return resources[resource]

    @staticmethod
    def _apply_mutable_values(resource: str, row: Any, values: dict[str, object]) -> None:
        allowed: set[str] = {
            "memberships": {"status"},
            "policy-delegations": {"capabilities", "is_active"},
            "direct-user-policy-grants": {"capabilities", "is_active"},
            "object-use-grants": set(),
            "zone-grants": set(),
            "ip-range-grants": set(),
            "object-create-grants": set(),
            "category-mappings": {"category_id", "expected_category_name", "sync_state"},
        }[resource]
        for key in allowed:
            if key in values:
                setattr(row, key, values[key])

    def _save(self, row: Any) -> None:
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise InvalidInputError from exc

    def _audit_change(
        self, organization_id: UUID, actor_user_id: UUID, resource_id: UUID, resource: str
    ) -> None:
        self._session.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="manage_grants",
                resource_type=resource,
                resource_id=resource_id,
                decision="CHANGE",
                reason_code="ADMINISTRATIVE_CHANGE",
                interface="rest",
                details={},
            )
        )

    def _rows(
        self, model: type[Any], organization_id: UUID, order: tuple[Any, ...]
    ) -> list[dict[str, object]]:
        return [
            self._model_dict(row)
            for row in self._session.scalars(
                select(model).where(model.organization_id == organization_id).order_by(*order)
            )
        ]

    @staticmethod
    def _model_dict(row: Any) -> dict[str, object]:
        excluded = {"created_at", "updated_at", "native_metadata"}
        return {
            column.name: getattr(row, column.name)
            for column in row.__table__.columns
            if column.name not in excluded
        }

    @staticmethod
    def _user_dict(row: User) -> dict[str, object]:
        return {
            "id": row.id,
            "identity_issuer": row.identity_issuer,
            "identity_subject": row.identity_subject,
            "email": row.email,
            "display_name": row.display_name,
            "role": row.role,
            "enabled": row.is_active,
            "revision": row.revision,
        }

    @staticmethod
    def _group_dict(row: Group) -> dict[str, object]:
        return {
            "id": row.id,
            "name": row.name,
            "provider_slug": row.provider_slug,
            "enabled": row.is_active,
            "approval_required": row.approval_required,
            "revision": row.revision,
        }


class SqlSyncRepository:
    """Transactional persistence for provider-independent synchronization."""

    def __init__(self, session: Session) -> None:
        self._session = session

    @staticmethod
    def _resource_snapshot(resource: Any) -> dict[str, object]:
        values: dict[str, object] = {
            "name": resource.name,
            "fingerprint": resource.provider_fingerprint,
        }
        for key in (
            "action",
            "position",
            "category_id",
            "object_type",
            "normalized_value",
            "zone_type",
            "model",
        ):
            value = getattr(resource, key, None)
            if value is not None:
                values[key] = str(value) if isinstance(value, UUID) else value
        return values

    def manager_context(self, manager_id: UUID) -> tuple[UUID, ProviderKind] | None:
        row = self._session.execute(
            select(FirewallManager.organization_id, FirewallManager.provider).where(
                FirewallManager.id == manager_id
            )
        ).one_or_none()
        return (row[0], ProviderKind(row[1])) if row else None

    def start_sync(self, organization_id: UUID, manager_id: UUID) -> UUID:
        run = SyncRun(
            organization_id=organization_id,
            manager_id=manager_id,
            status=SyncStatus.RUNNING,
            complete=False,
        )
        self._session.add(run)
        self._session.flush()
        return run.id

    def record_provider_info(self, manager_id: UUID, info: ProviderInfo) -> None:
        manager = self._session.get(FirewallManager, manager_id)
        if manager is None:
            return
        try:
            if manager.provider_connection_id is not None:
                expected = {
                    name: CapabilityStatus(status) for name, status in manager.capabilities.items()
                }
                if (
                    info.evidence_profile is not ProviderEvidenceProfile.REAL
                    or info.capabilities != expected
                ):
                    raise CapabilityEvidenceMismatchError
            else:
                expected = verify_capability_evidence(
                    load_capabilities(default_capability_path()),
                    ProviderKind(manager.provider),
                    is_mock=manager.is_mock,
                    reported_profile=info.evidence_profile,
                    reported_capabilities=info.capabilities,
                )
        except (CapabilityEvidenceMismatchError, ValueError) as exc:
            raise ProviderContractError(
                details={"code": "CAPABILITY_EVIDENCE_PROFILE_MISMATCH"}
            ) from exc
        capabilities = {name: status.value for name, status in expected.items()}
        values_changed = (
            manager.provider_version != info.provider_version
            or manager.capabilities != capabilities
            or manager.read_only == info.writable
        )
        manager.provider_version = info.provider_version
        manager.capabilities = capabilities
        manager.read_only = not info.writable
        if values_changed:
            manager.revision += 1

    def _upsert(
        self,
        entity_type: type[SyncedModel],
        organization_id: UUID,
        manager_id: UUID,
        run_id: UUID,
        item: NativeResource,
        **extra: object,
    ) -> SyncedModel:
        row = self._session.scalar(
            select(entity_type).where(
                entity_type.manager_id == manager_id, entity_type.native_id == item.native_id
            )
        )
        observed_snapshot: dict[str, object] = {
            "name": item.name,
            "provider_version": item.native_version,
            "fingerprint": item.fingerprint,
            "metadata": sanitize_provider_metadata(item.native_metadata),
        }
        observed_snapshot.update(
            {
                key: str(value) if isinstance(value, UUID) else value
                for key, value in extra.items()
                if value is not None
            }
        )
        if row is None:
            row = entity_type(
                organization_id=organization_id,
                manager_id=manager_id,
                native_id=item.native_id,
                name=item.name,
                provider_version=item.native_version,
                provider_fingerprint=item.fingerprint,
                native_metadata=sanitize_provider_metadata(item.native_metadata),
                application_snapshot=observed_snapshot,
                management_state=ResourceState.OBSERVED,
                revision=1,
                last_seen_sync_run_id=run_id,
                **extra,
            )
            self._session.add(row)
        else:
            changed = row.provider_fingerprint != item.fingerprint
            baseline_missing = not row.application_snapshot
            previous = row.provider_fingerprint
            previous_snapshot = {
                **self._resource_snapshot(row),
                "application_snapshot": row.application_snapshot or {},
            }
            ownership_name_conflict = bool(
                isinstance(row, FirewallObject)
                and row.owner_group_id is not None
                and row.expected_provider_name
                and item.name != row.expected_provider_name
            )
            desired_snapshot = row.application_snapshot or {}
            observed_managed_fields = {
                "name": item.name,
                **{
                    key: value
                    for key, value in extra.items()
                    if key in {"action", "enabled", "position", "category_id"}
                },
            }
            representation_only_change = (
                isinstance(row, AccessRule)
                and row.owner_group_id is not None
                and all(
                    key not in desired_snapshot or str(desired_snapshot[key]) == str(value)
                    for key, value in observed_managed_fields.items()
                )
            )
            row.name = item.name
            row.provider_version = item.native_version
            row.provider_fingerprint = item.fingerprint
            row.native_metadata = sanitize_provider_metadata(item.native_metadata)
            row.last_seen_sync_run_id = run_id
            for key, value in extra.items():
                # Provider observations never assign or clear application ownership/control scope.
                if key not in {
                    "owner_group_id",
                    "owner_policy_id",
                    "created_by_user_id",
                    "modified_by_user_id",
                }:
                    setattr(row, key, value)
            if baseline_missing and not ownership_name_conflict:
                row.application_snapshot = observed_snapshot
                row.management_state = (
                    ResourceState.MANAGED
                    if getattr(row, "owner_group_id", None) is not None
                    else ResourceState.OBSERVED
                )
                row.revision += 1
            elif representation_only_change:
                # Provider representations can change fingerprints after a successful
                # application-owned update (metadata/version/link changes) even when
                # the managed rule fields are unchanged. Do not turn that into a
                # false authorization drift.
                row.management_state = ResourceState.MANAGED
                row.revision += 1
            elif changed or ownership_name_conflict:
                row.management_state = (
                    ResourceState.CONFLICT if ownership_name_conflict else ResourceState.DRIFTED
                )
                row.revision += 1
                self._session.add(
                    DriftRecord(
                        organization_id=organization_id,
                        manager_id=manager_id,
                        sync_run_id=run_id,
                        resource_type=entity_type.__tablename__,
                        resource_id=row.id,
                        status=row.management_state,
                        previous_fingerprint=previous,
                        observed_fingerprint=item.fingerprint,
                        previous_snapshot=previous_snapshot,
                        observed_snapshot={
                            **observed_snapshot,
                        },
                        details={
                            "summary": (
                                "Application-owned provider name no longer matches its "
                                "authoritative owner prefix"
                                if ownership_name_conflict
                                else "Provider fingerprint changed"
                            ),
                            "expected_provider_name": (
                                getattr(row, "expected_provider_name", None)
                                if ownership_name_conflict
                                else None
                            ),
                        },
                    )
                )
            elif row.management_state == ResourceState.MISSING:
                row.management_state = ResourceState.OBSERVED
                row.revision += 1
        self._session.flush()
        return row

    def upsert_domain(
        self, organization_id: UUID, manager_id: UUID, run_id: UUID, item: DiscoveredDomain
    ) -> UUID:
        return self._upsert(ProviderDomain, organization_id, manager_id, run_id, item).id

    def _native_resource_id(
        self, model: type[SyncedModel], manager_id: UUID, native_id: str | None
    ) -> UUID | None:
        if not native_id:
            return None
        return self._session.scalar(
            select(model.id).where(model.manager_id == manager_id, model.native_id == native_id)
        )

    def _prefixed_group_policies(
        self, organization_id: UUID, manager_id: UUID, provider_name: str
    ) -> list[tuple[UUID, UUID]]:
        """Return active group/policy scopes matching a provider-owned name prefix."""
        prefix, separator, _component = provider_name.partition("__")
        if not separator or not prefix:
            return []
        return list(
            self._session.execute(
                select(Group.id, AccessPolicy.id)
                .join(
                    PolicyDelegation,
                    (PolicyDelegation.group_id == Group.id)
                    & (PolicyDelegation.organization_id == Group.organization_id),
                )
                .join(
                    AccessPolicy,
                    (AccessPolicy.id == PolicyDelegation.policy_id)
                    & (AccessPolicy.organization_id == PolicyDelegation.organization_id),
                )
                .where(
                    Group.organization_id == organization_id,
                    Group.provider_slug == prefix,
                    Group.is_active.is_(True),
                    PolicyDelegation.is_active.is_(True),
                    AccessPolicy.manager_id == manager_id,
                    AccessPolicy.management_state.notin_(("MISSING", "CONFLICT")),
                )
                .order_by(AccessPolicy.id)
            )
        )

    def _adopt_prefixed_object(
        self,
        organization_id: UUID,
        manager_id: UUID,
        row: FirewallObject,
        provider_name: str,
    ) -> None:
        if row.object_type in _PROVIDER_SHARED_OBJECT_TYPES:
            # Application catalogs are provider-owned, read-only, and shared
            # with every delegated group; they never receive group grants.
            self._session.query(ObjectUseGrant).filter(
                ObjectUseGrant.organization_id == organization_id,
                ObjectUseGrant.object_id == row.id,
            ).delete(synchronize_session=False)
            row.owner_group_id = None
            row.owner_policy_id = None
            row.expected_provider_name = None
            return
        scopes = self._prefixed_group_policies(organization_id, manager_id, provider_name)
        if row.owner_group_id is not None:
            if row.created_by_user_id is not None:
                return
            allowed = any(
                self._network_object_scope_allowed(row, group_id, policy_id, organization_id)
                for group_id, policy_id in scopes
                if group_id == row.owner_group_id
            )
            if allowed:
                return
            self._session.query(ObjectUseGrant).filter(
                ObjectUseGrant.organization_id == organization_id,
                ObjectUseGrant.group_id == row.owner_group_id,
                ObjectUseGrant.object_id == row.id,
            ).delete(synchronize_session=False)
            row.owner_group_id = None
            row.owner_policy_id = None
            row.expected_provider_name = None
            row.management_state = ResourceState.UNMANAGED
            row.revision += 1
            return
        if not scopes:
            return
        scopes = [
            (group_id, policy_id)
            for group_id, policy_id in scopes
            if self._network_object_scope_allowed(row, group_id, policy_id, organization_id)
        ]
        if not scopes:
            return
        group_id = scopes[0][0]
        row.owner_group_id = group_id
        row.owner_policy_id = scopes[0][1]
        row.expected_provider_name = provider_name
        row.management_state = ResourceState.MANAGED
        row.revision += 1
        for _group_id, policy_id in scopes:
            for permission in ("read", "use"):
                exists = self._session.scalar(
                    select(ObjectUseGrant.id).where(
                        ObjectUseGrant.organization_id == organization_id,
                        ObjectUseGrant.group_id == group_id,
                        ObjectUseGrant.policy_id == policy_id,
                        ObjectUseGrant.object_id == row.id,
                        ObjectUseGrant.permission == permission,
                    )
                )
                if exists is None:
                    self._session.add(
                        ObjectUseGrant(
                            organization_id=organization_id,
                            group_id=group_id,
                            policy_id=policy_id,
                            object_id=row.id,
                            permission=permission,
                        )
                    )

    def _network_object_scope_allowed(
        self, row: FirewallObject, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> bool:
        if row.object_type not in {"NETWORK", "NETWORK_GROUP"}:
            return True
        ranges = list(
            self._session.scalars(
                select(IpRangeGrant.network).where(
                    IpRangeGrant.organization_id == organization_id,
                    IpRangeGrant.policy_id == policy_id,
                    IpRangeGrant.group_id == group_id,
                )
            )
        )
        if row.object_type == "NETWORK":
            return bool(row.normalized_value) and any(
                network_is_contained(str(row.normalized_value), str(grant)) for grant in ranges
            )
        member_ids = list(
            self._session.scalars(
                select(ObjectReference.target_object_id).where(
                    ObjectReference.organization_id == organization_id,
                    ObjectReference.source_object_id == row.id,
                )
            )
        )
        if not member_ids:
            return False
        members = list(
            self._session.scalars(
                select(FirewallObject).where(
                    FirewallObject.organization_id == organization_id,
                    FirewallObject.id.in_(member_ids),
                )
            )
        )
        return len(members) == len(member_ids) and all(
            member.object_type == "NETWORK"
            and bool(member.normalized_value)
            and any(
                network_is_contained(str(member.normalized_value), str(grant)) for grant in ranges
            )
            for member in members
        )

    def _adopt_prefixed_rule(  # noqa: PLR0913, PLR0917 -- adoption scope is explicit
        self,
        organization_id: UUID,
        manager_id: UUID,
        policy_id: UUID,
        category_id: UUID | None,
        row: AccessRule,
        provider_name: str,
    ) -> None:
        """Adopt only rules inside the matching immutable group category."""
        if row.owner_group_id is not None or category_id is None:
            return
        category = self._session.get(RuleCategory, category_id)
        if category is None:
            return
        scopes = self._prefixed_group_policies(organization_id, manager_id, provider_name)
        prefix, _separator, _component = provider_name.partition("__")
        for group_id, delegated_policy_id in scopes:
            if delegated_policy_id != policy_id or category.name != f"{prefix}__RULES":
                continue
            category_mapping = self._session.scalar(
                select(GroupPolicyCategoryMapping).where(
                    GroupPolicyCategoryMapping.organization_id == organization_id,
                    GroupPolicyCategoryMapping.category_id == category.id,
                )
            )
            if category_mapping is not None and (
                category_mapping.group_id != group_id or category_mapping.policy_id != policy_id
            ):
                continue
            mapping = self._session.scalar(
                select(GroupPolicyCategoryMapping).where(
                    GroupPolicyCategoryMapping.organization_id == organization_id,
                    GroupPolicyCategoryMapping.group_id == group_id,
                    GroupPolicyCategoryMapping.policy_id == policy_id,
                )
            )
            if mapping is None:
                mapping = GroupPolicyCategoryMapping(
                    organization_id=organization_id,
                    group_id=group_id,
                    policy_id=policy_id,
                    category_id=category.id,
                    expected_category_name=category.name,
                    sync_state="SYNCED",
                    revision=1,
                )
                self._session.add(mapping)
            elif mapping.category_id != category.id:
                continue
            else:
                mapping.sync_state = "SYNCED"
                mapping.expected_category_name = category.name
                mapping.revision += 1
            row.owner_group_id = group_id
            row.management_state = ResourceState.MANAGED
            row.revision += 1
            return

    def upsert_device(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredDevice,
    ) -> UUID:
        return self._upsert(
            Device, organization_id, manager_id, run_id, item, domain_id=domain_id, model=item.model
        ).id

    def upsert_policy(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredPolicy,
    ) -> UUID:
        return self._upsert(
            AccessPolicy,
            organization_id,
            manager_id,
            run_id,
            item,
            domain_id=domain_id,
        ).id

    def upsert_category(
        self,
        organization_id: UUID,
        manager_id: UUID,
        policy_id: UUID,
        run_id: UUID,
        item: DiscoveredCategory,
    ) -> UUID:
        return self._upsert(
            RuleCategory,
            organization_id,
            manager_id,
            run_id,
            item,
            policy_id=policy_id,
            position=item.position,
        ).id

    def upsert_intrusion_policy(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredIntrusionPolicy,
    ) -> UUID:
        return self._upsert(
            IntrusionPolicy,
            organization_id,
            manager_id,
            run_id,
            item,
            domain_id=domain_id,
            default_variable_set_native_id=item.default_variable_set_native_id,
        ).id

    def upsert_variable_set(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredVariableSet,
    ) -> UUID:
        return self._upsert(
            VariableSet,
            organization_id,
            manager_id,
            run_id,
            item,
            domain_id=domain_id,
            is_default=item.is_default,
        ).id

    def upsert_file_policy(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredFilePolicy,
    ) -> UUID:
        return self._upsert(
            FilePolicy,
            organization_id,
            manager_id,
            run_id,
            item,
            domain_id=domain_id,
        ).id

    def upsert_rule(  # noqa: PLR0913, PLR0917
        self,
        organization_id: UUID,
        manager_id: UUID,
        policy_id: UUID,
        category_id: UUID | None,
        run_id: UUID,
        item: DiscoveredRule,
    ) -> UUID:
        intrusion_policy_id = self._native_resource_id(
            IntrusionPolicy, manager_id, item.intrusion_policy_native_id
        )
        variable_set_id = self._native_resource_id(
            VariableSet, manager_id, item.variable_set_native_id
        )
        if intrusion_policy_id is not None and variable_set_id is None:
            default_variable_set_native_id = self._session.scalar(
                select(IntrusionPolicy.default_variable_set_native_id).where(
                    IntrusionPolicy.id == intrusion_policy_id
                )
            )
            variable_set_id = self._native_resource_id(
                VariableSet, manager_id, default_variable_set_native_id
            )
        row = self._upsert(
            AccessRule,
            organization_id,
            manager_id,
            run_id,
            item,
            policy_id=policy_id,
            category_id=category_id,
            action=item.action,
            enabled=item.enabled,
            log_begin=item.log_begin,
            log_end=item.log_end,
            intrusion_policy_id=intrusion_policy_id,
            variable_set_id=variable_set_id,
            file_policy_id=self._native_resource_id(
                FilePolicy, manager_id, item.file_policy_native_id
            ),
            position=item.position,
        )
        self._adopt_prefixed_rule(
            organization_id,
            manager_id,
            policy_id,
            category_id,
            row,
            item.name,
        )
        return row.id

    def upsert_object(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredObject,
    ) -> UUID:
        row = self._upsert(
            FirewallObject,
            organization_id,
            manager_id,
            run_id,
            item,
            domain_id=domain_id,
            object_type=item.object_type,
            normalized_value=item.normalized_value,
            sharing_mode=item.sharing_mode,
        )
        return row.id

    def upsert_zone(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredZone,
    ) -> UUID:
        return self._upsert(
            SecurityZone,
            organization_id,
            manager_id,
            run_id,
            item,
            domain_id=domain_id,
            zone_type=item.zone_type,
        ).id

    def _target_object_ids(self, manager_id: UUID, native_ids: Sequence[str]) -> dict[str, UUID]:
        if not native_ids:
            return {}
        rows = self._session.execute(
            select(FirewallObject.native_id, FirewallObject.id).where(
                FirewallObject.manager_id == manager_id,
                FirewallObject.native_id.in_(native_ids),
            )
        ).tuples()
        targets: dict[str, UUID] = {}
        for native_id, object_id in rows:
            targets.setdefault(native_id, object_id)
        return targets

    def replace_rule_object_references(
        self,
        organization_id: UUID,
        manager_id: UUID,
        rule_id: UUID,
        references: Sequence[DiscoveredObjectReference],
    ) -> None:
        self._session.query(ObjectReference).filter(
            ObjectReference.source_rule_id == rule_id
        ).delete()
        targets = self._target_object_ids(
            manager_id, [reference.object_native_id for reference in references]
        )
        self._session.add_all(
            ObjectReference(
                organization_id=organization_id,
                manager_id=manager_id,
                source_rule_id=rule_id,
                target_object_id=targets[reference.object_native_id],
                element_type=reference.element,
            )
            for reference in references
            if reference.object_native_id in targets
        )

    def replace_rule_zone_references(
        self,
        organization_id: UUID,
        manager_id: UUID,
        rule_id: UUID,
        references: Sequence[DiscoveredZoneReference],
    ) -> None:
        self._session.query(RuleZoneReference).filter(RuleZoneReference.rule_id == rule_id).delete()
        native_ids = [reference.zone_native_id for reference in references]
        zone_rows = self._session.execute(
            select(SecurityZone.native_id, SecurityZone.id).where(
                SecurityZone.manager_id == manager_id,
                SecurityZone.native_id.in_(native_ids),
            )
        ).tuples()
        targets: dict[str, UUID] = {}
        for native_id, zone_id in zone_rows:
            targets.setdefault(native_id, zone_id)
        self._session.add_all(
            RuleZoneReference(
                organization_id=organization_id,
                manager_id=manager_id,
                rule_id=rule_id,
                zone_id=targets[reference.zone_native_id],
                element_type=reference.element,
            )
            for reference in references
            if reference.zone_native_id in targets
        )

    def refresh_rule_application_snapshot(self, organization_id: UUID, rule_id: UUID) -> None:
        row = self._session.scalar(
            select(AccessRule).where(
                AccessRule.id == rule_id,
                AccessRule.organization_id == organization_id,
            )
        )
        if row is not None and row.management_state not in {
            ResourceState.DRIFTED,
            ResourceState.CONFLICT,
            ResourceState.MISSING,
        }:
            row.application_snapshot = self._resource_snapshot(row)

    def replace_object_references(
        self,
        organization_id: UUID,
        manager_id: UUID,
        source_object_id: UUID,
        object_native_ids: Sequence[str],
    ) -> None:
        self._session.query(ObjectReference).filter(
            ObjectReference.source_object_id == source_object_id
        ).delete()
        targets = self._target_object_ids(manager_id, object_native_ids)
        self._session.add_all(
            ObjectReference(
                organization_id=organization_id,
                manager_id=manager_id,
                source_object_id=source_object_id,
                target_object_id=target_id,
                element_type="MEMBER",
            )
            for target_id in targets.values()
        )
        row = self._session.get(FirewallObject, source_object_id)
        if row is not None:
            self._adopt_prefixed_object(organization_id, manager_id, row, row.name)

    def complete_sync(
        self,
        run_id: UUID,
        manager_id: UUID,
        resources_seen: int,
        applications_only: bool = False,
    ) -> SyncResult:
        for model in (
            ProviderDomain,
            Device,
            AccessPolicy,
            IntrusionPolicy,
            VariableSet,
            FilePolicy,
            RuleCategory,
            AccessRule,
            FirewallObject,
            SecurityZone,
        ):
            if applications_only and model is not FirewallObject:
                continue
            conditions = [
                model.manager_id == manager_id,
                or_(
                    model.last_seen_sync_run_id.is_(None),
                    model.last_seen_sync_run_id != run_id,
                ),
                model.management_state != ResourceState.MISSING,
            ]
            if model is FirewallObject and not applications_only:
                conditions.append(~model.object_type.in_(_PROVIDER_SHARED_OBJECT_TYPES))
            elif model is FirewallObject:
                conditions.append(model.object_type.in_(_PROVIDER_SHARED_OBJECT_TYPES))
            missing_ids = list(self._session.scalars(select(model.id).where(*conditions)))
            if missing_ids:
                self._session.execute(
                    update(model)
                    .where(model.id.in_(missing_ids))
                    .values(management_state=ResourceState.MISSING, revision=model.revision + 1)
                )
        return self._finish(run_id, SyncStatus.COMPLETED, True, resources_seen, None)

    def fail_sync(
        self, run_id: UUID, status: SyncStatus, resources_seen: int, error_code: str
    ) -> SyncResult:
        return self._finish(run_id, status, False, resources_seen, error_code)

    def _finish(
        self,
        run_id: UUID,
        status: SyncStatus,
        complete: bool,
        resources_seen: int,
        error_code: str | None,
    ) -> SyncResult:
        run = self._session.get(SyncRun, run_id)
        if run is None:
            msg = "sync run disappeared"
            raise RuntimeError(msg)
        completed_at = datetime.now(UTC)
        run.status = status
        run.complete = complete
        run.resources_seen = resources_seen
        run.error_code = error_code
        run.completed_at = completed_at
        self._session.commit()
        return SyncResult(run.id, status, resources_seen, run.started_at, completed_at)
