"""SQLAlchemy implementations of application repository ports."""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import UUID

from sqlalchemy import ColumnElement, func, or_, select, update
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
    DiscoveredCategory,
    DiscoveredDevice,
    DiscoveredDomain,
    DiscoveredObject,
    DiscoveredObjectReference,
    DiscoveredPolicy,
    DiscoveredRule,
    DiscoveredZone,
    DiscoveredZoneReference,
    NativeResource,
    Principal,
    ProviderEvidenceProfile,
    ProviderInfo,
    ProviderKind,
    ResourceState,
    SyncResult,
    SyncStatus,
)
from firewall_manager.persistence.models import (
    AccessPolicy,
    AccessRule,
    AuditEvent,
    ChangeSet,
    Device,
    DirectUserPolicyGrant,
    DriftRecord,
    FirewallManager,
    FirewallObject,
    Group,
    GroupMembership,
    GroupPolicyCategoryMapping,
    IpRangeGrant,
    ObjectCreateGrant,
    ObjectReference,
    ObjectUseGrant,
    Organization,
    PolicyDelegation,
    ProviderDomain,
    RuleCategory,
    RuleZoneReference,
    SecurityZone,
    SyncRun,
    User,
    ZoneGrant,
)
from firewall_manager.providers.capabilities import (
    CapabilityEvidenceMismatchError,
    default_capability_path,
    load_capabilities,
    verify_capability_evidence,
)

SyncedModel = TypeVar(
    "SyncedModel",
    ProviderDomain,
    Device,
    AccessPolicy,
    RuleCategory,
    AccessRule,
    FirewallObject,
    SecurityZone,
)
_SENSITIVE_METADATA_PARTS = ("secret", "password", "token", "authorization", "private_key")
_USABLE_STATES = ("OBSERVED", "UNMANAGED", "MANAGED")
_OBJECT_CREATE_CAPABILITY_NAMES = {
    "NETWORK": "network_object_create",
    "PORT_SERVICE": "port_service_object_create",
    "URL": "url_object_create",
    "APPLICATION": "application_object_create",
    "APPLICATION_FILTER": "application_object_create",
}


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
        return {
            "managers": self._count(
                FirewallManager, FirewallManager.organization_id == organization_id
            ),
            "policies": self._count(AccessPolicy, AccessPolicy.organization_id == organization_id),
            "rules": self._count(AccessRule, AccessRule.organization_id == organization_id),
            "objects": self._count(
                FirewallObject, FirewallObject.organization_id == organization_id
            ),
            "change_sets": self._count(ChangeSet, ChangeSet.organization_id == organization_id),
        }

    def _count(self, model: type[Any], where: ColumnElement[bool]) -> int:
        value = self._session.scalar(select(func.count()).select_from(model).where(where))
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
            [FirewallManager.organization_id == organization_id],
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
        where = [AccessPolicy.organization_id == organization_id]
        if manager_id is not None:
            where.append(AccessPolicy.manager_id == manager_id)
        rows, total = self._page(AccessPolicy, where, offset, limit)
        return [self._resource_dict(row) for row in rows], total

    def list_rules(
        self, organization_id: UUID, policy_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        where = [AccessRule.organization_id == organization_id]
        if policy_id is not None:
            where.append(AccessRule.policy_id == policy_id)
        rows, total = self._page(AccessRule, where, offset, limit)
        return [
            {
                **self._resource_dict(row),
                "policy_id": row.policy_id,
                "category_id": row.category_id,
                "action": row.action,
                "position": row.position,
            }
            for row in rows
        ], total

    def list_objects(
        self, organization_id: UUID, manager_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        where = [FirewallObject.organization_id == organization_id]
        if manager_id is not None:
            where.append(FirewallObject.manager_id == manager_id)
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
        managers = list(
            self._session.scalars(
                select(FirewallManager)
                .where(FirewallManager.organization_id == organization_id)
                .order_by(FirewallManager.display_name)
            )
        )
        result: list[dict[str, object]] = []
        for manager in managers:
            latest = self._session.scalar(
                select(SyncRun)
                .where(
                    SyncRun.organization_id == organization_id,
                    SyncRun.manager_id == manager.id,
                )
                .order_by(SyncRun.started_at.desc())
                .limit(1)
            )
            result.append(
                {
                    "manager_id": manager.id,
                    "provider": manager.provider,
                    "display_name": manager.display_name,
                    "provider_version": manager.provider_version,
                    "capabilities": manager.capabilities,
                    "evidence_profile": (
                        ProviderEvidenceProfile.MOCK.value
                        if manager.is_mock
                        else ProviderEvidenceProfile.REAL.value
                    ),
                    "writable": not manager.read_only,
                    "sync_status": latest.status if latest else None,
                    "sync_complete": latest.complete if latest else False,
                    "resources_seen": latest.resources_seen if latest else 0,
                    "last_sync_at": latest.completed_at if latest else None,
                    "error_code": latest.error_code if latest else None,
                }
            )
        return result


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
        row = self._session.execute(
            select(
                AccessPolicy.manager_id,
                FirewallManager.capabilities,
                FirewallManager.is_mock,
                ObjectCreateGrant.revision,
            )
            .join(
                ObjectCreateGrant,
                (ObjectCreateGrant.policy_id == AccessPolicy.id)
                & (ObjectCreateGrant.organization_id == AccessPolicy.organization_id),
            )
            .join(FirewallManager, FirewallManager.id == AccessPolicy.manager_id)
            .where(
                ObjectCreateGrant.organization_id == organization_id,
                ObjectCreateGrant.group_id == group_id,
                ObjectCreateGrant.policy_id == policy_id,
                ObjectCreateGrant.object_type == object_type,
            )
        ).one_or_none()
        if row is None:
            return None
        return row[0], dict(row[1]), int(row[3])

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
                    actor_user_id=decision.principal_id,
                    active_group_id=active_group_id,
                    policy_id=policy_id,
                    action=decision.action.value,
                    resource_type=decision.resource_type.value,
                    resource_id=decision.resource_id,
                    decision="ALLOW" if decision.allowed else "DENY",
                    reason_code=decision.reason.value,
                    interface=interface,
                    correlation_id=correlation_id,
                    details={"authorization_revision": decision.authorization_revision},
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

    def delegated_context_view(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
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
        rules = list(
            self._session.scalars(
                select(AccessRule)
                .where(
                    AccessRule.organization_id == organization_id,
                    AccessRule.policy_id == policy_id,
                    AccessRule.owner_group_id == group_id,
                    AccessRule.management_state.notin_(("MISSING", "CONFLICT")),
                )
                .order_by(AccessRule.position, AccessRule.id)
            )
        )
        objects = list(
            self._session.execute(
                select(
                    FirewallObject.id,
                    FirewallObject.name,
                    FirewallObject.object_type,
                    FirewallObject.owner_group_id,
                    FirewallObject.owner_policy_id,
                    FirewallObject.created_by_user_id,
                )
                .join(
                    ObjectUseGrant,
                    (ObjectUseGrant.object_id == FirewallObject.id)
                    & (ObjectUseGrant.organization_id == FirewallObject.organization_id),
                )
                .where(
                    FirewallObject.organization_id == organization_id,
                    FirewallObject.manager_id == policy.manager_id,
                    FirewallObject.management_state.in_(_USABLE_STATES),
                    ObjectUseGrant.group_id == group_id,
                    ObjectUseGrant.policy_id == policy_id,
                    ObjectUseGrant.permission == "use",
                )
                .distinct()
                .order_by(FirewallObject.name, FirewallObject.id)
            )
        )
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
        manager = self._session.get(FirewallManager, policy.manager_id)
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
        return {
            "policy": {
                "id": policy.id,
                "manager_id": policy.manager_id,
                "name": policy.name,
                "management_state": policy.management_state,
                "revision": policy.revision,
            },
            "capabilities": sorted(capabilities),
            "rules": [
                {
                    "id": row.id,
                    "name": row.name,
                    "action": row.action,
                    "position": row.position,
                    "management_state": row.management_state,
                    "revision": row.revision,
                    "category_id": row.category_id,
                }
                for row in rules
            ],
            "objects": [
                {
                    "id": row[0],
                    "name": row[1],
                    "object_type": row[2],
                    "owner_type": "GROUP" if row[3] is not None else "PROVIDER",
                    "owner_group_id": row[3],
                    "owner_policy_id": row[4],
                    "created_by_user_id": row[5],
                }
                for row in objects
            ],
            "zones": [{"id": row[0], "name": row[1], "direction": row[2]} for row in zones],
            "categories": [{"id": row[0], "name": row[1]} for row in categories],
            "ip_ranges": ranges,
            "object_create": [
                {
                    "object_type": object_type,
                    "provider_supported": bool(manager)
                    and manager.capabilities.get(
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
            revision=1,
        )
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
            "revision": row.revision,
        }


class SqlSyncRepository:
    """Transactional persistence for provider-independent synchronization."""

    def __init__(self, session: Session) -> None:
        self._session = session

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
                read_capabilities = {
                    "authentication_session",
                    "manager_tenant_discovery",
                    "device_discovery",
                    "access_policy_discovery",
                    "rule_category_read",
                    "access_rule_read",
                    "network_object_read",
                    "network_groups",
                    "security_zone_read",
                }
                write_promoted = any(
                    status is not CapabilityStatus.NOT_STARTED
                    for name, status in expected.items()
                    if name not in read_capabilities
                )
                if (
                    info.evidence_profile is not ProviderEvidenceProfile.REAL
                    or info.capabilities != expected
                    or info.writable
                    or write_promoted
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
        if row is None:
            row = entity_type(
                organization_id=organization_id,
                manager_id=manager_id,
                native_id=item.native_id,
                name=item.name,
                provider_version=item.native_version,
                provider_fingerprint=item.fingerprint,
                native_metadata=sanitize_provider_metadata(item.native_metadata),
                management_state=ResourceState.OBSERVED,
                revision=1,
                last_seen_sync_run_id=run_id,
                **extra,
            )
            self._session.add(row)
        else:
            changed = row.provider_fingerprint != item.fingerprint
            previous = row.provider_fingerprint
            ownership_name_conflict = bool(
                isinstance(row, FirewallObject)
                and row.owner_group_id is not None
                and row.expected_provider_name
                and item.name != row.expected_provider_name
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
            if changed or ownership_name_conflict:
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

    def upsert_rule(  # noqa: PLR0913, PLR0917
        self,
        organization_id: UUID,
        manager_id: UUID,
        policy_id: UUID,
        category_id: UUID | None,
        run_id: UUID,
        item: DiscoveredRule,
    ) -> UUID:
        return self._upsert(
            AccessRule,
            organization_id,
            manager_id,
            run_id,
            item,
            policy_id=policy_id,
            category_id=category_id,
            action=item.action,
            position=item.position,
        ).id

    def upsert_object(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredObject,
    ) -> UUID:
        return self._upsert(
            FirewallObject,
            organization_id,
            manager_id,
            run_id,
            item,
            domain_id=domain_id,
            object_type=item.object_type,
            normalized_value=item.normalized_value,
            sharing_mode=item.sharing_mode,
        ).id

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

    def complete_sync(self, run_id: UUID, manager_id: UUID, resources_seen: int) -> SyncResult:
        for model in (
            ProviderDomain,
            Device,
            AccessPolicy,
            RuleCategory,
            AccessRule,
            FirewallObject,
            SecurityZone,
        ):
            missing_ids = list(
                self._session.scalars(
                    select(model.id).where(
                        model.manager_id == manager_id,
                        or_(
                            model.last_seen_sync_run_id.is_(None),
                            model.last_seen_sync_run_id != run_id,
                        ),
                        model.management_state != ResourceState.MISSING,
                    )
                )
            )
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
