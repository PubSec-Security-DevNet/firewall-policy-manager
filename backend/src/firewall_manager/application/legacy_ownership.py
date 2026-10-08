# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Explicit, individual Platform Admin reconfirmation of preserved legacy authority."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from firewall_manager.application.authorization import require_action
from firewall_manager.application.errors import (
    InvalidInputError,
    ResourceOutOfScopeError,
    StaleWriteError,
)
from firewall_manager.domain.models import Action, Principal
from firewall_manager.persistence.models import (
    AccessRule,
    AuditEvent,
    FirewallObject,
    GroupPolicyCategoryMapping,
    LegacyOwnershipReview,
    ObjectUseGrant,
    User,
)

_MODELS = {
    "RULE": AccessRule,
    "OBJECT": FirewallObject,
    "CATEGORY": GroupPolicyCategoryMapping,
    "OBJECT_USE": ObjectUseGrant,
}


class LegacyOwnershipService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def _admin(self, principal: Principal) -> None:
        require_action(principal, Action.MANAGE_GRANTS)
        user = self._session.get(User, principal.user_id, populate_existing=True)
        if (
            user is None
            or not user.is_active
            or user.role != "admin"
            or user.organization_id != principal.organization_id
        ):
            raise ResourceOutOfScopeError

    def list(self, principal: Principal) -> list[dict[str, object]]:
        self._admin(principal)
        rows = self._session.scalars(
            select(LegacyOwnershipReview)
            .where(
                LegacyOwnershipReview.organization_id == principal.organization_id,
                LegacyOwnershipReview.confirmed_at.is_(None),
            )
            .order_by(LegacyOwnershipReview.created_at, LegacyOwnershipReview.id)
            .limit(100)
        )
        return [self._view(row) for row in rows]

    def _view(self, row: LegacyOwnershipReview) -> dict[str, object]:
        resource = self._session.get(_MODELS[row.resource_type], row.resource_id)
        return {
            "id": str(row.id),
            "resource_type": row.resource_type,
            "resource_id": str(row.resource_id),
            "group_id": str(row.group_id),
            "policy_id": str(row.policy_id) if row.policy_id else None,
            "name": str(
                row.snapshot.get("name")
                or row.snapshot.get("expected_category_name")
                or row.resource_id
            ),
            "legacy_assignment": row.snapshot,
            "resource_revision": resource.revision if resource else None,
            "status": "CONFIRMED" if row.confirmed_at else "REVIEW_REQUIRED",
        }

    def confirm(  # noqa: PLR0913, PLR0917 -- explicit review scope
        self,
        principal: Principal,
        review_id: UUID,
        group_id: UUID,
        policy_id: UUID,
        resource_revision: int,
        reason: str,
    ) -> dict[str, object]:
        self._admin(principal)
        if not 10 <= len(reason.strip()) <= 1000:
            raise InvalidInputError(details={"field": "reason"})
        row = self._session.scalar(
            select(LegacyOwnershipReview)
            .where(
                LegacyOwnershipReview.id == review_id,
                LegacyOwnershipReview.organization_id == principal.organization_id,
                LegacyOwnershipReview.group_id == group_id,
                LegacyOwnershipReview.policy_id == policy_id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if row is None:
            raise ResourceOutOfScopeError
        if row.confirmed_at is not None:
            raise StaleWriteError
        resource = self._session.scalar(
            select(_MODELS[row.resource_type])
            .where(
                _MODELS[row.resource_type].id == row.resource_id,
                _MODELS[row.resource_type].organization_id == principal.organization_id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if resource is None or resource.revision != resource_revision:
            raise StaleWriteError
        actual_group = getattr(resource, "owner_group_id", getattr(resource, "group_id", None))
        actual_policy = getattr(resource, "owner_policy_id", getattr(resource, "policy_id", None))
        if actual_group != group_id or actual_policy != policy_id:
            raise ResourceOutOfScopeError
        row.confirmed_at = datetime.now(UTC)
        row.confirmed_by = principal.audit_user_id
        row.confirmation_reason = reason.strip()
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                active_group_id=group_id,
                policy_id=policy_id,
                action="manage_grants",
                resource_type="legacy_ownership_review",
                resource_id=row.id,
                decision="CONFIRM",
                reason_code="EXPLICIT_LEGACY_AUTHORITY_CONFIRMATION",
                interface="rest",
                details={
                    "resource_type": row.resource_type,
                    "resource_id": str(row.resource_id),
                    "group_id": str(group_id),
                    "policy_id": str(policy_id),
                    "resource_revision": resource_revision,
                    "reason": reason.strip(),
                },
            )
        )
        self._session.flush()
        return self._view(row)
