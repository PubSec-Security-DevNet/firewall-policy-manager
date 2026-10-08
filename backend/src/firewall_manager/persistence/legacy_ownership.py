# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Durable legacy authority quarantine, independent of provider sync state."""

from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from firewall_manager.persistence.models import LegacyOwnershipReview


def pending_review(
    session: Session,
    organization_id: UUID,
    *,
    group_id: UUID | None = None,
    policy_id: UUID | None = None,
    resource_id: UUID | None = None,
) -> bool:
    clauses = [
        LegacyOwnershipReview.organization_id == organization_id,
        LegacyOwnershipReview.confirmed_at.is_(None),
    ]
    if group_id is not None:
        clauses.append(LegacyOwnershipReview.group_id == group_id)
    if policy_id is not None:
        clauses.append(
            or_(
                LegacyOwnershipReview.policy_id == policy_id,
                LegacyOwnershipReview.policy_id.is_(None),
            )
        )
    if resource_id is not None:
        clauses.append(LegacyOwnershipReview.resource_id == resource_id)
    return session.scalar(select(LegacyOwnershipReview.id).where(*clauses).limit(1)) is not None
