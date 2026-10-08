# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

# ruff: noqa: F811 -- imported pytest fixture is injected by name.

"""Upgraded authority stays quarantined until individual, audited scope confirmation."""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import select

from firewall_manager.application.authorization import AuthorizationService
from firewall_manager.application.errors import ResourceOutOfScopeError, StaleWriteError
from firewall_manager.application.legacy_ownership import LegacyOwnershipService
from firewall_manager.domain.models import (
    Action,
    AuthorizationResource,
    AuthorizationResourceType,
    DelegatedPolicyContext,
    Principal,
)
from firewall_manager.persistence.models import (
    AuditEvent,
    FirewallObject,
    LegacyOwnershipReview,
    ObjectUseGrant,
)
from firewall_manager.persistence.repositories import SqlAuthorizationRepository
from test_rc_persistence import database  # noqa: F401 -- shared migrated-PostgreSQL fixture


def quarantine(session):
    path = (
        Path(__file__).parents[1] / "alembic/versions/20261007_0045_quarantine_legacy_authority.py"
    )
    spec = importlib.util.spec_from_file_location("legacy_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with Operations.context(MigrationContext.configure(session.connection())):
        module.quarantine_existing_authority()
    session.expire_all()


def legacy_object(session, rows):
    obj = FirewallObject(
        organization_id=rows["org"].id,
        manager_id=rows["manager"].id,
        domain_id=rows["domain"].id,
        native_id=str(uuid4()),
        name="FINANCE__LEGACY",
        provider_fingerprint="legacy",
        object_type="NETWORK",
        normalized_value="10.1.1.1",
        owner_group_id=rows["group"].id,
        owner_policy_id=rows["policy"].id,
        expected_provider_name="FINANCE__LEGACY",
        management_state="MANAGED",
    )
    session.add(obj)
    session.flush()
    session.add(
        ObjectUseGrant(
            organization_id=rows["org"].id,
            group_id=rows["group"].id,
            policy_id=rows["policy"].id,
            object_id=obj.id,
            permission="use",
        )
    )
    session.flush()
    return obj


def test_upgrade_quarantines_mutation_and_use_until_scoped_audited_review(database):
    session, rows = database
    obj = legacy_object(session, rows)
    auth = SqlAuthorizationRepository(session)
    args = (rows["group"].id, rows["policy"].id, obj.id, rows["org"].id)
    assert auth.object_grant_state(*args) is not None
    quarantine(session)
    service = LegacyOwnershipService(session)
    reviews = service.list(rows["principal"])
    assert len(reviews) == 2
    assert auth.object_grant_state(*args) is None
    assert auth.object_mutation_state(*args) is None
    # Provider synchronization/state changes cannot release the independent quarantine.
    obj.management_state = "MANAGED"
    obj.revision += 1
    session.flush()
    assert auth.object_mutation_state(*args) is None
    reviews = service.list(rows["principal"])
    for review in reviews:
        with pytest.raises(ResourceOutOfScopeError):
            service.confirm(
                rows["principal"],
                review["id"],
                uuid4(),
                rows["policy"].id,
                review["resource_revision"],
                "Verified original assignment",
            )
        service.confirm(
            rows["principal"],
            review["id"],
            rows["group"].id,
            rows["policy"].id,
            review["resource_revision"],
            "Verified original assignment",
        )
    grant = auth.object_grant_state(*args)
    ownership = auth.object_mutation_state(*args)
    assert grant is not None
    assert grant[2] == {"use"}
    assert ownership is not None
    assert ownership["owner_group_id"] == rows["group"].id
    assert (
        not AuthorizationService(auth)
        .authorize(
            DelegatedPolicyContext(rows["principal"], uuid4(), rows["policy"].id),
            Action.MODIFY,
            AuthorizationResource(AuthorizationResourceType.OBJECT, obj.id),
        )
        .allowed
    )
    events = list(
        session.scalars(
            select(AuditEvent).where(AuditEvent.resource_type == "legacy_ownership_review")
        )
    )
    assert len(events) == 2
    assert all(
        e.actor_user_id == rows["user"].id and e.active_group_id == rows["group"].id for e in events
    )
    assert all(e.details["reason"] == "Verified original assignment" for e in events)


def test_legacy_review_rejects_nonadmin_stale_and_cross_policy_confirmation(database):
    session, rows = database
    legacy_object(session, rows)
    quarantine(session)
    service = LegacyOwnershipService(session)
    review = service.list(rows["principal"])[0]
    user = rows["user"]
    delegated = Principal(user.id, user.organization_id, user.email, "user")
    with pytest.raises(ResourceOutOfScopeError):
        service.confirm(
            delegated, review["id"], rows["group"].id, rows["policy"].id, 1, "Reviewed individually"
        )
    with pytest.raises(ResourceOutOfScopeError):
        service.confirm(
            rows["principal"], review["id"], rows["group"].id, uuid4(), 1, "Reviewed individually"
        )
    with pytest.raises(StaleWriteError):
        service.confirm(
            rows["principal"],
            review["id"],
            rows["group"].id,
            rows["policy"].id,
            999,
            "Reviewed individually",
        )


def test_legacy_data_migration_is_idempotent_and_fresh_resources_are_not_quarantined(database):
    session, rows = database
    assert list(session.scalars(select(LegacyOwnershipReview))) == []
    legacy_object(session, rows)
    # A resource explicitly created after the migration is not automatically legacy.
    assert list(session.scalars(select(LegacyOwnershipReview))) == []
    quarantine(session)
    first = set(session.scalars(select(LegacyOwnershipReview.id)))
    quarantine(session)
    assert set(session.scalars(select(LegacyOwnershipReview.id))) == first
    assert len(first) == 2
