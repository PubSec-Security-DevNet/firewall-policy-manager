"""Structural persistence invariants that do not require a running database."""

from typing import cast
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from sqlalchemy import CheckConstraint, DateTime, Table, UniqueConstraint
from sqlalchemy.orm import Session

from firewall_manager.application.errors import ResourceOutOfScopeError
from firewall_manager.persistence.models import (
    AccessPolicy,
    AccessRule,
    AuditEvent,
    ChangeSet,
    FirewallManager,
    FirewallObject,
    Group,
    GroupMembership,
    GroupPolicyCategoryMapping,
    IpRangeGrant,
    ObjectCreateGrant,
    ObjectReference,
    ObjectUseGrant,
    PolicyDelegation,
    ProviderCapabilityEvidence,
    ProviderConnection,
    ProviderConnectionScope,
    ProviderDomain,
    ResourceGrant,
    ResourceOwnership,
    RuleCategory,
    RuleZoneReference,
    SecretRecord,
    SecurityZone,
    SyncRun,
    User,
    ZoneGrant,
)
from firewall_manager.persistence.repositories import (
    SqlAdministrationRepository,
    sanitize_provider_metadata,
)
from firewall_manager.seed import upsert_authorization_seed_row


def test_internal_identity_is_distinct_from_provider_native_identity() -> None:
    manager_table = cast(Table, FirewallManager.__table__)
    assert [column.name for column in manager_table.primary_key.columns] == ["id"]
    assert manager_table.c.native_id.primary_key is False
    unique_sets = {
        tuple(column.name for column in constraint.columns)
        for constraint in manager_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("organization_id", "provider", "native_id") in unique_sets


def test_real_provider_connections_reference_secrets_and_namespace_evidence() -> None:
    connection_table = cast(Table, ProviderConnection.__table__)
    assert {
        "organization_id",
        "provider_type",
        "lifecycle",
        "credential_reference",
        "provider_version",
        "sync_status",
        "revision",
    } <= set(connection_table.c.keys())
    credential_fk = next(iter(connection_table.c.credential_reference.foreign_keys))
    assert credential_fk.target_fullname == "secret_records.id"
    assert credential_fk.ondelete == "RESTRICT"
    assert "password" not in connection_table.c
    assert "token" not in connection_table.c
    assert {"ciphertext", "nonce", "key_version", "purpose"} <= set(SecretRecord.__table__.c.keys())

    manager_connection_fk = next(
        iter(FirewallManager.__table__.c.provider_connection_id.foreign_keys)
    )
    assert manager_connection_fk.ondelete == "RESTRICT"
    assert {"connection_id", "native_id", "scope_type"} <= set(
        ProviderConnectionScope.__table__.c.keys()
    )
    evidence_table = cast(Table, ProviderCapabilityEvidence.__table__)
    evidence_unique_sets = {
        tuple(column.name for column in constraint.columns)
        for constraint in evidence_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("connection_id", "provider_version", "capability") in evidence_unique_sets


def test_all_provider_resources_have_structural_org_manager_and_sync_scope() -> None:
    for model in (
        ProviderDomain,
        AccessPolicy,
        RuleCategory,
        AccessRule,
        FirewallObject,
        SecurityZone,
    ):
        assert {"organization_id", "manager_id", "last_seen_sync_run_id"} <= set(
            model.__table__.c.keys()
        )
        assert model.__table__.c.organization_id.foreign_keys
        assert model.__table__.c.manager_id.foreign_keys


def test_dependency_ownership_grant_and_sync_relationships_are_constrained() -> None:
    reference_foreign_keys = {
        foreign_key.target_fullname
        for column in ObjectReference.__table__.columns
        for foreign_key in column.foreign_keys
    }
    assert "access_rules.id" in reference_foreign_keys
    assert "firewall_objects.id" in reference_foreign_keys
    assert ResourceOwnership.__table__.c.owner_group_id.foreign_keys
    assert ResourceGrant.__table__.c.ownership_id.foreign_keys
    assert ObjectReference.__table__.c.element_type is not None
    assert RuleZoneReference.__table__.c.zone_id.foreign_keys
    completed_at_type = cast(DateTime, SyncRun.__table__.c.completed_at.type)
    assert completed_at_type.timezone is True


def test_mutable_resources_enforce_positive_revision() -> None:
    for model in (FirewallManager, AccessPolicy, RuleCategory, AccessRule, FirewallObject):
        table = cast(Table, model.__table__)
        checks = {
            str(constraint.sqltext)
            for constraint in table.constraints
            if isinstance(constraint, CheckConstraint)
        }
        assert "revision >= 1" in checks


def test_provider_metadata_sanitization_prevents_secret_storage() -> None:
    assert sanitize_provider_metadata(
        {
            "display_hint": "edge",
            "access_token": "must-not-persist",
            "clientSecret": "must-not-persist",
            "authorization": "must-not-persist",
        }
    ) == {"display_hint": "edge"}


def test_user_and_group_are_distinct_and_membership_supports_multiple_groups() -> None:
    assert Group.__tablename__ == "application_groups"
    assert "team_id" not in User.__table__.c
    assert {"user_id", "group_id", "organization_id"} <= set(GroupMembership.__table__.c.keys())
    membership_table = cast(Table, GroupMembership.__table__)
    membership_uniques = {
        tuple(column.name for column in constraint.columns)
        for constraint in membership_table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("user_id", "group_id") in membership_uniques
    assert Group.__table__.c.provider_slug.nullable is False


def test_group_policy_rule_and_changeset_contexts_are_structurally_distinct() -> None:
    shared_policy_id = UUID("10000000-0000-0000-0000-000000000001")
    first_mapping = GroupPolicyCategoryMapping(
        group_id=UUID("20000000-0000-0000-0000-000000000001"),
        policy_id=shared_policy_id,
        category_id=UUID("30000000-0000-0000-0000-000000000001"),
    )
    second_mapping = GroupPolicyCategoryMapping(
        group_id=UUID("20000000-0000-0000-0000-000000000002"),
        policy_id=shared_policy_id,
        category_id=UUID("30000000-0000-0000-0000-000000000002"),
    )
    other_policy_mapping = GroupPolicyCategoryMapping(
        group_id=first_mapping.group_id,
        policy_id=UUID("10000000-0000-0000-0000-000000000002"),
        category_id=UUID("30000000-0000-0000-0000-000000000003"),
    )
    assert first_mapping.policy_id == second_mapping.policy_id
    assert first_mapping.group_id != second_mapping.group_id
    assert first_mapping.category_id != second_mapping.category_id
    assert first_mapping.group_id == other_policy_mapping.group_id
    assert first_mapping.policy_id != other_policy_mapping.policy_id
    assert first_mapping.category_id != other_policy_mapping.category_id
    assert AccessRule.__table__.c.owner_group_id.foreign_keys
    assert AccessRule.__table__.c.created_by_user_id.foreign_keys
    assert AccessRule.__table__.c.modified_by_user_id.foreign_keys
    assert ChangeSet.__table__.c.principal_id.foreign_keys
    assert ChangeSet.__table__.c.acting_group_id.foreign_keys
    assert ChangeSet.__table__.c.access_policy_id.foreign_keys


def test_objects_and_zones_retain_authorizable_normalized_structure() -> None:
    assert "normalized_value" in FirewallObject.__table__.c
    assert "value" not in FirewallObject.__table__.c
    assert FirewallObject.__table__.c.owner_group_id.foreign_keys
    assert FirewallObject.__table__.c.owner_policy_id.foreign_keys
    assert "expected_provider_name" in FirewallObject.__table__.c
    object_table = cast(Table, FirewallObject.__table__)
    checks = {
        constraint.name
        for constraint in object_table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert "ck_firewall_objects_authoritative_owner" in checks
    assert {"manager_id", "native_id", "zone_type"} <= set(SecurityZone.__table__.c.keys())


def test_delegated_grants_are_durable_and_explicitly_context_scoped() -> None:
    for model in (
        PolicyDelegation,
        ObjectUseGrant,
        ZoneGrant,
        IpRangeGrant,
        ObjectCreateGrant,
    ):
        assert {"organization_id", "group_id", "policy_id", "revision"} <= set(
            model.__table__.c.keys()
        )
    assert "permission" in ObjectUseGrant.__table__.c
    assert "direction" in ZoneGrant.__table__.c
    assert {"network", "ip_version"} <= set(IpRangeGrant.__table__.c.keys())
    assert "object_type" in ObjectCreateGrant.__table__.c


@pytest.mark.parametrize(
    ("resource", "resource_key"),
    [("object-use-grants", "object_id"), ("zone-grants", "zone_id")],
)
def test_provider_resource_grants_require_the_policy_manager(
    resource: str, resource_key: str
) -> None:
    policy_manager_id = UUID("40000000-0000-0000-0000-000000000001")
    other_manager_id = UUID("40000000-0000-0000-0000-000000000002")
    session = MagicMock(spec=Session)
    repository = SqlAdministrationRepository(session)
    values: dict[str, object] = {
        "policy_id": UUID("50000000-0000-0000-0000-000000000001"),
        resource_key: UUID("60000000-0000-0000-0000-000000000001"),
    }

    session.scalar.side_effect = [policy_manager_id, other_manager_id]
    with pytest.raises(ResourceOutOfScopeError):
        repository._validate_provider_resource_manager(  # pyright: ignore[reportPrivateUsage]
            UUID("10000000-0000-0000-0000-000000000001"), resource, values
        )

    session.scalar.side_effect = [policy_manager_id, policy_manager_id]
    repository._validate_provider_resource_manager(  # pyright: ignore[reportPrivateUsage]
        UUID("10000000-0000-0000-0000-000000000001"), resource, values
    )


def test_identity_and_audit_models_preserve_security_context() -> None:
    assert {"identity_issuer", "identity_subject", "is_active", "revision"} <= set(
        User.__table__.c.keys()
    )
    assert {"actor_user_id", "active_group_id", "policy_id", "decision", "reason_code"} <= set(
        AuditEvent.__table__.c.keys()
    )


def test_authorization_seed_upsert_matches_natural_key_after_admin_recreates_grant() -> None:
    organization_id = UUID("10000000-0000-0000-0000-000000000001")
    group_id = UUID("20000000-0000-0000-0000-000000000002")
    policy_id = UUID("50000000-0000-0000-0000-000000000001")
    recreated_id = UUID("80000000-0000-0000-0000-000000000001")
    existing = PolicyDelegation(
        id=recreated_id,
        organization_id=organization_id,
        group_id=group_id,
        policy_id=policy_id,
        capabilities=["view"],
        is_active=False,
        revision=4,
    )
    seeded = PolicyDelegation(
        id=UUID("80000000-0000-0000-0000-000000000002"),
        organization_id=organization_id,
        group_id=group_id,
        policy_id=policy_id,
        capabilities=["reorder_rule"],
    )
    session = MagicMock(spec=Session)
    session.scalar.return_value = existing

    upsert_authorization_seed_row(session, seeded)

    assert existing.id == recreated_id
    assert existing.revision == 4
    assert existing.capabilities == ["reorder_rule"]
    assert existing.is_active is False
    session.add.assert_not_called()
