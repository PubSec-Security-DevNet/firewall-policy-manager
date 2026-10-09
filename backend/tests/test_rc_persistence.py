# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Security regressions against a migrated, explicitly selected PostgreSQL database."""

import os
from collections.abc import Iterator
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from firewall_manager.application.errors import InvalidChangeSetStateError, ResourceOutOfScopeError
from firewall_manager.domain.models import (
    DiscoveredCategory,
    DiscoveredObject,
    DiscoveredRule,
    Principal,
)
from firewall_manager.persistence.changesets import SqlChangeSetRepository
from firewall_manager.persistence.models import (
    AccessPolicy,
    AccessRule,
    ChangeSet,
    FirewallManager,
    FirewallObject,
    Group,
    GroupPolicyCategoryMapping,
    IntrusionPolicy,
    IpRangeGrant,
    ObjectUseGrant,
    Organization,
    PolicyDelegation,
    ProviderDomain,
    RuleCategory,
    SyncRun,
    User,
)
from firewall_manager.persistence.repositories import SqlSyncRepository


@pytest.fixture
def database() -> Iterator[tuple[Session, dict]]:
    url = os.environ.get("FPM_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set FPM_TEST_DATABASE_URL to a migrated disposable PostgreSQL database")
    engine = create_engine(url)
    with engine.connect() as connection, connection.begin() as transaction:
        with Session(
            connection, join_transaction_mode="create_savepoint", expire_on_commit=False
        ) as session:
            org = Organization(name=f"rc-test-{uuid4()}")
            session.add(org)
            session.flush()
            manager = FirewallManager(
                organization_id=org.id,
                provider="fmc",
                native_id="test",
                display_name="Test",
                base_url="https://fmc.example.test",
            )
            group = Group(
                organization_id=org.id,
                name="Finance",
                provider_slug="FINANCE",
                approval_required=True,
            )
            user = User(
                organization_id=org.id,
                identity_issuer="https://id.example.test",
                identity_subject=str(uuid4()),
                email="user@example.test",
                display_name="User",
                role="admin",
            )
            session.add_all([manager, group, user])
            session.flush()
            domain = ProviderDomain(
                organization_id=org.id,
                manager_id=manager.id,
                native_id="domain",
                name="Domain",
                provider_fingerprint="domain",
            )
            run = SyncRun(organization_id=org.id, manager_id=manager.id, status="RUNNING")
            session.add_all([domain, run])
            session.flush()
            policy = AccessPolicy(
                organization_id=org.id,
                manager_id=manager.id,
                domain_id=domain.id,
                native_id="policy",
                name="Policy",
                provider_fingerprint="policy",
            )
            session.add(policy)
            session.flush()
            session.add_all(
                [
                    PolicyDelegation(
                        organization_id=org.id,
                        group_id=group.id,
                        policy_id=policy.id,
                        capabilities=["view", "modify_rule", "modify_object"],
                    ),
                    IpRangeGrant(
                        organization_id=org.id,
                        group_id=group.id,
                        policy_id=policy.id,
                        network="10.0.0.0/8",
                        ip_version=4,
                    ),
                ]
            )
            session.flush()
            principal = Principal(user.id, org.id, user.email, user.role)
            yield (
                session,
                {
                    "org": org,
                    "manager": manager,
                    "group": group,
                    "user": user,
                    "domain": domain,
                    "policy": policy,
                    "run": run,
                    "principal": principal,
                },
            )
        transaction.rollback()
    engine.dispose()


def test_provider_prefixes_never_create_ownership_or_grants(database) -> None:
    session, rows = database
    repo = SqlSyncRepository(session)
    org, manager, policy, run, domain = (
        rows[k].id for k in ("org", "manager", "policy", "run", "domain")
    )
    category = repo.upsert_category(
        org,
        manager,
        policy,
        run,
        DiscoveredCategory(
            native_id="cat",
            name="FINANCE__RULES",
            native_version="1",
            fingerprint="cat",
            policy_native_id="policy",
            position=1,
        ),
    )
    rule = repo.upsert_rule(
        org,
        manager,
        policy,
        category,
        run,
        DiscoveredRule(
            native_id="rule",
            name="FINANCE__ALLOW",
            native_version="1",
            fingerprint="rule",
            policy_native_id="policy",
            position=1,
            action="ALLOW",
            enabled=True,
        ),
    )
    obj = repo.upsert_object(
        org,
        manager,
        domain,
        run,
        DiscoveredObject(
            native_id="obj",
            name="FINANCE__HOST",
            native_version="1",
            fingerprint="obj",
            object_type="NETWORK",
            normalized_value="10.1.1.1",
        ),
    )
    repo.replace_object_references(org, manager, obj, [])
    session.flush()
    assert session.get(AccessRule, rule).owner_group_id is None
    assert session.get(FirewallObject, obj).owner_group_id is None
    assert (
        session.scalar(
            select(GroupPolicyCategoryMapping.id).where(
                GroupPolicyCategoryMapping.organization_id == org
            )
        )
        is None
    )
    assert (
        session.scalar(select(ObjectUseGrant.id).where(ObjectUseGrant.organization_id == org))
        is None
    )


def test_recovered_category_receipt_creates_authoritative_mapping(database) -> None:
    session, rows = database
    sync = SqlSyncRepository(session)
    org, manager, policy, run = (rows[k].id for k in ("org", "manager", "policy", "run"))
    category_id = sync.upsert_category(
        org,
        manager,
        policy,
        run,
        DiscoveredCategory(
            native_id="cat",
            name="FINANCE__RULES",
            native_version="1",
            fingerprint="observed-category",
            policy_native_id="policy",
            position=1,
        ),
    )
    repo = SqlChangeSetRepository(session)
    operation_id = uuid4()
    repo.reconcile_successful_operations(
        {},
        rows["principal"],
        rows["group"].id,
        [
            {
                "id": str(operation_id),
                "kind": "ENSURE_RULE_CATEGORY",
                "access_policy_id": str(policy),
                "manager_id": str(manager),
                "payload": {},
                "resolution": {"provider_name": "FINANCE__RULES"},
            }
        ],
        [
            {
                "operation_id": str(operation_id),
                "status": "SUCCEEDED",
                "mutated": False,
                "receipt_recovered": True,
                "provider_resource_id": "CAT",
                "provider_resource": {
                    "fingerprint": "recovered-category",
                    "native_version": "2",
                    "position": 1,
                },
            }
        ],
    )
    category = session.get(RuleCategory, category_id)
    mapping = session.scalar(
        select(GroupPolicyCategoryMapping).where(
            GroupPolicyCategoryMapping.organization_id == org,
            GroupPolicyCategoryMapping.group_id == rows["group"].id,
            GroupPolicyCategoryMapping.policy_id == policy,
        )
    )
    assert category is not None
    assert category.management_state == "MANAGED"
    assert category.provider_fingerprint == "recovered-category"
    assert mapping is not None
    assert mapping.category_id == category.id
    assert mapping.sync_state == "SYNCED"


def test_rule_native_id_is_scoped_to_policy(database) -> None:
    session, rows = database
    repo = SqlSyncRepository(session)
    org, manager, policy, run, domain = (
        rows[k].id for k in ("org", "manager", "policy", "run", "domain")
    )
    other_policy = AccessPolicy(
        organization_id=org,
        manager_id=manager,
        domain_id=domain,
        native_id="other-policy",
        name="Other Policy",
        provider_fingerprint="other-policy",
    )
    session.add(other_policy)
    session.flush()
    first = repo.upsert_rule(
        org,
        manager,
        policy,
        None,
        run,
        DiscoveredRule(
            native_id="reused-rule-id",
            name="FINANCE__RULE",
            native_version="1",
            fingerprint="rule-one",
            policy_native_id="policy",
            position=1,
            action="ALLOW",
        ),
    )
    second = repo.upsert_rule(
        org,
        manager,
        other_policy.id,
        None,
        run,
        DiscoveredRule(
            native_id="reused-rule-id",
            name="OTHER__RULE",
            native_version="1",
            fingerprint="rule-two",
            policy_native_id="other-policy",
            position=1,
            action="DENY",
        ),
    )
    assert first != second
    assert session.get(AccessRule, first).policy_id == policy
    assert session.get(AccessRule, second).policy_id == other_policy.id


def test_successful_rule_create_without_provider_position_uses_next_local_position(
    database,
) -> None:
    session, rows = database
    repo = SqlChangeSetRepository(session)
    sync = SqlSyncRepository(session)
    org, manager, policy, run = (rows[k].id for k in ("org", "manager", "policy", "run"))
    category = sync.upsert_category(
        org,
        manager,
        policy,
        run,
        DiscoveredCategory(
            native_id="cat-position",
            name="FINANCE__RULES",
            native_version="1",
            fingerprint="cat-position",
            policy_native_id="policy",
            position=1,
        ),
    )
    sync.upsert_rule(
        org,
        manager,
        policy,
        category,
        run,
        DiscoveredRule(
            native_id="rule-existing",
            name="FINANCE__EXISTING",
            native_version="1",
            fingerprint="rule-existing",
            policy_native_id="policy",
            position=3,
            action="ALLOW",
            enabled=True,
        ),
    )
    intrusion = IntrusionPolicy(
        organization_id=org,
        manager_id=manager,
        domain_id=rows["domain"].id,
        native_id="intrusion-position",
        name="Intrusion position",
        provider_fingerprint="intrusion-position",
        management_state="MANAGED",
    )
    session.add(intrusion)
    session.flush()
    operation_id = uuid4()
    repo.reconcile_successful_operations(
        {},
        rows["principal"],
        rows["group"].id,
        [
            {
                "id": operation_id,
                "kind": "CREATE_RULE",
                "access_policy_id": policy,
                "payload": {
                    "category_id": category,
                    "name": "FINANCE__CREATED",
                    "action": "ALLOW",
                    "enabled": True,
                    "intrusion_policy_id": str(intrusion.id),
                },
                "resolution": {"provider_name": "FINANCE__CREATED"},
            }
        ],
        [
            {
                "operation_id": operation_id,
                "status": "SUCCEEDED",
                "mutated": True,
                "provider_resource_id": "rule-created",
                "provider_resource": {"native_version": "", "fingerprint": "created"},
            }
        ],
    )
    created = session.scalar(
        select(AccessRule).where(
            AccessRule.organization_id == org,
            AccessRule.native_id == "rule-created",
        )
    )
    assert created is not None
    assert created.position == 4


def test_successful_rule_insert_shifts_following_application_baselines(database) -> None:
    session, rows = database
    repo = SqlChangeSetRepository(session)
    sync = SqlSyncRepository(session)
    org, manager, policy, run = (rows[k].id for k in ("org", "manager", "policy", "run"))
    category = sync.upsert_category(
        org,
        manager,
        policy,
        run,
        DiscoveredCategory(
            native_id="cat-insert",
            name="FINANCE__INSERT",
            native_version="1",
            fingerprint="cat-insert",
            policy_native_id="policy",
            position=1,
        ),
    )
    sync.upsert_rule(
        org,
        manager,
        policy,
        category,
        run,
        DiscoveredRule(
            native_id="rule-before",
            name="FINANCE__BEFORE",
            native_version="1",
            fingerprint="rule-before",
            policy_native_id="policy",
            position=3,
            action="ALLOW",
        ),
    )
    following_id = sync.upsert_rule(
        org,
        manager,
        policy,
        category,
        run,
        DiscoveredRule(
            native_id="rule-following",
            name="FINANCE__FOLLOWING",
            native_version="1",
            fingerprint="rule-following",
            policy_native_id="policy",
            position=4,
            action="ALLOW",
        ),
    )
    operation_id = uuid4()
    repo.reconcile_successful_operations(
        {},
        rows["principal"],
        rows["group"].id,
        [
            {
                "id": operation_id,
                "kind": "CREATE_RULE",
                "access_policy_id": policy,
                "payload": {
                    "category_id": category,
                    "name": "FINANCE__INSERTED",
                    "action": "ALLOW",
                    "enabled": True,
                    "position": 4,
                },
                "resolution": {"provider_name": "FINANCE__INSERTED"},
            }
        ],
        [
            {
                "operation_id": operation_id,
                "status": "SUCCEEDED",
                "mutated": True,
                "provider_resource_id": "rule-inserted",
                "provider_resource": {
                    "position": 4,
                    "native_version": "",
                    "fingerprint": "inserted",
                },
            }
        ],
    )
    following = session.get(AccessRule, following_id)
    assert following is not None
    assert following.position == 5
    assert following.application_snapshot is not None
    assert following.application_snapshot["position"] == 5


def test_successful_rule_delete_shifts_following_application_baselines(database) -> None:
    session, rows = database
    repo = SqlChangeSetRepository(session)
    sync = SqlSyncRepository(session)
    org, manager, policy, run = (rows[k].id for k in ("org", "manager", "policy", "run"))
    category = sync.upsert_category(
        org,
        manager,
        policy,
        run,
        DiscoveredCategory(
            native_id="cat-delete",
            name="FINANCE__DELETE",
            native_version="1",
            fingerprint="cat-delete",
            policy_native_id="policy",
            position=1,
        ),
    )
    sync.upsert_rule(
        org,
        manager,
        policy,
        category,
        run,
        DiscoveredRule(
            native_id="rule-before-delete",
            name="FINANCE__BEFORE_DELETE",
            native_version="1",
            fingerprint="rule-before-delete",
            policy_native_id="policy",
            position=3,
            action="ALLOW",
        ),
    )
    deleted_id = sync.upsert_rule(
        org,
        manager,
        policy,
        category,
        run,
        DiscoveredRule(
            native_id="rule-delete",
            name="FINANCE__DELETE",
            native_version="1",
            fingerprint="rule-delete",
            policy_native_id="policy",
            position=4,
            action="ALLOW",
        ),
    )
    following_id = sync.upsert_rule(
        org,
        manager,
        policy,
        category,
        run,
        DiscoveredRule(
            native_id="rule-following-delete",
            name="FINANCE__FOLLOWING_DELETE",
            native_version="1",
            fingerprint="rule-following-delete",
            policy_native_id="policy",
            position=5,
            action="ALLOW",
        ),
    )
    operation_id = uuid4()
    repo.reconcile_successful_operations(
        {},
        rows["principal"],
        rows["group"].id,
        [
            {
                "id": operation_id,
                "kind": "DELETE_RULE",
                "access_policy_id": policy,
                "payload": {"rule_id": deleted_id},
            }
        ],
        [
            {
                "operation_id": operation_id,
                "status": "SUCCEEDED",
                "mutated": True,
                "provider_resource_id": "rule-delete",
                "provider_resource": {"native_version": "", "fingerprint": "deleted"},
            }
        ],
    )
    assert session.get(AccessRule, deleted_id) is None
    following = session.get(AccessRule, following_id)
    assert following is not None
    assert following.position == 4
    assert following.application_snapshot is not None
    assert following.application_snapshot["position"] == 4


def test_successful_rule_move_shifts_sibling_application_baselines(database) -> None:
    session, rows = database
    repo = SqlChangeSetRepository(session)
    sync = SqlSyncRepository(session)
    org, manager, policy, run = (rows[k].id for k in ("org", "manager", "policy", "run"))
    category = sync.upsert_category(
        org,
        manager,
        policy,
        run,
        DiscoveredCategory(
            native_id="cat-move",
            name="FINANCE__MOVE",
            native_version="1",
            fingerprint="cat-move",
            policy_native_id="policy",
            position=1,
        ),
    )
    moved_id = sync.upsert_rule(
        org,
        manager,
        policy,
        category,
        run,
        DiscoveredRule(
            native_id="rule-moved",
            name="FINANCE__MOVED",
            native_version="1",
            fingerprint="rule-moved",
            policy_native_id="policy",
            position=4,
            action="ALLOW",
        ),
    )
    following_id = sync.upsert_rule(
        org,
        manager,
        policy,
        category,
        run,
        DiscoveredRule(
            native_id="rule-following-move",
            name="FINANCE__FOLLOWING_MOVE",
            native_version="1",
            fingerprint="rule-following-move",
            policy_native_id="policy",
            position=5,
            action="ALLOW",
        ),
    )
    operation_id = uuid4()
    repo.reconcile_successful_operations(
        {},
        rows["principal"],
        rows["group"].id,
        [
            {
                "id": operation_id,
                "kind": "MOVE_RULE",
                "access_policy_id": policy,
                "payload": {
                    "rule_id": moved_id,
                    "category_id": category,
                    "position": 5,
                },
            }
        ],
        [
            {
                "operation_id": operation_id,
                "status": "SUCCEEDED",
                "mutated": True,
                "provider_resource_id": "rule-moved",
                "provider_resource": {"native_version": "", "fingerprint": "moved"},
            }
        ],
    )
    moved = session.get(AccessRule, moved_id)
    following = session.get(AccessRule, following_id)
    assert moved is not None
    assert moved.position == 5
    assert following is not None
    assert following.position == 4
    assert following.application_snapshot is not None
    assert following.application_snapshot["position"] == 4


def test_old_approval_cannot_authorize_revalidated_revision(database) -> None:
    session, rows = database
    repo = SqlChangeSetRepository(session)
    principal, group = rows["principal"], rows["group"].id
    created = repo.create_change_set(principal, group, rows["policy"].id, "Test", "", {})
    row = session.get(ChangeSet, created["id"])
    author = User(
        organization_id=rows["org"].id,
        identity_issuer="https://id.example.test",
        identity_subject=str(uuid4()),
        email="author@example.test",
        display_name="Author",
        role="user",
    )
    session.add(author)
    session.flush()
    row.principal_id = author.id
    row.state = "READY"
    row.validated_revision = row.revision
    session.flush()
    repo.approve_change_set(principal, group, row.id)
    # A failed approved attempt is reset to DRAFT by retry_execution.
    repo.set_execution_state(principal, group, row.id, "FAILED", {}, {})
    repo.set_execution_state(principal, group, row.id, "DRAFT", {}, {})
    repo.update_change_set_metadata(principal, group, row.id, "Changed", "", row.revision)
    repo.save_preflight(principal, group, row.id, [], "READY", {})
    assert row.approved_revision is None
    assert row.approval_invalidated_at is not None
    with pytest.raises(InvalidChangeSetStateError):
        repo.queue_execution(principal, group, row.id)


def test_retry_reset_clears_prior_dispatch_intent(database) -> None:
    session, rows = database
    repo = SqlChangeSetRepository(session)
    principal, group = rows["principal"], rows["group"].id
    created = repo.create_change_set(principal, group, rows["policy"].id, "Retry", "", {})
    row = session.get(ChangeSet, created["id"])
    row.mutation_intent = {
        "epoch": 1,
        "state": "OUTCOME_UNCERTAIN",
        "entries": [{"method": "POST", "path": "/objects"}],
    }
    repo.set_execution_state(principal, group, row.id, "FAILED", {}, {})
    repo.set_execution_state(principal, group, row.id, "DRAFT", {}, {})

    session.refresh(row)
    assert row.mutation_intent == {}
    assert row.execution_owner is None
    assert row.execution_lease_until is None
    assert row.execution_heartbeat_at is None


def test_operation_cannot_change_changeset_policy(database) -> None:
    session, rows = database
    repo = SqlChangeSetRepository(session)
    principal, group = rows["principal"], rows["group"].id
    created = repo.create_change_set(principal, group, rows["policy"].id, "Test", "", {})
    with pytest.raises(ResourceOutOfScopeError):
        repo.add_operation(
            principal, group, created["id"], "CREATE_RULE", {"policy_id": str(uuid4())}
        )


@pytest.mark.parametrize("after_queue", [False, True])
def test_revoked_approver_cannot_authorize_execution(database, after_queue: bool) -> None:
    session, rows = database
    repo = SqlChangeSetRepository(session)
    principal, group = rows["principal"], rows["group"].id
    created = repo.create_change_set(principal, group, rows["policy"].id, "Approval", "", {})
    row = session.get(ChangeSet, created["id"])
    author = User(
        organization_id=rows["org"].id,
        identity_issuer="https://id.example.test",
        identity_subject=str(uuid4()),
        email="author@example.test",
        display_name="Author",
        role="user",
    )
    session.add(author)
    session.flush()
    row.principal_id = author.id
    row.state = "READY"
    row.validated_revision = row.revision
    session.flush()
    repo.approve_change_set(principal, group, row.id)
    if after_queue:
        repo.queue_execution(principal, group, row.id)
    rows["user"].is_active = False
    session.flush()
    if after_queue:
        with pytest.raises(InvalidChangeSetStateError):
            repo.claim_queued_execution(
                Principal(author.id, author.organization_id, author.email, author.role),
                group,
                row.id,
                "test-worker",
            )
    else:
        with pytest.raises(InvalidChangeSetStateError):
            repo.queue_execution(principal, group, row.id)


@pytest.mark.parametrize("role", ["admin", "firewall_operator"])
def test_global_roles_cannot_approve_their_own_changeset(database, role: str) -> None:
    session, rows = database
    repo = SqlChangeSetRepository(session)
    user = rows["user"]
    user.role = role
    principal = Principal(user.id, user.organization_id, user.email, role)
    group = rows["group"].id
    created = repo.create_change_set(principal, group, rows["policy"].id, "Own change", "", {})
    row = session.get(ChangeSet, created["id"])
    row.state = "READY"
    row.validated_revision = row.revision
    session.flush()
    with pytest.raises(InvalidChangeSetStateError) as error:
        repo.approve_change_set(principal, group, row.id)
    assert error.value.details["code"] == "SEPARATION_OF_DUTY"
    assert row.approved_revision is None
