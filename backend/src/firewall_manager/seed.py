"""Idempotent deterministic local identity and manager seed data."""

from typing import Any, cast
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.models import (
    AccessPolicy,
    AccessRule,
    Base,
    ChangeSet,
    ChangeSetOperation,
    DirectUserPolicyGrant,
    FirewallManager,
    FirewallObject,
    Group,
    GroupMembership,
    GroupPolicyCategoryMapping,
    IpRangeGrant,
    ObjectCreateGrant,
    ObjectUseGrant,
    Organization,
    PolicyDelegation,
    ProviderTransaction,
    RuleCategory,
    SecurityZone,
    User,
    ZoneGrant,
)

IDS = {
    "org": UUID("10000000-0000-0000-0000-000000000001"),
    "other_org": UUID("10000000-0000-0000-0000-000000000002"),
    "group_finance": UUID("20000000-0000-0000-0000-000000000001"),
    "group_engineering": UUID("20000000-0000-0000-0000-000000000002"),
    "group_datacenter": UUID("20000000-0000-0000-0000-000000000004"),
    "other_group": UUID("20000000-0000-0000-0000-000000000003"),
    "membership_viewer_finance": UUID("21000000-0000-0000-0000-000000000001"),
    "membership_viewer_engineering": UUID("21000000-0000-0000-0000-000000000002"),
    "membership_editor_finance": UUID("21000000-0000-0000-0000-000000000003"),
    "membership_approver_engineering": UUID("21000000-0000-0000-0000-000000000004"),
    "membership_other": UUID("21000000-0000-0000-0000-000000000005"),
    "obsolete_membership_editor_datacenter": UUID("21000000-0000-0000-0000-000000000006"),
    "viewer": UUID("30000000-0000-0000-0000-000000000001"),
    "editor": UUID("30000000-0000-0000-0000-000000000002"),
    "approver": UUID("30000000-0000-0000-0000-000000000003"),
    "other_viewer": UUID("30000000-0000-0000-0000-000000000004"),
    "admin": UUID("30000000-0000-0000-0000-000000000005"),
    "auditor": UUID("30000000-0000-0000-0000-000000000006"),
    "firewall_admin": UUID("30000000-0000-0000-0000-000000000007"),
    "group_admin": UUID("30000000-0000-0000-0000-000000000008"),
    "carol": UUID("30000000-0000-0000-0000-000000000009"),
    "viewer_only": UUID("30000000-0000-0000-0000-000000000010"),
    "disabled_user": UUID("30000000-0000-0000-0000-000000000011"),
    "no_groups": UUID("30000000-0000-0000-0000-000000000012"),
    "membership_auditor_datacenter": UUID("21000000-0000-0000-0000-000000000007"),
    "membership_firewall_admin_datacenter": UUID("21000000-0000-0000-0000-000000000008"),
    "membership_group_admin_finance": UUID("21000000-0000-0000-0000-000000000009"),
    "membership_carol_engineering": UUID("21000000-0000-0000-0000-000000000010"),
    "membership_viewer_datacenter": UUID("21000000-0000-0000-0000-000000000011"),
    "membership_disabled_finance": UUID("21000000-0000-0000-0000-000000000012"),
    "fmc": UUID("40000000-0000-0000-0000-000000000001"),
    "scc": UUID("40000000-0000-0000-0000-000000000002"),
    "other_fmc": UUID("40000000-0000-0000-0000-000000000003"),
    "draft": UUID("90000000-0000-0000-0000-000000000001"),
}


def seed() -> None:
    """Upsert non-secret identities/managers; provider resources arrive only through sync."""
    with new_session() as session, session.begin():
        rows = [
            Organization(id=IDS["org"], name="Example Organization"),
            Organization(id=IDS["other_org"], name="Isolated Organization"),
            Group(
                id=IDS["group_finance"],
                organization_id=IDS["org"],
                name="Finance",
                provider_slug="FINANCE",
            ),
            Group(
                id=IDS["group_engineering"],
                organization_id=IDS["org"],
                name="Engineering",
                provider_slug="ENGINEERING",
            ),
            Group(
                id=IDS["group_datacenter"],
                organization_id=IDS["org"],
                name="Datacenter",
                provider_slug="DATACENTER",
            ),
            Group(
                id=IDS["other_group"],
                organization_id=IDS["other_org"],
                name="Other Group",
                provider_slug="OTHER-GROUP",
            ),
            User(
                id=IDS["viewer"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="alice",
                email="viewer@example.test",
                display_name="Alice — Finance + Engineering",
                role="viewer",
                is_active=True,
            ),
            User(
                id=IDS["auditor"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="auditor",
                email="auditor@example.test",
                display_name="Dev Auditor",
                role="viewer",
                is_active=True,
            ),
            User(
                id=IDS["editor"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="bob",
                email="editor@example.test",
                display_name="Bob — Finance only",
                role="editor",
                is_active=True,
            ),
            User(
                id=IDS["approver"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="approver",
                email="approver@example.test",
                display_name="Ari Approver",
                role="approver",
                is_active=True,
            ),
            User(
                id=IDS["other_viewer"],
                organization_id=IDS["other_org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="other-viewer",
                email="other-viewer@example.test",
                display_name="Other Viewer",
                role="viewer",
                is_active=True,
            ),
            User(
                id=IDS["admin"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="admin",
                email="admin@example.test",
                display_name="Platform Admin",
                role="admin",
                is_active=True,
            ),
            User(
                id=IDS["firewall_admin"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="firewall-admin",
                email="firewall-admin@example.test",
                display_name="Firewall Admin",
                role="firewall_admin",
                is_active=True,
            ),
            User(
                id=IDS["group_admin"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="group-admin",
                email="group-admin@example.test",
                display_name="Group Admin",
                role="group_admin",
                is_active=True,
            ),
            User(
                id=IDS["carol"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="carol",
                email="carol@example.test",
                display_name="Carol — Engineering only",
                role="editor",
                is_active=True,
            ),
            User(
                id=IDS["viewer_only"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="viewer",
                email="read-only@example.test",
                display_name="Viewer",
                role="viewer",
                is_active=True,
            ),
            User(
                id=IDS["disabled_user"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="disabled",
                email="disabled@example.test",
                display_name="Disabled User",
                role="viewer",
                is_active=False,
            ),
            User(
                id=IDS["no_groups"],
                organization_id=IDS["org"],
                identity_issuer="urn:firewall-manager:development",
                identity_subject="no-groups",
                email="no-groups@example.test",
                display_name="No Groups",
                role="viewer",
                is_active=True,
            ),
            GroupMembership(
                id=IDS["membership_viewer_finance"],
                organization_id=IDS["org"],
                user_id=IDS["viewer"],
                group_id=IDS["group_finance"],
            ),
            GroupMembership(
                id=IDS["membership_viewer_engineering"],
                organization_id=IDS["org"],
                user_id=IDS["viewer"],
                group_id=IDS["group_engineering"],
            ),
            GroupMembership(
                id=IDS["membership_editor_finance"],
                organization_id=IDS["org"],
                user_id=IDS["editor"],
                group_id=IDS["group_finance"],
            ),
            GroupMembership(
                id=IDS["membership_approver_engineering"],
                organization_id=IDS["org"],
                user_id=IDS["approver"],
                group_id=IDS["group_engineering"],
            ),
            GroupMembership(
                id=IDS["membership_other"],
                organization_id=IDS["other_org"],
                user_id=IDS["other_viewer"],
                group_id=IDS["other_group"],
            ),
            GroupMembership(
                id=IDS["membership_auditor_datacenter"],
                organization_id=IDS["org"],
                user_id=IDS["auditor"],
                group_id=IDS["group_datacenter"],
            ),
            GroupMembership(
                id=IDS["membership_firewall_admin_datacenter"],
                organization_id=IDS["org"],
                user_id=IDS["firewall_admin"],
                group_id=IDS["group_datacenter"],
            ),
            GroupMembership(
                id=IDS["membership_group_admin_finance"],
                organization_id=IDS["org"],
                user_id=IDS["group_admin"],
                group_id=IDS["group_finance"],
            ),
            GroupMembership(
                id=IDS["membership_carol_engineering"],
                organization_id=IDS["org"],
                user_id=IDS["carol"],
                group_id=IDS["group_engineering"],
            ),
            GroupMembership(
                id=IDS["membership_viewer_datacenter"],
                organization_id=IDS["org"],
                user_id=IDS["viewer_only"],
                group_id=IDS["group_datacenter"],
            ),
            GroupMembership(
                id=IDS["membership_disabled_finance"],
                organization_id=IDS["org"],
                user_id=IDS["disabled_user"],
                group_id=IDS["group_finance"],
            ),
            FirewallManager(
                id=IDS["fmc"],
                organization_id=IDS["org"],
                provider="fmc",
                native_id="mock-fmc",
                display_name="Local FMC Mock",
                base_url="http://mock-fmc:9000",
                read_only=True,
                is_mock=True,
            ),
            FirewallManager(
                id=IDS["scc"],
                organization_id=IDS["org"],
                provider="scc",
                native_id="mock-scc",
                display_name="Local SCC Mock",
                base_url="http://mock-scc:9000",
                read_only=True,
                is_mock=True,
            ),
            FirewallManager(
                id=IDS["other_fmc"],
                organization_id=IDS["other_org"],
                provider="fmc",
                native_id="mock-fmc",
                display_name="Isolated FMC Mock",
                base_url="http://mock-fmc:9000",
                read_only=True,
            ),
        ]
        for row in rows:
            session.merge(row)
        obsolete_membership = session.get(
            GroupMembership, IDS["obsolete_membership_editor_datacenter"]
        )
        if obsolete_membership is not None:
            session.delete(obsolete_membership)
        if session.get(ChangeSet, IDS["draft"]) is None:
            session.add(
                ChangeSet(
                    id=IDS["draft"],
                    organization_id=IDS["org"],
                    principal_id=IDS["editor"],
                    acting_group_id=IDS["group_finance"],
                    title="Future example change",
                    state="DRAFT",
                    revision=1,
                    summary="Display-only placeholder; provider mutation is not implemented.",
                )
            )


def _seed_id(name: str) -> UUID:
    return uuid5(UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), name)


_AUTHORIZATION_NATURAL_KEYS: dict[type[Base], tuple[str, ...]] = {
    PolicyDelegation: ("group_id", "policy_id"),
    DirectUserPolicyGrant: ("user_id", "group_id", "policy_id"),
    ObjectUseGrant: ("group_id", "policy_id", "object_id", "permission"),
    ZoneGrant: ("group_id", "policy_id", "zone_id", "direction"),
    IpRangeGrant: ("group_id", "policy_id", "network"),
    ObjectCreateGrant: ("group_id", "policy_id", "object_type"),
    GroupPolicyCategoryMapping: ("group_id", "policy_id"),
}


def upsert_authorization_seed_row(session: Session, row: Base) -> None:
    """Upsert by the database uniqueness key, preserving an admin-recreated row's UUID."""
    model: type[Base] = type(row)
    keys = _AUTHORIZATION_NATURAL_KEYS[model]
    scope_keys = ("organization_id", *keys)
    existing = session.scalar(
        select(model).where(
            *(getattr(model, key) == getattr(row, key) for key in scope_keys),
        )
    )
    if existing is None:
        session.add(row)
        return
    excluded = {"id", "created_at", "updated_at", "revision"}
    for column in row.__table__.columns:
        if column.name not in excluded:
            value = getattr(row, column.name)
            if value is not None:
                setattr(existing, column.name, value)


def seed_authorization_scenarios(session: Session) -> None:
    """Seed deterministic Group-isolation grants after provider inventory synchronization."""
    policies = list(
        session.scalars(
            select(AccessPolicy).where(
                AccessPolicy.organization_id == IDS["org"],
                AccessPolicy.manager_id.in_((IDS["fmc"], IDS["scc"])),
            )
        )
    )
    for policy in policies:
        manager_prefix = "fmc" if policy.manager_id == IDS["fmc"] else "scc"
        finance_object = session.scalar(
            select(FirewallObject).where(
                FirewallObject.manager_id == policy.manager_id,
                FirewallObject.native_id == f"{manager_prefix}-object-finance-servers",
            )
        )
        engineering_object = session.scalar(
            select(FirewallObject).where(
                FirewallObject.manager_id == policy.manager_id,
                FirewallObject.native_id == f"{manager_prefix}-object-engineering-servers",
            )
        )
        shared_object = session.scalar(
            select(FirewallObject).where(
                FirewallObject.manager_id == policy.manager_id,
                FirewallObject.native_id == f"{manager_prefix}-object-dns",
            )
        )
        finance_zone = session.scalar(
            select(SecurityZone).where(
                SecurityZone.manager_id == policy.manager_id,
                SecurityZone.native_id == f"{manager_prefix}-zone-finance",
            )
        )
        engineering_zone = session.scalar(
            select(SecurityZone).where(
                SecurityZone.manager_id == policy.manager_id,
                SecurityZone.native_id == f"{manager_prefix}-zone-engineering",
            )
        )
        finance_category = session.scalar(
            select(RuleCategory).where(
                RuleCategory.policy_id == policy.id,
                RuleCategory.native_id == f"{manager_prefix}-category-finance",
            )
        )
        engineering_category = session.scalar(
            select(RuleCategory).where(
                RuleCategory.policy_id == policy.id,
                RuleCategory.native_id == f"{manager_prefix}-category-engineering",
            )
        )
        if not all(
            (
                finance_object,
                engineering_object,
                finance_zone,
                engineering_zone,
                finance_category,
                engineering_category,
                shared_object,
            )
        ):
            raise RuntimeError("synchronized authorization fixture resources are incomplete")
        finance_object = cast("FirewallObject", finance_object)
        engineering_object = cast("FirewallObject", engineering_object)
        finance_zone = cast("SecurityZone", finance_zone)
        engineering_zone = cast("SecurityZone", engineering_zone)
        finance_category = cast("RuleCategory", finance_category)
        engineering_category = cast("RuleCategory", engineering_category)
        shared_object = cast("FirewallObject", shared_object)
        rows: list[Any] = [
            PolicyDelegation(
                id=_seed_id(f"finance-delegation-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_finance"],
                policy_id=policy.id,
                capabilities=[
                    "view",
                    "create_rule",
                    "modify_rule",
                    "delete_rule",
                    "modify_object",
                    "delete_object",
                ],
            ),
            PolicyDelegation(
                id=_seed_id(f"engineering-delegation-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_engineering"],
                policy_id=policy.id,
                capabilities=["view", "create_rule", "modify_rule", "modify_object"],
            ),
            PolicyDelegation(
                id=_seed_id(f"datacenter-delegation-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_datacenter"],
                policy_id=policy.id,
                capabilities=["view"],
            ),
            DirectUserPolicyGrant(
                id=_seed_id(f"alice-engineering-direct-{policy.id}"),
                organization_id=IDS["org"],
                user_id=IDS["viewer"],
                group_id=IDS["group_engineering"],
                policy_id=policy.id,
                capabilities=["reorder_rule"],
            ),
            ObjectUseGrant(
                id=_seed_id(f"finance-object-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_finance"],
                policy_id=policy.id,
                object_id=finance_object.id,
                permission="use",
            ),
            ObjectUseGrant(
                id=_seed_id(f"finance-object-read-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_finance"],
                policy_id=policy.id,
                object_id=finance_object.id,
                permission="read",
            ),
            ObjectUseGrant(
                id=_seed_id(f"datacenter-shared-object-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_datacenter"],
                policy_id=policy.id,
                object_id=shared_object.id,
                permission="use",
            ),
            ObjectUseGrant(
                id=_seed_id(f"engineering-object-read-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_engineering"],
                policy_id=policy.id,
                object_id=engineering_object.id,
                permission="read",
            ),
            ObjectUseGrant(
                id=_seed_id(f"engineering-object-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_engineering"],
                policy_id=policy.id,
                object_id=engineering_object.id,
                permission="use",
            ),
            ZoneGrant(
                id=_seed_id(f"finance-zone-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_finance"],
                policy_id=policy.id,
                zone_id=finance_zone.id,
                direction="BOTH",
            ),
            ZoneGrant(
                id=_seed_id(f"engineering-zone-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_engineering"],
                policy_id=policy.id,
                zone_id=engineering_zone.id,
                direction="BOTH",
            ),
            IpRangeGrant(
                id=_seed_id(f"finance-range-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_finance"],
                policy_id=policy.id,
                network="10.20.0.0/16",
                ip_version=4,
            ),
            IpRangeGrant(
                id=_seed_id(f"engineering-range-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_engineering"],
                policy_id=policy.id,
                network="172.16.0.0/12",
                ip_version=4,
            ),
            GroupPolicyCategoryMapping(
                id=_seed_id(f"finance-category-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_finance"],
                policy_id=policy.id,
                category_id=finance_category.id,
                expected_category_name="FINANCE__RULES",
                sync_state="SYNCED",
            ),
            GroupPolicyCategoryMapping(
                id=_seed_id(f"engineering-category-{policy.id}"),
                organization_id=IDS["org"],
                group_id=IDS["group_engineering"],
                policy_id=policy.id,
                category_id=engineering_category.id,
                expected_category_name="ENGINEERING__RULES",
                sync_state="SYNCED",
            ),
        ]
        for group_name, object_types in (
            ("finance", ("NETWORK", "PORT_SERVICE")),
            ("engineering", ("NETWORK",)),
        ):
            group_id = IDS[f"group_{group_name}"]
            rows.extend(
                ObjectCreateGrant(
                    id=_seed_id(f"{group_name}-create-{object_type}-{policy.id}"),
                    organization_id=IDS["org"],
                    group_id=group_id,
                    policy_id=policy.id,
                    object_type=object_type,
                )
                for object_type in object_types
            )
        for row in rows:
            upsert_authorization_seed_row(session, row)
        finance_object.owner_group_id = IDS["group_finance"]
        finance_object.owner_policy_id = policy.id
        finance_object.created_by_user_id = IDS["viewer"]
        finance_object.modified_by_user_id = IDS["viewer"]
        finance_object.expected_provider_name = "FINANCE__APP-SUBNET"
        finance_object.management_state = "MANAGED"
        engineering_object.owner_group_id = IDS["group_engineering"]
        engineering_object.owner_policy_id = policy.id
        engineering_object.created_by_user_id = IDS["viewer"]
        engineering_object.modified_by_user_id = IDS["viewer"]
        engineering_object.expected_provider_name = "ENGINEERING__BUILD-SERVERS"
        engineering_object.management_state = "MANAGED"
        rules = list(session.scalars(select(AccessRule).where(AccessRule.policy_id == policy.id)))
        for rule in rules:
            if rule.category_id == finance_category.id:
                rule.owner_group_id = IDS["group_finance"]
            elif rule.category_id == engineering_category.id:
                rule.owner_group_id = IDS["group_engineering"]
        if policy.manager_id == IDS["fmc"]:
            draft = session.get(ChangeSet, IDS["draft"])
            if draft is not None:
                draft.access_policy_id = policy.id
                draft.target_policy_ids = [str(policy.id)]
            _seed_change_set_execution_examples(session, policy)
    session.commit()


def _seed_change_set_execution_examples(session: Session, policy: AccessPolicy) -> None:
    """Create deterministic terminal transaction examples for the development UI."""
    scenarios = (
        ("succeeded", "SUCCEEDED", "SUCCEEDED", False),
        ("failed", "FAILED", "FAILED", False),
        ("partial", "PARTIALLY_SUCCEEDED", "PARTIALLY_SUCCEEDED", False),
        (
            "ambiguous",
            "RECONCILIATION_REQUIRED",
            "RECONCILIATION_REQUIRED",
            True,
        ),
    )
    for name, change_state, transaction_state, ambiguous in scenarios:
        change_id = _seed_id(f"changeset-{name}")
        operation_id = _seed_id(f"changeset-operation-{name}")
        transaction_id = _seed_id(f"provider-transaction-{name}")
        if session.get(ChangeSet, change_id) is not None:
            continue
        operation_status = (
            "AMBIGUOUS" if ambiguous else "SUCCEEDED" if change_state == "SUCCEEDED" else "FAILED"
        )
        operation_result = {
            "operation_id": str(operation_id),
            "status": operation_status,
            "mutated": "unknown" if ambiguous else change_state == "SUCCEEDED",
        }
        transaction_result = {
            "id": str(transaction_id),
            "manager_id": str(policy.manager_id),
            "state": transaction_state,
            "operation_results": [operation_result],
            "failure_info": {} if change_state == "SUCCEEDED" else {"code": change_state},
            "reconciliation_required": ambiguous,
        }
        session.add(
            ChangeSet(
                id=change_id,
                organization_id=IDS["org"],
                principal_id=IDS["editor"],
                acting_group_id=IDS["group_finance"],
                access_policy_id=policy.id,
                target_policy_ids=[str(policy.id)],
                title=f"Mock {name} transaction",
                description="Deterministic Milestone 3 execution example.",
                summary="Deterministic Milestone 3 execution example.",
                state=change_state,
                revision=2,
                validated_revision=2,
                execution_results={"transactions": [transaction_result], "atomic": False},
                failure_info={} if change_state == "SUCCEEDED" else {"code": change_state},
                audit_metadata={"seed_scenario": name},
            )
        )
        session.add(
            ChangeSetOperation(
                id=operation_id,
                organization_id=IDS["org"],
                change_set_id=change_id,
                manager_id=policy.manager_id,
                access_policy_id=policy.id,
                sequence=1,
                kind="CREATE_RULE",
                payload={"name": f"Mock {name}", "mock_behavior": name},
                status=operation_status,
                execution_result=operation_result,
            )
        )
        session.add(
            ProviderTransaction(
                id=transaction_id,
                organization_id=IDS["org"],
                change_set_id=change_id,
                manager_id=policy.manager_id,
                state=transaction_state,
                operation_results=[operation_result],
                failure_info={} if change_state == "SUCCEEDED" else {"code": change_state},
                reconciliation_required=ambiguous,
                external_operation_id=f"seed-{name}",
            )
        )


if __name__ == "__main__":
    seed()
