"""Add delegated authorization identities, grants, and audit evidence.

Revision ID: 20260919_0006
Revises: 20260919_0005
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260919_0006"
down_revision: str | None = "20260919_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def timestamps() -> tuple[sa.Column[object], sa.Column[object]]:
    return (
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def context_foreign_keys(*, include_user: bool = False) -> list[sa.ForeignKeyConstraint]:
    constraints = [
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(
            ["organization_id", "group_id"],
            ["application_groups.organization_id", "application_groups.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            ["access_policies.organization_id", "access_policies.id"],
        ),
    ]
    if include_user:
        constraints.append(
            sa.ForeignKeyConstraint(
                ["organization_id", "user_id"], ["users.organization_id", "users.id"]
            )
        )
    return constraints


def grant_context_columns() -> tuple[sa.Column[object], ...]:
    return (
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
    )


def upgrade() -> None:
    op.add_column("users", sa.Column("identity_issuer", sa.String(500)))
    op.add_column("users", sa.Column("identity_subject", sa.String(500)))
    op.add_column("users", sa.Column("revision", sa.Integer(), server_default="1", nullable=False))
    op.execute(
        "UPDATE users SET identity_issuer = 'urn:firewall-manager:development', identity_subject = id::text"
    )
    op.alter_column("users", "identity_issuer", nullable=False)
    op.alter_column("users", "identity_subject", nullable=False)
    op.drop_constraint("users_email_key", "users", type_="unique")
    op.create_unique_constraint(
        "uq_users_identity", "users", ["identity_issuer", "identity_subject"]
    )
    op.create_unique_constraint("uq_users_org_email", "users", ["organization_id", "email"])
    op.create_check_constraint("ck_users_revision", "users", "revision >= 1")

    op.add_column(
        "application_groups",
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.add_column(
        "application_groups",
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
    )
    op.create_check_constraint(
        "ck_application_groups_revision", "application_groups", "revision >= 1"
    )
    op.add_column(
        "group_memberships",
        sa.Column("status", sa.String(20), server_default="ACTIVE", nullable=False),
    )
    op.add_column(
        "group_memberships", sa.Column("revision", sa.Integer(), server_default="1", nullable=False)
    )
    op.create_check_constraint(
        "ck_group_memberships_status", "group_memberships", "status IN ('ACTIVE','SUSPENDED')"
    )
    op.create_check_constraint(
        "ck_group_memberships_revision", "group_memberships", "revision >= 1"
    )

    for table in ("access_policies", "firewall_objects", "security_zones"):
        op.create_unique_constraint(f"uq_{table}_org_id", table, ["organization_id", "id"])

    op.add_column(
        "group_policy_category_mappings", sa.Column("expected_category_name", sa.String(200))
    )
    op.add_column(
        "group_policy_category_mappings",
        sa.Column("sync_state", sa.String(30), server_default="PENDING", nullable=False),
    )
    op.execute(
        """
        UPDATE group_policy_category_mappings AS mapping
        SET expected_category_name = groups.provider_slug
        FROM application_groups AS groups
        WHERE groups.id = mapping.group_id
        """
    )
    op.alter_column("group_policy_category_mappings", "expected_category_name", nullable=False)

    op.create_table(
        "policy_delegations",
        *grant_context_columns(),
        sa.Column("capabilities", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        *context_foreign_keys(),
        sa.UniqueConstraint("group_id", "policy_id"),
        sa.CheckConstraint("revision >= 1", name="ck_policy_delegations_revision"),
    )
    op.create_index(
        "ix_policy_delegations_organization_id", "policy_delegations", ["organization_id"]
    )
    op.create_index("ix_policy_delegations_group_id", "policy_delegations", ["group_id"])
    op.create_index("ix_policy_delegations_policy_id", "policy_delegations", ["policy_id"])
    op.create_index(
        "ix_policy_delegations_org_group", "policy_delegations", ["organization_id", "group_id"]
    )

    op.create_table(
        "direct_user_policy_grants",
        *grant_context_columns(),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("capabilities", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        *context_foreign_keys(include_user=True),
        sa.UniqueConstraint("user_id", "group_id", "policy_id"),
        sa.CheckConstraint("revision >= 1", name="ck_direct_user_policy_grants_revision"),
    )
    for name in ("organization_id", "user_id", "group_id", "policy_id"):
        op.create_index(f"ix_direct_user_policy_grants_{name}", "direct_user_policy_grants", [name])
    op.create_index(
        "ix_direct_user_policy_grants_context",
        "direct_user_policy_grants",
        ["user_id", "group_id", "policy_id"],
    )

    op.create_table(
        "object_use_grants",
        *grant_context_columns(),
        sa.Column("object_id", sa.Uuid(), nullable=False),
        sa.Column("permission", sa.String(20), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        *context_foreign_keys(),
        sa.ForeignKeyConstraint(
            ["organization_id", "object_id"],
            ["firewall_objects.organization_id", "firewall_objects.id"],
        ),
        sa.UniqueConstraint("group_id", "policy_id", "object_id", "permission"),
        sa.CheckConstraint(
            "permission IN ('read','use','modify')", name="ck_object_use_permission"
        ),
        sa.CheckConstraint("revision >= 1", name="ck_object_use_grants_revision"),
    )
    op.create_table(
        "zone_grants",
        *grant_context_columns(),
        sa.Column("zone_id", sa.Uuid(), nullable=False),
        sa.Column("direction", sa.String(20), server_default="BOTH", nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        *context_foreign_keys(),
        sa.ForeignKeyConstraint(
            ["organization_id", "zone_id"], ["security_zones.organization_id", "security_zones.id"]
        ),
        sa.UniqueConstraint("group_id", "policy_id", "zone_id", "direction"),
        sa.CheckConstraint(
            "direction IN ('SOURCE','DESTINATION','BOTH')", name="ck_zone_grants_direction"
        ),
        sa.CheckConstraint("revision >= 1", name="ck_zone_grants_revision"),
    )
    op.create_table(
        "ip_range_grants",
        *grant_context_columns(),
        sa.Column("network", sa.String(64), nullable=False),
        sa.Column("ip_version", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        *context_foreign_keys(),
        sa.UniqueConstraint("group_id", "policy_id", "network"),
        sa.CheckConstraint("ip_version IN (4, 6)", name="ck_ip_range_grants_version"),
        sa.CheckConstraint("revision >= 1", name="ck_ip_range_grants_revision"),
    )
    op.create_table(
        "object_create_grants",
        *grant_context_columns(),
        sa.Column("object_type", sa.String(50), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        *context_foreign_keys(),
        sa.UniqueConstraint("group_id", "policy_id", "object_type"),
        sa.CheckConstraint(
            "object_type IN ('NETWORK','PORT_SERVICE','URL','APPLICATION','APPLICATION_FILTER')",
            name="ck_object_create_grants_type",
        ),
        sa.CheckConstraint("revision >= 1", name="ck_object_create_grants_revision"),
    )
    for table, resource in (
        ("object_use_grants", "object_id"),
        ("zone_grants", "zone_id"),
        ("ip_range_grants", None),
        ("object_create_grants", None),
    ):
        for name in ("organization_id", "group_id", "policy_id"):
            op.create_index(f"ix_{table}_{name}", table, [name])
        if resource:
            op.create_index(f"ix_{table}_{resource}", table, [resource])
            op.create_index(f"ix_{table}_context", table, ["group_id", "policy_id", resource])
        else:
            op.create_index(f"ix_{table}_context", table, ["group_id", "policy_id"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("active_group_id", sa.Uuid(), sa.ForeignKey("application_groups.id")),
        sa.Column("policy_id", sa.Uuid(), sa.ForeignKey("access_policies.id")),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.Uuid()),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("interface", sa.String(30), server_default="application", nullable=False),
        sa.Column("correlation_id", sa.String(100)),
        sa.Column("details", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_audit_events_organization_id", "audit_events", ["organization_id"])
    op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])
    op.create_index(
        "ix_audit_events_org_occurred", "audit_events", ["organization_id", "occurred_at"]
    )
    op.create_index(
        "ix_audit_events_context", "audit_events", ["actor_user_id", "active_group_id", "policy_id"]
    )


def downgrade() -> None:
    for table in (
        "audit_events",
        "object_create_grants",
        "ip_range_grants",
        "zone_grants",
        "object_use_grants",
        "direct_user_policy_grants",
        "policy_delegations",
    ):
        op.drop_table(table)
    op.drop_column("group_policy_category_mappings", "sync_state")
    op.drop_column("group_policy_category_mappings", "expected_category_name")
    for table in ("security_zones", "firewall_objects", "access_policies"):
        op.drop_constraint(f"uq_{table}_org_id", table, type_="unique")
    op.drop_constraint("ck_group_memberships_revision", "group_memberships", type_="check")
    op.drop_constraint("ck_group_memberships_status", "group_memberships", type_="check")
    op.drop_column("group_memberships", "revision")
    op.drop_column("group_memberships", "status")
    op.drop_constraint("ck_application_groups_revision", "application_groups", type_="check")
    op.drop_column("application_groups", "revision")
    op.drop_column("application_groups", "is_active")
    op.drop_constraint("ck_users_revision", "users", type_="check")
    op.drop_constraint("uq_users_org_email", "users", type_="unique")
    op.drop_constraint("uq_users_identity", "users", type_="unique")
    op.create_unique_constraint("users_email_key", "users", ["email"])
    op.drop_column("users", "revision")
    op.drop_column("users", "identity_subject")
    op.drop_column("users", "identity_issuer")
