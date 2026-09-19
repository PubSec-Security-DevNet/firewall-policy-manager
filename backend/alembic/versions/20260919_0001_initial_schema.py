"""Create the Milestone 0 normalized schema.

Revision ID: 20260919_0001
Revises:
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260919_0001"
down_revision: str | None = None
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


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        *timestamps(),
    )
    op.create_table(
        "teams",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("organization_id", "name"),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("role", sa.String(50), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        *timestamps(),
    )
    op.create_index("ix_users_organization_id", "users", ["organization_id"])
    op.create_index("ix_users_team_id", "users", ["team_id"])
    op.create_table(
        "firewall_managers",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("native_id", sa.String(200), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("base_url", sa.String(500), nullable=False),
        sa.Column("read_only", sa.Boolean(), nullable=False, server_default=sa.true()),
        *timestamps(),
        sa.UniqueConstraint("provider", "native_id"),
    )
    op.create_index(
        "ix_firewall_managers_organization_id", "firewall_managers", ["organization_id"]
    )
    op.create_table(
        "access_policies",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("native_id", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        *timestamps(),
        sa.UniqueConstraint("manager_id", "native_id"),
    )
    op.create_index("ix_access_policies_manager_id", "access_policies", ["manager_id"])
    op.create_index("ix_access_policies_team_id", "access_policies", ["team_id"])
    op.create_table(
        "policy_categories",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("policy_id", sa.Uuid(), sa.ForeignKey("access_policies.id"), nullable=False),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("policy_id", "name"),
    )
    op.create_index("ix_policy_categories_policy_id", "policy_categories", ["policy_id"])
    op.create_index("ix_policy_categories_team_id", "policy_categories", ["team_id"])
    op.create_table(
        "access_rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("policy_id", sa.Uuid(), sa.ForeignKey("access_policies.id"), nullable=False),
        sa.Column("category_id", sa.Uuid(), sa.ForeignKey("policy_categories.id"), nullable=False),
        sa.Column("owner_team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("native_id", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("action", sa.String(30), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        *timestamps(),
        sa.UniqueConstraint("policy_id", "native_id"),
    )
    op.create_index("ix_access_rules_policy_id", "access_rules", ["policy_id"])
    op.create_index("ix_access_rules_category_id", "access_rules", ["category_id"])
    op.create_index("ix_access_rules_owner_team_id", "access_rules", ["owner_team_id"])
    op.create_table(
        "network_objects",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("owner_team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("native_id", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("value", sa.String(200), nullable=False),
        sa.Column("sharing_mode", sa.String(30), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("manager_id", "native_id"),
    )
    op.create_index("ix_network_objects_manager_id", "network_objects", ["manager_id"])
    op.create_index("ix_network_objects_owner_team_id", "network_objects", ["owner_team_id"])
    op.create_table(
        "change_sets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("owner_user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("summary", sa.Text(), nullable=False),
        *timestamps(),
    )
    op.create_index("ix_change_sets_organization_id", "change_sets", ["organization_id"])
    op.create_index("ix_change_sets_owner_user_id", "change_sets", ["owner_user_id"])
    op.create_table(
        "drift_records",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *timestamps(),
    )
    op.create_index("ix_drift_records_manager_id", "drift_records", ["manager_id"])


def downgrade() -> None:
    op.drop_table("drift_records")
    op.drop_table("change_sets")
    op.drop_table("network_objects")
    op.drop_table("access_rules")
    op.drop_table("policy_categories")
    op.drop_table("access_policies")
    op.drop_table("firewall_managers")
    op.drop_table("users")
    op.drop_table("teams")
    op.drop_table("organizations")
