"""Persist authoritative delegated-object naming evidence.

Revision ID: 20260919_0008
Revises: 20260919_0007
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260919_0008"
down_revision: str | None = "20260919_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("firewall_objects", sa.Column("expected_provider_name", sa.String(200)))
    op.add_column(
        "firewall_objects",
        sa.Column("owner_policy_id", sa.Uuid(), sa.ForeignKey("access_policies.id")),
    )
    op.create_index("ix_firewall_objects_owner_policy_id", "firewall_objects", ["owner_policy_id"])
    op.create_check_constraint(
        "ck_firewall_objects_authoritative_owner",
        "firewall_objects",
        "(owner_group_id IS NULL AND owner_policy_id IS NULL "
        "AND expected_provider_name IS NULL) OR "
        "(owner_group_id IS NOT NULL AND owner_policy_id IS NOT NULL "
        "AND expected_provider_name IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_firewall_objects_authoritative_owner", "firewall_objects", type_="check")
    op.drop_index("ix_firewall_objects_owner_policy_id", table_name="firewall_objects")
    op.drop_column("firewall_objects", "owner_policy_id")
    op.drop_column("firewall_objects", "expected_provider_name")
