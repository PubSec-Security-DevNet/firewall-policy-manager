"""Persist each user's default delegated working context.

Revision ID: 20260920_0012
Revises: 20260920_0011
Create Date: 2026-09-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260920_0012"
down_revision: str | None = "20260920_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("default_group_id", sa.Uuid(), nullable=True))
    op.add_column("users", sa.Column("default_policy_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_users_default_group_id_application_groups",
        "users",
        "application_groups",
        ["default_group_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_users_default_policy_id_access_policies",
        "users",
        "access_policies",
        ["default_policy_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_users_default_policy_id_access_policies", "users", type_="foreignkey")
    op.drop_constraint("fk_users_default_group_id_application_groups", "users", type_="foreignkey")
    op.drop_column("users", "default_policy_id")
    op.drop_column("users", "default_group_id")
