"""Align Milestone 1 indexes and object value width.

Revision ID: 20260919_0003
Revises: 20260919_0002
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260919_0003"
down_revision: str | None = "20260919_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_teams_organization_id", "teams", ["organization_id"])
    op.alter_column(
        "firewall_objects",
        "value",
        existing_type=sa.String(200),
        type_=sa.String(500),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "firewall_objects",
        "value",
        existing_type=sa.String(500),
        type_=sa.String(200),
        existing_nullable=True,
    )
    op.drop_index("ix_teams_organization_id", table_name="teams")
