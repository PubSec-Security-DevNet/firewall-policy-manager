"""Add the explicit, default-deny real-provider write safety gate.

Revision ID: 20260920_0010
Revises: 20260919_0009
Create Date: 2026-09-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260920_0010"
down_revision: str | None = "20260919_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "provider_connections",
        sa.Column("write_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("provider_connections", sa.Column("write_enabled_at", sa.DateTime(timezone=True)))
    op.add_column(
        "provider_connections",
        sa.Column("write_enabled_by_user_id", sa.Uuid(), sa.ForeignKey("users.id")),
    )
    op.create_index(
        "ix_provider_connections_write_enabled_by_user_id",
        "provider_connections",
        ["write_enabled_by_user_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_provider_connections_write_enabled_by_user_id",
        table_name="provider_connections",
    )
    op.drop_column("provider_connections", "write_enabled_by_user_id")
    op.drop_column("provider_connections", "write_enabled_at")
    op.drop_column("provider_connections", "write_enabled")
