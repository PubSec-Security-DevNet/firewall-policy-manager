"""Persist rule enabled and logging controls."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260923_0016"
down_revision: str | None = "20260923_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("access_rules", sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("access_rules", sa.Column("log_begin", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("access_rules", sa.Column("log_end", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("access_rules", "log_end")
    op.drop_column("access_rules", "log_begin")
    op.drop_column("access_rules", "enabled")
