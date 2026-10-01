"""Persist per-Group ChangeSet approval policy."""

import sqlalchemy as sa
from alembic import op

revision = "20260927_0022"
down_revision = "20260927_0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "application_groups",
        sa.Column("approval_required", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("application_groups", "approval_required")
