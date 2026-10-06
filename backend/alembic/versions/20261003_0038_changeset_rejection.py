"""Add ChangeSet rejection audit fields."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261003_0038"
down_revision: str | None = "20261003_0037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("change_sets", sa.Column("rejected_at", sa.DateTime(timezone=True)))
    op.add_column(
        "change_sets",
        sa.Column("rejected_by_user_id", sa.Uuid(), sa.ForeignKey("users.id")),
    )
    op.add_column("change_sets", sa.Column("rejection_reason", sa.Text()))


def downgrade() -> None:
    op.drop_column("change_sets", "rejection_reason")
    op.drop_column("change_sets", "rejected_by_user_id")
    op.drop_column("change_sets", "rejected_at")
