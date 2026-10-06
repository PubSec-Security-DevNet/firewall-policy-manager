"""Add ChangeSet rejection notice dismissal timestamp."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261004_0039"
down_revision: str | None = "20261003_0038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "change_sets",
        sa.Column("rejection_notice_dismissed_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_column("change_sets", "rejection_notice_dismissed_at")
