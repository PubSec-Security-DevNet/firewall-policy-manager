"""Store application state needed to build compensating ChangeSets."""

import sqlalchemy as sa
from alembic import op

revision = "20260930_0027"
down_revision = "20260930_0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "change_set_operations",
        sa.Column("rollback_snapshot", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("change_set_operations", "rollback_snapshot")
