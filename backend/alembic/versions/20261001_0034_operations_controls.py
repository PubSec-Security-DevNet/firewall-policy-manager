"""Add durable deployment pause controls."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261001_0034"
down_revision: str | None = "20261001_0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "provider_connections",
        sa.Column("deployment_paused", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("provider_connections", sa.Column("deployment_pause_reason", sa.String(500)))
    op.add_column(
        "provider_connections", sa.Column("deployment_paused_at", sa.DateTime(timezone=True))
    )
    op.add_column(
        "provider_connections", sa.Column("deployment_pause_until", sa.DateTime(timezone=True))
    )
    op.add_column(
        "provider_connections",
        sa.Column("deployment_paused_by_user_id", sa.Uuid(), sa.ForeignKey("users.id")),
    )


def downgrade() -> None:
    op.drop_column("provider_connections", "deployment_paused_by_user_id")
    op.drop_column("provider_connections", "deployment_pause_until")
    op.drop_column("provider_connections", "deployment_paused_at")
    op.drop_column("provider_connections", "deployment_pause_reason")
    op.drop_column("provider_connections", "deployment_paused")
