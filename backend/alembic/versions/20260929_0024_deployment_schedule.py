"""Add per-connector automatic deployment scheduling state."""

import sqlalchemy as sa
from alembic import op

revision = "20260929_0024"
down_revision = "20260928_0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "provider_connections",
        sa.Column(
            "deployment_schedule_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    op.add_column("provider_connections", sa.Column("deployment_status", sa.String(30)))
    op.add_column(
        "provider_connections", sa.Column("deployment_next_at", sa.DateTime(timezone=True))
    )
    op.add_column(
        "provider_connections", sa.Column("deployment_last_started_at", sa.DateTime(timezone=True))
    )
    op.add_column(
        "provider_connections",
        sa.Column("deployment_last_completed_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    for name in (
        "deployment_last_completed_at",
        "deployment_last_started_at",
        "deployment_next_at",
        "deployment_status",
        "deployment_schedule_enabled",
    ):
        op.drop_column("provider_connections", name)
