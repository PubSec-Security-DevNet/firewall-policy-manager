"""Separate application catalog synchronization cadence and state."""

from alembic import op
import sqlalchemy as sa

revision = "20260925_0020"
down_revision = "20260924_0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "provider_connections",
        sa.Column("applications_sync_interval_minutes", sa.Integer(), nullable=False, server_default="1440"),
    )
    op.add_column("provider_connections", sa.Column("applications_sync_status", sa.String(30)))
    op.add_column("provider_connections", sa.Column("applications_last_sync", sa.DateTime(timezone=True)))
    op.add_column(
        "provider_connections",
        sa.Column("applications_last_successful_sync", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "provider_connections", sa.Column("applications_next_sync_at", sa.DateTime(timezone=True))
    )
    op.create_check_constraint(
        "ck_provider_connections_applications_sync_interval",
        "provider_connections",
        "applications_sync_interval_minutes >= 60 AND applications_sync_interval_minutes <= 43200",
    )
    op.execute(
        "UPDATE provider_connections SET applications_next_sync_at = COALESCE(next_sync_at, now()) "
        "WHERE lifecycle = 'ACTIVE' AND applications_next_sync_at IS NULL"
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_provider_connections_applications_sync_interval", "provider_connections", type_="check"
    )
    for name in (
        "applications_next_sync_at",
        "applications_last_successful_sync",
        "applications_last_sync",
        "applications_sync_status",
        "applications_sync_interval_minutes",
    ):
        op.drop_column("provider_connections", name)
