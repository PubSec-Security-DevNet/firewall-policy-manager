"""Add per-provider deployment scheduling intervals."""

import sqlalchemy as sa
from alembic import op

revision = "20261005_0043"
down_revision = "20261005_0042"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "provider_connections",
        sa.Column("deployment_interval_minutes", sa.Integer(), nullable=False, server_default="15"),
    )
    op.create_check_constraint(
        "ck_provider_connections_deployment_interval",
        "provider_connections",
        "deployment_interval_minutes >= 5 AND deployment_interval_minutes <= 10080",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_provider_connections_deployment_interval",
        "provider_connections",
        type_="check",
    )
    op.drop_column("provider_connections", "deployment_interval_minutes")
