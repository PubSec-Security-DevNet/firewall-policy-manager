"""Add deployment rollback tracking."""

import sqlalchemy as sa
from alembic import op

revision = "20260930_0026"
down_revision = "20260929_0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("deployments", sa.Column("rollback_state", sa.String(length=30), nullable=True))
    op.add_column(
        "deployments", sa.Column("rollback_external_operation_id", sa.String(length=200), nullable=True)
    )
    op.add_column(
        "deployments", sa.Column("rollback_requested_by_user_id", sa.Uuid(), nullable=True)
    )
    op.add_column("deployments", sa.Column("rollback_device_results", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("deployments", sa.Column("rollback_failure_info", sa.JSON(), nullable=False, server_default="{}"))
    op.create_foreign_key(
        "fk_deployments_rollback_requested_by_user_id",
        "deployments",
        "users",
        ["rollback_requested_by_user_id"],
        ["id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_deployments_rollback_requested_by_user_id", "deployments", type_="foreignkey")
    op.drop_column("deployments", "rollback_failure_info")
    op.drop_column("deployments", "rollback_device_results")
    op.drop_column("deployments", "rollback_requested_by_user_id")
    op.drop_column("deployments", "rollback_external_operation_id")
    op.drop_column("deployments", "rollback_state")
