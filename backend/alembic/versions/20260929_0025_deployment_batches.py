"""Add connector ownership to deployment batches."""

import sqlalchemy as sa
from alembic import op

revision = "20260929_0025"
down_revision = "20260929_0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("deployments", sa.Column("provider_connection_id", sa.Uuid(), nullable=True))
    op.add_column("deployments", sa.Column("manager_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_deployments_provider_connection_id",
        "deployments",
        "provider_connections",
        ["provider_connection_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_deployments_manager_id", "deployments", "firewall_managers", ["manager_id"], ["id"]
    )
    op.create_index(
        "ix_deployments_provider_connection_id", "deployments", ["provider_connection_id"]
    )
    op.create_index("ix_deployments_manager_id", "deployments", ["manager_id"])


def downgrade() -> None:
    op.drop_index("ix_deployments_manager_id", table_name="deployments")
    op.drop_index("ix_deployments_provider_connection_id", table_name="deployments")
    op.drop_constraint("fk_deployments_manager_id", "deployments", type_="foreignkey")
    op.drop_constraint("fk_deployments_provider_connection_id", "deployments", type_="foreignkey")
    op.drop_column("deployments", "manager_id")
    op.drop_column("deployments", "provider_connection_id")
