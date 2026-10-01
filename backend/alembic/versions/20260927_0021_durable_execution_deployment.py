"""Durable execution leases, approval evidence, and deployment lifecycle state."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260927_0021"
down_revision = "20260925_0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("change_sets", sa.Column("submitted_at", sa.DateTime(timezone=True)))
    op.add_column(
        "change_sets", sa.Column("submitted_by_user_id", sa.Uuid(), sa.ForeignKey("users.id"))
    )
    op.add_column("change_sets", sa.Column("approved_at", sa.DateTime(timezone=True)))
    op.add_column(
        "change_sets", sa.Column("approved_by_user_id", sa.Uuid(), sa.ForeignKey("users.id"))
    )
    op.add_column("change_sets", sa.Column("approved_revision", sa.Integer()))
    op.add_column("change_sets", sa.Column("approval_invalidated_at", sa.DateTime(timezone=True)))
    op.add_column("change_sets", sa.Column("execution_owner", sa.String(200)))
    op.add_column("change_sets", sa.Column("execution_lease_until", sa.DateTime(timezone=True)))
    op.add_column("change_sets", sa.Column("execution_heartbeat_at", sa.DateTime(timezone=True)))
    op.add_column("change_sets", sa.Column("execution_operation", sa.String(100)))

    for name, column in (
        ("lease_owner", sa.String(200)),
        ("lease_until", sa.DateTime(timezone=True)),
        ("heartbeat_at", sa.DateTime(timezone=True)),
        ("last_probe_at", sa.DateTime(timezone=True)),
    ):
        op.add_column("provider_transactions", sa.Column(name, column))
    op.add_column(
        "provider_transactions",
        sa.Column("provider_metadata", postgresql.JSONB(), nullable=False, server_default="{}"),
    )

    for name, column in (
        ("requested_by_user_id", sa.Uuid()),
        ("approved_by_user_id", sa.Uuid()),
    ):
        op.add_column("deployments", sa.Column(name, column, sa.ForeignKey("users.id")))
    for name in ("target_device_ids", "included_change_set_ids"):
        op.add_column(
            "deployments", sa.Column(name, postgresql.JSONB(), nullable=False, server_default="[]")
        )
    for name in ("plan_snapshot", "pending_change_evidence", "failure_info"):
        op.add_column(
            "deployments", sa.Column(name, postgresql.JSONB(), nullable=False, server_default="{}")
        )
    op.add_column(
        "deployments",
        sa.Column("device_results", postgresql.JSONB(), nullable=False, server_default="[]"),
    )
    for name in ("lease_owner", "heartbeat_at"):
        op.add_column(
            "deployments",
            sa.Column(
                name, sa.String(200) if name == "lease_owner" else sa.DateTime(timezone=True)
            ),
        )
    op.add_column("deployments", sa.Column("lease_until", sa.DateTime(timezone=True)))


def downgrade() -> None:
    for name in (
        "lease_until",
        "heartbeat_at",
        "lease_owner",
        "device_results",
        "failure_info",
        "pending_change_evidence",
        "plan_snapshot",
        "included_change_set_ids",
        "target_device_ids",
        "approved_by_user_id",
        "requested_by_user_id",
    ):
        op.drop_column("deployments", name)
    for name in (
        "provider_metadata",
        "last_probe_at",
        "heartbeat_at",
        "lease_until",
        "lease_owner",
    ):
        op.drop_column("provider_transactions", name)
    for name in (
        "execution_operation",
        "execution_heartbeat_at",
        "execution_lease_until",
        "execution_owner",
        "approval_invalidated_at",
        "approved_revision",
        "approved_by_user_id",
        "approved_at",
        "submitted_by_user_id",
        "submitted_at",
    ):
        op.drop_column("change_sets", name)
