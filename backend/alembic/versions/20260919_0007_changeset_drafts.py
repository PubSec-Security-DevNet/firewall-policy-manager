"""Add Milestone 3 ChangeSet drafts and mock transaction evidence.

Revision ID: 20260919_0007
Revises: 20260919_0006
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260919_0007"
down_revision: str | None = "20260919_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def timestamps() -> tuple[sa.Column[object], sa.Column[object]]:
    return (
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def upgrade() -> None:
    op.add_column(
        "firewall_managers",
        sa.Column("is_mock", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    # Existing deterministic local managers are explicit mock targets. No provider discovery
    # response can flip this application-controlled safety bit.
    op.execute(
        "UPDATE firewall_managers SET is_mock = true "
        "WHERE native_id IN ('mock-fmc', 'mock-scc') "
        "AND base_url LIKE 'http://mock-%'"
    )
    for _name, column in (
        ("description", sa.Column("description", sa.Text(), server_default="", nullable=False)),
        (
            "target_policy_ids",
            sa.Column("target_policy_ids", postgresql.JSONB(), server_default="[]", nullable=False),
        ),
        (
            "provider_revision_snapshot",
            sa.Column(
                "provider_revision_snapshot",
                postgresql.JSONB(),
                server_default="{}",
                nullable=False,
            ),
        ),
        (
            "validation_results",
            sa.Column(
                "validation_results", postgresql.JSONB(), server_default="[]", nullable=False
            ),
        ),
        (
            "execution_results",
            sa.Column("execution_results", postgresql.JSONB(), server_default="{}", nullable=False),
        ),
        (
            "failure_info",
            sa.Column("failure_info", postgresql.JSONB(), server_default="{}", nullable=False),
        ),
        (
            "audit_metadata",
            sa.Column("audit_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
        ),
        ("validated_revision", sa.Column("validated_revision", sa.Integer())),
    ):
        op.add_column("change_sets", column)
    op.execute(
        "UPDATE change_sets SET target_policy_ids = "
        "CASE WHEN access_policy_id IS NULL THEN '[]'::jsonb "
        "ELSE jsonb_build_array(access_policy_id::text) END"
    )

    op.create_table(
        "change_set_operations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("change_set_id", sa.Uuid(), sa.ForeignKey("change_sets.id"), nullable=False),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column(
            "access_policy_id", sa.Uuid(), sa.ForeignKey("access_policies.id"), nullable=False
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("payload", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("expected_revisions", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("status", sa.String(30), server_default="DRAFT", nullable=False),
        sa.Column("validation_results", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("resolution", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("execution_result", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("failure_info", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        sa.UniqueConstraint("change_set_id", "sequence"),
        sa.CheckConstraint("revision >= 1", name="ck_change_set_operations_revision"),
    )
    for column in ("organization_id", "change_set_id", "manager_id", "access_policy_id"):
        op.create_index(f"ix_change_set_operations_{column}", "change_set_operations", [column])
    op.create_index(
        "ix_change_set_operations_change_set",
        "change_set_operations",
        ["change_set_id", "sequence"],
    )
    op.create_index(
        "ix_change_set_operations_manager",
        "change_set_operations",
        ["manager_id", "status"],
    )
    op.add_column(
        "provider_transactions",
        sa.Column("operation_results", postgresql.JSONB(), server_default="[]", nullable=False),
    )
    op.add_column(
        "provider_transactions",
        sa.Column("failure_info", postgresql.JSONB(), server_default="{}", nullable=False),
    )
    op.add_column(
        "provider_transactions",
        sa.Column(
            "reconciliation_required", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )


def downgrade() -> None:
    for column in ("reconciliation_required", "failure_info", "operation_results"):
        op.drop_column("provider_transactions", column)
    op.drop_table("change_set_operations")
    for column in (
        "validated_revision",
        "audit_metadata",
        "failure_info",
        "execution_results",
        "validation_results",
        "provider_revision_snapshot",
        "target_policy_ids",
        "description",
    ):
        op.drop_column("change_sets", column)
    op.drop_column("firewall_managers", "is_mock")
