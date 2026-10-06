"""Add imported file policies and access-rule file policy references."""

import sqlalchemy as sa
from alembic import op

revision = "20260924_0018"
down_revision = "20260923_0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "file_policies",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("organization_id", sa.UUID(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("manager_id", sa.UUID(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("native_id", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("provider_version", sa.String(200)),
        sa.Column("provider_fingerprint", sa.String(200), nullable=False),
        sa.Column("native_metadata", sa.JSON(), nullable=False),
        sa.Column("application_snapshot", sa.JSON()),
        sa.Column("management_state", sa.String(30), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("last_seen_sync_run_id", sa.UUID(), sa.ForeignKey("sync_runs.id")),
        sa.Column("domain_id", sa.UUID(), sa.ForeignKey("provider_domains.id"), nullable=False),
        sa.UniqueConstraint("manager_id", "native_id"),
    )
    op.add_column("access_rules", sa.Column("file_policy_id", sa.UUID()))
    op.create_foreign_key(
        "fk_access_rules_file_policy", "access_rules", "file_policies", ["file_policy_id"], ["id"]
    )


def downgrade() -> None:
    op.drop_constraint("fk_access_rules_file_policy", "access_rules", type_="foreignkey")
    op.drop_column("access_rules", "file_policy_id")
    op.drop_table("file_policies")
