"""Add administrator-managed organization SMTP settings."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261002_0035"
down_revision: str | None = "20261001_0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "smtp_settings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("host", sa.String(500), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="587"),
        sa.Column("from_address", sa.String(320), nullable=False),
        sa.Column("encryption", sa.String(20), nullable=False, server_default="STARTTLS"),
        sa.Column(
            "authentication_required", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("username", sa.String(320)),
        sa.Column(
            "password_reference",
            sa.Uuid(),
            sa.ForeignKey("secret_records.id", ondelete="RESTRICT"),
            unique=True,
        ),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("organization_id"),
        sa.CheckConstraint(
            "encryption IN ('NONE','STARTTLS','SSL_TLS')", name="ck_smtp_encryption"
        ),
        sa.CheckConstraint("port >= 1 AND port <= 65535", name="ck_smtp_port"),
        sa.CheckConstraint("revision >= 1", name="ck_smtp_revision"),
    )
    op.create_index("ix_smtp_settings_organization_id", "smtp_settings", ["organization_id"])


def downgrade() -> None:
    op.drop_index("ix_smtp_settings_organization_id", table_name="smtp_settings")
    op.drop_table("smtp_settings")
