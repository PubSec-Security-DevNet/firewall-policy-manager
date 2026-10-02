"""Add administrator-managed OIDC provider configuration."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261001_0029"
down_revision: str | None = "20261001_0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oidc_providers",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("provider_id", sa.String(80), nullable=False, unique=True),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("issuer_url", sa.String(500), nullable=False),
        sa.Column("client_id", sa.String(300), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column(
            "username_claim", sa.String(100), nullable=False, server_default="preferred_username"
        ),
        sa.Column("display_name_claim", sa.String(100), nullable=False, server_default="name"),
        sa.Column("email_claim", sa.String(100), nullable=False, server_default="email"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("logout", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "secret_reference", sa.Uuid(), sa.ForeignKey("secret_records.id"), nullable=False
        ),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("revision >= 1", name="ck_oidc_providers_revision"),
    )
    op.create_index("ix_oidc_providers_organization_id", "oidc_providers", ["organization_id"])


def downgrade() -> None:
    op.drop_index("ix_oidc_providers_organization_id", table_name="oidc_providers")
    op.drop_table("oidc_providers")
