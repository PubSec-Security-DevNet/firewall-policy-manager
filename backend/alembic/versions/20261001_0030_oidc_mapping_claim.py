"""Add administrator-selected OIDC account mapping claim."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261001_0030"
down_revision: str | None = "20261001_0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "oidc_providers",
        sa.Column("mapping_claim", sa.String(100), nullable=False, server_default="email"),
    )


def downgrade() -> None:
    op.drop_column("oidc_providers", "mapping_claim")
