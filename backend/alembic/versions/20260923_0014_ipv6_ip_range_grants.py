"""Allow full-length IPv6 address ranges in delegated grants."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260923_0014"
down_revision: str | None = "20260921_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "ip_range_grants",
        "network",
        existing_type=sa.String(length=64),
        type_=sa.String(length=128),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "ip_range_grants",
        "network",
        existing_type=sa.String(length=128),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
