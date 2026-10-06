"""Add custom CA support for SMTP TLS verification."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261002_0036"
down_revision: str | None = "20261002_0035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("smtp_settings", sa.Column("custom_ca_certificate", sa.Text()))


def downgrade() -> None:
    op.drop_column("smtp_settings", "custom_ca_certificate")
