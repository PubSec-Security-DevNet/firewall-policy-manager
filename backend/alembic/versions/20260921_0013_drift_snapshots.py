"""Retain normalized before/after evidence for provider drift."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260921_0013"
down_revision: str | None = "20260920_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "drift_records", sa.Column("previous_snapshot", postgresql.JSONB(), nullable=True)
    )
    op.add_column(
        "drift_records", sa.Column("observed_snapshot", postgresql.JSONB(), nullable=True)
    )
    for table in (
        "provider_domains",
        "devices",
        "access_policies",
        "rule_categories",
        "access_rules",
        "firewall_objects",
        "security_zones",
    ):
        op.add_column(table, sa.Column("application_snapshot", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("drift_records", "observed_snapshot")
    op.drop_column("drift_records", "previous_snapshot")
    for table in reversed(
        (
            "provider_domains",
            "devices",
            "access_policies",
            "rule_categories",
            "access_rules",
            "firewall_objects",
            "security_zones",
        )
    ):
        op.drop_column(table, "application_snapshot")
