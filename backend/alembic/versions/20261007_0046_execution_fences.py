# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Monotonic claim generations and durable external mutation intents."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261007_0046"
down_revision = "20261007_0045"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("change_sets", "deployments"):
        op.add_column(
            table, sa.Column("execution_epoch", sa.Integer(), nullable=False, server_default="0")
        )
        op.add_column(
            table,
            sa.Column("mutation_intent", postgresql.JSONB(), nullable=False, server_default="{}"),
        )


def downgrade() -> None:
    raise RuntimeError("Execution fencing cannot be removed while old workers may exist")
