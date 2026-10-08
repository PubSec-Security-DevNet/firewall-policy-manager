# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Remove the unused delegated policy deploy capability."""

import sqlalchemy as sa
from alembic import op

revision = "20261007_0047"
down_revision = "20261007_0046"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            UPDATE policy_delegations
            SET capabilities = COALESCE(
                (
                    SELECT jsonb_agg(value ORDER BY ordinal)
                    FROM jsonb_array_elements(capabilities) WITH ORDINALITY AS item(value, ordinal)
                    WHERE value <> to_jsonb('deploy'::text)
                ),
                '[]'::jsonb
            )
            WHERE capabilities @> '["deploy"]'::jsonb
            """
        )
    )


def downgrade() -> None:
    raise RuntimeError("The delegated policy deploy capability was intentionally removed")
