# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Remove the redundant delegated policy Changeset submission capability."""

import sqlalchemy as sa
from alembic import op

revision = "20261007_0048"
down_revision = "20261007_0047"
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
                    WHERE value <> to_jsonb('submit'::text)
                ),
                '[]'::jsonb
            )
            WHERE capabilities @> '["submit"]'::jsonb
            """
        )
    )


def downgrade() -> None:
    raise RuntimeError("The delegated policy submit capability was intentionally removed")
