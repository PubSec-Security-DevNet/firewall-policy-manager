"""Replace overlapping platform roles with the effective role model."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261005_0040"
down_revision: str | None = "20261004_0039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Delegated write access remains controlled by Group/policy grants. The old
    # viewer/editor/group_admin distinctions did not add platform authority.
    op.execute(
        sa.text(
            """
            UPDATE users
            SET role = CASE role
                WHEN 'viewer' THEN 'user'
                WHEN 'editor' THEN 'user'
                WHEN 'group_admin' THEN 'user'
                WHEN 'firewall_admin' THEN 'firewall_operator'
                ELSE role
            END
            WHERE role IN ('viewer', 'editor', 'group_admin', 'firewall_admin')
            """
        )
    )


def downgrade() -> None:
    # The retired roles were overlapping aliases. A downgrade restores the
    # closest read-only/operator names but cannot infer former editor/group
    # administrator intent from the persisted data.
    op.execute(
        sa.text(
            """
            UPDATE users
            SET role = CASE role
                WHEN 'user' THEN 'viewer'
                WHEN 'firewall_operator' THEN 'firewall_admin'
                ELSE role
            END
            WHERE role IN ('user', 'firewall_operator')
            """
        )
    )
