"""Remove the unsupported direct-user policy grant model."""

from collections.abc import Sequence

from alembic import op

revision: str = "20261005_0041"
down_revision: str | None = "20261005_0040"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("direct_user_policy_grants")


def downgrade() -> None:
    # The retired grant type is intentionally not recreated on downgrade.
    pass
