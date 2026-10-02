"""Add audited administrator proxy-session state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261001_0031"
down_revision: str | None = "20261001_0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("auth_sessions", sa.Column("actor_user_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_auth_sessions_actor_user_id_users",
        "auth_sessions",
        "users",
        ["actor_user_id"],
        ["id"],
    )
    op.create_index("ix_auth_sessions_actor_user_id", "auth_sessions", ["actor_user_id"])
    op.add_column("auth_sessions", sa.Column("proxy_started_at", sa.DateTime(timezone=True)))
    op.add_column("auth_sessions", sa.Column("proxy_reason", sa.String(500)))


def downgrade() -> None:
    op.drop_column("auth_sessions", "proxy_reason")
    op.drop_column("auth_sessions", "proxy_started_at")
    op.drop_index("ix_auth_sessions_actor_user_id", table_name="auth_sessions")
    op.drop_constraint("fk_auth_sessions_actor_user_id_users", "auth_sessions", type_="foreignkey")
    op.drop_column("auth_sessions", "actor_user_id")
