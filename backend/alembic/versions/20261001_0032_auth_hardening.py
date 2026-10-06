"""Add explicit external identities and authentication evidence."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261001_0032"
down_revision: str | None = "20261001_0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "external_identities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("provider_id", sa.String(80), nullable=False),
        sa.Column("issuer", sa.String(500), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("email_claim", sa.String(320)),
        sa.Column("display_name_claim", sa.String(200)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("issuer", "subject"),
    )
    op.create_index("ix_external_identities_user_id", "external_identities", ["user_id"])
    op.create_index("ix_external_identities_provider_id", "external_identities", ["provider_id"])
    op.create_table(
        "authentication_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id")),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id")),
        sa.Column("provider_id", sa.String(80)),
        sa.Column("event", sa.String(60), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("correlation_id", sa.String(100)),
        sa.Column("details", sa.dialects.postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_authentication_events_occurred", "authentication_events", ["occurred_at"])
    op.create_index(
        "ix_authentication_events_provider", "authentication_events", ["provider_id", "occurred_at"]
    )
    op.execute(
        sa.text(
            """
            INSERT INTO external_identities
                (id, organization_id, user_id, provider_id, issuer, subject, email_claim, display_name_claim)
            SELECT gen_random_uuid(), organization_id, id, 'legacy', identity_issuer, identity_subject, email, display_name
            FROM users
            WHERE identity_issuer IS NOT NULL AND identity_subject IS NOT NULL
            ON CONFLICT (issuer, subject) DO NOTHING
            """
        )
    )


def downgrade() -> None:
    op.drop_index("ix_authentication_events_provider", table_name="authentication_events")
    op.drop_index("ix_authentication_events_occurred", table_name="authentication_events")
    op.drop_table("authentication_events")
    op.drop_index("ix_external_identities_provider_id", table_name="external_identities")
    op.drop_index("ix_external_identities_user_id", table_name="external_identities")
    op.drop_table("external_identities")
