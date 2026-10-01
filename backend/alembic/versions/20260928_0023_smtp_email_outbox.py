"""Add durable SMTP notification outbox."""

import sqlalchemy as sa
from alembic import op

revision = "20260928_0023"
down_revision = "20260927_0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "email_notifications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("recipient_user_id", sa.Uuid(), nullable=False),
        sa.Column("recipient_email", sa.String(length=320), nullable=False),
        sa.Column("kind", sa.String(length=50), nullable=False),
        sa.Column("dedupe_key", sa.String(length=300), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="PENDING"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_owner", sa.String(length=200), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["recipient_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "recipient_user_id", "dedupe_key"),
    )
    op.create_index(
        "ix_email_notifications_organization_id", "email_notifications", ["organization_id"]
    )
    op.create_index(
        "ix_email_notifications_recipient_user_id", "email_notifications", ["recipient_user_id"]
    )
    op.create_index(
        "ix_email_notifications_due", "email_notifications", ["status", "next_attempt_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_email_notifications_due", table_name="email_notifications")
    op.drop_index("ix_email_notifications_recipient_user_id", table_name="email_notifications")
    op.drop_index("ix_email_notifications_organization_id", table_name="email_notifications")
    op.drop_table("email_notifications")
