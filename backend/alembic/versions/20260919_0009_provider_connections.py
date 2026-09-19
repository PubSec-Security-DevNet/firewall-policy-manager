"""Add real provider connection, encrypted secret, scope, and evidence state.

Revision ID: 20260919_0009
Revises: 20260919_0008
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260919_0009"
down_revision: str | None = "20260919_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def timestamps() -> tuple[sa.Column[object], sa.Column[object]]:
    return (
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def upgrade() -> None:
    op.create_table(
        "secret_records",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("purpose", sa.String(100), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column(
            "rotated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        *timestamps(),
        sa.UniqueConstraint("organization_id", "id"),
        sa.CheckConstraint("key_version >= 1", name="ck_secret_records_key_version"),
    )
    op.create_index("ix_secret_records_organization_id", "secret_records", ["organization_id"])
    op.create_index(
        "ix_secret_records_org_purpose", "secret_records", ["organization_id", "purpose"]
    )

    op.create_table(
        "provider_connections",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("provider_type", sa.String(20), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("lifecycle", sa.String(20), server_default="DISABLED", nullable=False),
        sa.Column("connection_mode", sa.String(30), nullable=False),
        sa.Column("evidence_profile", sa.String(20), server_default="real", nullable=False),
        sa.Column("base_endpoint", sa.String(500)),
        sa.Column("region", sa.String(30)),
        sa.Column("tls_mode", sa.String(20), server_default="SYSTEM", nullable=False),
        sa.Column(
            "credential_reference",
            sa.Uuid(),
            sa.ForeignKey("secret_records.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("credential_type", sa.String(30), nullable=False),
        sa.Column("credential_username", sa.String(320)),
        sa.Column("credential_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provider_version", sa.String(100)),
        sa.Column(
            "connection_status", sa.String(50), server_default="NEVER_TESTED", nullable=False
        ),
        sa.Column("sync_status", sa.String(30)),
        sa.Column("last_connection_test", sa.DateTime(timezone=True)),
        sa.Column("last_successful_connection", sa.DateTime(timezone=True)),
        sa.Column("last_sync", sa.DateTime(timezone=True)),
        sa.Column("last_successful_sync", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(100)),
        sa.Column("last_error_message", sa.String(500)),
        sa.Column("last_error_correlation_id", sa.String(100)),
        sa.Column("certificate_info", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("sync_interval_minutes", sa.Integer(), server_default="60", nullable=False),
        sa.Column("next_sync_at", sa.DateTime(timezone=True)),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        sa.UniqueConstraint("organization_id", "display_name"),
        sa.UniqueConstraint("organization_id", "id"),
        sa.CheckConstraint("provider_type IN ('fmc','scc')", name="ck_provider_connections_type"),
        sa.CheckConstraint(
            "lifecycle IN ('ACTIVE','DISABLED','RETIRED')",
            name="ck_provider_connections_lifecycle",
        ),
        sa.CheckConstraint(
            "evidence_profile = 'real'", name="ck_provider_connections_real_evidence"
        ),
        sa.CheckConstraint(
            "tls_mode IN ('SYSTEM','CUSTOM_CA')", name="ck_provider_connections_tls_mode"
        ),
        sa.CheckConstraint("revision >= 1", name="ck_provider_connections_revision"),
        sa.CheckConstraint(
            "sync_interval_minutes >= 5 AND sync_interval_minutes <= 10080",
            name="ck_provider_connections_sync_interval",
        ),
    )
    op.create_index(
        "ix_provider_connections_organization_id", "provider_connections", ["organization_id"]
    )
    op.create_index(
        "ix_provider_connections_credential_reference",
        "provider_connections",
        ["credential_reference"],
        unique=True,
    )
    op.create_index(
        "ix_provider_connections_org_lifecycle",
        "provider_connections",
        ["organization_id", "lifecycle"],
    )
    op.create_index(
        "ix_provider_connections_sync_due", "provider_connections", ["lifecycle", "next_sync_at"]
    )

    op.add_column(
        "firewall_managers",
        sa.Column(
            "provider_connection_id",
            sa.Uuid(),
            sa.ForeignKey("provider_connections.id", ondelete="RESTRICT"),
        ),
    )
    op.create_index(
        "ix_firewall_managers_provider_connection_id",
        "firewall_managers",
        ["provider_connection_id"],
        unique=True,
    )

    op.create_table(
        "provider_connection_scopes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column(
            "connection_id",
            sa.Uuid(),
            sa.ForeignKey("provider_connections.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("native_id", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("scope_type", sa.String(30), nullable=False),
        sa.Column("native_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("connection_id", "native_id"),
    )
    op.create_index(
        "ix_provider_connection_scopes_organization_id",
        "provider_connection_scopes",
        ["organization_id"],
    )
    op.create_index(
        "ix_provider_connection_scopes_connection_id",
        "provider_connection_scopes",
        ["connection_id"],
    )
    op.create_index(
        "ix_provider_connection_scopes_org_connection",
        "provider_connection_scopes",
        ["organization_id", "connection_id"],
    )

    op.create_table(
        "provider_capability_evidence",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column(
            "connection_id",
            sa.Uuid(),
            sa.ForeignKey("provider_connections.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("provider_version", sa.String(100), nullable=False),
        sa.Column("capability", sa.String(100), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("evidence_level", sa.String(30), server_default="NOT_STARTED", nullable=False),
        sa.Column("evidence_summary", sa.String(500), server_default="", nullable=False),
        sa.Column("tested_at", sa.DateTime(timezone=True)),
        *timestamps(),
        sa.UniqueConstraint("connection_id", "provider_version", "capability"),
        sa.CheckConstraint(
            "evidence_level IN ('TESTED','EXPECTED_COMPATIBLE','NOT_STARTED')",
            name="ck_provider_capability_evidence_level",
        ),
    )
    op.create_index(
        "ix_provider_capability_evidence_organization_id",
        "provider_capability_evidence",
        ["organization_id"],
    )
    op.create_index(
        "ix_provider_capability_evidence_connection_id",
        "provider_capability_evidence",
        ["connection_id"],
    )
    op.create_index(
        "ix_provider_capability_evidence_connection_version",
        "provider_capability_evidence",
        ["connection_id", "provider_version"],
    )


def downgrade() -> None:
    op.drop_table("provider_capability_evidence")
    op.drop_table("provider_connection_scopes")
    op.drop_index("ix_firewall_managers_provider_connection_id", table_name="firewall_managers")
    op.drop_column("firewall_managers", "provider_connection_id")
    op.drop_table("provider_connections")
    op.drop_table("secret_records")
