# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

# ruff: noqa: S608 -- identifiers come only from the fixed migration tuple.

"""Quarantine pre-provenance ownership and grants without deleting their evidence."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261007_0045"
down_revision = "20261007_0044"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "legacy_ownership_reviews",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("resource_type", sa.String(30), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), sa.ForeignKey("application_groups.id"), nullable=False),
        sa.Column("policy_id", sa.Uuid(), sa.ForeignKey("access_policies.id")),
        sa.Column("snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True)),
        sa.Column("confirmed_by", sa.Uuid(), sa.ForeignKey("users.id")),
        sa.Column("confirmation_reason", sa.String(1000)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("resource_type", "resource_id"),
    )
    op.create_index(
        "ix_legacy_reviews_scope",
        "legacy_ownership_reviews",
        ["organization_id", "group_id", "policy_id", "confirmed_at"],
    )
    quarantine_existing_authority()


def quarantine_existing_authority() -> None:
    # No reliable, complete assignment provenance exists in older schemas. Preserve every
    # assignment for individual review rather than guessing from timestamps/names/audit prose.
    for table, kind, group, policy in (
        ("access_rules", "RULE", "owner_group_id", "policy_id"),
        ("firewall_objects", "OBJECT", "owner_group_id", "owner_policy_id"),
        ("group_policy_category_mappings", "CATEGORY", "group_id", "policy_id"),
        ("object_use_grants", "OBJECT_USE", "group_id", "policy_id"),
    ):
        op.execute(
            sa.text(f"""
            INSERT INTO legacy_ownership_reviews
                (id, organization_id, resource_type, resource_id, group_id, policy_id, snapshot)
            SELECT gen_random_uuid(), organization_id, '{kind}', id, {group}, {policy}, to_jsonb(r)
            FROM {table} r WHERE {group} IS NOT NULL
            ON CONFLICT (resource_type, resource_id) DO NOTHING
        """)
        )
    # Old approvals were made while legacy authority was trusted. Require fresh validation.
    op.execute("""UPDATE change_sets SET state='RECONCILIATION_REQUIRED',
        approved_revision=NULL, approval_invalidated_at=now(),
        execution_owner=NULL, execution_lease_until=NULL, revision=revision+1,
        failure_info='{"code":"LEGACY_AUTHORITY_REVIEW_REQUIRED"}'::jsonb
        WHERE state IN ('READY','APPROVED','QUEUED','EXECUTING')""")
    op.execute("""UPDATE provider_connections SET write_enabled=false,
        deployment_paused=true, deployment_pause_reason='Legacy ownership review required'
        WHERE EXISTS (SELECT 1 FROM legacy_ownership_reviews r
                      WHERE r.organization_id=provider_connections.organization_id)""")
    op.execute("""UPDATE deployments SET state='RECONCILIATION_REQUIRED',
        lease_owner=NULL, lease_until=NULL,
        failure_info='{"code":"LEGACY_AUTHORITY_REVIEW_REQUIRED"}'::jsonb
        WHERE state IN ('READY','DEPLOYING')""")


def downgrade() -> None:
    # Dropping quarantine would silently reactivate untrusted authority.
    raise RuntimeError("Legacy authority quarantine is irreversible; restore a reviewed backup")
