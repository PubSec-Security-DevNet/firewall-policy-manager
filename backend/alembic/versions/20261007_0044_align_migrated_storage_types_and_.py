# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Align migrated storage types and indexes with models

Revision ID: 20261007_0044
Revises: 20261005_0043
Create Date: 2026-10-07 09:04:58.157518
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261007_0044"
down_revision: str | None = "20261005_0043"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        op.f("ix_access_rules_file_policy_id"), "access_rules", ["file_policy_id"], unique=False
    )
    op.create_index(
        op.f("ix_access_rules_intrusion_policy_id"),
        "access_rules",
        ["intrusion_policy_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_access_rules_variable_set_id"), "access_rules", ["variable_set_id"], unique=False
    )
    op.create_index(
        op.f("ix_api_tokens_organization_id"), "api_tokens", ["organization_id"], unique=False
    )
    op.create_index(
        op.f("ix_authentication_events_user_id"), "authentication_events", ["user_id"], unique=False
    )
    op.alter_column(
        "change_set_operations",
        "rollback_snapshot",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=False,
        existing_server_default=sa.text("'{}'::json"),
    )
    op.alter_column(
        "deployments",
        "rollback_device_results",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=False,
        existing_server_default=sa.text("'[]'::json"),
    )
    op.alter_column(
        "deployments",
        "rollback_failure_info",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=False,
        existing_server_default=sa.text("'{}'::json"),
    )
    op.create_index(
        op.f("ix_external_identities_organization_id"),
        "external_identities",
        ["organization_id"],
        unique=False,
    )
    op.alter_column(
        "file_policies",
        "native_metadata",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=False,
    )
    op.alter_column(
        "file_policies",
        "application_snapshot",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=True,
    )
    op.create_index(
        op.f("ix_file_policies_domain_id"), "file_policies", ["domain_id"], unique=False
    )
    op.create_index(
        op.f("ix_file_policies_manager_id"), "file_policies", ["manager_id"], unique=False
    )
    op.create_index(
        "ix_file_policies_org_manager",
        "file_policies",
        ["organization_id", "manager_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_file_policies_organization_id"), "file_policies", ["organization_id"], unique=False
    )
    op.alter_column(
        "intrusion_policies",
        "native_metadata",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=False,
    )
    op.alter_column(
        "intrusion_policies",
        "application_snapshot",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=True,
    )
    op.create_index(
        op.f("ix_intrusion_policies_domain_id"), "intrusion_policies", ["domain_id"], unique=False
    )
    op.create_index(
        op.f("ix_intrusion_policies_manager_id"), "intrusion_policies", ["manager_id"], unique=False
    )
    op.create_index(
        "ix_intrusion_policies_org_manager",
        "intrusion_policies",
        ["organization_id", "manager_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_intrusion_policies_organization_id"),
        "intrusion_policies",
        ["organization_id"],
        unique=False,
    )
    op.alter_column(
        "oidc_providers",
        "scopes",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=False,
        existing_server_default=sa.text("'[]'::json"),
    )
    op.create_unique_constraint(
        "uq_oidc_providers_org_id", "oidc_providers", ["organization_id", "id"]
    )
    op.alter_column(
        "variable_sets",
        "native_metadata",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=False,
    )
    op.alter_column(
        "variable_sets",
        "application_snapshot",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=True,
    )
    op.create_index(
        op.f("ix_variable_sets_domain_id"), "variable_sets", ["domain_id"], unique=False
    )
    op.create_index(
        op.f("ix_variable_sets_manager_id"), "variable_sets", ["manager_id"], unique=False
    )
    op.create_index(
        "ix_variable_sets_org_manager",
        "variable_sets",
        ["organization_id", "manager_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_variable_sets_organization_id"), "variable_sets", ["organization_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_variable_sets_organization_id"), table_name="variable_sets")
    op.drop_index("ix_variable_sets_org_manager", table_name="variable_sets")
    op.drop_index(op.f("ix_variable_sets_manager_id"), table_name="variable_sets")
    op.drop_index(op.f("ix_variable_sets_domain_id"), table_name="variable_sets")
    op.alter_column(
        "variable_sets",
        "application_snapshot",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=True,
    )
    op.alter_column(
        "variable_sets",
        "native_metadata",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=False,
    )
    op.drop_constraint("uq_oidc_providers_org_id", "oidc_providers", type_="unique")
    op.alter_column(
        "oidc_providers",
        "scopes",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=False,
        existing_server_default=sa.text("'[]'::json"),
    )
    op.drop_index(op.f("ix_intrusion_policies_organization_id"), table_name="intrusion_policies")
    op.drop_index("ix_intrusion_policies_org_manager", table_name="intrusion_policies")
    op.drop_index(op.f("ix_intrusion_policies_manager_id"), table_name="intrusion_policies")
    op.drop_index(op.f("ix_intrusion_policies_domain_id"), table_name="intrusion_policies")
    op.alter_column(
        "intrusion_policies",
        "application_snapshot",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=True,
    )
    op.alter_column(
        "intrusion_policies",
        "native_metadata",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=False,
    )
    op.drop_index(op.f("ix_file_policies_organization_id"), table_name="file_policies")
    op.drop_index("ix_file_policies_org_manager", table_name="file_policies")
    op.drop_index(op.f("ix_file_policies_manager_id"), table_name="file_policies")
    op.drop_index(op.f("ix_file_policies_domain_id"), table_name="file_policies")
    op.alter_column(
        "file_policies",
        "application_snapshot",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=True,
    )
    op.alter_column(
        "file_policies",
        "native_metadata",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=False,
    )
    op.drop_index(op.f("ix_external_identities_organization_id"), table_name="external_identities")
    op.alter_column(
        "deployments",
        "rollback_failure_info",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=False,
        existing_server_default=sa.text("'{}'::json"),
    )
    op.alter_column(
        "deployments",
        "rollback_device_results",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=False,
        existing_server_default=sa.text("'[]'::json"),
    )
    op.alter_column(
        "change_set_operations",
        "rollback_snapshot",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=False,
        existing_server_default=sa.text("'{}'::json"),
    )
    op.drop_index(op.f("ix_authentication_events_user_id"), table_name="authentication_events")
    op.drop_index(op.f("ix_api_tokens_organization_id"), table_name="api_tokens")
    op.drop_index(op.f("ix_access_rules_variable_set_id"), table_name="access_rules")
    op.drop_index(op.f("ix_access_rules_intrusion_policy_id"), table_name="access_rules")
    op.drop_index(op.f("ix_access_rules_file_policy_id"), table_name="access_rules")
