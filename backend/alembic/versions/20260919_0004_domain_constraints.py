"""Constrain provider, management state, and mutable revisions.

Revision ID: 20260919_0004
Revises: 20260919_0003
Create Date: 2026-09-19
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260919_0004"
down_revision: str | None = "20260919_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RESOURCE_STATES = (
    "management_state IN "
    "('OBSERVED','UNMANAGED','PENDING_ADOPTION','MANAGED','DRIFTED','MISSING','CONFLICT')"
)


def upgrade() -> None:
    op.create_check_constraint(
        "ck_firewall_managers_provider", "firewall_managers", "provider IN ('fmc','scc')"
    )
    for table in (
        "provider_domains",
        "devices",
        "access_policies",
        "rule_categories",
        "access_rules",
        "firewall_objects",
    ):
        op.create_check_constraint(f"ck_{table}_management_state", table, RESOURCE_STATES)
    for table in (
        "resource_ownerships",
        "resource_grants",
        "provider_transactions",
        "deployments",
    ):
        op.create_check_constraint(f"ck_{table}_revision", table, "revision >= 1")


def downgrade() -> None:
    for table in (
        "deployments",
        "provider_transactions",
        "resource_grants",
        "resource_ownerships",
    ):
        op.drop_constraint(f"ck_{table}_revision", table, type_="check")
    for table in (
        "firewall_objects",
        "access_rules",
        "rule_categories",
        "access_policies",
        "devices",
        "provider_domains",
    ):
        op.drop_constraint(f"ck_{table}_management_state", table, type_="check")
    op.drop_constraint("ck_firewall_managers_provider", "firewall_managers", type_="check")
