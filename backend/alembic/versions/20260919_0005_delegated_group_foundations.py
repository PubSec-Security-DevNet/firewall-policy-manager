"""Add delegated Group context and normalized zone/reference foundations.

Revision ID: 20260919_0005
Revises: 20260919_0004
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260919_0005"
down_revision: str | None = "20260919_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RESOURCE_STATES = (
    "management_state IN "
    "('OBSERVED','UNMANAGED','PENDING_ADOPTION','MANAGED','DRIFTED','MISSING','CONFLICT')"
)


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
    # Team was an overloaded single-membership concept. Preserve IDs while naming the product
    # boundary explicitly and introducing a many-to-many membership relation.
    op.rename_table("teams", "application_groups")
    op.execute(
        "ALTER INDEX ix_teams_organization_id RENAME TO ix_application_groups_organization_id"
    )
    op.add_column("application_groups", sa.Column("provider_slug", sa.String(64)))
    op.execute(
        """
        UPDATE application_groups
        SET provider_slug = 'G-' ||
          left(upper(trim(both '-' from regexp_replace(name, '[^A-Za-z0-9]+', '-', 'g'))), 45)
          || '-' || left(replace(id::text, '-', ''), 8)
        """
    )
    op.alter_column("application_groups", "provider_slug", nullable=False)
    op.create_unique_constraint(
        "uq_application_groups_org_slug",
        "application_groups",
        ["organization_id", "provider_slug"],
    )
    op.create_unique_constraint(
        "uq_application_groups_org_id", "application_groups", ["organization_id", "id"]
    )
    op.create_check_constraint(
        "ck_application_groups_provider_slug",
        "application_groups",
        "provider_slug ~ '^[A-Z][A-Z0-9-]*$'",
    )
    op.create_unique_constraint("uq_users_org_id", "users", ["organization_id", "id"])

    op.create_table(
        "group_memberships",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        *timestamps(),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"], ["users.organization_id", "users.id"]
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "group_id"],
            ["application_groups.organization_id", "application_groups.id"],
        ),
        sa.UniqueConstraint("user_id", "group_id"),
    )
    op.execute(
        """
        INSERT INTO group_memberships
          (id, organization_id, user_id, group_id, created_at, updated_at)
        SELECT md5(id::text || team_id::text)::uuid, organization_id, id, team_id, now(), now()
        FROM users
        """
    )
    for name in ("organization_id", "user_id", "group_id"):
        op.create_index(f"ix_group_memberships_{name}", "group_memberships", [name])
    op.create_index(
        "ix_group_memberships_org_group",
        "group_memberships",
        ["organization_id", "group_id"],
    )
    op.create_index(
        "ix_group_memberships_org_user",
        "group_memberships",
        ["organization_id", "user_id"],
    )
    op.drop_index("ix_users_team_id", table_name="users")
    op.drop_constraint("users_team_id_fkey", "users", type_="foreignkey")
    op.drop_column("users", "team_id")

    for table, constraint, index in (
        ("access_policies", "access_policies_team_id_fkey", "ix_access_policies_team_id"),
        ("rule_categories", "policy_categories_team_id_fkey", "ix_rule_categories_team_id"),
    ):
        op.drop_index(index, table_name=table)
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.drop_column(table, "team_id")

    for table, old_column, new_column, old_index, new_index in (
        (
            "access_rules",
            "owner_team_id",
            "owner_group_id",
            "ix_access_rules_owner_team_id",
            "ix_access_rules_owner_group_id",
        ),
        (
            "firewall_objects",
            "owner_team_id",
            "owner_group_id",
            "ix_firewall_objects_owner_team_id",
            "ix_firewall_objects_owner_group_id",
        ),
        (
            "resource_ownerships",
            "owner_team_id",
            "owner_group_id",
            "ix_resource_ownerships_owner_team_id",
            "ix_resource_ownerships_owner_group_id",
        ),
        (
            "resource_grants",
            "grantee_team_id",
            "grantee_group_id",
            "ix_resource_grants_grantee_team_id",
            "ix_resource_grants_grantee_group_id",
        ),
    ):
        op.alter_column(table, old_column, new_column_name=new_column)
        op.execute(f"ALTER INDEX {old_index} RENAME TO {new_index}")
    op.execute("ALTER INDEX ix_resource_ownerships_team RENAME TO ix_resource_ownerships_group")
    op.execute("ALTER INDEX ix_resource_grants_org_team RENAME TO ix_resource_grants_org_group")

    for column in ("created_by_user_id", "modified_by_user_id"):
        op.add_column("access_rules", sa.Column(column, sa.Uuid()))
        op.create_foreign_key(
            f"fk_access_rules_{column}", "access_rules", "users", [column], ["id"]
        )
        op.create_index(f"ix_access_rules_{column}", "access_rules", [column])
        op.add_column("firewall_objects", sa.Column(column, sa.Uuid()))
        op.create_foreign_key(
            f"fk_firewall_objects_{column}", "firewall_objects", "users", [column], ["id"]
        )
        op.create_index(f"ix_firewall_objects_{column}", "firewall_objects", [column])

    op.alter_column("firewall_objects", "value", new_column_name="normalized_value")
    op.execute(
        """
        UPDATE firewall_objects SET object_type = CASE object_type
          WHEN 'network' THEN 'NETWORK'
          WHEN 'network_group' THEN 'NETWORK_GROUP'
          ELSE upper(object_type)
        END
        """
    )
    op.create_check_constraint(
        "ck_firewall_objects_type",
        "firewall_objects",
        "object_type IN ('NETWORK','NETWORK_GROUP','PORT_SERVICE','URL',"
        "'APPLICATION','APPLICATION_FILTER')",
    )
    op.create_index(
        "ix_firewall_objects_equivalence",
        "firewall_objects",
        ["manager_id", "object_type", "normalized_value"],
    )

    op.add_column(
        "object_references",
        sa.Column("element_type", sa.String(40), server_default="UNSPECIFIED", nullable=False),
    )
    op.execute(
        "UPDATE object_references SET element_type = 'MEMBER' WHERE source_object_id IS NOT NULL"
    )
    op.drop_constraint(
        "object_references_source_rule_id_target_object_id_key",
        "object_references",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_object_references_rule_target_element",
        "object_references",
        ["source_rule_id", "target_object_id", "element_type"],
    )
    op.create_check_constraint(
        "ck_object_references_element_type",
        "object_references",
        "element_type IN ('UNSPECIFIED','SOURCE_NETWORK','DESTINATION_NETWORK',"
        "'PORT_SERVICE','APPLICATION','URL','MEMBER')",
    )

    op.alter_column("change_sets", "owner_user_id", new_column_name="principal_id")
    op.execute("ALTER INDEX ix_change_sets_owner_user_id RENAME TO ix_change_sets_principal_id")
    op.add_column("change_sets", sa.Column("acting_group_id", sa.Uuid()))
    op.add_column("change_sets", sa.Column("access_policy_id", sa.Uuid()))
    op.create_foreign_key(
        "fk_change_sets_acting_group",
        "change_sets",
        "application_groups",
        ["acting_group_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_change_sets_access_policy",
        "change_sets",
        "access_policies",
        ["access_policy_id"],
        ["id"],
    )
    op.create_index("ix_change_sets_acting_group_id", "change_sets", ["acting_group_id"])
    op.create_index("ix_change_sets_access_policy_id", "change_sets", ["access_policy_id"])
    op.create_index(
        "ix_change_sets_group_policy",
        "change_sets",
        ["organization_id", "acting_group_id", "access_policy_id"],
    )

    op.create_table(
        "security_zones",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("native_id", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("provider_version", sa.String(200)),
        sa.Column("provider_fingerprint", sa.String(200), nullable=False),
        sa.Column("native_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("management_state", sa.String(30), server_default="OBSERVED", nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("last_seen_sync_run_id", sa.Uuid(), sa.ForeignKey("sync_runs.id")),
        sa.Column("domain_id", sa.Uuid(), sa.ForeignKey("provider_domains.id"), nullable=False),
        sa.Column("zone_type", sa.String(30), server_default="SECURITY", nullable=False),
        *timestamps(),
        sa.UniqueConstraint("manager_id", "native_id"),
        sa.CheckConstraint(RESOURCE_STATES, name="ck_security_zones_management_state"),
        sa.CheckConstraint("revision >= 1", name="ck_security_zones_revision"),
    )
    for name in ("organization_id", "manager_id", "domain_id"):
        op.create_index(f"ix_security_zones_{name}", "security_zones", [name])
    op.create_index(
        "ix_security_zones_org_manager", "security_zones", ["organization_id", "manager_id"]
    )

    op.create_table(
        "rule_zone_references",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("rule_id", sa.Uuid(), sa.ForeignKey("access_rules.id"), nullable=False),
        sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("security_zones.id"), nullable=False),
        sa.Column("element_type", sa.String(20), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("rule_id", "zone_id", "element_type"),
        sa.CheckConstraint(
            "element_type IN ('SOURCE','DESTINATION')",
            name="ck_rule_zone_references_element_type",
        ),
    )
    for name in ("organization_id", "manager_id", "rule_id", "zone_id"):
        op.create_index(f"ix_rule_zone_references_{name}", "rule_zone_references", [name])
    op.create_index(
        "ix_rule_zone_references_org_zone",
        "rule_zone_references",
        ["organization_id", "zone_id"],
    )

    op.create_table(
        "group_policy_category_mappings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("group_id", sa.Uuid(), sa.ForeignKey("application_groups.id"), nullable=False),
        sa.Column("policy_id", sa.Uuid(), sa.ForeignKey("access_policies.id"), nullable=False),
        sa.Column("category_id", sa.Uuid(), sa.ForeignKey("rule_categories.id"), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        sa.UniqueConstraint("group_id", "policy_id"),
        sa.UniqueConstraint("category_id"),
        sa.CheckConstraint("revision >= 1", name="ck_group_policy_category_mappings_revision"),
    )
    for name in ("organization_id", "group_id", "policy_id", "category_id"):
        op.create_index(
            f"ix_group_policy_category_mappings_{name}",
            "group_policy_category_mappings",
            [name],
        )
    op.create_index(
        "ix_group_policy_category_mappings_org_policy",
        "group_policy_category_mappings",
        ["organization_id", "policy_id"],
    )


def downgrade() -> None:
    # Multiple memberships and explicit acting-Group context cannot be represented safely in the
    # old single-team schema. Never choose a membership implicitly during downgrade.
    raise RuntimeError("Delegated Group foundations require an explicit data migration plan")
