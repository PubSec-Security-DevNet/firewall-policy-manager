"""Add Milestone 1 core domain, provider, and synchronization persistence.

Revision ID: 20260919_0002
Revises: 20260919_0001
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260919_0002"
down_revision: str | None = "20260919_0001"
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


def synced_columns() -> tuple[sa.Column[object], ...]:
    return (
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("native_id", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("provider_version", sa.String(200)),
        sa.Column("provider_fingerprint", sa.String(200), nullable=False),
        sa.Column("native_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("management_state", sa.String(30), server_default="OBSERVED", nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("last_seen_sync_run_id", sa.Uuid()),
    )


def upgrade() -> None:
    op.drop_constraint(
        "firewall_managers_provider_native_id_key", "firewall_managers", type_="unique"
    )
    op.create_unique_constraint(
        "uq_firewall_managers_org_provider_native",
        "firewall_managers",
        ["organization_id", "provider", "native_id"],
    )
    op.add_column("firewall_managers", sa.Column("provider_version", sa.String(100)))
    op.add_column(
        "firewall_managers",
        sa.Column("capabilities", postgresql.JSONB(), server_default="{}", nullable=False),
    )
    op.add_column(
        "firewall_managers",
        sa.Column("native_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
    )
    op.add_column(
        "firewall_managers", sa.Column("revision", sa.Integer(), server_default="1", nullable=False)
    )
    op.create_check_constraint(
        "ck_firewall_managers_revision", "firewall_managers", "revision >= 1"
    )

    op.create_table(
        "sync_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("scope", sa.String(100), server_default="full", nullable=False),
        sa.Column("complete", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("resources_seen", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_code", sa.String(100)),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('RUNNING','COMPLETED','INCOMPLETE','FAILED')", name="ck_sync_runs_status"
        ),
    )
    op.create_index("ix_sync_runs_organization_id", "sync_runs", ["organization_id"])
    op.create_index("ix_sync_runs_manager_id", "sync_runs", ["manager_id"])
    op.create_index("ix_sync_runs_manager_started", "sync_runs", ["manager_id", "started_at"])

    op.create_table(
        "provider_domains",
        sa.Column("id", sa.Uuid(), primary_key=True),
        *synced_columns(),
        *timestamps(),
        sa.UniqueConstraint("manager_id", "native_id"),
        sa.CheckConstraint("revision >= 1", name="ck_provider_domains_revision"),
    )
    op.create_index("ix_provider_domains_organization_id", "provider_domains", ["organization_id"])
    op.create_index("ix_provider_domains_manager_id", "provider_domains", ["manager_id"])
    op.create_index(
        "ix_provider_domains_org_manager", "provider_domains", ["organization_id", "manager_id"]
    )
    op.create_foreign_key(
        "fk_provider_domains_last_sync",
        "provider_domains",
        "sync_runs",
        ["last_seen_sync_run_id"],
        ["id"],
    )
    op.execute(
        """
        INSERT INTO provider_domains
          (id, organization_id, manager_id, native_id, name, provider_fingerprint,
           native_metadata, management_state, revision, created_at, updated_at)
        SELECT md5(id::text)::uuid, organization_id, id, 'legacy-domain', 'Legacy imported scope',
               'legacy', '{}'::jsonb, 'OBSERVED', 1, now(), now()
        FROM firewall_managers
        """
    )

    op.create_table(
        "devices",
        sa.Column("id", sa.Uuid(), primary_key=True),
        *synced_columns(),
        sa.Column("domain_id", sa.Uuid(), sa.ForeignKey("provider_domains.id"), nullable=False),
        sa.Column("model", sa.String(200)),
        *timestamps(),
        sa.UniqueConstraint("manager_id", "native_id"),
        sa.CheckConstraint("revision >= 1", name="ck_devices_revision"),
    )
    for name in ("organization_id", "manager_id", "domain_id"):
        op.create_index(f"ix_devices_{name}", "devices", [name])
    op.create_index("ix_devices_org_domain", "devices", ["organization_id", "domain_id"])
    op.create_foreign_key(
        "fk_devices_last_sync", "devices", "sync_runs", ["last_seen_sync_run_id"], ["id"]
    )

    op.add_column("access_policies", sa.Column("organization_id", sa.Uuid()))
    op.add_column("access_policies", sa.Column("domain_id", sa.Uuid()))
    op.add_column("access_policies", sa.Column("provider_version", sa.String(200)))
    op.add_column("access_policies", sa.Column("provider_fingerprint", sa.String(200)))
    op.add_column(
        "access_policies",
        sa.Column("native_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
    )
    op.add_column(
        "access_policies",
        sa.Column("management_state", sa.String(30), server_default="OBSERVED", nullable=False),
    )
    op.add_column("access_policies", sa.Column("last_seen_sync_run_id", sa.Uuid()))
    op.execute(
        """
        UPDATE access_policies p SET
          organization_id = m.organization_id,
          domain_id = md5(m.id::text)::uuid,
          provider_fingerprint = 'legacy-' || p.id::text
        FROM firewall_managers m WHERE p.manager_id = m.id
        """
    )
    op.alter_column("access_policies", "organization_id", nullable=False)
    op.alter_column("access_policies", "domain_id", nullable=False)
    op.alter_column("access_policies", "provider_fingerprint", nullable=False)
    op.alter_column("access_policies", "team_id", nullable=True)
    op.create_foreign_key(
        "fk_access_policies_org", "access_policies", "organizations", ["organization_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_access_policies_domain", "access_policies", "provider_domains", ["domain_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_access_policies_last_sync",
        "access_policies",
        "sync_runs",
        ["last_seen_sync_run_id"],
        ["id"],
    )
    op.create_index("ix_access_policies_organization_id", "access_policies", ["organization_id"])
    op.create_index("ix_access_policies_domain_id", "access_policies", ["domain_id"])
    op.create_index(
        "ix_access_policies_org_manager", "access_policies", ["organization_id", "manager_id"]
    )
    op.create_check_constraint("ck_access_policies_revision", "access_policies", "revision >= 1")

    op.rename_table("policy_categories", "rule_categories")
    op.add_column("rule_categories", sa.Column("organization_id", sa.Uuid()))
    op.add_column("rule_categories", sa.Column("manager_id", sa.Uuid()))
    op.add_column("rule_categories", sa.Column("native_id", sa.String(200)))
    op.add_column("rule_categories", sa.Column("provider_version", sa.String(200)))
    op.add_column("rule_categories", sa.Column("provider_fingerprint", sa.String(200)))
    op.add_column(
        "rule_categories",
        sa.Column("native_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
    )
    op.add_column(
        "rule_categories",
        sa.Column("management_state", sa.String(30), server_default="OBSERVED", nullable=False),
    )
    op.add_column(
        "rule_categories", sa.Column("revision", sa.Integer(), server_default="1", nullable=False)
    )
    op.add_column("rule_categories", sa.Column("last_seen_sync_run_id", sa.Uuid()))
    op.execute(
        """
        UPDATE rule_categories c SET
          organization_id = p.organization_id, manager_id = p.manager_id,
          native_id = 'legacy-' || c.id::text, provider_fingerprint = 'legacy-' || c.id::text
        FROM access_policies p WHERE c.policy_id = p.id
        """
    )
    for column in ("organization_id", "manager_id", "native_id", "provider_fingerprint"):
        op.alter_column("rule_categories", column, nullable=False)
    op.alter_column("rule_categories", "team_id", nullable=True)
    op.drop_constraint("policy_categories_policy_id_name_key", "rule_categories", type_="unique")
    op.create_unique_constraint(
        "uq_rule_categories_policy_native", "rule_categories", ["policy_id", "native_id"]
    )
    op.create_foreign_key(
        "fk_rule_categories_org", "rule_categories", "organizations", ["organization_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_rule_categories_manager", "rule_categories", "firewall_managers", ["manager_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_rule_categories_last_sync",
        "rule_categories",
        "sync_runs",
        ["last_seen_sync_run_id"],
        ["id"],
    )
    op.create_index("ix_rule_categories_organization_id", "rule_categories", ["organization_id"])
    op.create_index("ix_rule_categories_manager_id", "rule_categories", ["manager_id"])
    op.create_index(
        "ix_rule_categories_org_policy", "rule_categories", ["organization_id", "policy_id"]
    )
    op.create_check_constraint("ck_rule_categories_revision", "rule_categories", "revision >= 1")
    op.execute("ALTER INDEX ix_policy_categories_policy_id RENAME TO ix_rule_categories_policy_id")
    op.execute("ALTER INDEX ix_policy_categories_team_id RENAME TO ix_rule_categories_team_id")

    op.add_column("access_rules", sa.Column("organization_id", sa.Uuid()))
    op.add_column("access_rules", sa.Column("manager_id", sa.Uuid()))
    op.add_column("access_rules", sa.Column("provider_version", sa.String(200)))
    op.add_column("access_rules", sa.Column("provider_fingerprint", sa.String(200)))
    op.add_column(
        "access_rules",
        sa.Column("native_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
    )
    op.add_column(
        "access_rules",
        sa.Column("management_state", sa.String(30), server_default="OBSERVED", nullable=False),
    )
    op.add_column("access_rules", sa.Column("last_seen_sync_run_id", sa.Uuid()))
    op.execute(
        """
        UPDATE access_rules r SET organization_id = p.organization_id, manager_id = p.manager_id,
          provider_fingerprint = 'legacy-' || r.id::text
        FROM access_policies p WHERE r.policy_id = p.id
        """
    )
    for column in ("organization_id", "manager_id", "provider_fingerprint"):
        op.alter_column("access_rules", column, nullable=False)
    op.alter_column("access_rules", "category_id", nullable=True)
    op.alter_column("access_rules", "owner_team_id", nullable=True)
    op.create_foreign_key(
        "fk_access_rules_org", "access_rules", "organizations", ["organization_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_access_rules_manager", "access_rules", "firewall_managers", ["manager_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_access_rules_last_sync", "access_rules", "sync_runs", ["last_seen_sync_run_id"], ["id"]
    )
    op.create_index("ix_access_rules_organization_id", "access_rules", ["organization_id"])
    op.create_index("ix_access_rules_manager_id", "access_rules", ["manager_id"])
    op.create_index("ix_access_rules_org_policy", "access_rules", ["organization_id", "policy_id"])
    op.create_check_constraint("ck_access_rules_revision", "access_rules", "revision >= 1")

    op.rename_table("network_objects", "firewall_objects")
    op.add_column("firewall_objects", sa.Column("organization_id", sa.Uuid()))
    op.add_column("firewall_objects", sa.Column("domain_id", sa.Uuid()))
    op.add_column(
        "firewall_objects",
        sa.Column("object_type", sa.String(50), server_default="network", nullable=False),
    )
    op.add_column("firewall_objects", sa.Column("provider_version", sa.String(200)))
    op.add_column("firewall_objects", sa.Column("provider_fingerprint", sa.String(200)))
    op.add_column(
        "firewall_objects",
        sa.Column("native_metadata", postgresql.JSONB(), server_default="{}", nullable=False),
    )
    op.add_column(
        "firewall_objects",
        sa.Column("management_state", sa.String(30), server_default="OBSERVED", nullable=False),
    )
    op.add_column(
        "firewall_objects", sa.Column("revision", sa.Integer(), server_default="1", nullable=False)
    )
    op.add_column("firewall_objects", sa.Column("last_seen_sync_run_id", sa.Uuid()))
    op.execute(
        """
        UPDATE firewall_objects o SET organization_id = m.organization_id,
          domain_id = md5(m.id::text)::uuid, provider_fingerprint = 'legacy-' || o.id::text
        FROM firewall_managers m WHERE o.manager_id = m.id
        """
    )
    for column in ("organization_id", "domain_id", "provider_fingerprint"):
        op.alter_column("firewall_objects", column, nullable=False)
    op.alter_column("firewall_objects", "owner_team_id", nullable=True)
    op.alter_column("firewall_objects", "value", nullable=True)
    op.create_foreign_key(
        "fk_firewall_objects_org", "firewall_objects", "organizations", ["organization_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_firewall_objects_domain", "firewall_objects", "provider_domains", ["domain_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_firewall_objects_last_sync",
        "firewall_objects",
        "sync_runs",
        ["last_seen_sync_run_id"],
        ["id"],
    )
    op.create_index("ix_firewall_objects_organization_id", "firewall_objects", ["organization_id"])
    op.create_index("ix_firewall_objects_domain_id", "firewall_objects", ["domain_id"])
    op.create_index(
        "ix_firewall_objects_org_manager", "firewall_objects", ["organization_id", "manager_id"]
    )
    op.create_check_constraint("ck_firewall_objects_revision", "firewall_objects", "revision >= 1")
    op.execute("ALTER INDEX ix_network_objects_manager_id RENAME TO ix_firewall_objects_manager_id")
    op.execute(
        "ALTER INDEX ix_network_objects_owner_team_id RENAME TO ix_firewall_objects_owner_team_id"
    )

    op.create_table(
        "object_references",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("source_rule_id", sa.Uuid(), sa.ForeignKey("access_rules.id")),
        sa.Column("source_object_id", sa.Uuid(), sa.ForeignKey("firewall_objects.id")),
        sa.Column(
            "target_object_id", sa.Uuid(), sa.ForeignKey("firewall_objects.id"), nullable=False
        ),
        *timestamps(),
        sa.CheckConstraint(
            "(source_rule_id IS NOT NULL) <> (source_object_id IS NOT NULL)",
            name="ck_object_references_one_source",
        ),
        sa.CheckConstraint(
            "source_object_id IS NULL OR source_object_id <> target_object_id",
            name="ck_object_references_not_self",
        ),
        sa.UniqueConstraint("source_rule_id", "target_object_id"),
        sa.UniqueConstraint("source_object_id", "target_object_id"),
    )
    for name in ("organization_id", "manager_id"):
        op.create_index(f"ix_object_references_{name}", "object_references", [name])
    op.create_index(
        "ix_object_references_org_target",
        "object_references",
        ["organization_id", "target_object_id"],
    )

    op.create_table(
        "resource_ownerships",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("owner_team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        sa.UniqueConstraint("organization_id", "resource_type", "resource_id"),
    )
    op.create_index(
        "ix_resource_ownerships_organization_id", "resource_ownerships", ["organization_id"]
    )
    op.create_index(
        "ix_resource_ownerships_owner_team_id", "resource_ownerships", ["owner_team_id"]
    )
    op.create_index(
        "ix_resource_ownerships_team", "resource_ownerships", ["organization_id", "owner_team_id"]
    )

    op.create_table(
        "resource_grants",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column(
            "ownership_id", sa.Uuid(), sa.ForeignKey("resource_ownerships.id"), nullable=False
        ),
        sa.Column("grantee_team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("action", sa.String(30), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        sa.UniqueConstraint("ownership_id", "grantee_team_id", "action"),
    )
    for name in ("organization_id", "ownership_id", "grantee_team_id"):
        op.create_index(f"ix_resource_grants_{name}", "resource_grants", [name])
    op.create_index(
        "ix_resource_grants_org_team", "resource_grants", ["organization_id", "grantee_team_id"]
    )
    op.create_check_constraint("ck_change_sets_revision", "change_sets", "revision >= 1")
    op.create_index("ix_change_sets_org_state", "change_sets", ["organization_id", "state"])

    op.create_table(
        "provider_transactions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("change_set_id", sa.Uuid(), sa.ForeignKey("change_sets.id"), nullable=False),
        sa.Column("manager_id", sa.Uuid(), sa.ForeignKey("firewall_managers.id"), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("expected_provider_fingerprint", sa.String(200)),
        sa.Column("external_operation_id", sa.String(200)),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
        sa.UniqueConstraint("change_set_id", "manager_id"),
    )
    for name in ("organization_id", "change_set_id", "manager_id"):
        op.create_index(f"ix_provider_transactions_{name}", "provider_transactions", [name])
    op.create_index(
        "ix_provider_transactions_org_state", "provider_transactions", ["organization_id", "state"]
    )

    op.create_table(
        "deployments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column(
            "provider_transaction_id",
            sa.Uuid(),
            sa.ForeignKey("provider_transactions.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("external_operation_id", sa.String(200)),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        *timestamps(),
    )
    op.create_index("ix_deployments_organization_id", "deployments", ["organization_id"])
    op.create_index(
        "ix_deployments_provider_transaction_id", "deployments", ["provider_transaction_id"]
    )

    op.add_column("drift_records", sa.Column("organization_id", sa.Uuid()))
    op.add_column("drift_records", sa.Column("sync_run_id", sa.Uuid()))
    op.add_column("drift_records", sa.Column("previous_fingerprint", sa.String(200)))
    op.add_column("drift_records", sa.Column("observed_fingerprint", sa.String(200)))
    op.execute(
        "UPDATE drift_records d SET organization_id = m.organization_id FROM firewall_managers m WHERE d.manager_id = m.id"
    )
    op.alter_column("drift_records", "organization_id", nullable=False)
    op.create_foreign_key(
        "fk_drift_records_org", "drift_records", "organizations", ["organization_id"], ["id"]
    )
    op.create_foreign_key(
        "fk_drift_records_sync", "drift_records", "sync_runs", ["sync_run_id"], ["id"]
    )
    op.create_index("ix_drift_records_organization_id", "drift_records", ["organization_id"])
    op.create_index("ix_drift_records_sync_run_id", "drift_records", ["sync_run_id"])
    op.create_index("ix_drift_records_org_status", "drift_records", ["organization_id", "status"])
    op.create_index(
        "ix_drift_records_manager_resource",
        "drift_records",
        ["manager_id", "resource_type", "resource_id"],
    )


def downgrade() -> None:
    # Milestone 1 data has no lossless representation in the Milestone 0 schema.
    raise RuntimeError("Milestone 1 downgrade requires an explicit data migration plan")
