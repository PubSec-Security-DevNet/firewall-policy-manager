"""SQLAlchemy 2 models for normalized application and provider state."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    """Alembic metadata root."""


class TimestampMixin:
    """Timezone-aware creation/update timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), unique=True)


class Group(TimestampMixin, Base):
    __tablename__ = "application_groups"
    __table_args__ = (
        UniqueConstraint("organization_id", "name"),
        UniqueConstraint("organization_id", "provider_slug"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(
            "provider_slug ~ '^[A-Z][A-Z0-9-]*$'", name="ck_application_groups_provider_slug"
        ),
        CheckConstraint("revision >= 1", name="ck_application_groups_revision"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    provider_slug: Mapped[str] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class User(TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        UniqueConstraint("identity_issuer", "identity_subject"),
        UniqueConstraint("organization_id", "email"),
        CheckConstraint("revision >= 1", name="ck_users_revision"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    identity_issuer: Mapped[str] = mapped_column(String(500))
    identity_subject: Mapped[str] = mapped_column(String(500))
    email: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(50))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    default_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("application_groups.id"), nullable=True
    )
    default_policy_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("access_policies.id"), nullable=True
    )
    revision: Mapped[int] = mapped_column(Integer, default=1)


class EmailNotification(TimestampMixin, Base):
    """Durable outbound email work item; message delivery is independent of approval state."""

    __tablename__ = "email_notifications"
    __table_args__ = (
        UniqueConstraint("organization_id", "recipient_user_id", "dedupe_key"),
        Index("ix_email_notifications_due", "status", "next_attempt_at"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    recipient_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), index=True)
    recipient_email: Mapped[str] = mapped_column(String(320))
    kind: Mapped[str] = mapped_column(String(50))
    dedupe_key: Mapped[str] = mapped_column(String(300))
    subject: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_error: Mapped[str | None] = mapped_column(String(500))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecretRecord(TimestampMixin, Base):
    """Authenticated ciphertext; the root key is deliberately external to PostgreSQL."""

    __tablename__ = "secret_records"
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        CheckConstraint("key_version >= 1", name="ck_secret_records_key_version"),
        Index("ix_secret_records_org_purpose", "organization_id", "purpose"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    purpose: Mapped[str] = mapped_column(String(100))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(Integer)
    rotated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ProviderConnection(TimestampMixin, Base):
    """Administrative connection and health state; never contains plaintext credentials."""

    __tablename__ = "provider_connections"
    __table_args__ = (
        UniqueConstraint("organization_id", "display_name"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint("provider_type IN ('fmc','scc')", name="ck_provider_connections_type"),
        CheckConstraint(
            "lifecycle IN ('ACTIVE','DISABLED','RETIRED')",
            name="ck_provider_connections_lifecycle",
        ),
        CheckConstraint("evidence_profile = 'real'", name="ck_provider_connections_real_evidence"),
        CheckConstraint(
            "tls_mode IN ('SYSTEM','CUSTOM_CA')", name="ck_provider_connections_tls_mode"
        ),
        CheckConstraint("revision >= 1", name="ck_provider_connections_revision"),
        CheckConstraint(
            "sync_interval_minutes >= 5 AND sync_interval_minutes <= 10080",
            name="ck_provider_connections_sync_interval",
        ),
        CheckConstraint(
            "applications_sync_interval_minutes >= 60 "
            "AND applications_sync_interval_minutes <= 43200",
            name="ck_provider_connections_applications_sync_interval",
        ),
        Index("ix_provider_connections_org_lifecycle", "organization_id", "lifecycle"),
        Index("ix_provider_connections_sync_due", "lifecycle", "next_sync_at"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    provider_type: Mapped[str] = mapped_column(String(20))
    display_name: Mapped[str] = mapped_column(String(200))
    lifecycle: Mapped[str] = mapped_column(String(20), default="DISABLED")
    connection_mode: Mapped[str] = mapped_column(String(30))
    evidence_profile: Mapped[str] = mapped_column(String(20), default="real")
    base_endpoint: Mapped[str | None] = mapped_column(String(500))
    region: Mapped[str | None] = mapped_column(String(30))
    tls_mode: Mapped[str] = mapped_column(String(20), default="SYSTEM")
    credential_reference: Mapped[UUID] = mapped_column(
        ForeignKey("secret_records.id", ondelete="RESTRICT"), unique=True, index=True
    )
    credential_type: Mapped[str] = mapped_column(String(30))
    credential_username: Mapped[str | None] = mapped_column(String(320))
    credential_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    provider_version: Mapped[str | None] = mapped_column(String(100))
    connection_status: Mapped[str] = mapped_column(String(50), default="NEVER_TESTED")
    sync_status: Mapped[str | None] = mapped_column(String(30))
    last_connection_test: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_successful_connection: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_successful_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(100))
    last_error_message: Mapped[str | None] = mapped_column(String(500))
    last_error_correlation_id: Mapped[str | None] = mapped_column(String(100))
    certificate_info: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    next_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applications_sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    applications_sync_status: Mapped[str | None] = mapped_column(String(30))
    applications_last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applications_last_successful_sync: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    applications_next_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deployment_schedule_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    deployment_status: Mapped[str | None] = mapped_column(String(30))
    deployment_next_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deployment_last_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deployment_last_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    write_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    write_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    write_enabled_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class GroupMembership(TimestampMixin, Base):
    __tablename__ = "group_memberships"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "user_id"], ["users.organization_id", "users.id"]),
        ForeignKeyConstraint(
            ["organization_id", "group_id"],
            ["application_groups.organization_id", "application_groups.id"],
        ),
        UniqueConstraint("user_id", "group_id"),
        Index("ix_group_memberships_org_group", "organization_id", "group_id"),
        Index("ix_group_memberships_org_user", "organization_id", "user_id"),
        CheckConstraint("status IN ('ACTIVE','SUSPENDED')", name="ck_group_memberships_status"),
        CheckConstraint("revision >= 1", name="ck_group_memberships_revision"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[UUID] = mapped_column(index=True)
    group_id: Mapped[UUID] = mapped_column(index=True)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    revision: Mapped[int] = mapped_column(Integer, default=1)


class FirewallManager(TimestampMixin, Base):
    __tablename__ = "firewall_managers"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", "native_id"),
        CheckConstraint("provider IN ('fmc','scc')", name="ck_firewall_managers_provider"),
        CheckConstraint("revision >= 1", name="ck_firewall_managers_revision"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    provider_connection_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("provider_connections.id", ondelete="RESTRICT"), unique=True, index=True
    )
    provider: Mapped[str] = mapped_column(String(20))
    native_id: Mapped[str] = mapped_column(String(200))
    display_name: Mapped[str] = mapped_column(String(200))
    base_url: Mapped[str] = mapped_column(String(500))
    read_only: Mapped[bool] = mapped_column(Boolean, default=True)
    # This is an application safety boundary, not provider-supplied metadata. Only explicitly
    # seeded/local managers may execute Milestone 3 transactions.
    is_mock: Mapped[bool] = mapped_column(Boolean, default=False)
    provider_version: Mapped[str | None] = mapped_column(String(100))
    capabilities: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    native_metadata: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class ProviderConnectionScope(TimestampMixin, Base):
    """Domain, tenant, or organization discovered through one configured credential."""

    __tablename__ = "provider_connection_scopes"
    __table_args__ = (
        UniqueConstraint("connection_id", "native_id"),
        Index("ix_provider_connection_scopes_org_connection", "organization_id", "connection_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    connection_id: Mapped[UUID] = mapped_column(
        ForeignKey("provider_connections.id", ondelete="RESTRICT"), index=True
    )
    native_id: Mapped[str] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(200))
    scope_type: Mapped[str] = mapped_column(String(30))
    native_metadata: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ProviderCapabilityEvidence(TimestampMixin, Base):
    """Version-specific compatibility evidence isolated to one real connection."""

    __tablename__ = "provider_capability_evidence"
    __table_args__ = (
        UniqueConstraint("connection_id", "provider_version", "capability"),
        CheckConstraint(
            "evidence_level IN ('TESTED','EXPECTED_COMPATIBLE','NOT_STARTED')",
            name="ck_provider_capability_evidence_level",
        ),
        Index(
            "ix_provider_capability_evidence_connection_version",
            "connection_id",
            "provider_version",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    connection_id: Mapped[UUID] = mapped_column(
        ForeignKey("provider_connections.id", ondelete="RESTRICT"), index=True
    )
    provider_version: Mapped[str] = mapped_column(String(100))
    capability: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(30))
    evidence_level: Mapped[str] = mapped_column(String(30), default="NOT_STARTED")
    evidence_summary: Mapped[str] = mapped_column(String(500), default="")
    tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SyncRun(Base):
    __tablename__ = "sync_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('RUNNING','COMPLETED','INCOMPLETE','FAILED')",
            name="ck_sync_runs_status",
        ),
        Index("ix_sync_runs_manager_started", "manager_id", "started_at"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    manager_id: Mapped[UUID] = mapped_column(ForeignKey("firewall_managers.id"), index=True)
    status: Mapped[str] = mapped_column(String(20))
    scope: Mapped[str] = mapped_column(String(100), default="full")
    complete: Mapped[bool] = mapped_column(Boolean, default=False)
    resources_seen: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(100))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SyncedResourceMixin(TimestampMixin):
    """Provider identity and synchronization attributes shared by discovered resources."""

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    manager_id: Mapped[UUID] = mapped_column(ForeignKey("firewall_managers.id"), index=True)
    native_id: Mapped[str] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(200))
    provider_version: Mapped[str | None] = mapped_column(String(200))
    provider_fingerprint: Mapped[str] = mapped_column(String(200))
    native_metadata: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    # Desired application-managed state is retained separately from the latest provider snapshot.
    # Provider observations must never overwrite it during drift detection.
    application_snapshot: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    management_state: Mapped[str] = mapped_column(String(30), default="OBSERVED")
    revision: Mapped[int] = mapped_column(Integer, default=1)
    last_seen_sync_run_id: Mapped[UUID | None] = mapped_column(ForeignKey("sync_runs.id"))


class ProviderDomain(SyncedResourceMixin, Base):
    __tablename__ = "provider_domains"
    __table_args__ = (
        UniqueConstraint("manager_id", "native_id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_provider_domains_management_state",
        ),
        CheckConstraint("revision >= 1", name="ck_provider_domains_revision"),
        Index("ix_provider_domains_org_manager", "organization_id", "manager_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)


class Device(SyncedResourceMixin, Base):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("manager_id", "native_id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_devices_management_state",
        ),
        CheckConstraint("revision >= 1", name="ck_devices_revision"),
        Index("ix_devices_org_domain", "organization_id", "domain_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    domain_id: Mapped[UUID] = mapped_column(ForeignKey("provider_domains.id"), index=True)
    model: Mapped[str | None] = mapped_column(String(200))


class AccessPolicy(SyncedResourceMixin, Base):
    __tablename__ = "access_policies"
    __table_args__ = (
        UniqueConstraint("manager_id", "native_id"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_access_policies_management_state",
        ),
        CheckConstraint("revision >= 1", name="ck_access_policies_revision"),
        Index("ix_access_policies_org_manager", "organization_id", "manager_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    domain_id: Mapped[UUID] = mapped_column(ForeignKey("provider_domains.id"), index=True)


class IntrusionPolicy(SyncedResourceMixin, Base):
    __tablename__ = "intrusion_policies"
    __table_args__ = (
        UniqueConstraint("manager_id", "native_id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_intrusion_policies_management_state",
        ),
        Index("ix_intrusion_policies_org_manager", "organization_id", "manager_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    domain_id: Mapped[UUID] = mapped_column(ForeignKey("provider_domains.id"), index=True)
    default_variable_set_native_id: Mapped[str | None] = mapped_column(String(200))


class VariableSet(SyncedResourceMixin, Base):
    __tablename__ = "variable_sets"
    __table_args__ = (
        UniqueConstraint("manager_id", "native_id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_variable_sets_management_state",
        ),
        Index("ix_variable_sets_org_manager", "organization_id", "manager_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    domain_id: Mapped[UUID] = mapped_column(ForeignKey("provider_domains.id"), index=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)


class FilePolicy(SyncedResourceMixin, Base):
    __tablename__ = "file_policies"
    __table_args__ = (
        UniqueConstraint("manager_id", "native_id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_file_policies_management_state",
        ),
        Index("ix_file_policies_org_manager", "organization_id", "manager_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    domain_id: Mapped[UUID] = mapped_column(ForeignKey("provider_domains.id"), index=True)


class RuleCategory(SyncedResourceMixin, Base):
    __tablename__ = "rule_categories"
    __table_args__ = (
        UniqueConstraint("policy_id", "native_id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_rule_categories_management_state",
        ),
        CheckConstraint("revision >= 1", name="ck_rule_categories_revision"),
        Index("ix_rule_categories_org_policy", "organization_id", "policy_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(ForeignKey("access_policies.id"), index=True)
    position: Mapped[int] = mapped_column(Integer)


class GroupPolicyCategoryMapping(TimestampMixin, Base):
    """Authoritative application mapping from Group+Policy to provider category."""

    __tablename__ = "group_policy_category_mappings"
    __table_args__ = (
        UniqueConstraint("group_id", "policy_id"),
        UniqueConstraint("category_id"),
        CheckConstraint("revision >= 1", name="ck_group_policy_category_mappings_revision"),
        Index(
            "ix_group_policy_category_mappings_org_policy",
            "organization_id",
            "policy_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    group_id: Mapped[UUID] = mapped_column(ForeignKey("application_groups.id"), index=True)
    policy_id: Mapped[UUID] = mapped_column(ForeignKey("access_policies.id"), index=True)
    category_id: Mapped[UUID] = mapped_column(ForeignKey("rule_categories.id"), index=True)
    expected_category_name: Mapped[str] = mapped_column(String(200))
    sync_state: Mapped[str] = mapped_column(String(30), default="PENDING")
    revision: Mapped[int] = mapped_column(Integer, default=1)


class AccessRule(SyncedResourceMixin, Base):
    __tablename__ = "access_rules"
    __table_args__ = (
        UniqueConstraint("policy_id", "native_id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_access_rules_management_state",
        ),
        CheckConstraint("revision >= 1", name="ck_access_rules_revision"),
        Index("ix_access_rules_org_policy", "organization_id", "policy_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(ForeignKey("access_policies.id"), index=True)
    category_id: Mapped[UUID | None] = mapped_column(ForeignKey("rule_categories.id"), index=True)
    intrusion_policy_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("intrusion_policies.id"), index=True
    )
    variable_set_id: Mapped[UUID | None] = mapped_column(ForeignKey("variable_sets.id"), index=True)
    file_policy_id: Mapped[UUID | None] = mapped_column(ForeignKey("file_policies.id"), index=True)
    owner_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("application_groups.id"), index=True
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    modified_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(30))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    log_begin: Mapped[bool] = mapped_column(Boolean, default=False)
    log_end: Mapped[bool] = mapped_column(Boolean, default=False)
    position: Mapped[int] = mapped_column(Integer)


class FirewallObject(SyncedResourceMixin, Base):
    __tablename__ = "firewall_objects"
    __table_args__ = (
        UniqueConstraint("manager_id", "native_id"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_firewall_objects_management_state",
        ),
        CheckConstraint("revision >= 1", name="ck_firewall_objects_revision"),
        CheckConstraint(
            "object_type IN ('NETWORK','NETWORK_GROUP','PORT_SERVICE','PORT_SERVICE_GROUP',"
            "'URL','URL_GROUP','APPLICATION','APPLICATION_FILTER')",
            name="ck_firewall_objects_type",
        ),
        CheckConstraint(
            "(owner_group_id IS NULL AND owner_policy_id IS NULL "
            "AND expected_provider_name IS NULL) OR "
            "(owner_group_id IS NOT NULL AND owner_policy_id IS NOT NULL "
            "AND expected_provider_name IS NOT NULL)",
            name="ck_firewall_objects_authoritative_owner",
        ),
        Index("ix_firewall_objects_org_manager", "organization_id", "manager_id"),
        Index(
            "ix_firewall_objects_equivalence",
            "manager_id",
            "object_type",
            "normalized_value",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    domain_id: Mapped[UUID] = mapped_column(ForeignKey("provider_domains.id"), index=True)
    owner_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("application_groups.id"), index=True
    )
    owner_policy_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("access_policies.id"), index=True
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    modified_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    expected_provider_name: Mapped[str | None] = mapped_column(String(200))
    object_type: Mapped[str] = mapped_column(String(50))
    normalized_value: Mapped[str | None] = mapped_column(String(500))
    sharing_mode: Mapped[str] = mapped_column(String(30), default="private")


class SecurityZone(SyncedResourceMixin, Base):
    __tablename__ = "security_zones"
    __table_args__ = (
        UniqueConstraint("manager_id", "native_id"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(
            "management_state IN ('OBSERVED','UNMANAGED','PENDING_ADOPTION',"
            "'MANAGED','DRIFTED','MISSING','CONFLICT')",
            name="ck_security_zones_management_state",
        ),
        CheckConstraint("revision >= 1", name="ck_security_zones_revision"),
        Index("ix_security_zones_org_manager", "organization_id", "manager_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    domain_id: Mapped[UUID] = mapped_column(ForeignKey("provider_domains.id"), index=True)
    zone_type: Mapped[str] = mapped_column(String(30), default="SECURITY")


class ObjectReference(TimestampMixin, Base):
    __tablename__ = "object_references"
    __table_args__ = (
        CheckConstraint(
            "(source_rule_id IS NOT NULL) <> (source_object_id IS NOT NULL)",
            name="ck_object_references_one_source",
        ),
        CheckConstraint(
            "source_object_id IS NULL OR source_object_id <> target_object_id",
            name="ck_object_references_not_self",
        ),
        CheckConstraint(
            "element_type IN ('UNSPECIFIED','SOURCE_NETWORK','DESTINATION_NETWORK','PORT_SERVICE',"
            "'SOURCE_PORT','DESTINATION_PORT','APPLICATION','URL','MEMBER')",
            name="ck_object_references_element_type",
        ),
        UniqueConstraint("source_rule_id", "target_object_id", "element_type"),
        UniqueConstraint("source_object_id", "target_object_id"),
        Index("ix_object_references_org_target", "organization_id", "target_object_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    manager_id: Mapped[UUID] = mapped_column(ForeignKey("firewall_managers.id"), index=True)
    source_rule_id: Mapped[UUID | None] = mapped_column(ForeignKey("access_rules.id"))
    source_object_id: Mapped[UUID | None] = mapped_column(ForeignKey("firewall_objects.id"))
    target_object_id: Mapped[UUID] = mapped_column(ForeignKey("firewall_objects.id"))
    element_type: Mapped[str] = mapped_column(String(40), default="MEMBER")


class RuleZoneReference(TimestampMixin, Base):
    __tablename__ = "rule_zone_references"
    __table_args__ = (
        UniqueConstraint("rule_id", "zone_id", "element_type"),
        CheckConstraint(
            "element_type IN ('SOURCE','DESTINATION')",
            name="ck_rule_zone_references_element_type",
        ),
        Index("ix_rule_zone_references_org_zone", "organization_id", "zone_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    manager_id: Mapped[UUID] = mapped_column(ForeignKey("firewall_managers.id"), index=True)
    rule_id: Mapped[UUID] = mapped_column(ForeignKey("access_rules.id"), index=True)
    zone_id: Mapped[UUID] = mapped_column(ForeignKey("security_zones.id"), index=True)
    element_type: Mapped[str] = mapped_column(String(20))


class ResourceOwnership(TimestampMixin, Base):
    __tablename__ = "resource_ownerships"
    __table_args__ = (
        UniqueConstraint("organization_id", "resource_type", "resource_id"),
        CheckConstraint("revision >= 1", name="ck_resource_ownerships_revision"),
        Index("ix_resource_ownerships_group", "organization_id", "owner_group_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[UUID]
    owner_group_id: Mapped[UUID] = mapped_column(ForeignKey("application_groups.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class ResourceGrant(TimestampMixin, Base):
    __tablename__ = "resource_grants"
    __table_args__ = (
        UniqueConstraint("ownership_id", "grantee_group_id", "action"),
        CheckConstraint("revision >= 1", name="ck_resource_grants_revision"),
        Index("ix_resource_grants_org_group", "organization_id", "grantee_group_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    ownership_id: Mapped[UUID] = mapped_column(ForeignKey("resource_ownerships.id"), index=True)
    grantee_group_id: Mapped[UUID] = mapped_column(ForeignKey("application_groups.id"), index=True)
    action: Mapped[str] = mapped_column(String(30))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class PolicyDelegation(TimestampMixin, Base):
    """Group capabilities for exactly one provider-synchronized Access Policy."""

    __tablename__ = "policy_delegations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "group_id"],
            ["application_groups.organization_id", "application_groups.id"],
        ),
        ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            ["access_policies.organization_id", "access_policies.id"],
        ),
        UniqueConstraint("group_id", "policy_id"),
        CheckConstraint("revision >= 1", name="ck_policy_delegations_revision"),
        Index("ix_policy_delegations_org_group", "organization_id", "group_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    group_id: Mapped[UUID] = mapped_column(index=True)
    policy_id: Mapped[UUID] = mapped_column(index=True)
    capabilities: Mapped[list[str]] = mapped_column(JSONB, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class DirectUserPolicyGrant(TimestampMixin, Base):
    """Capabilities granted to one User without escaping its Group+Policy context."""

    __tablename__ = "direct_user_policy_grants"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "user_id"], ["users.organization_id", "users.id"]),
        ForeignKeyConstraint(
            ["organization_id", "group_id"],
            ["application_groups.organization_id", "application_groups.id"],
        ),
        ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            ["access_policies.organization_id", "access_policies.id"],
        ),
        UniqueConstraint("user_id", "group_id", "policy_id"),
        CheckConstraint("revision >= 1", name="ck_direct_user_policy_grants_revision"),
        Index("ix_direct_user_policy_grants_context", "user_id", "group_id", "policy_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[UUID] = mapped_column(index=True)
    group_id: Mapped[UUID] = mapped_column(index=True)
    policy_id: Mapped[UUID] = mapped_column(index=True)
    capabilities: Mapped[list[str]] = mapped_column(JSONB, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class ObjectUseGrant(TimestampMixin, Base):
    """Explicit READ/USE/MODIFY permission for one synchronized object."""

    __tablename__ = "object_use_grants"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "group_id"],
            ["application_groups.organization_id", "application_groups.id"],
        ),
        ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            ["access_policies.organization_id", "access_policies.id"],
        ),
        ForeignKeyConstraint(
            ["organization_id", "object_id"],
            ["firewall_objects.organization_id", "firewall_objects.id"],
        ),
        UniqueConstraint("group_id", "policy_id", "object_id", "permission"),
        CheckConstraint("permission IN ('read','use','modify')", name="ck_object_use_permission"),
        CheckConstraint("revision >= 1", name="ck_object_use_grants_revision"),
        Index("ix_object_use_grants_context", "group_id", "policy_id", "object_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    group_id: Mapped[UUID] = mapped_column(index=True)
    policy_id: Mapped[UUID] = mapped_column(index=True)
    object_id: Mapped[UUID] = mapped_column(index=True)
    permission: Mapped[str] = mapped_column(String(20))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class ZoneGrant(TimestampMixin, Base):
    """Explicit source/destination use permission for one synchronized zone."""

    __tablename__ = "zone_grants"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "group_id"],
            ["application_groups.organization_id", "application_groups.id"],
        ),
        ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            ["access_policies.organization_id", "access_policies.id"],
        ),
        ForeignKeyConstraint(
            ["organization_id", "zone_id"],
            ["security_zones.organization_id", "security_zones.id"],
        ),
        UniqueConstraint("group_id", "policy_id", "zone_id", "direction"),
        CheckConstraint(
            "direction IN ('SOURCE','DESTINATION','BOTH')", name="ck_zone_grants_direction"
        ),
        CheckConstraint("revision >= 1", name="ck_zone_grants_revision"),
        Index("ix_zone_grants_context", "group_id", "policy_id", "zone_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    group_id: Mapped[UUID] = mapped_column(index=True)
    policy_id: Mapped[UUID] = mapped_column(index=True)
    zone_id: Mapped[UUID] = mapped_column(index=True)
    direction: Mapped[str] = mapped_column(String(20), default="BOTH")
    revision: Mapped[int] = mapped_column(Integer, default=1)


class IpRangeGrant(TimestampMixin, Base):
    """Canonical IPv4/IPv6 network authorized for manual addresses."""

    __tablename__ = "ip_range_grants"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "group_id"],
            ["application_groups.organization_id", "application_groups.id"],
        ),
        ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            ["access_policies.organization_id", "access_policies.id"],
        ),
        UniqueConstraint("group_id", "policy_id", "network"),
        CheckConstraint("ip_version IN (4, 6)", name="ck_ip_range_grants_version"),
        CheckConstraint("revision >= 1", name="ck_ip_range_grants_revision"),
        Index("ix_ip_range_grants_context", "group_id", "policy_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    group_id: Mapped[UUID] = mapped_column(index=True)
    policy_id: Mapped[UUID] = mapped_column(index=True)
    network: Mapped[str] = mapped_column(String(128))
    ip_version: Mapped[int] = mapped_column(Integer)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class ObjectCreateGrant(TimestampMixin, Base):
    """Application permission to create one normalized object class."""

    __tablename__ = "object_create_grants"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "group_id"],
            ["application_groups.organization_id", "application_groups.id"],
        ),
        ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            ["access_policies.organization_id", "access_policies.id"],
        ),
        UniqueConstraint("group_id", "policy_id", "object_type"),
        CheckConstraint(
            "object_type IN ('NETWORK','PORT_SERVICE','URL','APPLICATION','APPLICATION_FILTER')",
            name="ck_object_create_grants_type",
        ),
        CheckConstraint("revision >= 1", name="ck_object_create_grants_revision"),
        Index("ix_object_create_grants_context", "group_id", "policy_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    group_id: Mapped[UUID] = mapped_column(index=True)
    policy_id: Mapped[UUID] = mapped_column(index=True)
    object_type: Mapped[str] = mapped_column(String(50))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class AuditEvent(Base):
    """Append-oriented authorization and grant-management evidence."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_org_occurred", "organization_id", "occurred_at"),
        Index("ix_audit_events_context", "actor_user_id", "active_group_id", "policy_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    actor_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), index=True)
    active_group_id: Mapped[UUID | None] = mapped_column(ForeignKey("application_groups.id"))
    policy_id: Mapped[UUID | None] = mapped_column(ForeignKey("access_policies.id"))
    action: Mapped[str] = mapped_column(String(50))
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[UUID | None]
    decision: Mapped[str] = mapped_column(String(20))
    reason_code: Mapped[str] = mapped_column(String(100))
    interface: Mapped[str] = mapped_column(String(30), default="application")
    correlation_id: Mapped[str | None] = mapped_column(String(100))
    details: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ChangeSet(TimestampMixin, Base):
    __tablename__ = "change_sets"
    __table_args__ = (
        CheckConstraint("revision >= 1", name="ck_change_sets_revision"),
        Index("ix_change_sets_org_state", "organization_id", "state"),
        Index(
            "ix_change_sets_group_policy",
            "organization_id",
            "acting_group_id",
            "access_policy_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    principal_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), index=True)
    acting_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("application_groups.id"), index=True
    )
    access_policy_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("access_policies.id"), index=True
    )
    target_policy_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    state: Mapped[str] = mapped_column(String(30))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    summary: Mapped[str] = mapped_column(Text)
    provider_revision_snapshot: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    validation_results: Mapped[list[dict[str, object]]] = mapped_column(JSONB, default=list)
    execution_results: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    failure_info: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    audit_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    validated_revision: Mapped[int | None] = mapped_column(Integer)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submitted_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    approved_revision: Mapped[int | None] = mapped_column(Integer)
    approval_invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_owner: Mapped[str | None] = mapped_column(String(200))
    execution_lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_operation: Mapped[str | None] = mapped_column(String(100))


class ChangeSetOperation(TimestampMixin, Base):
    """One ordered provider-neutral draft mutation with independent execution evidence."""

    __tablename__ = "change_set_operations"
    __table_args__ = (
        UniqueConstraint("change_set_id", "sequence"),
        CheckConstraint("revision >= 1", name="ck_change_set_operations_revision"),
        Index("ix_change_set_operations_change_set", "change_set_id", "sequence"),
        Index("ix_change_set_operations_manager", "manager_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    change_set_id: Mapped[UUID] = mapped_column(ForeignKey("change_sets.id"), index=True)
    manager_id: Mapped[UUID] = mapped_column(ForeignKey("firewall_managers.id"), index=True)
    access_policy_id: Mapped[UUID] = mapped_column(ForeignKey("access_policies.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    expected_revisions: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(30), default="DRAFT")
    validation_results: Mapped[list[dict[str, object]]] = mapped_column(JSONB, default=list)
    resolution: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    rollback_snapshot: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    execution_result: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    failure_info: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class ProviderTransaction(TimestampMixin, Base):
    __tablename__ = "provider_transactions"
    __table_args__ = (
        UniqueConstraint("change_set_id", "manager_id"),
        CheckConstraint("revision >= 1", name="ck_provider_transactions_revision"),
        Index("ix_provider_transactions_org_state", "organization_id", "state"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    change_set_id: Mapped[UUID] = mapped_column(ForeignKey("change_sets.id"), index=True)
    manager_id: Mapped[UUID] = mapped_column(ForeignKey("firewall_managers.id"), index=True)
    state: Mapped[str] = mapped_column(String(30))
    expected_provider_fingerprint: Mapped[str | None] = mapped_column(String(200))
    external_operation_id: Mapped[str | None] = mapped_column(String(200))
    operation_results: Mapped[list[dict[str, object]]] = mapped_column(JSONB, default=list)
    failure_info: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    reconciliation_required: Mapped[bool] = mapped_column(Boolean, default=False)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_probe_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provider_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)


class Deployment(TimestampMixin, Base):
    __tablename__ = "deployments"
    __table_args__ = (
        UniqueConstraint("provider_transaction_id"),
        CheckConstraint("revision >= 1", name="ck_deployments_revision"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    provider_connection_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("provider_connections.id"), index=True
    )
    manager_id: Mapped[UUID | None] = mapped_column(ForeignKey("firewall_managers.id"), index=True)
    provider_transaction_id: Mapped[UUID] = mapped_column(
        ForeignKey("provider_transactions.id"), index=True
    )
    state: Mapped[str] = mapped_column(String(30))
    external_operation_id: Mapped[str | None] = mapped_column(String(200))
    rollback_state: Mapped[str | None] = mapped_column(String(30))
    rollback_external_operation_id: Mapped[str | None] = mapped_column(String(200))
    rollback_requested_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    rollback_device_results: Mapped[list[dict[str, object]]] = mapped_column(JSONB, default=list)
    rollback_failure_info: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    requested_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    approved_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    target_device_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    included_change_set_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    plan_snapshot: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    pending_change_evidence: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    device_results: Mapped[list[dict[str, object]]] = mapped_column(JSONB, default=list)
    failure_info: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class DriftRecord(TimestampMixin, Base):
    __tablename__ = "drift_records"
    __table_args__ = (
        Index("ix_drift_records_org_status", "organization_id", "status"),
        Index("ix_drift_records_manager_resource", "manager_id", "resource_type", "resource_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    manager_id: Mapped[UUID] = mapped_column(ForeignKey("firewall_managers.id"), index=True)
    sync_run_id: Mapped[UUID | None] = mapped_column(ForeignKey("sync_runs.id"), index=True)
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[UUID]
    status: Mapped[str] = mapped_column(String(30))
    previous_fingerprint: Mapped[str | None] = mapped_column(String(200))
    observed_fingerprint: Mapped[str | None] = mapped_column(String(200))
    previous_snapshot: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    observed_snapshot: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    details: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)


# Temporary source-compatibility alias while Milestone 0 callers migrate to generic objects.
NetworkObject = FirewallObject
PolicyCategory = RuleCategory
