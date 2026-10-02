"""Typed REST response schemas."""

from datetime import datetime
from typing import Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict[str, object]
    correlation_id: str


class ErrorEnvelope(BaseModel):
    error: ErrorBody


class HealthResponse(BaseModel):
    status: Literal["ok", "not_ready"]


class SessionResponse(BaseModel):
    authentication_mode: Literal["development", "oidc"]
    user_id: UUID
    email: str
    role: str
    groups: list["ActiveGroupResponse"]
    default_group_id: UUID | None = None
    default_policy_id: UUID | None = None
    proxied: bool = False
    proxy_actor_email: str | None = None
    proxy_actor_role: str | None = None


class ProxyStartRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class DefaultContextRequest(BaseModel):
    group_id: UUID
    policy_id: UUID


class DefaultContextResponse(BaseModel):
    group_id: UUID
    policy_id: UUID


class DevelopmentIdentityResponse(BaseModel):
    email: str
    display_name: str
    role: str
    enabled: bool


class ActiveGroupResponse(BaseModel):
    id: UUID
    name: str
    provider_slug: str
    revision: int


class CountSummary(BaseModel):
    managers: int
    policies: int
    rules: int
    objects: int
    change_sets: int


class ProviderSummary(BaseModel):
    provider: Literal["fmc", "scc"]
    display_name: str
    provider_version: str
    policy_count: int
    rule_count: int = 0
    object_count: int
    writable: bool


class OverviewResponse(BaseModel):
    organization: str
    counts: CountSummary
    providers: list[ProviderSummary]


class ManagerResponse(BaseModel):
    id: UUID
    provider: Literal["fmc", "scc"]
    display_name: str
    read_only: bool
    provider_version: str | None
    revision: int


class ResourceResponse(BaseModel):
    id: UUID
    manager_id: UUID
    name: str
    management_state: str
    revision: int
    provider_version: str | None


class PolicyResponse(ResourceResponse):
    pass


class RuleResponse(ResourceResponse):
    policy_id: UUID
    category_id: UUID | None
    action: str
    position: int


class ObjectResponse(ResourceResponse):
    object_type: str
    value: str | None
    sharing_mode: str


ItemT = TypeVar("ItemT")


class PageResponse[ItemT](BaseModel):
    items: list[ItemT]
    total: int
    next_cursor: str | None


class ProviderStatusResponse(BaseModel):
    manager_id: UUID
    connection_id: UUID | None = None
    provider: Literal["fmc", "scc"]
    display_name: str
    provider_version: str | None
    capabilities: dict[str, str]
    evidence_profile: Literal["mock", "real"]
    writable: bool
    sync_status: str | None
    sync_complete: bool
    resources_seen: int
    last_sync_at: datetime | None
    error_code: str | None


class SynchronizationDiscrepancyResponse(BaseModel):
    id: UUID
    manager_id: UUID
    connection_id: UUID | None = None
    provider: Literal["fmc", "scc"]
    name: str
    policy_id: UUID | None = None
    provider_only: bool = False
    resource_type: str
    resource_id: UUID
    state: str
    previous_fingerprint: str | None
    observed_fingerprint: str | None
    previous_snapshot: dict[str, object]
    observed_snapshot: dict[str, object]
    details: dict[str, object]
    created_at: datetime


class ReconciliationRestoreRequest(BaseModel):
    active_group_id: UUID


class ReconciliationActionResponse(BaseModel):
    action: str
    drift_id: UUID
    state: str
    change_set_id: UUID | None = None


class DelegatedPolicySummary(BaseModel):
    id: UUID
    manager_id: UUID
    name: str
    management_state: str
    revision: int


class DelegatedRuleResponse(BaseModel):
    id: UUID
    name: str
    action: str
    enabled: bool = True
    logging: Literal["NONE", "BEGIN", "END"] = "NONE"
    position: int
    management_state: str
    firewall_state: Literal["DEPLOYED", "UNDEPLOYED", "NOT_PRESENT", "UNKNOWN"] = "UNKNOWN"
    revision: int
    category_id: UUID | None = None
    intrusion_policy_id: UUID | None = None
    variable_set_id: UUID | None = None
    file_policy_id: UUID | None = None
    source_zones: list[str] = Field(default_factory=list)
    destination_zones: list[str] = Field(default_factory=list)
    source_networks: list[str] = Field(default_factory=list)
    destination_networks: list[str] = Field(default_factory=list)
    source_services: list[str] = Field(default_factory=list)
    destination_services: list[str] = Field(default_factory=list)
    applications: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class DelegatedObjectResponse(BaseModel):
    id: UUID
    name: str
    object_type: str
    normalized_value: str | None = None
    management_state: str = "OBSERVED"
    firewall_state: Literal["DEPLOYED", "UNDEPLOYED", "NOT_PRESENT", "UNKNOWN"] = "UNKNOWN"
    owner_type: Literal["GROUP", "PROVIDER"] = "PROVIDER"
    owner_group_id: UUID | None = None
    owner_policy_id: UUID | None = None
    created_by_user_id: UUID | None = None
    member_object_ids: list[UUID] = Field(default_factory=list)


class DelegatedZoneResponse(BaseModel):
    id: UUID
    name: str
    direction: str


class ObjectCreateCapabilityResponse(BaseModel):
    object_type: str
    provider_supported: bool


class DelegatedCategoryResponse(BaseModel):
    id: UUID
    name: str


class DelegatedIntrusionPolicyResponse(BaseModel):
    id: UUID
    name: str
    default_variable_set_id: UUID | None = None


class DelegatedVariableSetResponse(BaseModel):
    id: UUID
    name: str
    is_default: bool = False


class DelegatedFilePolicyResponse(BaseModel):
    id: UUID
    name: str


class DelegatedContextResponse(BaseModel):
    policy: DelegatedPolicySummary
    provider_writable: bool = False
    firewall_deployment_status: Literal["SUPPORTED", "NOT_AVAILABLE"] = "NOT_AVAILABLE"
    provider_type: Literal["fmc", "scc"] = "fmc"
    provider_name: str = "Provider"
    provider_is_mock: bool = True
    capabilities: list[str]
    rules: list[DelegatedRuleResponse]
    objects: list[DelegatedObjectResponse]
    zones: list[DelegatedZoneResponse]
    categories: list[DelegatedCategoryResponse]
    intrusion_policies: list[DelegatedIntrusionPolicyResponse] = Field(default_factory=list)
    variable_sets: list[DelegatedVariableSetResponse] = Field(default_factory=list)
    file_policies: list[DelegatedFilePolicyResponse] = Field(default_factory=list)
    ip_ranges: list[str]
    object_create: list[ObjectCreateCapabilityResponse]


class UserCreateRequest(BaseModel):
    identity_issuer: str
    identity_subject: str
    display_name: str
    email: str
    role: str = "viewer"


class ExternalIdentityCreateRequest(BaseModel):
    provider_id: str = Field(min_length=1, max_length=80)
    issuer: str = Field(min_length=1, max_length=500)
    subject: str = Field(min_length=1, max_length=500)
    email_claim: str | None = Field(default=None, max_length=320)
    display_name_claim: str | None = Field(default=None, max_length=200)


class ExternalIdentityResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    user_id: UUID
    provider_id: str
    issuer: str
    subject: str
    email_claim: str | None
    display_name_claim: str | None
    created_at: datetime


class ApiTokenCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[Literal["read", "write", "admin"]] = Field(min_length=1)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return value


class ApiTokenResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    user_id: UUID
    name: str
    token_prefix: str
    scopes: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ApiTokenCreatedResponse(ApiTokenResponse):
    token: str


class GroupCreateRequest(BaseModel):
    name: str
    provider_slug: str
    approval_required: bool = False


class EnabledUpdateRequest(BaseModel):
    enabled: bool
    expected_revision: int


class GroupApprovalUpdateRequest(BaseModel):
    approval_required: bool
    expected_revision: int = Field(ge=1)


class UserRoleUpdateRequest(BaseModel):
    role: Literal["viewer", "editor", "approver", "group_admin", "firewall_admin", "admin"]
    expected_revision: int


class OidcProviderCreateRequest(BaseModel):
    id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9-]+$")
    kind: Literal["entra", "duo", "generic"]
    display_name: str = Field(min_length=1, max_length=120)
    issuer_url: str
    client_id: str = Field(min_length=1, max_length=300)
    client_secret: SecretStr
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    username_claim: str = "preferred_username"
    display_name_claim: str = "name"
    email_claim: str = "email"
    mapping_claim: str = "email"
    enabled: bool = True
    logout: bool = True


class OidcProviderUpdateRequest(BaseModel):
    expected_revision: int = Field(ge=1)
    display_name: str | None = None
    issuer_url: str | None = None
    client_id: str | None = None
    scopes: list[str] | None = None
    username_claim: str | None = None
    display_name_claim: str | None = None
    email_claim: str | None = None
    mapping_claim: str | None = None
    enabled: bool | None = None
    logout: bool | None = None


class OidcProviderSecretRequest(BaseModel):
    expected_revision: int = Field(ge=1)
    client_secret: SecretStr


class OidcProviderResponse(BaseModel):
    id: UUID
    provider_id: str
    kind: Literal["entra", "duo", "generic"]
    display_name: str
    issuer_url: str
    client_id: str
    scopes: list[str]
    enabled: bool
    logout: bool
    username_claim: str
    display_name_claim: str
    email_claim: str
    mapping_claim: str
    secret_configured: bool
    revision: int
    updated_at: datetime


class OidcLoginProviderResponse(BaseModel):
    provider_id: str
    kind: Literal["entra", "duo", "generic"]
    display_name: str


class AuthorizationResourceUpsertRequest(BaseModel):
    user_id: UUID | None = None
    group_id: UUID | None = None
    policy_id: UUID | None = None
    object_id: UUID | None = None
    zone_id: UUID | None = None
    category_id: UUID | None = None
    status: str | None = None
    capabilities: list[str] | None = None
    is_active: bool | None = None
    permission: str | None = None
    direction: str | None = None
    network: str | None = None
    object_type: str | None = None
    expected_category_name: str | None = None
    sync_state: str | None = None
    expected_revision: int | None = None


class AdministrationSnapshotResponse(BaseModel):
    users: list[dict[str, object]]
    groups: list[dict[str, object]]
    policies: list[dict[str, object]]
    objects: list[dict[str, object]]
    zones: list[dict[str, object]]
    categories: list[dict[str, object]]
    memberships: list[dict[str, object]]
    policy_delegations: list[dict[str, object]]
    direct_user_policy_grants: list[dict[str, object]]
    object_use_grants: list[dict[str, object]]
    zone_grants: list[dict[str, object]]
    ip_range_grants: list[dict[str, object]]
    object_create_grants: list[dict[str, object]]
    category_mappings: list[dict[str, object]]
    audit_events: list[dict[str, object]] = Field(default_factory=list)


class ProviderConnectionScopeResponse(BaseModel):
    id: UUID
    native_id: str
    name: str
    scope_type: str
    last_seen_at: datetime


class ProviderCapabilityEvidenceResponse(BaseModel):
    capability: str
    status: str
    evidence_level: str
    provider_version: str
    tested_at: datetime | None


class ProviderConnectionResponse(BaseModel):
    id: UUID
    provider_type: Literal["fmc", "scc"]
    display_name: str
    lifecycle: Literal["ACTIVE", "DISABLED", "RETIRED"]
    enabled: bool
    connection_mode: str
    evidence_profile: Literal["real"]
    base_endpoint: str | None
    region: str | None
    tls_mode: Literal["SYSTEM", "CUSTOM_CA"]
    credential_present: bool
    credential_type: str
    credential_username: str | None
    credential_updated_at: datetime
    provider_version: str | None
    connection_status: str
    sync_status: str | None
    last_connection_test: datetime | None
    last_successful_connection: datetime | None
    last_sync: datetime | None
    last_successful_sync: datetime | None
    last_error_code: str | None
    last_error_message: str | None
    last_error_correlation_id: str | None
    certificate_info: dict[str, str]
    sync_interval_minutes: int
    applications_sync_interval_minutes: int
    applications_sync_status: str | None
    applications_last_sync: datetime | None
    applications_last_successful_sync: datetime | None
    applications_next_sync_at: datetime | None
    deployment_schedule_enabled: bool = True
    deployment_paused: bool = False
    deployment_pause_reason: str | None = None
    deployment_paused_at: datetime | None = None
    deployment_pause_until: datetime | None = None
    deployment_paused_by_user_id: UUID | None = None
    deployment_status: str | None = None
    deployment_next_at: datetime | None = None
    deployment_last_started_at: datetime | None = None
    deployment_last_completed_at: datetime | None = None
    write_enabled: bool = False
    write_validation_mode: bool = False
    version_family_tested: bool = False
    compatibility_warning: str | None = None
    write_enabled_at: datetime | None = None
    write_enabled_by_user_id: UUID | None = None
    scopes: list[ProviderConnectionScopeResponse]
    capability_evidence: list[ProviderCapabilityEvidenceResponse]
    created_at: datetime
    updated_at: datetime
    revision: int


class ProviderConnectionPageResponse(BaseModel):
    items: list[ProviderConnectionResponse]
    total: int


class ProviderConnectionCreateRequest(BaseModel):
    provider_type: Literal["fmc", "scc"]
    display_name: str = Field(min_length=1, max_length=200)
    base_endpoint: str | None = Field(default=None, max_length=500)
    region: Literal["us", "eu", "apj", "au", "in", "uae", "fedramp", "il5"] | None = None
    tls_mode: Literal["SYSTEM", "CUSTOM_CA"] = "SYSTEM"
    username: str | None = Field(default=None, max_length=320)
    password: SecretStr | None = Field(default=None, repr=False)
    token: SecretStr | None = Field(default=None, repr=False)
    ca_certificate: SecretStr | None = Field(default=None, repr=False)
    sync_interval_minutes: int = Field(default=60, ge=5, le=10080)
    applications_sync_interval_minutes: int = Field(default=1440, ge=60, le=43200)

    @model_validator(mode="after")
    def validate_provider_fields(self) -> "ProviderConnectionCreateRequest":
        if self.provider_type == "fmc" and (
            not self.base_endpoint
            or not self.username
            or self.password is None
            or (self.tls_mode == "CUSTOM_CA" and self.ca_certificate is None)
        ):
            raise ValueError(
                "FMC endpoint, username, password, and selected TLS trust are required"
            )
        if self.provider_type == "scc" and (not self.region or self.token is None):
            raise ValueError("SCC region and API token are required")
        return self


class ProviderConnectionUpdateRequest(BaseModel):
    expected_revision: int = Field(ge=1)
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    base_endpoint: str | None = Field(default=None, max_length=500)
    region: Literal["us", "eu", "apj", "au", "in", "uae", "fedramp", "il5"] | None = None
    tls_mode: Literal["SYSTEM", "CUSTOM_CA"] | None = None
    sync_interval_minutes: int | None = Field(default=None, ge=5, le=10080)
    applications_sync_interval_minutes: int | None = Field(default=None, ge=60, le=43200)
    deployment_schedule_enabled: bool | None = None


class ProviderCredentialUpdateRequest(BaseModel):
    expected_revision: int = Field(ge=1)
    username: str | None = Field(default=None, max_length=320)
    password: SecretStr | None = Field(default=None, repr=False)
    token: SecretStr | None = Field(default=None, repr=False)
    ca_certificate: SecretStr | None = Field(default=None, repr=False)


class ProviderLifecycleRequest(BaseModel):
    expected_revision: int = Field(ge=1)
    lifecycle: Literal["ACTIVE", "DISABLED", "RETIRED"]


class ProviderWriteGateRequest(BaseModel):
    expected_revision: int = Field(ge=1)
    enabled: bool
    acknowledge_configuration_mutation: bool = False
    acknowledge_unvalidated_non_production_writes: bool = False


class ProviderConnectionTestResponse(BaseModel):
    status: str
    provider_version: str | None = None
    certificate_info: dict[str, str] = Field(default_factory=dict)
    tested_capabilities: list[str] = Field(default_factory=list)
    unverified_capabilities: list[str] = Field(default_factory=list)
    error_code: str | None = None
    safe_message: str | None = None
    missing_capability: str | None = None
    correlation_id: str | None = None
    connection: ProviderConnectionResponse


class ChangeSetCreateRequest(BaseModel):
    active_group_id: UUID
    policy_id: UUID
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)


class ChangeSetMetadataUpdateRequest(BaseModel):
    active_group_id: UUID
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    expected_revision: int = Field(ge=1)


class DraftRuleRequest(BaseModel):
    policy_id: UUID | None = None
    name: str | None = Field(default=None, max_length=200)
    rule_id: UUID | None = None
    action: Literal["ALLOW", "BLOCK", "TRUST", "MONITOR"] | None = None
    enabled: bool = True
    logging: Literal["NONE", "BEGIN", "END"] = "NONE"
    category_id: UUID | None = None
    intrusion_policy_id: UUID | None = None
    variable_set_id: UUID | None = None
    file_policy_id: UUID | None = None
    anchor_rule_id: UUID | None = None
    position: int | None = Field(default=None, ge=0)
    placement: Literal["BEFORE", "AFTER"] | None = None
    source_zone_ids: list[UUID] = Field(default_factory=list)
    destination_zone_ids: list[UUID] = Field(default_factory=list)
    source_object_ids: list[UUID] = Field(default_factory=list)
    destination_object_ids: list[UUID] = Field(default_factory=list)
    port_object_ids: list[UUID] = Field(default_factory=list)
    source_port_object_ids: list[UUID] = Field(default_factory=list)
    destination_port_object_ids: list[UUID] = Field(default_factory=list)
    application_object_ids: list[UUID] = Field(default_factory=list)
    url_object_ids: list[UUID] = Field(default_factory=list)
    manual_source_networks: list[str] = Field(default_factory=list)
    manual_destination_networks: list[str] = Field(default_factory=list)
    manual_ports: list[str] = Field(default_factory=list)
    settings: dict[str, object] = Field(default_factory=dict)
    mock_behavior: Literal[
        "success",
        "provider_failure",
        "rate_limit",
        "timeout_before_mutation",
        "timeout_after_mutation",
        "partial_failure",
    ] = "success"

    @model_validator(mode="after")
    def validate_logging(self) -> "DraftRuleRequest":
        if self.action == "BLOCK" and self.logging not in {"NONE", "BEGIN"}:
            raise ValueError("block rules may only use no logging or log at the beginning")
        if self.action == "MONITOR" and self.logging != "END":
            raise ValueError("monitor rules must log at the end")
        return self


class DraftRuleOperationRequest(BaseModel):
    active_group_id: UUID
    kind: Literal["CREATE_RULE", "MODIFY_RULE", "DELETE_RULE", "MOVE_RULE"]
    rule: DraftRuleRequest

    @model_validator(mode="after")
    def validate_rule_scope(self) -> "DraftRuleOperationRequest":
        if self.kind in {"CREATE_RULE", "MODIFY_RULE"}:
            rule = self.rule
            if not rule.source_zone_ids or not rule.destination_zone_ids:
                raise ValueError("source and destination zones are required")
            if not rule.source_object_ids and not rule.manual_source_networks:
                raise ValueError("at least one source network is required")
            if not rule.destination_object_ids and not rule.manual_destination_networks:
                raise ValueError("at least one destination network is required")
        return self


class DraftObjectRequest(BaseModel):
    policy_id: UUID | None = None
    object_id: UUID | None = None
    name: str | None = Field(default=None, min_length=1, max_length=200)
    object_type: Literal[
        "NETWORK",
        "NETWORK_GROUP",
        "PORT_SERVICE",
        "PORT_SERVICE_GROUP",
        "URL",
        "URL_GROUP",
        "APPLICATION",
        "APPLICATION_FILTER",
    ]
    value: str | None = Field(default=None, max_length=500)
    member_object_ids: list[UUID] = Field(default_factory=list, max_length=100)
    mock_behavior: Literal[
        "success",
        "provider_failure",
        "rate_limit",
        "timeout_before_mutation",
        "timeout_after_mutation",
        "partial_failure",
    ] = "success"


class DraftObjectOperationRequest(BaseModel):
    active_group_id: UUID
    kind: Literal["CREATE_OBJECT", "MODIFY_OBJECT", "DELETE_OBJECT"] = "CREATE_OBJECT"
    object: DraftObjectRequest


class DraftCategoryOperationRequest(BaseModel):
    active_group_id: UUID
    policy_id: UUID | None = None


class DraftOperationUpdateRequest(BaseModel):
    active_group_id: UUID
    expected_revision: int = Field(ge=1)
    payload: dict[str, object]


class ChangeSetActionRequest(BaseModel):
    active_group_id: UUID


class ChangeSetOperationResponse(BaseModel):
    id: UUID
    manager_id: UUID
    access_policy_id: UUID
    sequence: int
    kind: str
    payload: dict[str, object]
    expected_revisions: dict[str, str]
    status: str
    validation_results: list[dict[str, object]]
    resolution: dict[str, object]
    rollback_snapshot: dict[str, object]
    execution_result: dict[str, object]
    failure_info: dict[str, object]
    lease_until: datetime | None = None
    heartbeat_at: datetime | None = None
    revision: int
    created_at: datetime
    updated_at: datetime


class ProviderTransactionResponse(BaseModel):
    id: UUID
    manager_id: UUID
    state: str
    operation_results: list[dict[str, object]]
    failure_info: dict[str, object]
    reconciliation_required: bool
    external_operation_id: str | None
    revision: int
    created_at: datetime
    updated_at: datetime
    lease_owner: str | None = None
    lease_until: datetime | None = None
    heartbeat_at: datetime | None = None
    last_probe_at: datetime | None = None
    provider_metadata: dict[str, object] = Field(default_factory=dict)


class ChangeSetResponse(BaseModel):
    id: UUID
    organization_id: UUID
    creator_id: UUID
    creator_display_name: str | None = None
    creator_email: str | None = None
    active_group_id: UUID
    access_policy_id: UUID
    approval_required: bool = False
    target_policy_ids: list[str]
    title: str
    description: str
    state: str
    revision: int
    validated_revision: int | None
    submitted_at: datetime | None = None
    submitted_by_user_id: UUID | None = None
    approved_at: datetime | None = None
    approved_by_user_id: UUID | None = None
    approved_revision: int | None = None
    approval_invalidated_at: datetime | None = None
    execution_owner: str | None = None
    execution_lease_until: datetime | None = None
    execution_heartbeat_at: datetime | None = None
    execution_operation: str | None = None
    provider_revision_snapshot: dict[str, object]
    validation_results: list[dict[str, object]]
    execution_results: dict[str, object]
    failure_info: dict[str, object]
    audit_metadata: dict[str, object]
    created_at: datetime
    updated_at: datetime
    operations: list[ChangeSetOperationResponse]
    transactions: list[ProviderTransactionResponse]


class PendingApprovalsResponse(BaseModel):
    count: int
    items: list[ChangeSetResponse]


class DeploymentPlanRequest(BaseModel):
    change_set_id: UUID
    target_device_ids: list[str] = Field(default_factory=list, max_length=500)


class DeploymentActionRequest(BaseModel):
    deployment_id: UUID


class DeploymentPauseRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    until: datetime | None = None

    @field_validator("until")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("until must include a timezone")
        return value


class DeploymentRollbackRequest(BaseModel):
    selected_change_set_ids: list[UUID] = Field(min_length=1, max_length=100)


class DeploymentResponse(BaseModel):
    id: UUID
    organization_id: UUID
    provider_transaction_id: UUID
    provider_connection_id: UUID | None = None
    manager_id: UUID | None = None
    state: str
    external_operation_id: str | None = None
    rollback_state: str | None = None
    rollback_external_operation_id: str | None = None
    rollback_requested_by_user_id: UUID | None = None
    rollback_device_results: list[dict[str, object]]
    rollback_failure_info: dict[str, object]
    rollback_eligible: bool = False
    rollback_unavailable_reason: str | None = None
    requested_by_user_id: UUID | None = None
    approved_by_user_id: UUID | None = None
    target_device_ids: list[str]
    device_names: dict[str, str] = Field(default_factory=dict)
    included_change_set_ids: list[str]
    plan_snapshot: dict[str, object]
    pending_change_evidence: dict[str, object]
    device_results: list[dict[str, object]]
    failure_info: dict[str, object]
    revision: int
    created_at: datetime
    updated_at: datetime
