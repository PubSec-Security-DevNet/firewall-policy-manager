"""Typed REST response schemas."""

from datetime import datetime
from typing import Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field


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
    authentication_mode: Literal["development"]
    user_id: UUID
    email: str
    role: str
    groups: list["ActiveGroupResponse"]


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
    position: int
    management_state: str
    revision: int
    category_id: UUID | None = None


class DelegatedObjectResponse(BaseModel):
    id: UUID
    name: str
    object_type: str
    owner_type: Literal["GROUP", "PROVIDER"] = "PROVIDER"
    owner_group_id: UUID | None = None
    owner_policy_id: UUID | None = None
    created_by_user_id: UUID | None = None


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


class DelegatedContextResponse(BaseModel):
    policy: DelegatedPolicySummary
    capabilities: list[str]
    rules: list[DelegatedRuleResponse]
    objects: list[DelegatedObjectResponse]
    zones: list[DelegatedZoneResponse]
    categories: list[DelegatedCategoryResponse]
    ip_ranges: list[str]
    object_create: list[ObjectCreateCapabilityResponse]


class UserCreateRequest(BaseModel):
    identity_issuer: str
    identity_subject: str
    display_name: str
    email: str
    role: str = "viewer"


class GroupCreateRequest(BaseModel):
    name: str
    provider_slug: str


class EnabledUpdateRequest(BaseModel):
    enabled: bool
    expected_revision: int


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
    category_id: UUID | None = None
    position: int | None = Field(default=None, ge=0)
    source_zone_ids: list[UUID] = Field(default_factory=list)
    destination_zone_ids: list[UUID] = Field(default_factory=list)
    source_object_ids: list[UUID] = Field(default_factory=list)
    destination_object_ids: list[UUID] = Field(default_factory=list)
    port_object_ids: list[UUID] = Field(default_factory=list)
    application_object_ids: list[UUID] = Field(default_factory=list)
    url_object_ids: list[UUID] = Field(default_factory=list)
    manual_source_networks: list[str] = Field(default_factory=list)
    manual_destination_networks: list[str] = Field(default_factory=list)
    manual_ports: list[str] = Field(default_factory=list)
    logging: dict[str, object] = Field(default_factory=dict)
    settings: dict[str, object] = Field(default_factory=dict)
    mock_behavior: Literal[
        "success",
        "provider_failure",
        "rate_limit",
        "timeout_before_mutation",
        "timeout_after_mutation",
        "partial_failure",
    ] = "success"


class DraftRuleOperationRequest(BaseModel):
    active_group_id: UUID
    kind: Literal["CREATE_RULE", "MODIFY_RULE", "DELETE_RULE", "MOVE_RULE"]
    rule: DraftRuleRequest


class DraftObjectRequest(BaseModel):
    policy_id: UUID | None = None
    object_id: UUID | None = None
    name: str | None = Field(default=None, min_length=1, max_length=200)
    object_type: Literal["NETWORK", "PORT_SERVICE", "URL", "APPLICATION", "APPLICATION_FILTER"]
    value: str | None = Field(default=None, min_length=1, max_length=500)
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
    execution_result: dict[str, object]
    failure_info: dict[str, object]
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


class ChangeSetResponse(BaseModel):
    id: UUID
    organization_id: UUID
    creator_id: UUID
    active_group_id: UUID
    access_policy_id: UUID
    target_policy_ids: list[str]
    title: str
    description: str
    state: str
    revision: int
    validated_revision: int | None
    provider_revision_snapshot: dict[str, object]
    validation_results: list[dict[str, object]]
    execution_results: dict[str, object]
    failure_info: dict[str, object]
    audit_metadata: dict[str, object]
    created_at: datetime
    updated_at: datetime
    operations: list[ChangeSetOperationResponse]
    transactions: list[ProviderTransactionResponse]
