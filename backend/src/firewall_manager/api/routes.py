"""Thin versioned REST routes."""

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from firewall_manager.api.dependencies import (
    AdministrationRepositoryDependency,
    AuthorizationRepositoryDependency,
    ChangeSetExecutionDispatcherDependency,
    ChangeSetRepositoryDependency,
    DevelopmentIdentityRepositoryDependency,
    HealthServiceDependency,
    InventoryRepositoryDependency,
    PrincipalDependency,
    ProviderConnectionRepositoryDependency,
    ProviderFactoryDependency,
    ProviderSyncDispatcherDependency,
    RepositoryDependency,
    SecretStoreDependency,
)
from firewall_manager.api.schemas import (
    ActiveGroupResponse,
    AdministrationSnapshotResponse,
    AuthorizationResourceUpsertRequest,
    ChangeSetActionRequest,
    ChangeSetCreateRequest,
    ChangeSetMetadataUpdateRequest,
    ChangeSetResponse,
    DefaultContextRequest,
    DefaultContextResponse,
    DelegatedContextResponse,
    DelegatedPolicySummary,
    DevelopmentIdentityResponse,
    DraftCategoryOperationRequest,
    DraftObjectOperationRequest,
    DraftOperationUpdateRequest,
    DraftRuleOperationRequest,
    EnabledUpdateRequest,
    GroupCreateRequest,
    HealthResponse,
    ManagerResponse,
    ObjectResponse,
    OverviewResponse,
    PageResponse,
    PolicyResponse,
    ProviderConnectionCreateRequest,
    ProviderConnectionPageResponse,
    ProviderConnectionResponse,
    ProviderConnectionTestResponse,
    ProviderConnectionUpdateRequest,
    ProviderCredentialUpdateRequest,
    ProviderLifecycleRequest,
    ProviderStatusResponse,
    ProviderWriteGateRequest,
    RuleResponse,
    SessionResponse,
    UserCreateRequest,
    UserRoleUpdateRequest,
)
from firewall_manager.application.administration import AdministrationService
from firewall_manager.application.changesets import ChangeSetService
from firewall_manager.application.delegated import DelegatedPolicyService
from firewall_manager.application.errors import ResourceOutOfScopeError
from firewall_manager.application.inventory import InventoryService
from firewall_manager.application.overview import OverviewService
from firewall_manager.application.ports import ProviderFactory, ProviderReader
from firewall_manager.application.provider_connections import ProviderConnectionService
from firewall_manager.domain.models import ChangeOperationKind, DelegatedPolicyContext, ProviderKind
from firewall_manager.providers.transactions import (
    HttpMockTransactionExecutor,
    ProviderTransactionExecutor,
)

router = APIRouter(prefix="/api/v1")
dev_router = APIRouter(prefix="/api/v1/dev", tags=["development-auth"])


def get_provider_readers() -> tuple[ProviderReader, ...]:
    """Application wiring hook overridden by the process composition root."""
    msg = "provider readers are not configured"
    raise RuntimeError(msg)


@dev_router.get("/users")
async def development_users(
    repository: DevelopmentIdentityRepositoryDependency,
) -> list[DevelopmentIdentityResponse]:
    """Return deterministic identities; this router is never mounted in production."""
    return [
        DevelopmentIdentityResponse.model_validate(item)
        for item in repository.development_identities()
    ]


@router.get("/health/live", tags=["health"])
async def live() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get(
    "/health/ready",
    responses={503: {"description": "A required dependency is unavailable"}},
    tags=["health"],
)
async def ready(
    service: HealthServiceDependency,
) -> HealthResponse:
    await service.check_readiness()
    return HealthResponse(status="ok")


@router.get("/session", tags=["identity"])
async def session(
    principal: PrincipalDependency,
    repository: AuthorizationRepositoryDependency,
) -> SessionResponse:
    default_group_id, default_policy_id = repository.default_context_for_user(
        principal.user_id, principal.organization_id
    )
    return SessionResponse(
        authentication_mode="development",
        user_id=principal.user_id,
        email=principal.email,
        role=principal.role,
        groups=[
            ActiveGroupResponse.model_validate(item)
            for item in repository.active_groups_for_user(
                principal.user_id, principal.organization_id
            )
        ],
        default_group_id=default_group_id,
        default_policy_id=default_policy_id,
    )


@router.put("/session/default-context", tags=["identity"])
async def set_default_context(
    values: DefaultContextRequest,
    principal: PrincipalDependency,
    repository: AuthorizationRepositoryDependency,
) -> DefaultContextResponse:
    if not repository.set_default_context_for_user(
        principal.user_id,
        values.group_id,
        values.policy_id,
        principal.organization_id,
    ):
        raise ResourceOutOfScopeError
    return DefaultContextResponse(group_id=values.group_id, policy_id=values.policy_id)


@router.get("/delegated/context", tags=["delegated"])
async def delegated_context(
    request: Request,
    active_group_id: UUID,
    policy_id: UUID,
    principal: PrincipalDependency,
    repository: AuthorizationRepositoryDependency,
) -> DelegatedContextResponse:
    result = DelegatedPolicyService(repository).context_view(
        DelegatedPolicyContext(principal, active_group_id, policy_id),
        interface="rest",
        correlation_id=getattr(request.state, "correlation_id", None),
    )
    return DelegatedContextResponse.model_validate(result)


@router.get("/delegated/policies", tags=["delegated"])
async def delegated_policies(
    active_group_id: UUID,
    principal: PrincipalDependency,
    repository: AuthorizationRepositoryDependency,
) -> list[DelegatedPolicySummary]:
    result = DelegatedPolicyService(repository).policies(principal, active_group_id)
    return [DelegatedPolicySummary.model_validate(item) for item in result]


def _change_set_service(
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
    executor: ProviderTransactionExecutor | None = None,
) -> ChangeSetService:
    return ChangeSetService(
        authorization_repository,
        change_set_repository,
        executor or HttpMockTransactionExecutor(),
    )


@router.post("/changesets", status_code=201, tags=["change-sets"])
async def create_change_set(
    body: ChangeSetCreateRequest,
    request: Request,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).create(
        principal,
        body.active_group_id,
        body.policy_id,
        body.title,
        body.description,
        correlation_id=getattr(request.state, "correlation_id", None),
    )
    return ChangeSetResponse.model_validate(result)


@router.get("/changesets", tags=["change-sets"])
async def list_change_sets(
    active_group_id: UUID,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> list[ChangeSetResponse]:
    result = _change_set_service(authorization_repository, change_set_repository).list_for_group(
        principal, active_group_id
    )
    return [ChangeSetResponse.model_validate(item) for item in result]


@router.get("/changesets/{change_set_id}", tags=["change-sets"])
async def get_change_set(
    change_set_id: UUID,
    active_group_id: UUID,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).get(
        principal, active_group_id, change_set_id
    )
    return ChangeSetResponse.model_validate(result)


@router.patch("/changesets/{change_set_id}", tags=["change-sets"])
async def update_change_set(
    change_set_id: UUID,
    body: ChangeSetMetadataUpdateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).update_metadata(
        principal,
        body.active_group_id,
        change_set_id,
        body.title,
        body.description,
        body.expected_revision,
    )
    return ChangeSetResponse.model_validate(result)


@router.post("/changesets/{change_set_id}/operations/rules", tags=["change-sets"])
async def add_rule_operation(
    change_set_id: UUID,
    body: DraftRuleOperationRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).add_operation(
        principal,
        body.active_group_id,
        change_set_id,
        ChangeOperationKind(body.kind),
        body.rule.model_dump(mode="json", exclude_none=True),
    )
    return ChangeSetResponse.model_validate(result)


@router.post("/changesets/{change_set_id}/operations/objects", tags=["change-sets"])
async def add_object_operation(
    change_set_id: UUID,
    body: DraftObjectOperationRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).add_operation(
        principal,
        body.active_group_id,
        change_set_id,
        ChangeOperationKind(body.kind),
        body.object.model_dump(mode="json", exclude_none=True),
    )
    return ChangeSetResponse.model_validate(result)


@router.post("/changesets/{change_set_id}/operations/categories", tags=["change-sets"])
async def add_category_operation(
    change_set_id: UUID,
    body: DraftCategoryOperationRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).add_operation(
        principal,
        body.active_group_id,
        change_set_id,
        ChangeOperationKind.ENSURE_RULE_CATEGORY,
        {"policy_id": str(body.policy_id)} if body.policy_id else {},
    )
    return ChangeSetResponse.model_validate(result)


@router.put("/changesets/{change_set_id}/operations/{operation_id}", tags=["change-sets"])
async def update_change_set_operation(  # noqa: PLR0913, PLR0917
    change_set_id: UUID,
    operation_id: UUID,
    body: DraftOperationUpdateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).update_operation(
        principal,
        body.active_group_id,
        change_set_id,
        operation_id,
        body.payload,
        body.expected_revision,
    )
    return ChangeSetResponse.model_validate(result)


@router.delete("/changesets/{change_set_id}/operations/{operation_id}", tags=["change-sets"])
async def remove_change_set_operation(  # noqa: PLR0913, PLR0917
    change_set_id: UUID,
    operation_id: UUID,
    active_group_id: UUID,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).remove_operation(
        principal, active_group_id, change_set_id, operation_id
    )
    return ChangeSetResponse.model_validate(result)


@router.post("/changesets/{change_set_id}/preflight", tags=["change-sets"])
async def preflight_change_set(
    change_set_id: UUID,
    body: ChangeSetActionRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).preflight(
        principal, body.active_group_id, change_set_id
    )
    return ChangeSetResponse.model_validate(result)


@router.post("/changesets/{change_set_id}/refresh", tags=["change-sets"])
async def refresh_change_set(
    change_set_id: UUID,
    body: ChangeSetActionRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).refresh(
        principal, body.active_group_id, change_set_id
    )
    return ChangeSetResponse.model_validate(result)


@router.post("/changesets/{change_set_id}/execute", status_code=202, tags=["change-sets"])
async def execute_change_set(  # noqa: PLR0913, PLR0917 -- security dependencies are explicit
    change_set_id: UUID,
    body: ChangeSetActionRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
    dispatch: ChangeSetExecutionDispatcherDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).queue_execution(
        principal,
        body.active_group_id,
        change_set_id,
        dispatch,
    )
    return ChangeSetResponse.model_validate(result)


@router.post("/changesets/{change_set_id}/retry", tags=["change-sets"])
async def retry_change_set(  # noqa: PLR0913, PLR0917 -- security dependencies are explicit
    change_set_id: UUID,
    body: ChangeSetActionRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
    dispatch: ChangeSetExecutionDispatcherDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).retry_execution(
        principal,
        body.active_group_id,
        change_set_id,
        dispatch,
    )
    return ChangeSetResponse.model_validate(result)


@router.get("/changesets/{change_set_id}/transactions", tags=["change-sets"])
async def get_change_set_transactions(
    change_set_id: UUID,
    active_group_id: UUID,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> list[dict[str, object]]:
    result = _change_set_service(authorization_repository, change_set_repository).get(
        principal, active_group_id, change_set_id
    )
    return cast("list[dict[str, object]]", result["transactions"])


@router.post("/changesets/{change_set_id}/cancel", tags=["change-sets"])
async def cancel_change_set(
    change_set_id: UUID,
    body: ChangeSetActionRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).cancel(
        principal, body.active_group_id, change_set_id
    )
    return ChangeSetResponse.model_validate(result)


@router.delete("/changesets/{change_set_id}", status_code=204, tags=["change-sets"])
async def delete_change_set(
    change_set_id: UUID,
    active_group_id: UUID,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> None:
    _change_set_service(authorization_repository, change_set_repository).delete(
        principal, active_group_id, change_set_id
    )


@router.get("/admin/authorization", tags=["administration"])
async def administration_snapshot(
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    administration_repository: AdministrationRepositoryDependency,
) -> AdministrationSnapshotResponse:
    result = AdministrationService(authorization_repository, administration_repository).snapshot(
        principal
    )
    return AdministrationSnapshotResponse.model_validate(result)


def _provider_connection_service(
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
    provider_factory: ProviderFactory | None = None,
) -> ProviderConnectionService:
    return ProviderConnectionService(
        authorization_repository, connection_repository, secret_store, provider_factory
    )


@router.get("/admin/provider-connections", tags=["provider-connections"])
async def list_provider_connections(  # noqa: PLR0913, PLR0917 -- FastAPI dependencies
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> ProviderConnectionPageResponse:
    items, total = _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    ).list(principal, offset, limit)
    return ProviderConnectionPageResponse(
        items=[ProviderConnectionResponse.model_validate(item) for item in items], total=total
    )


@router.get("/admin/provider-connections/guidance/{provider_type}", tags=["provider-connections"])
async def provider_connection_guidance(
    provider_type: ProviderKind,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> dict[str, object]:
    service = _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    )
    # Listing is a cheap way to enforce the same explicit provider-admin boundary.
    service.list(principal, 0, 1)
    return service.guidance(provider_type)


@router.get("/admin/provider-connections/{connection_id}", tags=["provider-connections"])
async def get_provider_connection(
    connection_id: UUID,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> ProviderConnectionResponse:
    result = _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    ).get(principal, connection_id)
    return ProviderConnectionResponse.model_validate(result)


@router.post("/admin/provider-connections", status_code=201, tags=["provider-connections"])
async def create_provider_connection(
    body: ProviderConnectionCreateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> ProviderConnectionResponse:
    values: dict[str, object] = {
        "provider_type": body.provider_type,
        "display_name": body.display_name,
        "base_endpoint": body.base_endpoint,
        "region": body.region,
        "tls_mode": body.tls_mode,
        "username": body.username,
        "password": body.password.get_secret_value() if body.password else None,
        "token": body.token.get_secret_value() if body.token else None,
        "ca_certificate": body.ca_certificate.get_secret_value() if body.ca_certificate else None,
        "sync_interval_minutes": body.sync_interval_minutes,
    }
    result = _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    ).create(principal, values)
    return ProviderConnectionResponse.model_validate(result)


@router.patch(
    "/admin/provider-connections/{connection_id}/configuration",
    tags=["provider-connections"],
)
async def update_provider_connection(  # noqa: PLR0913, PLR0917 -- FastAPI dependencies
    connection_id: UUID,
    body: ProviderConnectionUpdateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> ProviderConnectionResponse:
    values = body.model_dump(exclude_none=True)
    expected_revision = int(values.pop("expected_revision"))
    result = _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    ).update(principal, connection_id, expected_revision, values)
    return ProviderConnectionResponse.model_validate(result)


@router.put(
    "/admin/provider-connections/{connection_id}/credentials",
    tags=["provider-connections"],
)
async def rotate_provider_credentials(  # noqa: PLR0913, PLR0917 -- FastAPI dependencies
    connection_id: UUID,
    body: ProviderCredentialUpdateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> ProviderConnectionResponse:
    values = {
        key: value
        for key, value in {
            "username": body.username,
            "password": body.password.get_secret_value() if body.password else None,
            "token": body.token.get_secret_value() if body.token else None,
            "ca_certificate": body.ca_certificate.get_secret_value()
            if body.ca_certificate
            else None,
        }.items()
        if value is not None
    }
    result = _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    ).rotate_credentials(principal, connection_id, body.expected_revision, values)
    return ProviderConnectionResponse.model_validate(result)


@router.post("/admin/provider-connections/{connection_id}/test", tags=["provider-connections"])
async def test_provider_connection(  # noqa: PLR0913, PLR0917 -- FastAPI dependencies
    connection_id: UUID,
    request: Request,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
    provider_factory: ProviderFactoryDependency,
) -> ProviderConnectionTestResponse:
    result = await _provider_connection_service(
        authorization_repository, connection_repository, secret_store, provider_factory
    ).test(
        principal,
        connection_id,
        getattr(request.state, "correlation_id", None),
    )
    return ProviderConnectionTestResponse.model_validate(result)


@router.put(
    "/admin/provider-connections/{connection_id}/lifecycle",
    tags=["provider-connections"],
)
async def set_provider_connection_lifecycle(  # noqa: PLR0913, PLR0917 -- FastAPI dependencies
    connection_id: UUID,
    body: ProviderLifecycleRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> ProviderConnectionResponse:
    result = _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    ).set_lifecycle(principal, connection_id, body.expected_revision, body.lifecycle)
    return ProviderConnectionResponse.model_validate(result)


@router.put(
    "/admin/provider-connections/{connection_id}/write-gate",
    tags=["provider-connections"],
)
async def set_provider_connection_write_gate(  # noqa: PLR0913, PLR0917
    connection_id: UUID,
    body: ProviderWriteGateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> ProviderConnectionResponse:
    result = _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    ).set_write_enabled(
        principal,
        connection_id,
        body.expected_revision,
        body.enabled,
        body.acknowledge_configuration_mutation,
        body.acknowledge_unvalidated_non_production_writes,
    )
    return ProviderConnectionResponse.model_validate(result)


@router.post(
    "/admin/provider-connections/{connection_id}/sync",
    status_code=202,
    tags=["provider-connections"],
)
async def request_provider_connection_sync(  # noqa: PLR0913, PLR0917 -- FastAPI dependencies
    connection_id: UUID,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    connection_repository: ProviderConnectionRepositoryDependency,
    secret_store: SecretStoreDependency,
    dispatch: ProviderSyncDispatcherDependency,
) -> dict[str, str]:
    _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    ).request_sync(
        principal,
        connection_id,
        dispatch,
    )
    return {"status": "QUEUED", "connection_id": str(connection_id)}


@router.post("/admin/users", status_code=201, tags=["administration"])
async def create_user(
    body: UserCreateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    administration_repository: AdministrationRepositoryDependency,
) -> dict[str, object]:
    return AdministrationService(authorization_repository, administration_repository).create_user(
        principal, body.model_dump()
    )


@router.post("/admin/groups", status_code=201, tags=["administration"])
async def create_group(
    body: GroupCreateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    administration_repository: AdministrationRepositoryDependency,
) -> dict[str, object]:
    return AdministrationService(authorization_repository, administration_repository).create_group(
        principal, body.model_dump()
    )


@router.patch("/admin/{resource}/{resource_id}", tags=["administration"])
async def update_enabled(  # noqa: PLR0913, PLR0917 -- FastAPI dependency signature
    resource: str,
    resource_id: UUID,
    body: EnabledUpdateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    administration_repository: AdministrationRepositoryDependency,
) -> dict[str, object]:
    return AdministrationService(
        authorization_repository, administration_repository
    ).update_enabled(principal, resource, resource_id, body.enabled, body.expected_revision)


@router.patch("/admin/users/{user_id}/role", tags=["administration"])
async def update_user_role(
    user_id: UUID,
    body: UserRoleUpdateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    administration_repository: AdministrationRepositoryDependency,
) -> dict[str, object]:
    return AdministrationService(
        authorization_repository, administration_repository
    ).update_user_role(principal, user_id, body.role, body.expected_revision)


@router.put("/admin/{resource}", tags=["administration"])
async def upsert_authorization_resource(
    resource: str,
    body: AuthorizationResourceUpsertRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    administration_repository: AdministrationRepositoryDependency,
) -> dict[str, object]:
    values = body.model_dump(exclude_none=True)
    expected_revision = values.pop("expected_revision", None)
    return AdministrationService(authorization_repository, administration_repository).upsert(
        principal, resource, values, expected_revision
    )


@router.delete("/admin/{resource}/{resource_id}", status_code=204, tags=["administration"])
async def revoke_authorization_resource(  # noqa: PLR0913, PLR0917 -- dependency signature
    resource: str,
    resource_id: UUID,
    expected_revision: Annotated[int, Query(ge=1)],
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    administration_repository: AdministrationRepositoryDependency,
) -> None:
    AdministrationService(authorization_repository, administration_repository).revoke(
        principal, resource, resource_id, expected_revision
    )


@router.get("/overview", tags=["inventory"])
async def overview(
    principal: PrincipalDependency,
    repository: RepositoryDependency,
    providers: Annotated[tuple[ProviderReader, ...], Depends(get_provider_readers)],
) -> OverviewResponse:
    service = OverviewService(repository, providers)
    result = await service.get(principal)
    return OverviewResponse.model_validate(result)


@router.get("/firewall-managers", tags=["inventory"])
async def firewall_managers(
    principal: PrincipalDependency,
    repository: InventoryRepositoryDependency,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> PageResponse[ManagerResponse]:
    result = InventoryService(repository).managers(principal, cursor, limit)
    return PageResponse[ManagerResponse](
        items=[ManagerResponse.model_validate(item) for item in result.items],
        total=result.total,
        next_cursor=result.next_cursor,
    )


@router.get("/policies", tags=["inventory"])
async def policies(
    principal: PrincipalDependency,
    repository: InventoryRepositoryDependency,
    manager_id: UUID | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> PageResponse[PolicyResponse]:
    result = InventoryService(repository).policies(principal, manager_id, cursor, limit)
    return PageResponse[PolicyResponse](
        items=[PolicyResponse.model_validate(item) for item in result.items],
        total=result.total,
        next_cursor=result.next_cursor,
    )


@router.get("/rules", tags=["inventory"])
async def rules(
    principal: PrincipalDependency,
    repository: InventoryRepositoryDependency,
    policy_id: UUID | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> PageResponse[RuleResponse]:
    result = InventoryService(repository).rules(principal, policy_id, cursor, limit)
    return PageResponse[RuleResponse](
        items=[RuleResponse.model_validate(item) for item in result.items],
        total=result.total,
        next_cursor=result.next_cursor,
    )


@router.get("/objects", tags=["inventory"])
async def objects(
    principal: PrincipalDependency,
    repository: InventoryRepositoryDependency,
    manager_id: UUID | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> PageResponse[ObjectResponse]:
    result = InventoryService(repository).objects(principal, manager_id, cursor, limit)
    return PageResponse[ObjectResponse](
        items=[ObjectResponse.model_validate(item) for item in result.items],
        total=result.total,
        next_cursor=result.next_cursor,
    )


@router.get("/providers/status", tags=["inventory"])
async def provider_status(
    principal: PrincipalDependency,
    repository: InventoryRepositoryDependency,
) -> list[ProviderStatusResponse]:
    result = InventoryService(repository).provider_status(principal)
    return [ProviderStatusResponse.model_validate(item) for item in result]
