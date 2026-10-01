"""Thin versioned REST routes."""

from typing import Annotated, Literal, cast
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
    SessionDependency,
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
    DeploymentPlanRequest,
    DeploymentResponse,
    DeploymentRollbackRequest,
    DevelopmentIdentityResponse,
    DraftCategoryOperationRequest,
    DraftObjectOperationRequest,
    DraftOperationUpdateRequest,
    DraftRuleOperationRequest,
    EnabledUpdateRequest,
    GroupApprovalUpdateRequest,
    GroupCreateRequest,
    HealthResponse,
    ManagerResponse,
    ObjectResponse,
    OverviewResponse,
    PageResponse,
    PendingApprovalsResponse,
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
    ReconciliationActionResponse,
    ReconciliationRestoreRequest,
    RuleResponse,
    SessionResponse,
    SynchronizationDiscrepancyResponse,
    UserCreateRequest,
    UserRoleUpdateRequest,
)
from firewall_manager.application.administration import AdministrationService
from firewall_manager.application.authorization import require_action
from firewall_manager.application.changesets import ChangeSetService
from firewall_manager.application.delegated import DelegatedPolicyService
from firewall_manager.application.deployments import DeploymentService
from firewall_manager.application.errors import InvalidChangeSetStateError, ResourceOutOfScopeError
from firewall_manager.application.inventory import InventoryService
from firewall_manager.application.overview import OverviewService
from firewall_manager.application.ports import ProviderFactory, ProviderReader
from firewall_manager.application.provider_connections import ProviderConnectionService
from firewall_manager.application.reconciliation import ReconciliationService
from firewall_manager.domain.models import (
    Action,
    ChangeOperationKind,
    ChangeSetState,
    DelegatedPolicyContext,
    ProviderKind,
)
from firewall_manager.persistence.models import ChangeSet, Deployment
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
async def delegated_context(  # noqa: PLR0913, PLR0917 -- explicit delegated context filters
    request: Request,
    active_group_id: UUID,
    policy_id: UUID,
    principal: PrincipalDependency,
    repository: AuthorizationRepositoryDependency,
    include_applications: bool = True,
    include_rules: bool = True,
) -> DelegatedContextResponse:
    result = DelegatedPolicyService(repository).context_view(
        DelegatedPolicyContext(principal, active_group_id, policy_id),
        include_applications=include_applications,
        include_rules=include_rules,
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


@router.get("/approvals/pending", tags=["approvals"])
async def pending_approvals(
    principal: PrincipalDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> PendingApprovalsResponse:
    require_action(principal, Action.APPROVE)
    result = change_set_repository.list_pending_approvals(principal)
    return PendingApprovalsResponse(count=len(result), items=result)


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


@router.get("/admin/changesets", tags=["administration"])
async def admin_change_sets(
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> list[ChangeSetResponse]:
    result = _change_set_service(authorization_repository, change_set_repository).list_for_admin(
        principal
    )
    return [ChangeSetResponse.model_validate(item) for item in result]


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


@router.post("/changesets/{change_set_id}/approve", tags=["change-sets"])
async def approve_change_set(
    change_set_id: UUID,
    body: ChangeSetActionRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).approve(
        principal, body.active_group_id, change_set_id
    )
    return ChangeSetResponse.model_validate(result)


@router.post("/deployments/plan", status_code=201, tags=["deployments"])
async def create_deployment_plan(
    body: DeploymentPlanRequest, principal: PrincipalDependency, session: SessionDependency
) -> DeploymentResponse:
    result = DeploymentService(session).plan(principal, body.change_set_id, body.target_device_ids)
    session.commit()
    return DeploymentResponse.model_validate(result)


@router.get("/deployments", tags=["deployments"])
async def list_deployments(
    principal: PrincipalDependency, session: SessionDependency
) -> list[DeploymentResponse]:
    return [
        DeploymentResponse.model_validate(item)
        for item in DeploymentService(session).list(principal)
    ]


@router.get("/deployments/{deployment_id}/changesets", tags=["deployments"])
async def list_deployment_change_sets(
    deployment_id: UUID,
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> list[ChangeSetResponse]:
    deployment = session.get(Deployment, deployment_id)
    if deployment is None or deployment.organization_id != principal.organization_id:
        raise ResourceOutOfScopeError
    service = _change_set_service(authorization_repository, change_set_repository)
    result: list[ChangeSetResponse] = []
    for change_set_id in deployment.included_change_set_ids:
        change_set = session.get(ChangeSet, UUID(change_set_id))
        if change_set is None:
            continue
        result.append(
            ChangeSetResponse.model_validate(
                service.get(principal, change_set.acting_group_id, change_set.id)
            )
        )
    return result


@router.post(
    "/admin/provider-connections/{connection_id}/deploy", status_code=202, tags=["deployments"]
)
async def force_connector_deployment(
    connection_id: UUID, principal: PrincipalDependency, session: SessionDependency
) -> DeploymentResponse | dict[str, object]:
    result = DeploymentService(session).queue_connector(principal, connection_id, force=True)
    session.commit()
    if result.get("id"):
        from firewall_manager.worker.tasks import execute_deployment_batch  # noqa: PLC0415

        execute_deployment_batch.send(str(result["id"]))
    if result.get("status") == "NO_PENDING_CHANGES":
        return result
    return DeploymentResponse.model_validate(result)


@router.post("/deployments/{deployment_id}/approve", tags=["deployments"])
async def approve_deployment(
    deployment_id: UUID, principal: PrincipalDependency, session: SessionDependency
) -> DeploymentResponse:
    result = DeploymentService(session).approve(principal, deployment_id)
    session.commit()
    return DeploymentResponse.model_validate(result)


@router.post("/deployments/{deployment_id}/retry", status_code=202, tags=["deployments"])
async def retry_deployment(
    deployment_id: UUID, principal: PrincipalDependency, session: SessionDependency
) -> DeploymentResponse | dict[str, object]:
    result = DeploymentService(session).retry(principal, deployment_id)
    session.commit()
    if result.get("id"):
        from firewall_manager.worker.tasks import execute_deployment_batch  # noqa: PLC0415

        execute_deployment_batch.send(str(result["id"]))
    if result.get("status") == "NO_PENDING_CHANGES":
        return result
    return DeploymentResponse.model_validate(result)


@router.post("/deployments/{deployment_id}/rollback", status_code=201, tags=["deployments"])
async def rollback_deployment(  # noqa: PLR0913, PLR0917 -- explicit security dependencies
    deployment_id: UUID,
    body: DeploymentRollbackRequest,
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
    dispatch: ChangeSetExecutionDispatcherDependency,
) -> list[ChangeSetResponse]:
    deployment = next(
        (
            item
            for item in DeploymentService(session).list(principal)
            if item["id"] == deployment_id
        ),
        None,
    )
    if deployment is None:
        raise InvalidChangeSetStateError(details={"code": "ROLLBACK_CHANGESET_SCOPE_UNCLEAR"})
    included_ids = {UUID(value) for value in deployment["included_change_set_ids"]}
    if not set(body.selected_change_set_ids).issubset(included_ids):
        raise ResourceOutOfScopeError
    service = _change_set_service(authorization_repository, change_set_repository)
    results: list[ChangeSetResponse] = []
    for original_id in body.selected_change_set_ids:
        original = session.get(ChangeSet, original_id)
        if original is None or original.organization_id != principal.organization_id:
            raise ResourceOutOfScopeError
        rollback = service.create_rollback(principal, original.acting_group_id, original.id)
        if rollback["state"] == ChangeSetState.READY.value and not rollback.get(
            "approval_required"
        ):
            rollback = service.queue_execution(
                principal,
                original.acting_group_id,
                UUID(str(rollback["id"])),
                dispatch,
            )
        results.append(ChangeSetResponse.model_validate(rollback))
    session.commit()
    return results


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


@router.delete("/admin/changesets/{change_set_id}", status_code=204, tags=["administration"])
async def admin_delete_change_set(
    change_set_id: UUID,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> None:
    _change_set_service(authorization_repository, change_set_repository).delete_for_admin(
        principal, change_set_id
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
        "applications_sync_interval_minutes": body.applications_sync_interval_minutes,
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
    mode: Literal["FULL", "NON_APPLICATIONS", "APPLICATIONS"] = "FULL",
) -> dict[str, str]:
    _provider_connection_service(
        authorization_repository, connection_repository, secret_store
    ).request_sync(
        principal,
        connection_id,
        dispatch,
        mode,
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


@router.patch("/admin/groups/{group_id}/approval", tags=["administration"])
async def update_group_approval(
    group_id: UUID,
    body: GroupApprovalUpdateRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    administration_repository: AdministrationRepositoryDependency,
) -> dict[str, object]:
    return AdministrationService(
        authorization_repository, administration_repository
    ).update_group_approval(principal, group_id, body.approval_required, body.expected_revision)


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


@router.get("/synchronization/discrepancies", tags=["inventory"])
async def synchronization_discrepancies(  # noqa: PLR0913, PLR0917 -- bounded filter surface
    principal: PrincipalDependency,
    repository: InventoryRepositoryDependency,
    manager_id: UUID | None = None,
    policy_id: UUID | None = None,
    resource_type: Annotated[str | None, Query(max_length=50)] = None,
    state: Annotated[str | None, Query(max_length=30)] = None,
    connection_id: UUID | None = None,
) -> list[SynchronizationDiscrepancyResponse]:
    result = InventoryService(repository).synchronization_discrepancies(
        principal, manager_id, policy_id, resource_type, state, connection_id
    )
    return [SynchronizationDiscrepancyResponse.model_validate(item) for item in result]


@router.post("/synchronization/discrepancies/{drift_id}/accept-provider-state", tags=["inventory"])
async def accept_provider_state(
    drift_id: UUID,
    principal: PrincipalDependency,
    repository: InventoryRepositoryDependency,
) -> dict[str, object]:
    return InventoryService(repository).accept_provider_state(principal, drift_id)


@router.post(
    "/synchronization/discrepancies/{drift_id}/restore-proposal",
    tags=["inventory"],
)
async def restore_provider_state_proposal(  # noqa: PLR0913, PLR0917 -- explicit security dependencies
    drift_id: UUID,
    body: ReconciliationRestoreRequest,
    principal: PrincipalDependency,
    inventory_repository: InventoryRepositoryDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ReconciliationActionResponse:
    result = ReconciliationService(
        inventory_repository, authorization_repository, change_set_repository
    ).restore(principal, drift_id, body.active_group_id)
    return ReconciliationActionResponse.model_validate(result)
