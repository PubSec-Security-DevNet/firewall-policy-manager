"""Thin versioned REST routes."""

import json
from datetime import UTC, datetime
from typing import Annotated, Literal, cast
from urllib.parse import quote
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import PlainTextResponse, RedirectResponse
from redis import Redis
from sqlalchemy import select

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
    AdministratorContactResponse,
    ApiTokenCreatedResponse,
    ApiTokenCreateRequest,
    ApiTokenResponse,
    AuthorizationResourceUpsertRequest,
    ChangeSetActionRequest,
    ChangeSetCreateRequest,
    ChangeSetMetadataUpdateRequest,
    ChangeSetNotificationDismissRequest,
    ChangeSetRejectionRequest,
    ChangeSetResponse,
    DefaultContextRequest,
    DefaultContextResponse,
    DelegatedContextResponse,
    DelegatedPolicySummary,
    DeploymentPauseRequest,
    DeploymentPlanRequest,
    DeploymentResponse,
    DeploymentRollbackRequest,
    DevelopmentIdentityResponse,
    DraftCategoryOperationRequest,
    DraftObjectOperationRequest,
    DraftOperationUpdateRequest,
    DraftRuleOperationRequest,
    EnabledUpdateRequest,
    ExternalIdentityCreateRequest,
    ExternalIdentityResponse,
    GroupApprovalUpdateRequest,
    GroupCreateRequest,
    HealthResponse,
    InitialSetupRequest,
    InitialSetupResponse,
    InitialSetupStatusResponse,
    InitialSetupTestRequest,
    InitialSetupTestResponse,
    ManagerResponse,
    ObjectResponse,
    OidcLoginProviderResponse,
    OidcProviderCreateRequest,
    OidcProviderResponse,
    OidcProviderSecretRequest,
    OidcProviderUpdateRequest,
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
    ProxyStartRequest,
    ReconciliationActionResponse,
    ReconciliationRestoreRequest,
    RuleResponse,
    SessionResponse,
    SmtpSettingsRequest,
    SmtpSettingsResponse,
    SynchronizationDiscrepancyResponse,
    UserCreateRequest,
    UserRoleUpdateRequest,
)
from firewall_manager.application.administration import AdministrationService
from firewall_manager.application.authorization import require_action
from firewall_manager.application.changesets import ChangeSetService
from firewall_manager.application.delegated import DelegatedPolicyService
from firewall_manager.application.deployments import DeploymentService
from firewall_manager.application.errors import (
    ApplicationError,
    InvalidChangeSetStateError,
    InvalidInputError,
    NotAuthenticatedError,
    ResourceOutOfScopeError,
)
from firewall_manager.application.inventory import InventoryService
from firewall_manager.application.oidc_admin import OidcAdministrationService
from firewall_manager.application.overview import OverviewService
from firewall_manager.application.ports import ProviderFactory, ProviderReader
from firewall_manager.application.provider_connections import ProviderConnectionService
from firewall_manager.application.reconciliation import ReconciliationService
from firewall_manager.application.setup import InitialSetupService
from firewall_manager.application.smtp_admin import SmtpAdministrationService
from firewall_manager.config import OidcProviderConfig, get_settings
from firewall_manager.domain.models import (
    Action,
    ChangeOperationKind,
    ChangeSetState,
    DelegatedPolicyContext,
    ProviderKind,
)
from firewall_manager.observability import render as render_metrics
from firewall_manager.persistence.models import (
    ApiToken,
    AuthenticationEvent,
    ChangeSet,
    Deployment,
    OidcProvider,
    User,
)
from firewall_manager.providers.transactions import (
    HttpMockTransactionExecutor,
    ProviderTransactionExecutor,
)
from firewall_manager.security import api_tokens
from firewall_manager.security.oidc import (
    STATE_COOKIE_PREFIX,
    OidcService,
    _unb64,
    _verify,
    redirect_uri,
)

router = APIRouter(prefix="/api/v1")
dev_router = APIRouter(prefix="/api/v1/dev", tags=["development-auth"])
auth_router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


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


@auth_router.get("/{provider_id}/login", include_in_schema=True)
async def oidc_login(
    provider_id: str,
    session: SessionDependency,
) -> RedirectResponse:
    """Start Authorization Code flow for a deployment-configured provider."""
    redirect = RedirectResponse("/", status_code=303)
    redirect.delete_cookie("fm_setup_test", path="/api/v1/auth")
    target = await OidcService(session, get_settings()).begin(provider_id, redirect)
    redirect.headers["location"] = target
    return redirect


@auth_router.get("/{provider_id}/test", include_in_schema=True)
async def oidc_test(
    provider_id: str,
    session: SessionDependency,
) -> RedirectResponse:
    """Validate an OIDC provider without requiring an application-user mapping."""
    redirect = RedirectResponse(
        f"{get_settings().app_public_url.rstrip('/')}/?oidc_test=success", status_code=303
    )
    target = await OidcService(session, get_settings()).begin(provider_id, redirect, test_only=True)
    redirect.headers["location"] = target
    return redirect


@auth_router.get("/providers", include_in_schema=True)
async def oidc_login_providers(session: SessionDependency) -> list[OidcLoginProviderResponse]:
    """Expose only safe provider labels for the unauthenticated sign-in page."""
    configured = {
        row.provider_id: OidcLoginProviderResponse(
            provider_id=row.provider_id, kind=row.kind, display_name=row.display_name
        )
        for row in session.scalars(select(OidcProvider).where(OidcProvider.enabled.is_(True)))
    }
    for provider in get_settings().oidc_provider_configs():
        configured.setdefault(
            provider.id,
            OidcLoginProviderResponse(
                provider_id=provider.id, kind=provider.kind, display_name=provider.display_name
            ),
        )
    return sorted(configured.values(), key=lambda item: item.display_name.casefold())


@auth_router.get("/contact", include_in_schema=True)
async def administrator_contact() -> AdministratorContactResponse:
    """Expose only the deployment-configured administrator contact address."""
    return AdministratorContactResponse(email=get_settings().administrator_email or None)


@auth_router.get("/setup/status", include_in_schema=True)
async def initial_setup_status(
    session: SessionDependency,
    secret_store: SecretStoreDependency,
    recovery_code: Annotated[str | None, Query()] = None,
) -> InitialSetupStatusResponse:
    service = InitialSetupService(session, secret_store)
    return InitialSetupStatusResponse(
        available=service.available(),
        recovery=service.recovery_available(recovery_code),
    )


@auth_router.post("/setup", status_code=201, include_in_schema=True)
async def initial_setup(
    body: InitialSetupRequest,
    session: SessionDependency,
    secret_store: SecretStoreDependency,
) -> InitialSetupResponse:
    values = body.model_dump(exclude={"provider_client_secret", "recovery_code", "setup_test_id"})
    values["admin_issuer"] = body.provider_issuer_url
    values["provider_client_secret"] = body.provider_client_secret.get_secret_value()
    await _test_setup_provider(
        values, body.recovery_code, body.setup_test_id, session, secret_store
    )
    result = InitialSetupService(session, secret_store).create(values)
    if body.setup_test_id:
        Redis.from_url(get_settings().redis_url, decode_responses=True).delete(
            f"firewall-manager:setup-test:{body.setup_test_id}"
        )
    return InitialSetupResponse.model_validate(result)


@auth_router.post("/setup/test", include_in_schema=True)
async def test_initial_setup(
    body: InitialSetupTestRequest,
    session: SessionDependency,
    secret_store: SecretStoreDependency,
) -> InitialSetupTestResponse:
    values = body.model_dump(exclude={"provider_client_secret", "recovery_code"})
    values["admin_issuer"] = body.provider_issuer_url
    values["provider_client_secret"] = body.provider_client_secret.get_secret_value()
    service = InitialSetupService(session, secret_store)
    if not service.available() and not service.recovery_available(body.recovery_code):
        raise ResourceOutOfScopeError
    config = _setup_provider_config(values)
    await OidcService(session, get_settings()).discover(config)
    draft_id = str(UUID(int=uuid4().int))
    Redis.from_url(get_settings().redis_url, decode_responses=True).setex(
        f"firewall-manager:setup-test:{draft_id}",
        600,
        json.dumps(
            {
                **values,
                "recovery_code": body.recovery_code,
                "provider_client_secret": config.client_secret.get_secret_value(),
                "tested": False,
            }
        ),
    )
    return InitialSetupTestResponse(login_url=f"/api/v1/auth/setup/test/login?draft_id={draft_id}")


@auth_router.get("/setup/test/draft/{draft_id}")
async def setup_test_draft(draft_id: str) -> dict[str, object]:
    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    raw = redis.get(f"firewall-manager:setup-test:{draft_id}")
    redis.close()
    if not raw:
        raise InvalidInputError(details={"reason": "test sign-in expired; test again"})
    draft = json.loads(raw)
    return {
        key: value
        for key, value in draft.items()
        if key not in {"provider_client_secret", "recovery_code", "tested"}
    }


async def _test_setup_provider(
    values: dict[str, object],
    recovery_code: str | None,
    setup_test_id: str | None,
    session: SessionDependency,
    secret_store: SecretStoreDependency,
) -> OidcProviderConfig:
    service = InitialSetupService(session, secret_store)
    if not setup_test_id:
        raise InvalidInputError(details={"reason": "test sign-in must succeed before saving"})
    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    draft = redis.get(f"firewall-manager:setup-test:{setup_test_id}")
    redis.close()
    if not draft:
        raise InvalidInputError(details={"reason": "test sign-in expired; test again"})
    draft_values = json.loads(draft)
    effective_recovery_code = recovery_code or draft_values.get("recovery_code")
    if not service.available() and not service.recovery_available(effective_recovery_code):
        raise ResourceOutOfScopeError
    values["admin_subject"] = draft_values.get("admin_subject")
    if any(
        values.get(key) != draft_values.get(key)
        for key in draft_values
        if key not in {"admin_email", "recovery_code", "tested", "provider_client_secret"}
    ):
        raise InvalidInputError(details={"reason": "provider settings changed; test again"})
    if not draft_values.get("tested"):
        raise InvalidInputError(details={"reason": "test sign-in did not succeed"})
    values["recovery_code"] = effective_recovery_code
    values["provider_client_secret"] = draft_values["provider_client_secret"]
    return _setup_provider_config(values)


def _setup_provider_config(values: dict[str, object]) -> OidcProviderConfig:
    try:
        return OidcProviderConfig.model_validate(
            {
                "id": values.get("provider_id"),
                "kind": values.get("provider_kind"),
                "display_name": values.get("provider_display_name"),
                "issuer_url": values.get("provider_issuer_url"),
                "client_id": values.get("provider_client_id"),
                "client_secret": values.get("provider_client_secret"),
            }
        )
    except ValueError as exc:
        raise InvalidInputError(details={"reason": "provider configuration is invalid"}) from exc


@auth_router.get("/setup/test/login")
async def setup_test_login(draft_id: str, session: SessionDependency) -> RedirectResponse:
    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    draft = redis.get(f"firewall-manager:setup-test:{draft_id}")
    redis.close()
    if not draft:
        raise InvalidInputError(details={"reason": "test sign-in expired; test again"})
    config = _setup_provider_config(json.loads(draft))
    redirect = RedirectResponse("/", status_code=303)
    target = await OidcService(session, get_settings()).begin_ephemeral_test(
        config,
        redirect,
        redirect_uri(get_settings(), config.id),
        draft_id,
    )
    redirect.headers["location"] = target
    return redirect


@auth_router.get("/setup/test/callback")
async def setup_test_callback(
    code: str,
    state: str,
    request: Request,
    session: SessionDependency,
) -> RedirectResponse:
    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        raw_state = _verify(state, get_settings())
        if raw_state is None:
            raise NotAuthenticatedError
        state_payload = json.loads(_unb64(raw_state))
        draft_id = str(state_payload["draft_id"])
        draft_json = redis.get(f"firewall-manager:setup-test:{draft_id}")
        if not draft_json:
            raise NotAuthenticatedError
        result = await OidcService(session, get_settings()).complete_ephemeral_test(
            _setup_provider_config(json.loads(draft_json)),
            code,
            state,
            request.cookies.get("fm_setup_test"),
            redirect_uri(get_settings(), _setup_provider_config(json.loads(draft_json)).id),
        )
        draft = json.loads(draft_json)
        email = result["claims"].get("email")
        if (
            not isinstance(email, str)
            or email.casefold() != str(draft.get("admin_email", "")).casefold()
        ):
            raise NotAuthenticatedError
        subject = result["claims"].get("sub")
        if not isinstance(subject, str) or not subject:
            raise NotAuthenticatedError
        draft["admin_subject"] = subject
        draft["tested"] = True
        redis.setex(f"firewall-manager:setup-test:{draft_id}", 600, json.dumps(draft))
    except (ApplicationError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        redis.close()
        return RedirectResponse("/?setup_test=failed", status_code=303)
    redis.close()
    recovery_query = (
        f"&setup_recovery={quote(str(draft.get('recovery_code')), safe='')}"
        if draft.get("recovery_code")
        else ""
    )
    response = RedirectResponse(
        f"/?setup_test=success&setup_test_id={draft_id}{recovery_query}", status_code=303
    )
    response.delete_cookie("fm_setup_test", path="/api/v1/auth")
    return response


@auth_router.get("/{provider_id}/callback", include_in_schema=True)
async def oidc_callback(
    provider_id: str,
    code: str,
    state: str,
    request: Request,
    session: SessionDependency,
) -> RedirectResponse:
    if request.cookies.get("fm_setup_test"):
        return await setup_test_callback(code, state, request, session)
    response = RedirectResponse(f"{get_settings().app_public_url.rstrip('/')}/", status_code=303)
    try:
        test_only = await OidcService(session, get_settings()).callback(
            provider_id, code, state, response, request.cookies.get(f"fm_oidc_state_{provider_id}")
        )
    except ApplicationError:
        response = RedirectResponse(
            f"{get_settings().app_public_url.rstrip('/')}/?auth_error=authentication_failed",
            status_code=303,
        )
        response.delete_cookie(
            f"{STATE_COOKIE_PREFIX}{provider_id}", path=f"/api/v1/auth/{provider_id}"
        )
        return response
    if test_only:
        response.headers["location"] = (
            f"{get_settings().app_public_url.rstrip('/')}/?oidc_test=success"
        )
    return response


@auth_router.post("/logout", status_code=204)
async def oidc_logout(request: Request, response: Response, session: SessionDependency) -> None:
    OidcService(session, get_settings()).logout(request.cookies.get("fm_session"), response)


@auth_router.post("/proxy/exit", status_code=204)
async def oidc_proxy_exit(request: Request, session: SessionDependency) -> None:
    OidcService(session, get_settings()).stop_proxy(request.cookies.get("fm_session"))


@auth_router.post("/proxy/{user_id}", status_code=204)
async def oidc_proxy_start(
    user_id: UUID,
    body: ProxyStartRequest,
    request: Request,
    session: SessionDependency,
) -> None:
    OidcService(session, get_settings()).start_proxy(
        request.cookies.get("fm_session"), user_id, body.reason
    )


@router.get("/health/live", tags=["health"])
async def live() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/metrics", include_in_schema=False)
async def metrics() -> PlainTextResponse:
    """Expose scrapeable process metrics; keep this endpoint network-policy protected."""
    return PlainTextResponse(render_metrics(), media_type="text/plain; version=0.0.4")


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
    session: SessionDependency,
) -> SessionResponse:
    default_group_id, default_policy_id = repository.default_context_for_user(
        principal.user_id, principal.organization_id
    )
    return SessionResponse(
        environment=get_settings().app_environment,
        authentication_mode="development" if get_settings().dev_auth_enabled else "oidc",
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
        proxied=principal.actor_user_id is not None,
        proxy_actor_email=(
            session.scalar(select(User.email).where(User.id == principal.actor_user_id))
            if principal.actor_user_id
            else None
        ),
        proxy_actor_role=(
            session.scalar(select(User.role).where(User.id == principal.actor_user_id))
            if principal.actor_user_id
            else None
        ),
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
async def approve_change_set(  # noqa: PLR0913, PLR0917 -- approval also publishes execution
    change_set_id: UUID,
    body: ChangeSetActionRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
    dispatch: ChangeSetExecutionDispatcherDependency,
) -> ChangeSetResponse:
    service = _change_set_service(authorization_repository, change_set_repository)
    service.approve(principal, body.active_group_id, change_set_id)
    result = service.queue_execution(principal, body.active_group_id, change_set_id, dispatch)
    return ChangeSetResponse.model_validate(result)


@router.post("/changesets/{change_set_id}/reject", tags=["change-sets"])
async def reject_change_set(
    change_set_id: UUID,
    body: ChangeSetRejectionRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(authorization_repository, change_set_repository).reject(
        principal, body.active_group_id, change_set_id, body.reason
    )
    return ChangeSetResponse.model_validate(result)


@router.post("/changesets/{change_set_id}/dismiss-rejection", tags=["change-sets"])
async def dismiss_rejection_notice(
    change_set_id: UUID,
    body: ChangeSetNotificationDismissRequest,
    principal: PrincipalDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    change_set_repository: ChangeSetRepositoryDependency,
) -> ChangeSetResponse:
    result = _change_set_service(
        authorization_repository, change_set_repository
    ).dismiss_rejection_notice(principal, body.active_group_id, change_set_id)
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


@router.post(
    "/admin/provider-connections/{connection_id}/deployment/pause",
    tags=["deployments"],
)
async def pause_connector_deployment(
    connection_id: UUID,
    body: DeploymentPauseRequest,
    principal: PrincipalDependency,
    session: SessionDependency,
) -> dict[str, object]:
    result = DeploymentService(session).pause_connector(
        principal, connection_id, body.reason, body.until
    )
    session.commit()
    return result


@router.post(
    "/admin/provider-connections/{connection_id}/deployment/resume",
    tags=["deployments"],
)
async def resume_connector_deployment(
    connection_id: UUID, principal: PrincipalDependency, session: SessionDependency
) -> dict[str, object]:
    result = DeploymentService(session).resume_connector(principal, connection_id)
    session.commit()
    return result


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


@router.get("/admin/oidc-providers", tags=["administration"])
async def list_oidc_providers(
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> list[OidcProviderResponse]:
    result = OidcAdministrationService(session, authorization_repository, secret_store).list(
        principal
    )
    return [OidcProviderResponse.model_validate(item) for item in result]


@router.get("/admin/smtp", tags=["administration"])
async def get_smtp_settings(
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> SmtpSettingsResponse:
    settings = get_settings()
    result = SmtpAdministrationService(session, authorization_repository, secret_store).get(
        principal,
        {
            "host": settings.smtp_host or "",
            "port": settings.smtp_port,
            "from_address": settings.smtp_from or "",
            "encryption": "SSL_TLS"
            if settings.smtp_use_ssl
            else "STARTTLS"
            if settings.smtp_use_starttls
            else "NONE",
            "authentication_required": bool(settings.smtp_username),
            "username": settings.smtp_username,
            "password_configured": settings.smtp_password is not None,
        },
    )
    return SmtpSettingsResponse.model_validate(result)


@router.put("/admin/smtp", tags=["administration"])
async def update_smtp_settings(
    body: SmtpSettingsRequest,
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> SmtpSettingsResponse:
    values = body.model_dump(exclude={"password"}, exclude_unset=True)
    if body.password is not None:
        values["password"] = body.password.get_secret_value()
    result = SmtpAdministrationService(session, authorization_repository, secret_store).upsert(
        principal, values
    )
    return SmtpSettingsResponse.model_validate(result)


@router.post("/admin/oidc-providers", status_code=201, tags=["administration"])
async def create_oidc_provider(
    body: OidcProviderCreateRequest,
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> OidcProviderResponse:
    result = OidcAdministrationService(session, authorization_repository, secret_store).create(
        principal, body.model_dump(exclude={"client_secret"}), body.client_secret.get_secret_value()
    )
    return OidcProviderResponse.model_validate(result)


@router.patch("/admin/oidc-providers/{provider_id}", tags=["administration"])
async def update_oidc_provider(  # noqa: PLR0913, PLR0917 -- explicit FastAPI dependencies
    provider_id: UUID,
    body: OidcProviderUpdateRequest,
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> OidcProviderResponse:
    result = OidcAdministrationService(session, authorization_repository, secret_store).update(
        principal, provider_id, body.model_dump(exclude_none=True)
    )
    return OidcProviderResponse.model_validate(result)


@router.put("/admin/oidc-providers/{provider_id}/secret", tags=["administration"])
async def rotate_oidc_provider_secret(  # noqa: PLR0913, PLR0917 -- explicit FastAPI dependencies
    provider_id: UUID,
    body: OidcProviderSecretRequest,
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> OidcProviderResponse:
    result = OidcAdministrationService(session, authorization_repository, secret_store).rotate(
        principal, provider_id, body.expected_revision, body.client_secret.get_secret_value()
    )
    return OidcProviderResponse.model_validate(result)


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
        "deployment_interval_minutes": body.deployment_interval_minutes,
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


@router.get("/admin/api-tokens", response_model=list[ApiTokenResponse], tags=["administration"])
async def list_api_tokens(
    principal: PrincipalDependency, session: SessionDependency
) -> list[ApiToken]:
    if principal.role != "admin":
        raise ResourceOutOfScopeError
    return list(
        session.scalars(
            select(ApiToken)
            .where(ApiToken.organization_id == principal.organization_id)
            .order_by(ApiToken.created_at.desc())
        )
    )


@router.post("/admin/users/{user_id}/api-tokens", status_code=201, tags=["administration"])
async def create_api_token(
    user_id: UUID,
    body: ApiTokenCreateRequest,
    principal: PrincipalDependency,
    session: SessionDependency,
) -> ApiTokenCreatedResponse:
    if principal.role != "admin":
        raise ResourceOutOfScopeError
    user = session.scalar(
        select(User).where(User.id == user_id, User.organization_id == principal.organization_id)
    )
    if user is None or not user.is_active:
        raise ResourceOutOfScopeError
    if body.expires_at is not None and body.expires_at <= datetime.now(UTC):
        raise InvalidInputError(details={"reason": "expires_at_must_be_in_the_future"})
    row, raw = api_tokens.create(session, user, body.name, list(body.scopes), body.expires_at)
    session.add(
        AuthenticationEvent(
            organization_id=principal.organization_id,
            user_id=user.id,
            event="api_token_created",
            outcome="SUCCESS",
            details={"token_id": str(row.id), "name": row.name, "scopes": row.scopes},
        )
    )
    return ApiTokenCreatedResponse.model_validate({**row.__dict__, "token": raw})


@router.delete("/admin/api-tokens/{token_id}", status_code=204, tags=["administration"])
async def revoke_api_token(
    token_id: UUID, principal: PrincipalDependency, session: SessionDependency
) -> None:
    if principal.role != "admin":
        raise ResourceOutOfScopeError
    token = session.scalar(
        select(ApiToken).where(
            ApiToken.id == token_id, ApiToken.organization_id == principal.organization_id
        )
    )
    if token is None or not api_tokens.revoke(session, token_id, principal.organization_id):
        raise ResourceOutOfScopeError
    session.add(
        AuthenticationEvent(
            organization_id=principal.organization_id,
            user_id=token.user_id,
            event="api_token_revoked",
            outcome="SUCCESS",
            details={"token_id": str(token.id), "name": token.name},
        )
    )


@router.get(
    "/admin/users/{user_id}/external-identities",
    tags=["administration"],
)
async def list_external_identities(
    user_id: UUID,
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> list[ExternalIdentityResponse]:
    rows = OidcAdministrationService(
        session, authorization_repository, secret_store
    ).list_identities(principal, user_id)
    return [ExternalIdentityResponse.model_validate(row) for row in rows]


@router.post(
    "/admin/users/{user_id}/external-identities",
    status_code=201,
    tags=["administration"],
)
async def add_external_identity(  # noqa: PLR0913, PLR0917 -- explicit FastAPI dependencies
    user_id: UUID,
    body: ExternalIdentityCreateRequest,
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> ExternalIdentityResponse:
    row = OidcAdministrationService(session, authorization_repository, secret_store).add_identity(
        principal, user_id, body.model_dump()
    )
    return ExternalIdentityResponse.model_validate(row)


@router.delete(
    "/admin/users/{user_id}/external-identities/{identity_id}",
    status_code=204,
    tags=["administration"],
)
async def remove_external_identity(  # noqa: PLR0913, PLR0917 -- explicit FastAPI dependencies
    user_id: UUID,
    identity_id: UUID,
    principal: PrincipalDependency,
    session: SessionDependency,
    authorization_repository: AuthorizationRepositoryDependency,
    secret_store: SecretStoreDependency,
) -> None:
    OidcAdministrationService(session, authorization_repository, secret_store).remove_identity(
        principal, user_id, identity_id
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
    body: ReconciliationRestoreRequest | None = None,
) -> dict[str, object]:
    return InventoryService(repository).accept_provider_state(
        principal, drift_id, body.active_group_id if body else None
    )


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
