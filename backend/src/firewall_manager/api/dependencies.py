# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Authentication and application dependency adapters."""

from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import Cookie, Depends, Header, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from firewall_manager.application.errors import NotAuthenticatedError, ResourceOutOfScopeError
from firewall_manager.application.health import HealthService
from firewall_manager.application.ports import (
    AdministrationRepository,
    AuthorizationRepository,
    ChangeSetExecutionDispatcher,
    ChangeSetRepository,
    DevelopmentIdentityRepository,
    InventoryRepository,
    OverviewRepository,
    ProviderConnectionRepository,
    ProviderFactory,
    ProviderSyncDispatcher,
    SecretStore,
)
from firewall_manager.config import Settings, get_settings
from firewall_manager.domain.models import Principal
from firewall_manager.persistence.changesets import SqlChangeSetRepository
from firewall_manager.persistence.database import get_session
from firewall_manager.persistence.health import SqlRedisHealthProbe
from firewall_manager.persistence.provider_connections import SqlProviderConnectionRepository
from firewall_manager.persistence.repositories import (
    SqlAdministrationRepository,
    SqlAuthorizationRepository,
    SqlOverviewRepository,
)
from firewall_manager.persistence.secrets import EncryptedDatabaseSecretStore
from firewall_manager.security.api_tokens import authenticate
from firewall_manager.security.oidc import OidcService
from firewall_manager.security.secret_provider import master_key

SessionDependency = Annotated[Session, Depends(get_session)]
BearerDependency = Annotated[
    HTTPAuthorizationCredentials | None,
    Security(HTTPBearer(auto_error=False)),
]


def get_overview_repository(session: SessionDependency) -> OverviewRepository:
    """Adapt request-scoped persistence to the application port."""
    return SqlOverviewRepository(session)


RepositoryDependency = Annotated[OverviewRepository, Depends(get_overview_repository)]
InventoryRepositoryDependency = Annotated[InventoryRepository, Depends(get_overview_repository)]
DevelopmentIdentityRepositoryDependency = Annotated[
    DevelopmentIdentityRepository, Depends(get_overview_repository)
]


def get_authorization_repository(session: SessionDependency) -> AuthorizationRepository:
    """Provide current-state authorization persistence for one request."""
    return SqlAuthorizationRepository(session)


def get_administration_repository(session: SessionDependency) -> AdministrationRepository:
    """Provide the bounded authorization administration persistence adapter."""
    return SqlAdministrationRepository(session)


AuthorizationRepositoryDependency = Annotated[
    AuthorizationRepository, Depends(get_authorization_repository)
]
AdministrationRepositoryDependency = Annotated[
    AdministrationRepository, Depends(get_administration_repository)
]


def get_provider_connection_repository(
    session: SessionDependency,
) -> ProviderConnectionRepository:
    """Provide organization-scoped real-provider connection persistence."""
    return SqlProviderConnectionRepository(session)


def get_secret_store(
    session: SessionDependency,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SecretStore:
    """Provide authenticated encryption backed by an external process secret."""
    encoded_key = master_key(settings)
    return EncryptedDatabaseSecretStore(session, encoded_key, settings.secret_store_key_version)


ProviderConnectionRepositoryDependency = Annotated[
    ProviderConnectionRepository, Depends(get_provider_connection_repository)
]
SecretStoreDependency = Annotated[SecretStore, Depends(get_secret_store)]


def get_provider_factory() -> ProviderFactory:
    """Composition hook supplied by the process root, never by a request payload."""
    msg = "real provider factory is not configured"
    raise RuntimeError(msg)


ProviderFactoryDependency = Annotated[ProviderFactory, Depends(get_provider_factory)]


def get_provider_sync_dispatcher() -> ProviderSyncDispatcher:
    """Composition hook for queue publication after durable sync request state."""
    msg = "provider sync dispatcher is not configured"
    raise RuntimeError(msg)


ProviderSyncDispatcherDependency = Annotated[
    ProviderSyncDispatcher, Depends(get_provider_sync_dispatcher)
]


def get_change_set_execution_dispatcher() -> ChangeSetExecutionDispatcher:
    """Composition hook for durable ChangeSet worker publication."""
    msg = "ChangeSet execution dispatcher is not configured"
    raise RuntimeError(msg)


ChangeSetExecutionDispatcherDependency = Annotated[
    ChangeSetExecutionDispatcher, Depends(get_change_set_execution_dispatcher)
]


def get_change_set_repository(session: SessionDependency) -> ChangeSetRepository:
    """Provide durable Group-scoped ChangeSet persistence."""
    return SqlChangeSetRepository(session)


ChangeSetRepositoryDependency = Annotated[ChangeSetRepository, Depends(get_change_set_repository)]


def get_health_service(
    session: SessionDependency,
    settings: Annotated[Settings, Depends(get_settings)],
) -> HealthService:
    """Wire readiness infrastructure at the delivery boundary."""
    return HealthService(SqlRedisHealthProbe(session, settings.redis_url))


HealthServiceDependency = Annotated[HealthService, Depends(get_health_service)]


def get_principal(  # noqa: PLR0913, PLR0917 -- FastAPI dependency inputs
    request: Request,
    repository: RepositoryDependency,
    session: SessionDependency,
    settings: Annotated[Settings, Depends(get_settings)],
    dev_user: Annotated[str | None, Header(alias="X-Dev-User")] = None,
    session_cookie: Annotated[str | None, Cookie(alias="fm_session")] = None,
    bearer: BearerDependency = None,
) -> Principal:
    """Resolve a database identity through production OIDC or isolated development auth."""
    if bearer is not None:
        raw = bearer.credentials.strip()
        authenticated_token = authenticate(session, raw) if raw else None
        if authenticated_token is None:
            raise NotAuthenticatedError
        token, user = authenticated_token
        required_scope = (
            "admin"
            if request.url.path.startswith("/api/v1/admin/")
            else ("write" if request.method in {"POST", "PUT", "PATCH", "DELETE"} else "read")
        )
        token_scopes = set(token.scopes)
        if required_scope not in token_scopes and "admin" not in token_scopes:
            raise ResourceOutOfScopeError
        session.info["api_token_id"] = str(token.id)
        session.info["api_token_scopes"] = token.scopes
        session.info["auth_actor_user_id"] = str(user.id)
        session.info["auth_effective_user_id"] = str(user.id)
        return Principal(
            user_id=user.id,
            organization_id=user.organization_id,
            email=user.email,
            role=user.role,
            issuer=user.identity_issuer,
            subject=user.identity_subject,
        )
    if settings.dev_auth_enabled:
        email = dev_user or settings.dev_auth_default_user
        principal = repository.principal_by_email(email)
        if principal is None:
            raise NotAuthenticatedError
        session.info["auth_actor_user_id"] = str(principal.user_id)
        session.info["auth_effective_user_id"] = str(principal.user_id)
        return principal
    authenticated = OidcService(session, settings).principal(session_cookie)
    if authenticated is None:
        raise NotAuthenticatedError
    user, _auth_session = authenticated
    auth_session = authenticated[1]
    actor_user_id = auth_session.actor_user_id
    session.info["auth_actor_user_id"] = str(actor_user_id or user.id)
    session.info["auth_effective_user_id"] = str(user.id)
    return Principal(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        role=user.role,
        issuer=user.identity_issuer,
        subject=user.identity_subject,
        actor_user_id=actor_user_id,
    )


PrincipalDependency = Annotated[Principal, Depends(get_principal)]


def get_deployment_dispatcher() -> Callable[[UUID], object]:
    """Composition hook for durable deployment queue publication."""
    raise RuntimeError("deployment dispatcher is not configured")


DeploymentDispatcherDependency = Annotated[
    Callable[[UUID], object], Depends(get_deployment_dispatcher)
]
