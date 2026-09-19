"""Authentication and application dependency adapters."""

from typing import Annotated

from fastapi import Depends, Header
from sqlalchemy.orm import Session

from firewall_manager.application.errors import NotAuthenticatedError
from firewall_manager.application.health import HealthService
from firewall_manager.application.ports import (
    AdministrationRepository,
    AuthorizationRepository,
    ChangeSetRepository,
    InventoryRepository,
    OverviewRepository,
)
from firewall_manager.config import Settings, get_settings
from firewall_manager.domain.models import Principal
from firewall_manager.persistence.changesets import SqlChangeSetRepository
from firewall_manager.persistence.database import get_session
from firewall_manager.persistence.health import SqlRedisHealthProbe
from firewall_manager.persistence.repositories import (
    SqlAdministrationRepository,
    SqlAuthorizationRepository,
    SqlOverviewRepository,
)

SessionDependency = Annotated[Session, Depends(get_session)]


def get_overview_repository(session: SessionDependency) -> OverviewRepository:
    """Adapt request-scoped persistence to the application port."""
    return SqlOverviewRepository(session)


RepositoryDependency = Annotated[OverviewRepository, Depends(get_overview_repository)]
InventoryRepositoryDependency = Annotated[InventoryRepository, Depends(get_overview_repository)]


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


def get_principal(
    repository: RepositoryDependency,
    settings: Annotated[Settings, Depends(get_settings)],
    dev_user: Annotated[str | None, Header(alias="X-Dev-User")] = None,
) -> Principal:
    """Resolve a local identity only when the isolated development adapter is enabled."""
    if not settings.dev_auth_enabled:
        raise NotAuthenticatedError
    email = dev_user or settings.dev_auth_default_user
    principal = repository.principal_by_email(email)
    if principal is None:
        raise NotAuthenticatedError
    return principal


PrincipalDependency = Annotated[Principal, Depends(get_principal)]
