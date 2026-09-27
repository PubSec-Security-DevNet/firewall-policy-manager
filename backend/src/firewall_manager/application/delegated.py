"""Delegated read models built on the authoritative authorization boundary."""

from uuid import UUID

from firewall_manager.application.authorization import AuthorizationService
from firewall_manager.application.errors import ResourceOutOfScopeError
from firewall_manager.application.ports import AuthorizationRepository
from firewall_manager.domain.models import (
    Action,
    AuthorizationResource,
    AuthorizationResourceType,
    DelegatedPolicyContext,
    Principal,
)


class DelegatedPolicyService:
    """Load a Group-isolated policy workspace after current-state preflight."""

    def __init__(self, repository: AuthorizationRepository) -> None:
        self._repository = repository
        self._authorization = AuthorizationService(repository)

    def context_view(
        self,
        context: DelegatedPolicyContext,
        *,
        include_applications: bool = True,
        include_rules: bool = True,
        interface: str = "rest",
        correlation_id: str | None = None,
    ) -> dict[str, object]:
        """Return only resources granted in the exact selected Group+Policy context."""
        self._authorization.require(
            context,
            Action.READ,
            AuthorizationResource(AuthorizationResourceType.POLICY, context.access_policy_id),
            interface=interface,
            correlation_id=correlation_id,
        )
        if include_applications and include_rules:
            # Preserve compatibility with repository adapters that predate the optional filter.
            result = self._repository.delegated_context_view(
                context.principal.user_id,
                context.active_group_id,
                context.access_policy_id,
                context.principal.organization_id,
            )
        else:
            result = self._repository.delegated_context_view(
                context.principal.user_id,
                context.active_group_id,
                context.access_policy_id,
                context.principal.organization_id,
                include_applications=False,
                include_rules=include_rules,
            )
        if result is None:
            # This cannot normally occur after preflight, but fail closed under concurrent removal.
            raise ResourceOutOfScopeError
        return result

    def policies(self, principal: Principal, active_group_id: UUID) -> list[dict[str, object]]:
        """List policies delegated to one selected Group without searching other memberships."""
        user = self._repository.user_state(principal.user_id, principal.organization_id)
        membership = self._repository.membership_state(
            principal.user_id, active_group_id, principal.organization_id
        )
        if user is None or not user[0] or membership is None or not membership[0]:
            raise ResourceOutOfScopeError
        return self._repository.delegated_policies(
            principal.user_id, active_group_id, principal.organization_id
        )
