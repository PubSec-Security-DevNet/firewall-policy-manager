"""Authoritative, interface-independent delegated authorization service."""

from collections.abc import Mapping
from ipaddress import AddressValueError, NetmaskValueError

from firewall_manager.application.errors import ResourceOutOfScopeError
from firewall_manager.application.ports import AuthorizationRepository
from firewall_manager.domain.models import (
    Action,
    AuthorizationDecision,
    AuthorizationReason,
    AuthorizationResource,
    AuthorizationResourceType,
    DelegatedPolicyContext,
    FirewallObjectType,
    PolicyCapability,
    Principal,
    ProviderCapability,
)
from firewall_manager.domain.networks import network_is_contained

_ROLE_ACTIONS: dict[str, frozenset[Action]] = {
    "viewer": frozenset({Action.READ}),
    "editor": frozenset({Action.READ, Action.USE, Action.MODIFY}),
    "approver": frozenset({Action.READ, Action.APPROVE}),
    "group_admin": frozenset(
        {Action.READ, Action.USE, Action.CREATE, Action.MODIFY, Action.DELETE, Action.REORDER}
    ),
    "firewall_admin": frozenset(
        action for action in Action if action not in {Action.MANAGE_GRANTS, Action.MANAGE_PROVIDERS}
    ),
    "admin": frozenset(Action),
}


def require_action(principal: Principal, action: Action) -> None:
    """Raise a non-enumerating denial unless the initial role grants an action."""
    if action not in _ROLE_ACTIONS.get(principal.role, frozenset()):
        raise ResourceOutOfScopeError


_POLICY_ACTION_CAPABILITY: Mapping[Action, PolicyCapability] = {
    Action.READ: PolicyCapability.VIEW,
    Action.CREATE: PolicyCapability.CREATE_RULE,
    Action.MODIFY: PolicyCapability.MODIFY_RULE,
    Action.DELETE: PolicyCapability.DELETE_RULE,
    Action.REORDER: PolicyCapability.REORDER_RULE,
    Action.SUBMIT: PolicyCapability.SUBMIT,
    Action.APPROVE: PolicyCapability.APPROVE,
    Action.DEPLOY: PolicyCapability.DEPLOY,
}

_OBJECT_CREATE_CAPABILITY: Mapping[str, ProviderCapability] = {
    FirewallObjectType.NETWORK: ProviderCapability.NETWORK_OBJECT_CREATE,
    FirewallObjectType.PORT_SERVICE: ProviderCapability.PORT_SERVICE_OBJECT_CREATE,
    FirewallObjectType.URL: ProviderCapability.URL_OBJECT_CREATE,
    FirewallObjectType.APPLICATION: ProviderCapability.APPLICATION_OBJECT_CREATE,
    FirewallObjectType.APPLICATION_FILTER: ProviderCapability.APPLICATION_OBJECT_CREATE,
}

_OBJECT_POLICY_CAPABILITY: Mapping[Action, PolicyCapability] = {
    Action.MODIFY: PolicyCapability.MODIFY_OBJECT,
    Action.DELETE: PolicyCapability.DELETE_OBJECT,
}

_USABLE_RESOURCE_STATES = frozenset({"OBSERVED", "UNMANAGED", "MANAGED"})


class AuthorizationService:
    """Evaluate current grants for one explicit User+Group+Policy context.

    The repository is consulted on every decision. No frontend state or membership from another
    Group can contribute, and the service does not search for a Group that would allow a request.
    """

    def __init__(self, repository: AuthorizationRepository) -> None:
        self._repository = repository

    def authorize(  # noqa: PLR0911 -- explicit fail-closed decision sequence
        self,
        context: DelegatedPolicyContext,
        action: Action,
        resource: AuthorizationResource,
        *,
        interface: str = "application",
        correlation_id: str | None = None,
    ) -> AuthorizationDecision:
        """Return a structured allow/deny decision without leaking resource details."""
        principal = context.principal
        revision = 0
        user = self._repository.user_state(principal.user_id, principal.organization_id)
        if user is None or not user[0]:
            return self._decision(
                context,
                action,
                resource,
                AuthorizationReason.USER_DISABLED,
                revision,
                interface,
                correlation_id,
            )
        revision = max(revision, user[1])
        membership = self._repository.membership_state(
            principal.user_id, context.active_group_id, principal.organization_id
        )
        if membership is None:
            return self._decision(
                context,
                action,
                resource,
                AuthorizationReason.NOT_GROUP_MEMBER,
                revision,
                interface,
                correlation_id,
            )
        if not membership[0]:
            return self._decision(
                context,
                action,
                resource,
                AuthorizationReason.GROUP_DISABLED,
                revision,
                interface,
                correlation_id,
            )
        revision = max(revision, membership[1])
        policy = self._repository.policy_state(context.access_policy_id, principal.organization_id)
        if policy is None or policy[1] in {"MISSING", "CONFLICT"}:
            return self._decision(
                context,
                action,
                resource,
                AuthorizationReason.RESOURCE_OUT_OF_SCOPE,
                revision,
                interface,
                correlation_id,
            )
        manager_id, _policy_resource_state, policy_revision = policy
        revision = max(revision, policy_revision)
        # Policy fingerprint drift is a warning about pending provider state, not a direct
        # conflict with every delegated write. Each affected rule, object, position, grant,
        # and provider revision is checked below and again by ChangeSet preflight/execution.
        # MISSING and CONFLICT policies still fail closed above.
        capabilities, grant_revision, group_delegated = self._repository.policy_capabilities(
            principal.user_id,
            context.active_group_id,
            context.access_policy_id,
            principal.organization_id,
        )
        revision = max(revision, grant_revision)
        if not group_delegated:
            return self._decision(
                context,
                action,
                resource,
                AuthorizationReason.POLICY_NOT_DELEGATED,
                revision,
                interface,
                correlation_id,
            )
        if resource.resource_type in {
            AuthorizationResourceType.POLICY,
            AuthorizationResourceType.RULE,
        }:
            required = _POLICY_ACTION_CAPABILITY.get(action)
        elif resource.resource_type is AuthorizationResourceType.OBJECT:
            required = _OBJECT_POLICY_CAPABILITY.get(action, PolicyCapability.VIEW)
        else:
            required = PolicyCapability.VIEW
        if required is not None and required not in capabilities:
            return self._decision(
                context,
                action,
                resource,
                AuthorizationReason.ACTION_NOT_GRANTED,
                revision,
                interface,
                correlation_id,
            )

        reason, resource_revision = self._authorize_resource(context, action, resource, manager_id)
        return self._decision(
            context,
            action,
            resource,
            reason,
            max(revision, resource_revision),
            interface,
            correlation_id,
        )

    def authorize_administration(
        self,
        principal: Principal,
        *,
        interface: str = "application",
        correlation_id: str | None = None,
    ) -> AuthorizationDecision:
        """Authorize the explicit development/bootstrap grant administrator boundary."""
        resource = AuthorizationResource(AuthorizationResourceType.ADMINISTRATION)
        user = self._repository.user_state(principal.user_id, principal.organization_id)
        allowed = user is not None and user[0] and principal.role == "admin"
        decision = AuthorizationDecision(
            allowed=allowed,
            reason=AuthorizationReason.ALLOWED
            if allowed
            else AuthorizationReason.ACTION_NOT_GRANTED,
            action=Action.MANAGE_GRANTS,
            principal_id=principal.user_id,
            organization_id=principal.organization_id,
            active_group_id=None,
            access_policy_id=None,
            resource_type=resource.resource_type,
            authorization_revision=user[1] if user else 0,
        )
        self._repository.record_authorization_decision(
            decision, interface=interface, correlation_id=correlation_id
        )
        return decision

    def authorize_provider_administration(
        self,
        principal: Principal,
        *,
        interface: str = "application",
        correlation_id: str | None = None,
    ) -> AuthorizationDecision:
        """Authorize the distinct provider-connection administration boundary."""
        user = self._repository.user_state(principal.user_id, principal.organization_id)
        allowed = user is not None and user[0] and principal.role == "admin"
        decision = AuthorizationDecision(
            allowed=allowed,
            reason=AuthorizationReason.ALLOWED
            if allowed
            else AuthorizationReason.ACTION_NOT_GRANTED,
            action=Action.MANAGE_PROVIDERS,
            principal_id=principal.user_id,
            organization_id=principal.organization_id,
            active_group_id=None,
            access_policy_id=None,
            resource_type=AuthorizationResourceType.PROVIDER_CONNECTION,
            authorization_revision=user[1] if user else 0,
        )
        self._repository.record_authorization_decision(
            decision, interface=interface, correlation_id=correlation_id
        )
        return decision

    def require(
        self,
        context: DelegatedPolicyContext,
        action: Action,
        resource: AuthorizationResource,
        **metadata: str | None,
    ) -> AuthorizationDecision:
        """Return an allowed decision or raise the canonical non-enumerating denial."""
        decision = self.authorize(
            context,
            action,
            resource,
            interface=metadata.get("interface") or "application",
            correlation_id=metadata.get("correlation_id"),
        )
        if not decision.allowed:
            raise ResourceOutOfScopeError
        return decision

    def _authorize_resource(  # noqa: PLR0911, PLR0912 -- independent resource preflights
        self,
        context: DelegatedPolicyContext,
        action: Action,
        resource: AuthorizationResource,
        manager_id: object,
    ) -> tuple[AuthorizationReason, int]:
        organization_id = context.principal.organization_id
        if resource.resource_type is AuthorizationResourceType.POLICY:
            if resource.resource_id not in {None, context.access_policy_id}:
                return AuthorizationReason.RESOURCE_OUT_OF_SCOPE, 0
            return AuthorizationReason.ALLOWED, 0
        if resource.resource_type is AuthorizationResourceType.OBJECT and resource.resource_id:
            if action in {Action.MODIFY, Action.DELETE}:
                state = self._repository.object_mutation_state(
                    context.active_group_id,
                    context.access_policy_id,
                    resource.resource_id,
                    organization_id,
                )
                if state is None or state.get("manager_id") != manager_id:
                    return AuthorizationReason.RESOURCE_OUT_OF_SCOPE, 0
                revision = int(str(state.get("revision", 0)))
                if state.get("owner_group_id") != context.active_group_id:
                    return AuthorizationReason.NOT_OWNER, revision
                if state.get("owner_policy_id") != context.access_policy_id:
                    return AuthorizationReason.RESOURCE_OUT_OF_SCOPE, revision
                if state.get("management_state") != "MANAGED":
                    return AuthorizationReason.STALE_AUTHORIZATION_CONTEXT, revision
                if state.get("provider_name_matches") is not True:
                    return AuthorizationReason.OWNERSHIP_DRIFT, revision
                dependency_state = state.get("dependency_state")
                if dependency_state == "INCOMPLETE":
                    return AuthorizationReason.DEPENDENCY_STATE_INCOMPLETE, revision
                if action is Action.DELETE and dependency_state != "UNREFERENCED":
                    return AuthorizationReason.OBJECT_DEPENDENCY_CONFLICT, revision
                if action is Action.MODIFY and dependency_state not in {
                    "UNREFERENCED",
                    "WITHIN_SCOPE",
                }:
                    return AuthorizationReason.OBJECT_DEPENDENCY_CONFLICT, revision
                return AuthorizationReason.ALLOWED, revision
            state = self._repository.object_grant_state(
                context.active_group_id,
                context.access_policy_id,
                resource.resource_id,
                organization_id,
            )
            if state is None or state[0] != manager_id or state[1] not in _USABLE_RESOURCE_STATES:
                return AuthorizationReason.RESOURCE_NOT_USABLE, state[3] if state else 0
            permission = action.value
            return (
                (
                    AuthorizationReason.ALLOWED
                    if permission in state[2]
                    else AuthorizationReason.RESOURCE_NOT_USABLE
                ),
                state[3],
            )
        if resource.resource_type is AuthorizationResourceType.ZONE and resource.resource_id:
            state = self._repository.zone_grant_state(
                context.active_group_id,
                context.access_policy_id,
                resource.resource_id,
                organization_id,
            )
            direction = resource.element or "BOTH"
            allowed_directions = state[2] if state else set()
            allowed = (
                state is not None
                and state[0] == manager_id
                and state[1] in _USABLE_RESOURCE_STATES
                and ("BOTH" in allowed_directions or direction in allowed_directions)
            )
            return (
                AuthorizationReason.ALLOWED if allowed else AuthorizationReason.RESOURCE_NOT_USABLE,
                state[3] if state else 0,
            )
        if resource.resource_type is AuthorizationResourceType.IP_NETWORK and resource.value:
            grants, revision = self._repository.ip_range_grants(
                context.active_group_id, context.access_policy_id, organization_id
            )
            try:
                allowed = any(network_is_contained(resource.value, grant) for grant in grants)
            except (AddressValueError, NetmaskValueError, ValueError):
                allowed = False
            return (
                AuthorizationReason.ALLOWED
                if allowed
                else AuthorizationReason.IP_RANGE_NOT_GRANTED,
                revision,
            )
        if resource.resource_type is AuthorizationResourceType.OBJECT_TYPE and resource.value:
            state = self._repository.object_create_grant_state(
                context.active_group_id,
                context.access_policy_id,
                resource.value,
                organization_id,
            )
            if state is None or state[0] != manager_id:
                return AuthorizationReason.ACTION_NOT_GRANTED, state[2] if state else 0
            provider_capability = _OBJECT_CREATE_CAPABILITY.get(resource.value)
            if provider_capability is None or state[1].get(provider_capability) != "SUPPORTED":
                return AuthorizationReason.PROVIDER_CAPABILITY_UNAVAILABLE, state[2]
            return AuthorizationReason.ALLOWED, state[2]
        if resource.resource_type is AuthorizationResourceType.RULE and resource.resource_id:
            state = self._repository.rule_owner_state(
                resource.resource_id, context.access_policy_id, organization_id
            )
            if state is None or state[0] != context.active_group_id:
                return AuthorizationReason.NOT_OWNER, state[2] if state else 0
            if action is not Action.READ and state[1] not in _USABLE_RESOURCE_STATES:
                return AuthorizationReason.STALE_AUTHORIZATION_CONTEXT, state[2]
            return AuthorizationReason.ALLOWED, state[2]
        if resource.resource_type is AuthorizationResourceType.CATEGORY and resource.resource_id:
            state = self._repository.category_mapping_state(
                context.active_group_id,
                context.access_policy_id,
                resource.resource_id,
                organization_id,
            )
            allowed = (
                state is not None and state[0] == manager_id and state[1] in _USABLE_RESOURCE_STATES
            )
            return (
                AuthorizationReason.ALLOWED
                if allowed
                else AuthorizationReason.RESOURCE_OUT_OF_SCOPE,
                state[2] if state else 0,
            )
        return AuthorizationReason.RESOURCE_OUT_OF_SCOPE, 0

    def _decision(  # noqa: PLR0913, PLR0917 -- complete immutable audit context
        self,
        context: DelegatedPolicyContext,
        action: Action,
        resource: AuthorizationResource,
        reason: AuthorizationReason,
        revision: int,
        interface: str,
        correlation_id: str | None,
    ) -> AuthorizationDecision:
        decision = AuthorizationDecision(
            allowed=reason is AuthorizationReason.ALLOWED,
            reason=reason,
            action=action,
            principal_id=context.principal.user_id,
            organization_id=context.principal.organization_id,
            active_group_id=context.active_group_id,
            access_policy_id=context.access_policy_id,
            resource_type=resource.resource_type,
            resource_id=resource.resource_id,
            authorization_revision=revision,
        )
        self._repository.record_authorization_decision(
            decision, interface=interface, correlation_id=correlation_id
        )
        return decision
