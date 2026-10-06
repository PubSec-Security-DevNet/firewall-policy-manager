"""Authorization administration use cases shared by delivery interfaces."""

from ipaddress import ip_address, ip_network
from typing import cast
from uuid import UUID

from firewall_manager.application.authorization import AuthorizationService
from firewall_manager.application.errors import InvalidInputError, ResourceOutOfScopeError
from firewall_manager.application.ports import AdministrationRepository, AuthorizationRepository
from firewall_manager.domain.models import FirewallObjectType, PolicyCapability, Principal
from firewall_manager.domain.naming import normalize_provider_slug
from firewall_manager.domain.networks import normalize_ip_value

_RESOURCE_NAMES = frozenset(
    {
        "memberships",
        "policy-delegations",
        "object-use-grants",
        "zone-grants",
        "ip-range-grants",
        "object-create-grants",
    }
)
_USER_ROLES = frozenset({"user", "approver", "firewall_operator", "admin"})


class AdministrationService:
    """Validate and persist security-sensitive authorization configuration."""

    def __init__(
        self,
        authorization_repository: AuthorizationRepository,
        administration_repository: AdministrationRepository,
    ) -> None:
        self._authorization = AuthorizationService(authorization_repository)
        self._repository = administration_repository

    def snapshot(self, principal: Principal) -> dict[str, object]:
        self._require_admin(principal)
        return self._repository.authorization_snapshot(principal.organization_id)

    def create_user(self, principal: Principal, values: dict[str, object]) -> dict[str, object]:
        self._require_admin(principal)
        required = ("display_name", "email")
        if any(not isinstance(values.get(key), str) or not values[key] for key in required):
            raise InvalidInputError
        role = values.get("role", "user")
        if not isinstance(role, str) or role not in _USER_ROLES:
            raise InvalidInputError
        return self._repository.create_user(
            principal.organization_id, principal.audit_user_id, {**values, "role": role}
        )

    def create_group(self, principal: Principal, values: dict[str, object]) -> dict[str, object]:
        self._require_admin(principal)
        name, slug = values.get("name"), values.get("provider_slug")
        if not isinstance(name, str) or not name or not isinstance(slug, str):
            raise InvalidInputError
        try:
            values = {**values, "provider_slug": normalize_provider_slug(slug)}
        except ValueError as exc:
            raise InvalidInputError from exc
        return self._repository.create_group(
            principal.organization_id, principal.audit_user_id, values
        )

    def update_enabled(
        self,
        principal: Principal,
        resource: str,
        resource_id: UUID,
        enabled: bool,
        expected_revision: int,
    ) -> dict[str, object]:
        self._require_admin(principal)
        if resource not in {"users", "groups"} or expected_revision < 1:
            raise InvalidInputError
        return self._repository.update_enabled(
            principal.organization_id,
            principal.audit_user_id,
            resource,
            resource_id,
            enabled,
            expected_revision,
        )

    def update_group_approval(
        self,
        principal: Principal,
        group_id: UUID,
        approval_required: bool,
        expected_revision: int,
    ) -> dict[str, object]:
        self._require_admin(principal)
        if expected_revision < 1:
            raise InvalidInputError
        return self._repository.update_group_approval(
            principal.organization_id,
            principal.audit_user_id,
            group_id,
            approval_required,
            expected_revision,
        )

    def update_user_role(
        self, principal: Principal, user_id: UUID, role: str, expected_revision: int
    ) -> dict[str, object]:
        self._require_admin(principal)
        if role not in _USER_ROLES or expected_revision < 1:
            raise InvalidInputError
        return self._repository.update_user_role(
            principal.organization_id,
            principal.audit_user_id,
            user_id,
            role,
            expected_revision,
        )

    def upsert(
        self,
        principal: Principal,
        resource: str,
        values: dict[str, object],
        expected_revision: int | None,
    ) -> dict[str, object]:
        self._require_admin(principal)
        if resource not in _RESOURCE_NAMES:
            raise ResourceOutOfScopeError
        normalized = self._normalize(resource, values)
        return self._repository.upsert_authorization_resource(
            principal.organization_id,
            principal.audit_user_id,
            resource,
            normalized,
            expected_revision,
        )

    def revoke(
        self,
        principal: Principal,
        resource: str,
        resource_id: UUID,
        expected_revision: int,
    ) -> None:
        """Revoke one grant using its stable id and current revision."""
        self._require_admin(principal)
        if resource not in _RESOURCE_NAMES or expected_revision < 1:
            raise ResourceOutOfScopeError
        self._repository.revoke_authorization_resource(
            principal.organization_id,
            principal.audit_user_id,
            resource,
            resource_id,
            expected_revision,
        )

    def _require_admin(self, principal: Principal) -> None:
        if not self._authorization.authorize_administration(principal).allowed:
            raise ResourceOutOfScopeError

    @staticmethod
    def _normalize(  # noqa: PLR0912 -- explicit validation per security resource type
        resource: str, values: dict[str, object]
    ) -> dict[str, object]:
        normalized = dict(values)
        try:
            required = {
                "memberships": {"user_id", "group_id", "status"},
                "policy-delegations": {"group_id", "policy_id", "capabilities"},
                "object-use-grants": {"group_id", "policy_id", "object_id", "permission"},
                "zone-grants": {"group_id", "policy_id", "zone_id", "direction"},
                "ip-range-grants": {"group_id", "policy_id", "network"},
                "object-create-grants": {"group_id", "policy_id", "object_type"},
            }[resource]
            if not required <= values.keys():
                raise ValueError
            if resource == "policy-delegations":
                raw = values.get("capabilities")
                if not isinstance(raw, list) or not raw:
                    raise ValueError
                normalized["capabilities"] = sorted(
                    {PolicyCapability(str(value)).value for value in cast("list[object]", raw)}
                )
            elif resource == "object-use-grants":
                permission = str(values.get("permission"))
                if permission not in {"use", "modify"}:
                    raise ValueError
            elif resource == "zone-grants":
                direction = str(values.get("direction"))
                if direction not in {"SOURCE", "DESTINATION", "BOTH"}:
                    raise ValueError
            elif resource == "memberships":
                if values.get("status") not in {"ACTIVE", "SUSPENDED"}:
                    raise ValueError
            elif resource == "ip-range-grants":
                network = normalize_ip_value(str(values.get("network")))
                normalized["network"] = network
                if "-" in network:
                    normalized["ip_version"] = ip_address(network.split("-", 1)[0]).version
                else:
                    normalized["ip_version"] = ip_network(network).version
            elif resource == "object-create-grants":
                object_type = FirewallObjectType(str(values.get("object_type")))
                if object_type is FirewallObjectType.NETWORK_GROUP:
                    raise ValueError
                normalized["object_type"] = object_type.value
        except (TypeError, ValueError) as exc:
            raise InvalidInputError from exc
        return normalized
