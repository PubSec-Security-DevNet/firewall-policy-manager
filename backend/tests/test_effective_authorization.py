"""Effective delegated authorization invariants and negative matrix."""

from uuid import UUID

import pytest

from firewall_manager.application.authorization import AuthorizationService
from firewall_manager.domain.models import (
    Action,
    AuthorizationDecision,
    AuthorizationReason,
    AuthorizationResource,
    AuthorizationResourceType,
    DelegatedPolicyContext,
    Principal,
)

ORG = UUID("10000000-0000-0000-0000-000000000001")
USER = UUID("30000000-0000-0000-0000-000000000001")
FINANCE = UUID("20000000-0000-0000-0000-000000000001")
ENGINEERING = UUID("20000000-0000-0000-0000-000000000002")
UNRELATED = UUID("20000000-0000-0000-0000-000000000003")
POLICY_A = UUID("50000000-0000-0000-0000-000000000001")
POLICY_B = UUID("50000000-0000-0000-0000-000000000002")
MANAGER = UUID("40000000-0000-0000-0000-000000000001")
FINANCE_OBJECT = UUID("60000000-0000-0000-0000-000000000001")
ENGINEERING_OBJECT = UUID("60000000-0000-0000-0000-000000000002")
FINANCE_ZONE = UUID("70000000-0000-0000-0000-000000000001")
ENGINEERING_ZONE = UUID("70000000-0000-0000-0000-000000000002")
FINANCE_RULE = UUID("80000000-0000-0000-0000-000000000001")


class FakeAuthorizationRepository:
    def __init__(self) -> None:
        self.user_enabled = True
        self.memberships = {FINANCE: True, ENGINEERING: True}
        self.policy_capability_values = {
            (USER, FINANCE, POLICY_A): {"view", "create_rule"},
            (USER, ENGINEERING, POLICY_A): {"view", "modify_rule", "reorder_rule"},
        }
        self.delegated_contexts = {(FINANCE, POLICY_A), (ENGINEERING, POLICY_A)}
        self.objects = {
            (FINANCE, POLICY_A, FINANCE_OBJECT): (MANAGER, "OBSERVED", {"use"}, 3),
            (ENGINEERING, POLICY_A, ENGINEERING_OBJECT): (
                MANAGER,
                "OBSERVED",
                {"read", "use"},
                4,
            ),
        }
        self.zones = {
            (FINANCE, POLICY_A, FINANCE_ZONE): (MANAGER, "OBSERVED", {"BOTH"}, 3),
            (ENGINEERING, POLICY_A, ENGINEERING_ZONE): (
                MANAGER,
                "OBSERVED",
                {"SOURCE"},
                4,
            ),
        }
        self.ranges = {
            (FINANCE, POLICY_A): ["10.20.0.0/16", "192.0.2.0/24"],
            (ENGINEERING, POLICY_A): ["172.16.0.0/12", "2001:db8::/32"],
        }
        self.object_create = {
            (FINANCE, POLICY_A, "NETWORK"): (
                MANAGER,
                {"network_object_create": "SUPPORTED"},
                5,
            ),
            (FINANCE, POLICY_A, "PORT_SERVICE"): (
                MANAGER,
                {"port_service_object_create": "READ_ONLY"},
                5,
            ),
        }
        self.equivalents: dict[tuple[str, str], UUID] = {}
        self.rules = {
            (FINANCE_RULE, POLICY_A): (FINANCE, "MANAGED", 7),
        }
        self.decisions: list[AuthorizationDecision] = []

    def user_state(self, user_id: UUID, organization_id: UUID) -> tuple[bool, int] | None:
        return (self.user_enabled, 1) if (user_id, organization_id) == (USER, ORG) else None

    def membership_state(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> tuple[bool, int] | None:
        if user_id != USER or organization_id != ORG or group_id not in self.memberships:
            return None
        return self.memberships[group_id], 2

    def policy_state(self, policy_id: UUID, organization_id: UUID) -> tuple[UUID, str, int] | None:
        if organization_id == ORG and policy_id in {POLICY_A, POLICY_B}:
            return MANAGER, "OBSERVED", 2
        return None

    def policy_capabilities(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[set[str], int, bool]:
        key = (user_id, group_id, policy_id)
        return (
            set(self.policy_capability_values.get(key, set())),
            3,
            (group_id, policy_id) in self.delegated_contexts,
        )

    def object_grant_state(
        self, group_id: UUID, policy_id: UUID, object_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, set[str], int] | None:
        return (
            self.objects.get((group_id, policy_id, object_id)) if organization_id == ORG else None
        )

    def zone_grant_state(
        self, group_id: UUID, policy_id: UUID, zone_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, set[str], int] | None:
        return self.zones.get((group_id, policy_id, zone_id)) if organization_id == ORG else None

    def ip_range_grants(
        self, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[list[str], int]:
        return list(self.ranges.get((group_id, policy_id), [])), 4

    def object_create_grant_state(
        self, group_id: UUID, policy_id: UUID, object_type: str, organization_id: UUID
    ) -> tuple[UUID, dict[str, str], int] | None:
        return self.object_create.get((group_id, policy_id, object_type))

    def equivalent_object_id(
        self, manager_id: UUID, object_type: str, normalized_value: str, organization_id: UUID
    ) -> UUID | None:
        return self.equivalents.get((object_type, normalized_value))

    def rule_owner_state(
        self, rule_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[UUID | None, str, int] | None:
        return self.rules.get((rule_id, policy_id)) if organization_id == ORG else None

    def category_mapping_state(
        self, group_id: UUID, policy_id: UUID, category_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, int] | None:
        return None

    def record_authorization_decision(
        self, decision: AuthorizationDecision, *, interface: str, correlation_id: str | None
    ) -> None:
        self.decisions.append(decision)

    def active_groups_for_user(
        self, user_id: UUID, organization_id: UUID
    ) -> list[dict[str, object]]:
        return []

    def delegated_context_view(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None:
        return None

    def delegated_policies(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> list[dict[str, object]]:
        return []


def context(group_id: UUID = FINANCE, policy_id: UUID = POLICY_A) -> DelegatedPolicyContext:
    return DelegatedPolicyContext(
        Principal(USER, ORG, "alice@example.test", "viewer"), group_id, policy_id
    )


def authorize(  # noqa: PLR0913 -- compact matrix helper
    repository: FakeAuthorizationRepository,
    resource_type: AuthorizationResourceType,
    *,
    action: Action = Action.USE,
    resource_id: UUID | None = None,
    value: str | None = None,
    element: str | None = None,
    group_id: UUID = FINANCE,
    policy_id: UUID = POLICY_A,
) -> AuthorizationDecision:
    return AuthorizationService(repository).authorize(
        context(group_id, policy_id),
        action,
        AuthorizationResource(resource_type, resource_id, element, value),
    )


def test_membership_policy_and_disabled_state_default_deny() -> None:
    repository = FakeAuthorizationRepository()
    assert authorize(repository, AuthorizationResourceType.POLICY, action=Action.READ).allowed
    assert (
        authorize(
            repository,
            AuthorizationResourceType.POLICY,
            action=Action.READ,
            group_id=UNRELATED,
        ).reason
        is AuthorizationReason.NOT_GROUP_MEMBER
    )
    assert (
        authorize(
            repository,
            AuthorizationResourceType.POLICY,
            action=Action.READ,
            policy_id=POLICY_B,
        ).reason
        is AuthorizationReason.POLICY_NOT_DELEGATED
    )
    repository.user_enabled = False
    assert (
        authorize(repository, AuthorizationResourceType.POLICY, action=Action.READ).reason
        is AuthorizationReason.USER_DISABLED
    )


def test_other_group_membership_and_grants_never_contribute() -> None:
    repository = FakeAuthorizationRepository()
    finance_denial = authorize(
        repository, AuthorizationResourceType.OBJECT, resource_id=ENGINEERING_OBJECT
    )
    assert finance_denial.reason is AuthorizationReason.RESOURCE_NOT_USABLE
    repository.memberships[UNRELATED] = True
    repository.policy_capability_values[(USER, UNRELATED, POLICY_A)] = {"view", "deploy"}
    repository.objects[(UNRELATED, POLICY_A, ENGINEERING_OBJECT)] = (
        MANAGER,
        "OBSERVED",
        {"use"},
        99,
    )
    assert (
        authorize(repository, AuthorizationResourceType.OBJECT, resource_id=ENGINEERING_OBJECT)
        == finance_denial
    )


def test_switching_active_group_inverts_object_and_zone_entitlements() -> None:
    repository = FakeAuthorizationRepository()
    assert authorize(
        repository, AuthorizationResourceType.OBJECT, resource_id=FINANCE_OBJECT
    ).allowed
    assert not authorize(
        repository,
        AuthorizationResourceType.OBJECT,
        resource_id=FINANCE_OBJECT,
        group_id=ENGINEERING,
    ).allowed
    assert authorize(
        repository,
        AuthorizationResourceType.OBJECT,
        resource_id=ENGINEERING_OBJECT,
        group_id=ENGINEERING,
    ).allowed
    assert authorize(
        repository,
        AuthorizationResourceType.ZONE,
        resource_id=ENGINEERING_ZONE,
        element="SOURCE",
        group_id=ENGINEERING,
    ).allowed
    assert not authorize(
        repository,
        AuthorizationResourceType.ZONE,
        resource_id=ENGINEERING_ZONE,
        element="DESTINATION",
        group_id=ENGINEERING,
    ).allowed


def test_read_does_not_imply_object_use_and_drift_fails_closed() -> None:
    repository = FakeAuthorizationRepository()
    repository.objects[(FINANCE, POLICY_A, FINANCE_OBJECT)] = (
        MANAGER,
        "OBSERVED",
        {"read"},
        5,
    )
    assert authorize(
        repository,
        AuthorizationResourceType.OBJECT,
        action=Action.READ,
        resource_id=FINANCE_OBJECT,
    ).allowed
    assert not authorize(
        repository, AuthorizationResourceType.OBJECT, resource_id=FINANCE_OBJECT
    ).allowed
    repository.objects[(FINANCE, POLICY_A, FINANCE_OBJECT)] = (
        MANAGER,
        "DRIFTED",
        {"use"},
        6,
    )
    assert not authorize(
        repository, AuthorizationResourceType.OBJECT, resource_id=FINANCE_OBJECT
    ).allowed


@pytest.mark.parametrize(
    ("value", "allowed"),
    [
        ("10.20.1.5", True),
        ("10.20.10.0/24", True),
        ("10.20.0.0/16", True),
        ("10.21.1.5", False),
        ("10.20.0.0/15", False),
        ("192.0.2.255", True),
        ("2001:db8::1", False),
        ("invalid", False),
    ],
)
def test_ip_network_complete_containment(value: str, allowed: bool) -> None:
    decision = authorize(
        FakeAuthorizationRepository(), AuthorizationResourceType.IP_NETWORK, value=value
    )
    assert decision.allowed is allowed


def test_ipv6_and_group_crossover() -> None:
    repository = FakeAuthorizationRepository()
    assert authorize(
        repository,
        AuthorizationResourceType.IP_NETWORK,
        value="2001:db8:1::/48",
        group_id=ENGINEERING,
    ).allowed
    assert not authorize(
        repository,
        AuthorizationResourceType.IP_NETWORK,
        value="172.16.1.1",
        group_id=FINANCE,
    ).allowed


def test_object_create_requires_app_grant_and_provider_capability() -> None:
    repository = FakeAuthorizationRepository()
    assert authorize(
        repository,
        AuthorizationResourceType.OBJECT_TYPE,
        action=Action.CREATE,
        value="NETWORK",
    ).allowed
    assert (
        authorize(
            repository,
            AuthorizationResourceType.OBJECT_TYPE,
            action=Action.CREATE,
            value="PORT_SERVICE",
        ).reason
        is AuthorizationReason.PROVIDER_CAPABILITY_UNAVAILABLE
    )
    assert not authorize(
        repository,
        AuthorizationResourceType.OBJECT_TYPE,
        action=Action.CREATE,
        value="URL",
    ).allowed


def test_equivalent_object_cannot_be_duplicated_to_bypass_use() -> None:
    repository = FakeAuthorizationRepository()
    repository.equivalents[("NETWORK", "10.20.10.0/24")] = ENGINEERING_OBJECT
    denied = authorize(
        repository,
        AuthorizationResourceType.OBJECT_TYPE,
        action=Action.CREATE,
        value="NETWORK",
        element="10.20.10.0/24",
    )
    assert denied.reason is AuthorizationReason.RESOURCE_NOT_USABLE
    repository.objects[(FINANCE, POLICY_A, ENGINEERING_OBJECT)] = (
        MANAGER,
        "OBSERVED",
        {"use"},
        6,
    )
    conflict = authorize(
        repository,
        AuthorizationResourceType.OBJECT_TYPE,
        action=Action.CREATE,
        value="NETWORK",
        element="10.20.10.0/24",
    )
    assert conflict.reason is AuthorizationReason.EQUIVALENT_OBJECT_EXISTS


def test_rule_ownership_is_exactly_the_acting_group() -> None:
    repository = FakeAuthorizationRepository()
    assert authorize(
        repository,
        AuthorizationResourceType.RULE,
        action=Action.READ,
        resource_id=FINANCE_RULE,
    ).allowed
    assert not authorize(
        repository,
        AuthorizationResourceType.RULE,
        action=Action.MODIFY,
        resource_id=FINANCE_RULE,
        group_id=ENGINEERING,
    ).allowed


def test_direct_user_grant_is_only_effective_in_same_group_policy() -> None:
    repository = FakeAuthorizationRepository()
    assert authorize(
        repository,
        AuthorizationResourceType.POLICY,
        action=Action.REORDER,
        group_id=ENGINEERING,
    ).allowed
    assert not authorize(
        repository,
        AuthorizationResourceType.POLICY,
        action=Action.REORDER,
        group_id=FINANCE,
    ).allowed
    repository.policy_capability_values[(USER, UNRELATED, POLICY_A)] = {"view", "deploy"}
    repository.memberships[UNRELATED] = True
    assert not authorize(
        repository,
        AuthorizationResourceType.POLICY,
        action=Action.DEPLOY,
        group_id=UNRELATED,
    ).allowed


def test_only_current_enabled_admin_can_manage_grants() -> None:
    repository = FakeAuthorizationRepository()
    admin = Principal(USER, ORG, "admin@example.test", "admin")
    delegated = Principal(USER, ORG, "alice@example.test", "viewer")
    assert AuthorizationService(repository).authorize_administration(admin).allowed
    assert not AuthorizationService(repository).authorize_administration(delegated).allowed
    repository.user_enabled = False
    assert not AuthorizationService(repository).authorize_administration(admin).allowed
