"""Shared provider behavioral contracts for both first-class mock providers."""

from collections.abc import Callable
from uuid import uuid4

import httpx
import pytest

from firewall_manager.application.errors import (
    ProviderPaginationError,
    ProviderUnavailableError,
)
from firewall_manager.domain.models import (
    CapabilityStatus,
    FirewallObjectType,
    PageRequest,
    ProviderEvidenceProfile,
    ProviderKind,
    RuleObjectElement,
    ZoneElement,
)
from firewall_manager.providers.fmc import FmcProviderReader
from firewall_manager.providers.mock import DeterministicMockProvider, MockScenario
from firewall_manager.providers.scc import SccProviderReader


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(ProviderKind))
async def test_mock_provider_contract_supports_paginated_normalized_discovery(
    kind: ProviderKind,
) -> None:
    provider = DeterministicMockProvider(kind)
    info = await provider.information()
    assert info.provider is kind
    assert info.writable is True
    assert info.evidence_profile is ProviderEvidenceProfile.MOCK
    assert info.capabilities["access_rule_read"] is CapabilityStatus.READ_ONLY
    assert info.capabilities["rule_category_read"] is CapabilityStatus.READ_ONLY
    assert info.capabilities["security_zone_read"] is CapabilityStatus.READ_ONLY
    assert info.capabilities["rule_ordering"] is CapabilityStatus.SUPPORTED

    first = await provider.domains(PageRequest(limit=1))
    assert len(first.items) == 1
    assert first.next_cursor is not None
    second = await provider.domains(PageRequest(limit=1, cursor=first.next_cursor))
    assert len(second.items) == 1
    assert second.next_cursor is None

    domain_id = first.items[0].native_id
    policies = await provider.policies(domain_id, PageRequest())
    objects = await provider.objects(domain_id, PageRequest())
    zones = await provider.zones(domain_id, PageRequest())
    assert policies.items[0].native_id.startswith(kind.value)
    assert {item.sharing_mode for item in objects.items} == {"private", "shared_use"}
    assert {item.object_type for item in objects.items} == set(FirewallObjectType)
    group = next(
        item for item in objects.items if item.object_type is FirewallObjectType.NETWORK_GROUP
    )
    assert len(group.referenced_object_native_ids) == 2
    assert {zone.name for zone in zones.items} == {
        "Inside",
        "Outside",
        "Inside-Finance",
        "Inside-Engineering",
    }

    rules = await provider.rules(policies.items[0].native_id, PageRequest())
    categories = await provider.categories(policies.items[0].native_id, PageRequest())
    assert {category.name for category in categories.items} == {
        "FINANCE__RULES",
        "ENGINEERING__RULES",
        "ADMIN__RULES",
    }
    assert {reference.element for reference in rules.items[0].object_references} >= {
        RuleObjectElement.SOURCE_NETWORK,
        RuleObjectElement.DESTINATION_NETWORK,
        RuleObjectElement.PORT_SERVICE,
    }
    assert {reference.element for reference in rules.items[0].zone_references} == {
        ZoneElement.SOURCE,
        ZoneElement.DESTINATION,
    }
    assert all(not type(item).__module__.startswith("cisco") for item in rules.items)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(ProviderKind))
async def test_mock_provider_contract_maps_fault_scenarios(kind: ProviderKind) -> None:
    unavailable = DeterministicMockProvider(kind, MockScenario.UNAVAILABLE)
    with pytest.raises(ProviderUnavailableError):
        await unavailable.information()

    partial = DeterministicMockProvider(kind, MockScenario.FAIL_SECOND_PAGE)
    first = await partial.domains(PageRequest(limit=1))
    with pytest.raises(ProviderPaginationError):
        await partial.domains(PageRequest(limit=1, cursor=first.next_cursor))


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(ProviderKind))
async def test_supported_mock_rule_capabilities_mutate_provider_state(kind: ProviderKind) -> None:
    provider = DeterministicMockProvider(kind)
    manager_id = uuid4()
    prefix = kind.value
    policy_id = f"{prefix}-policy-edge"
    category_id = f"{prefix}-category-finance"

    create_id = str(uuid4())
    create = await provider.execute_transaction(
        uuid4(),
        manager_id,
        [
            {
                "id": create_id,
                "kind": "CREATE_RULE",
                "provider_payload": {
                    "name": "FINANCE delegated rule",
                    "action": "ALLOW",
                    "policy_native_id": policy_id,
                    "category_native_id": category_id,
                    "position": 11,
                    "expected_policy_version": "3",
                },
            }
        ],
    )
    assert create.state.value == "SUCCEEDED"
    rule_native_id = str(create.operation_results[0]["provider_resource_id"])
    rules = await provider.rules(policy_id, PageRequest())
    created = next(item for item in rules.items if item.native_id == rule_native_id)
    assert created.position == 11

    update = await provider.execute_transaction(
        uuid4(),
        manager_id,
        [
            {
                "id": str(uuid4()),
                "kind": "MODIFY_RULE",
                "provider_payload": {
                    "name": "FINANCE delegated rule updated",
                    "action": "BLOCK",
                    "policy_native_id": policy_id,
                    "category_native_id": category_id,
                    "rule_native_id": rule_native_id,
                    "expected_policy_version": "4",
                    "expected_rule_version": "1",
                },
            }
        ],
    )
    assert update.state.value == "SUCCEEDED"
    rules = await provider.rules(policy_id, PageRequest())
    updated = next(item for item in rules.items if item.native_id == rule_native_id)
    assert updated.action == "BLOCK"

    move = await provider.execute_transaction(
        uuid4(),
        manager_id,
        [
            {
                "id": str(uuid4()),
                "kind": "MOVE_RULE",
                "provider_payload": {
                    "policy_native_id": policy_id,
                    "category_native_id": category_id,
                    "rule_native_id": rule_native_id,
                    "position": 12,
                    "expected_policy_version": "5",
                    "expected_rule_version": "2",
                },
            }
        ],
    )
    assert move.state.value == "SUCCEEDED"

    boundary = await provider.execute_transaction(
        uuid4(),
        manager_id,
        [
            {
                "id": str(uuid4()),
                "kind": "MOVE_RULE",
                "provider_payload": {
                    "policy_native_id": policy_id,
                    "category_native_id": category_id,
                    "rule_native_id": rule_native_id,
                    "position": 20,
                    "expected_policy_version": "6",
                    "expected_rule_version": "3",
                },
            }
        ],
    )
    assert boundary.state.value == "CONFLICT"
    assert boundary.operation_results[0]["failure"] == {
        "code": "RULE_ORDERING_BOUNDARY_VIOLATION",
        "retry_safe": False,
    }

    delete = await provider.execute_transaction(
        uuid4(),
        manager_id,
        [
            {
                "id": str(uuid4()),
                "kind": "DELETE_RULE",
                "provider_payload": {
                    "policy_native_id": policy_id,
                    "rule_native_id": rule_native_id,
                    "expected_policy_version": "6",
                    "expected_rule_version": "3",
                },
            }
        ],
    )
    assert delete.state.value == "SUCCEEDED"
    assert all(
        item.native_id != rule_native_id
        for item in (await provider.rules(policy_id, PageRequest())).items
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(ProviderKind))
async def test_supported_mock_object_create_capabilities_match_behavior(
    kind: ProviderKind,
) -> None:
    provider = DeterministicMockProvider(kind)
    manager_id = uuid4()
    prefix = kind.value
    values = {
        FirewallObjectType.NETWORK: "10.20.77.0/24",
        FirewallObjectType.PORT_SERVICE: "tcp/8443",
        FirewallObjectType.URL: "reconciled.example.test",
    }
    expected_policy_version = 3
    for object_type, value in values.items():
        result = await provider.execute_transaction(
            uuid4(),
            manager_id,
            [
                {
                    "id": str(uuid4()),
                    "kind": "CREATE_OBJECT",
                    "provider_payload": {
                        "policy_native_id": f"{prefix}-policy-edge",
                        "expected_policy_version": str(expected_policy_version),
                        "object_type": object_type.value,
                        "provider_name": f"FINANCE__created-{object_type.value.lower()}",
                        "normalized_value": value,
                        "resolution": {"kind": "NEW_OBJECT_REQUIRED"},
                    },
                }
            ],
        )
        assert result.state.value == "SUCCEEDED"
        expected_policy_version += 1

    objects = await provider.objects(f"{prefix}-domain-main", PageRequest())
    assert {
        (item.object_type, item.normalized_value)
        for item in objects.items
        if item.name.startswith("FINANCE__created-")
    } == set(values.items())

    partial = await provider.execute_transaction(
        uuid4(),
        manager_id,
        [
            {
                "id": str(uuid4()),
                "kind": "CREATE_OBJECT",
                "provider_payload": {
                    "policy_native_id": f"{prefix}-policy-edge",
                    "expected_policy_version": str(expected_policy_version),
                    "object_type": FirewallObjectType.APPLICATION.value,
                    "provider_name": "FINANCE__created-application",
                    "normalized_value": "example-application",
                    "resolution": {"kind": "NEW_OBJECT_REQUIRED"},
                },
            }
        ],
    )
    assert partial.state.value == "CONFLICT"
    assert partial.operation_results[0]["failure"] == {
        "code": "PROVIDER_CAPABILITY_UNAVAILABLE",
        "retry_safe": False,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(ProviderKind))
async def test_mock_transactions_are_idempotent_and_reconcilable(kind: ProviderKind) -> None:
    provider = DeterministicMockProvider(kind)
    change_set_id = uuid4()
    manager_id = uuid4()
    operation: dict[str, object] = {
        "id": str(uuid4()),
        "kind": "CREATE_RULE",
        "provider_payload": {
            "name": "Idempotent rule",
            "action": "ALLOW",
            "policy_native_id": f"{kind.value}-policy-edge",
            "category_native_id": f"{kind.value}-category-finance",
            "position": 11,
            "expected_policy_version": "3",
            "mock_behavior": "timeout_after_mutation",
        },
    }
    first = await provider.execute_transaction(change_set_id, manager_id, [operation])
    repeated = await provider.execute_transaction(change_set_id, manager_id, [operation])
    assert first == repeated
    assert provider.transaction_result(first.external_operation_id) == first
    matching = [
        item
        for item in (await provider.rules(f"{kind.value}-policy-edge", PageRequest())).items
        if item.name == "Idempotent rule"
    ]
    assert len(matching) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reader_type", "kind"),
    [(FmcProviderReader, ProviderKind.FMC), (SccProviderReader, ProviderKind.SCC)],
)
async def test_http_adapter_contract_is_read_only(
    reader_type: Callable[..., FmcProviderReader | SccProviderReader], kind: ProviderKind
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/discovery"
        return httpx.Response(
            200,
            json={
                "provider": kind.value,
                "display_name": f"Mock {kind.upper()}",
                "provider_version": "mock-1",
                "policy_count": 2,
                "object_count": 4,
                "writable": False,
            },
        )

    inventory = await reader_type("http://provider", httpx.MockTransport(handler)).discover()
    assert inventory.provider is kind
    assert inventory.writable is False


@pytest.mark.asyncio
async def test_provider_mismatch_maps_to_safe_error() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            json={
                "provider": "scc",
                "display_name": "Wrong mock",
                "provider_version": "mock-1",
                "policy_count": 0,
                "object_count": 0,
                "writable": False,
            },
        )
    )
    with pytest.raises(ProviderUnavailableError):
        await FmcProviderReader("http://provider", transport).discover()
