# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Sanitized real-adapter parsing, write, deployment, and safety tests."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from firewall_manager.application.errors import (
    ProductionWriteDisabledError,
    ProviderConfigurationError,
    ProviderContractError,
    ProviderTlsValidationError,
    ProviderUnavailableError,
)
from firewall_manager.application.mutation_guard import current_mutation_guard
from firewall_manager.domain.models import (
    CapabilityStatus,
    PageRequest,
    ProviderCapability,
    ProviderTransactionState,
)
from firewall_manager.providers.fmc import RealFmcProvider
from firewall_manager.providers.real import CiscoReadOnlyProvider, normalize_fmc_endpoint
from firewall_manager.providers.scc import RealSccProvider


def _capabilities() -> dict[str, CapabilityStatus]:
    return {capability.value: CapabilityStatus.NOT_STARTED for capability in ProviderCapability}


def _test_credential(label: str) -> str:
    return f"sanitized-{label}-credential"


def _self_signed_certificate(common_name: str) -> tuple[str, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        certificate.public_bytes(serialization.Encoding.DER),
    )


def _collection(items: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(
        200,
        json={"items": items, "paging": {"offset": 0, "limit": 100, "count": len(items)}},
    )


def _fmc_transport(requests: list[httpx.Request]) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:  # noqa: PLR0911
        requests.append(request)
        path = request.url.path
        if path.endswith("/auth/generatetoken"):
            return httpx.Response(
                204,
                headers={
                    "X-auth-access-token": "sanitized-access-token",
                    "X-auth-refresh-token": "sanitized-refresh-token",
                },
            )
        if path.endswith("/info/serverversion"):
            return _collection([{"serverVersion": "7.7.0 (build 1)", "type": "ServerVersion"}])
        if path.endswith("/info/domain"):
            return _collection([{"uuid": "domain-1", "name": "Example Domain", "type": "Domain"}])
        if path.endswith("/devices/devicerecords"):
            return _collection([{"id": "device-1", "name": "Example Device", "model": "FTD"}])
        if path.endswith("/policy/accesspolicies"):
            return _collection([{"id": "policy-1", "name": "Example Policy", "version": "1"}])
        if path.endswith("/categories"):
            return _collection(
                [{"id": "category-1", "name": "Example Category", "metadata": {"position": 1}}]
            )
        if path.endswith("/accessrules"):
            return _collection(
                [
                    {
                        "id": "rule-1",
                        "name": "Example Rule",
                        "action": "ALLOW",
                        "ipsPolicy": {"id": "intrusion-1", "type": "IntrusionPolicy"},
                        "variableSet": {"id": "variables-1", "type": "VariableSet"},
                        "metadata": {"ruleIndex": 1, "category": {"id": "category-1"}},
                        "sourceNetworks": {"objects": [{"id": "network-1"}]},
                        "sourceZones": {"objects": [{"id": "zone-1"}]},
                    }
                ]
            )
        if path.endswith("/object/networks"):
            return _collection(
                [{"id": "network-1", "name": "Example Network", "value": "10.0.0.0/24"}]
            )
        if path.endswith("/object/securityzones"):
            return _collection([{"id": "zone-1", "name": "Inside", "interfaceMode": "ROUTED"}])
        return _collection([])

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_real_fmc_uses_token_auth_and_normalizes_read_only_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []
    clients: list[httpx.AsyncClient] = []
    async_client = httpx.AsyncClient

    def build_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        client = async_client(*args, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(httpx, "AsyncClient", build_client)
    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC — Test",
        username="api-user",
        password=_test_credential("fmc"),
        capabilities=_capabilities(),
        transport=_fmc_transport(requests),
        validate_network_target=False,
    )

    info = await provider.information()
    domains = await provider.domains(PageRequest(limit=100))
    domain_id = domains.items[0].native_id
    devices = await provider.devices(domain_id, PageRequest(limit=100))
    policies = await provider.policies(domain_id, PageRequest(limit=100))
    categories = await provider.categories(policies.items[0].native_id, PageRequest(limit=100))
    rules = await provider.rules(policies.items[0].native_id, PageRequest(limit=100))
    objects = await provider.objects(domain_id, PageRequest(limit=100))
    zones = await provider.zones(domain_id, PageRequest(limit=100))

    assert info.provider_version == "7.7.0 (build 1)"
    assert info.evidence_profile.value == "real"
    assert info.writable is False
    assert devices.items[0].native_id == "device-1"
    assert categories.items[0].native_id == "category-1"
    assert rules.items[0].object_references[0].object_native_id == "network-1"
    assert rules.items[0].zone_references[0].zone_native_id == "zone-1"
    assert rules.items[0].intrusion_policy_native_id == "intrusion-1"
    assert rules.items[0].variable_set_native_id == "variables-1"
    assert objects.items[0].normalized_value == "10.0.0.0/24"
    assert zones.items[0].zone_type == "ROUTED"
    assert [request.method for request in requests].count("POST") == 1
    assert all(
        request.method == "GET" or request.url.path.endswith("/auth/generatetoken")
        for request in requests
    )
    assert len(clients) == 1
    await provider.aclose()


@pytest.mark.asyncio
async def test_real_fmc_retries_transient_authentication_failure() -> None:
    auth_attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal auth_attempts
        assert request.url.path.endswith("/auth/generatetoken")
        auth_attempts += 1
        if auth_attempts == 1:
            return httpx.Response(401)
        return httpx.Response(204, headers={"X-auth-access-token": "recovered-token"})

    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC auth retry",
        username="api-user",
        password=_test_credential("fmc-auth-retry"),
        capabilities=_capabilities(),
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
    )
    try:
        await provider._authenticate_fmc()  # pyright: ignore[reportPrivateUsage]
        assert auth_attempts == 2
    finally:
        await provider.aclose()


@pytest.mark.asyncio
async def test_real_provider_operation_layer_rejects_configuration_post() -> None:
    class MutationProbe(RealFmcProvider):
        async def attempt_configuration_post(self) -> None:
            await self._send("POST", "/api/fmc_config/v1/domain/domain-1/object/networks")

    provider = MutationProbe(
        endpoint="https://fmc.example.test",
        display_name="FMC — Test",
        username="api-user",
        password=_test_credential("fmc"),
        capabilities=_capabilities(),
        transport=_fmc_transport([]),
        validate_network_target=False,
    )
    with pytest.raises(ProductionWriteDisabledError):
        await provider.attempt_configuration_post()
    await provider.aclose()


def _write_capabilities() -> dict[str, CapabilityStatus]:
    values = _capabilities()
    values[ProviderCapability.ACCESS_RULE_CREATE.value] = CapabilityStatus.SUPPORTED
    values[ProviderCapability.PENDING_CHANGE_INSPECTION.value] = CapabilityStatus.SUPPORTED
    return values


@pytest.mark.asyncio
async def test_real_fmc_empty_deployable_devices_without_items_is_known_empty() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/generatetoken"):
            return httpx.Response(204, headers={"X-auth-access-token": "token"})
        if request.url.path.endswith("/deployment/deployabledevices"):
            return httpx.Response(
                200,
                json={"paging": {"offset": 0, "limit": 0, "count": 0, "pages": 0}},
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC empty deployable devices",
        username="api-user",
        password=_test_credential("empty-deployable-devices"),
        capabilities=_write_capabilities(),
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
    )
    try:
        assert await provider.inspect_pending_changes("domain-1", "policy-1") == {
            "pending_change_count": 0,
            "scope_known": True,
            "changes": [],
        }
    finally:
        await provider.aclose()


@pytest.mark.asyncio
async def test_real_fmc_already_deployed_device_completes_without_starting_a_job() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/generatetoken"):
            return httpx.Response(204, headers={"X-auth-access-token": "token"})
        if request.url.path.endswith("/deployment/deployabledevices"):
            return httpx.Response(
                200,
                json={"paging": {"offset": 0, "limit": 0, "count": 0, "pages": 0}},
            )
        if request.url.path.endswith("/devices/devicerecords"):
            return _collection(
                [
                    {
                        "id": "device-1",
                        "deploymentStatus": "DEPLOYED",
                        "accessPolicy": {
                            "id": "policy-1",
                            "type": "AccessPolicy",
                        },
                    }
                ]
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC already deployed",
        username="api-user",
        password=_test_credential("already-deployed"),
        capabilities=_write_capabilities(),
        transport=httpx.MockTransport(handler),
        writable=True,
        validate_network_target=False,
    )
    try:
        result = await provider.start_deployment("domain-1", ["policy-1"], ["device-1"])
        assert result["state"] == "DEPLOYED"
        assert result["external_operation_id"] is None
        assert result["preflight"]["already_deployed"] is True
    finally:
        await provider.aclose()


def _create_rule_operation() -> list[dict[str, object]]:
    return [
        {
            "id": str(uuid4()),
            "kind": "CREATE_RULE",
            "provider_payload": {
                "domain_native_id": "domain-1",
                "policy_native_id": "policy-1",
                "expected_policy_version": "1",
                "category_native_id": "category-1",
                "category_provider_name": "FINANCE",
                "name": "FINANCE__allow-web",
                "action": "ALLOW",
                "source_object_native_ids": ["network-1"],
            },
        }
    ]


def _delete_rule_operation() -> list[dict[str, object]]:
    return [
        {
            "id": str(uuid4()),
            "kind": "DELETE_RULE",
            "provider_payload": {
                "domain_native_id": "domain-1",
                "policy_native_id": "policy-1",
                "rule_native_id": "rule-1",
                "expected_rule_name": "FINANCE__allow-web",
                "expected_rule_action": "ALLOW",
            },
        }
    ]


def _delete_object_operation() -> list[dict[str, object]]:
    return [
        {
            "id": str(uuid4()),
            "kind": "DELETE_OBJECT",
            "provider_payload": {
                "domain_native_id": "domain-1",
                "policy_native_id": "policy-1",
                "object_native_id": "object-1",
                "expected_object_version": "1",
                "expected_provider_name": "FINANCE__example",
                "object_type": "NETWORK",
                "normalized_value": "10.20.10.0/24",
            },
        }
    ]


def test_real_object_payload_maps_network_hosts_subnets_and_ranges() -> None:
    payload = {"object_type": "NETWORK", "provider_name": "FINANCE__example"}

    assert RealFmcProvider._object_payload(  # pyright: ignore[reportPrivateUsage]
        {**payload, "normalized_value": "10.10.10.1"}
    ) == ("hosts", {"type": "Host", "name": "FINANCE__example", "value": "10.10.10.1"})
    assert RealFmcProvider._object_payload(  # pyright: ignore[reportPrivateUsage]
        {**payload, "normalized_value": "10.10.10.0/24"}
    ) == (
        "networks",
        {"type": "Network", "name": "FINANCE__example", "value": "10.10.10.0/24"},
    )
    assert RealFmcProvider._object_payload(  # pyright: ignore[reportPrivateUsage]
        {**payload, "normalized_value": "10.10.10.1-10.10.20.30"}
    ) == (
        "ranges",
        {
            "type": "Range",
            "name": "FINANCE__example",
            "value": "10.10.10.1-10.10.20.30",
        },
    )


def test_real_object_payload_maps_fmc_icmp_fields() -> None:
    assert RealFmcProvider._object_payload(  # pyright: ignore[reportPrivateUsage]
        {
            "object_type": "PORT_SERVICE",
            "provider_name": "FINANCE__icmp",
            "normalized_value": "icmp/ECHO_REPLY/ANY",
        }
    ) == (
        "icmpv4objects",
        {
            "type": "ICMPV4Object",
            "name": "FINANCE__icmp",
            "icmpType": "0",
        },
    )
    assert (
        RealFmcProvider._object_payload(  # pyright: ignore[reportPrivateUsage]
            {
                "object_type": "PORT_SERVICE",
                "provider_name": "FINANCE__icmp",
                "normalized_value": "ipv6-icmp/ECHO_REQUEST/PORT_UNREACHABLE",
            }
        )[1]["code"]
        == 4
    )


@pytest.mark.parametrize(
    ("endpoint", "criterion"),
    [
        ("applicationtypes", "type"),
        ("applicationrisks", "risk"),
        ("applicationproductivities", "productivity"),
        ("applicationcategories", "category"),
        ("applicationtags", "tag"),
    ],
)
def test_system_application_criteria_are_normalized_with_stable_filter_ids(
    endpoint: str, criterion: str
) -> None:
    item = CiscoReadOnlyProvider._system_filter_item(  # pyright: ignore[reportPrivateUsage]
        {"id": "criterion-1", "name": "Example"}, endpoint
    )

    assert item["id"] == f"system-filter:{criterion}:criterion-1"
    assert f'"criterion":"{criterion}"' in str(item["value"])


def test_system_application_criteria_are_sent_as_provider_app_conditions() -> None:
    payload = CiscoReadOnlyProvider._application_reference_payload(  # pyright: ignore[reportPrivateUsage]
        {
            "id": "system-filter:category:category-1",
            "type": "ApplicationFilter",
            "normalized_value": '{"criterion":"category","id":"category-1","name":"Social"}',
        }
    )

    assert payload == {
        "type": "ApplicationFilterCondition",
        "categories": [
            {
                "id": "category-1",
                "name": "Social",
                "type": "ApplicationCategory",
            }
        ],
    }


def test_real_rule_logging_selects_fmc_event_viewer_destination() -> None:
    begin = CiscoReadOnlyProvider._rule_payload(  # pyright: ignore[reportPrivateUsage]
        {"name": "FINANCE__logged", "logging": "BEGIN"}
    )
    end = CiscoReadOnlyProvider._rule_payload(  # pyright: ignore[reportPrivateUsage]
        {"name": "FINANCE__logged", "logging": "END"}
    )
    no_logging = CiscoReadOnlyProvider._rule_payload(  # pyright: ignore[reportPrivateUsage]
        {"name": "FINANCE__quiet", "logging": "NONE"}
    )

    assert begin["sendEventsToFMC"] is True
    assert end["sendEventsToFMC"] is True
    assert "sendEventsToFMC" not in no_logging


@pytest.mark.asyncio
async def test_real_fmc_rule_create_is_guarded_and_normalized() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/auth/generatetoken"):
            return httpx.Response(204, headers={"X-auth-access-token": "token"})
        if request.url.path.endswith("/policy/accesspolicies/policy-1"):
            return httpx.Response(200, json={"id": "policy-1", "version": "1"})
        if request.url.path.endswith("/deployment/deployabledevices"):
            return _collection([])
        if request.url.path.endswith("/pendingchanges"):
            return _collection([])
        if request.method == "GET" and request.url.path.endswith("/accessrules"):
            return _collection([])
        if request.method == "POST" and request.url.path.endswith("/accessrules"):
            body = request.content.decode()
            assert "FINANCE__allow-web" in body
            assert "network-1" in body
            return httpx.Response(
                201,
                json={"id": "rule-created", "version": "2", "name": "FINANCE__allow-web"},
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC write test",
        username="api-user",
        password=_test_credential("fmc-write"),
        capabilities=_write_capabilities(),
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
        writable=True,
    )
    result = await provider.execute_transaction(uuid4(), uuid4(), _create_rule_operation())
    assert result.state is ProviderTransactionState.SUCCEEDED
    assert result.operation_results[0]["provider_resource_id"] == "rule-created"
    assert [request.method for request in requests].count("POST") == 2
    await provider.aclose()


@pytest.mark.asyncio
async def test_real_fmc_mutation_reauthenticates_once_after_expired_token() -> None:
    requests: list[httpx.Request] = []
    auth_count = 0
    mutation_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:  # noqa: PLR0911
        nonlocal auth_count, mutation_count
        requests.append(request)
        if request.url.path.endswith("/auth/generatetoken"):
            auth_count += 1
            return httpx.Response(
                204,
                headers={"X-auth-access-token": f"token-{auth_count}"},
            )
        if request.url.path.endswith("/policy/accesspolicies/policy-1"):
            return httpx.Response(200, json={"id": "policy-1", "version": "1"})
        if request.url.path.endswith("/deployment/deployabledevices"):
            return _collection([])
        if request.url.path.endswith("/pendingchanges"):
            return _collection([])
        if request.method == "GET" and request.url.path.endswith("/accessrules"):
            return _collection([])
        if request.method == "POST" and request.url.path.endswith("/accessrules"):
            mutation_count += 1
            if mutation_count == 1:
                return httpx.Response(401, json={"message": "expired token"})
            return httpx.Response(
                201,
                json={"id": "rule-created-after-reauth", "version": "2"},
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC re-auth test",
        username="api-user",
        password=_test_credential("fmc-reauth"),
        capabilities=_write_capabilities(),
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
        writable=True,
    )

    class RecordingGuard:
        def __init__(self) -> None:
            self.last_response_status: int | None = None

        def before_mutation(self, _method: str, _path: str, _payload: object = None) -> None:
            if self.last_response_status not in {None, 401}:
                raise AssertionError("a non-authenticated mutation was delivered twice")

        def after_mutation(self, result: object = None) -> None:
            assert isinstance(result, dict)
            self.last_response_status = int(result["status"])

    guard_token = current_mutation_guard.set(RecordingGuard())
    try:
        result = await provider.execute_transaction(uuid4(), uuid4(), _create_rule_operation())
    finally:
        current_mutation_guard.reset(guard_token)

    assert result.state is ProviderTransactionState.SUCCEEDED
    assert result.operation_results[0]["provider_resource_id"] == "rule-created-after-reauth"
    assert auth_count == 2
    assert mutation_count == 2
    mutation_tokens = [
        request.headers.get("x-auth-access-token")
        for request in requests
        if request.method == "POST" and request.url.path.endswith("/accessrules")
    ]
    assert mutation_tokens == [
        "token-1",
        "token-2",
    ]
    await provider.aclose()


@pytest.mark.asyncio
async def test_real_mutation_timeout_is_ambiguous_and_never_retried() -> None:
    mutation_attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal mutation_attempts
        if request.url.path.endswith("/auth/generatetoken"):
            return httpx.Response(204, headers={"X-auth-access-token": "token"})
        if request.url.path.endswith("/policy/accesspolicies/policy-1"):
            return httpx.Response(200, json={"id": "policy-1", "version": "1"})
        if request.url.path.endswith("/deployment/deployabledevices"):
            return _collection([])
        if request.url.path.endswith("/pendingchanges"):
            return _collection([])
        if request.method == "GET" and request.url.path.endswith("/accessrules"):
            return _collection([])
        mutation_attempts += 1
        raise httpx.ReadTimeout("result unknown", request=request)

    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC ambiguous test",
        username="api-user",
        password=_test_credential("fmc-ambiguous"),
        capabilities=_write_capabilities(),
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
        writable=True,
    )
    result = await provider.execute_transaction(uuid4(), uuid4(), _create_rule_operation())
    assert result.state is ProviderTransactionState.RECONCILIATION_REQUIRED
    assert result.operation_results[0]["status"] == "AMBIGUOUS"
    assert mutation_attempts == 1
    await provider.aclose()


@pytest.mark.asyncio
async def test_parallel_mutation_rejection_is_non_mutating_and_retryable() -> None:
    mutation_attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal mutation_attempts
        if request.url.path.endswith("/auth/generatetoken"):
            return httpx.Response(204, headers={"X-auth-access-token": "token"})
        if request.url.path.endswith("/policy/accesspolicies/policy-1"):
            return httpx.Response(200, json={"id": "policy-1", "version": "1"})
        if request.url.path.endswith("/deployment/deployabledevices"):
            return _collection([])
        if request.url.path.endswith("/pendingchanges"):
            return _collection([])
        if request.method == "GET" and request.url.path.endswith("/accessrules"):
            return _collection([])
        mutation_attempts += 1
        return httpx.Response(
            429,
            json={
                "error": {
                    "category": "FRAMEWORK",
                    "messages": [
                        {
                            "description": (
                                "Parallel add/update/delete operations are blocked. "
                                "Please retry the request."
                            )
                        }
                    ],
                }
            },
        )

    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC parallel mutation test",
        username="api-user",
        password=_test_credential("fmc-parallel-mutation"),
        capabilities=_write_capabilities(),
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
        writable=True,
    )
    result = await provider.execute_transaction(uuid4(), uuid4(), _create_rule_operation())
    assert result.state is ProviderTransactionState.CONFLICT
    assert result.operation_results[0]["status"] == "CONFLICT"
    assert result.operation_results[0]["mutated"] is False
    failure = result.operation_results[0]["failure"]
    assert failure["code"] == "PROVIDER_RATE_LIMITED"
    assert failure["retry_safe"] is True
    assert failure["provider_status"] == 429
    assert any(
        "parallel add/update/delete operations are blocked" in str(message).lower()
        for message in failure["provider_messages"]
    )
    assert mutation_attempts == 1
    await provider.aclose()


@pytest.mark.asyncio
async def test_delete_of_already_missing_rule_is_idempotent() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/generatetoken"):
            return httpx.Response(204, headers={"X-auth-access-token": "token"})
        if request.url.path.endswith("/policy/accesspolicies/policy-1"):
            return httpx.Response(200, json={"id": "policy-1", "version": "1"})
        if request.url.path.endswith("/deployment/deployabledevices"):
            return _collection([])
        if request.url.path.endswith("/pendingchanges"):
            return _collection([])
        if request.url.path.endswith("/accessrules/rule-1"):
            return httpx.Response(404, json={"message": "not found"})
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    capabilities = _write_capabilities()
    capabilities[ProviderCapability.ACCESS_RULE_DELETE.value] = CapabilityStatus.SUPPORTED
    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC idempotent delete test",
        username="api-user",
        password=_test_credential("fmc-idempotent-delete"),
        capabilities=capabilities,
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
        writable=True,
    )
    result = await provider.execute_transaction(uuid4(), uuid4(), _delete_rule_operation())
    assert result.state is ProviderTransactionState.SUCCEEDED
    assert result.operation_results[0]["status"] == "SUCCEEDED"
    assert result.operation_results[0]["mutated"] is False
    assert result.operation_results[0]["provider_resource_id"] == "rule-1"
    await provider.aclose()


@pytest.mark.asyncio
async def test_delete_of_already_missing_object_is_idempotent() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/generatetoken"):
            return httpx.Response(204, headers={"X-auth-access-token": "token"})
        if request.url.path.endswith("/policy/accesspolicies/policy-1"):
            return httpx.Response(200, json={"id": "policy-1", "version": "1"})
        if request.url.path.endswith("/deployment/deployabledevices"):
            return _collection([])
        if request.url.path.endswith("/pendingchanges"):
            return _collection([])
        if request.url.path.endswith("/object/networks/object-1"):
            return httpx.Response(404, json={"message": "not found"})
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    capabilities = _write_capabilities()
    capabilities[ProviderCapability.NETWORK_OBJECT_MUTATION.value] = CapabilityStatus.SUPPORTED
    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC idempotent object delete test",
        username="api-user",
        password=_test_credential("fmc-idempotent-object-delete"),
        capabilities=capabilities,
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
        writable=True,
    )
    result = await provider.execute_transaction(uuid4(), uuid4(), _delete_object_operation())
    assert result.state is ProviderTransactionState.SUCCEEDED
    assert result.operation_results[0]["status"] == "SUCCEEDED"
    assert result.operation_results[0]["mutated"] is False
    assert result.operation_results[0]["provider_resource_id"] == "object-1"
    await provider.aclose()


@pytest.mark.asyncio
async def test_custom_ca_name_mismatch_requires_exact_uploaded_leaf_pin() -> None:
    uploaded_pem, uploaded_der = _self_signed_certificate("firepower")
    _other_pem, other_der = _self_signed_certificate("firepower")
    provider = RealFmcProvider(
        endpoint="https://192.0.2.10",
        display_name="Pinned FMC",
        username="api-user",
        password=_test_credential("pinned-fmc"),
        capabilities=_capabilities(),
        ca_certificate=uploaded_pem,
        transport=_fmc_transport([]),
        validate_network_target=False,
    )

    assert provider._certificate_is_exactly_pinned(  # pyright: ignore[reportPrivateUsage]
        uploaded_der
    )
    assert not provider._certificate_is_exactly_pinned(  # pyright: ignore[reportPrivateUsage]
        other_der
    )
    provider._exact_pin_active = True  # pyright: ignore[reportPrivateUsage]

    class FakeSslObject:
        def __init__(self, certificate: bytes) -> None:
            self.certificate = certificate

        def getpeercert(self, *, binary_form: bool = False) -> bytes:
            assert binary_form is True
            return self.certificate

    class FakeStream:
        def __init__(self, certificate: bytes) -> None:
            self.certificate = certificate

        def get_extra_info(self, name: str) -> FakeSslObject | None:
            return FakeSslObject(self.certificate) if name == "ssl_object" else None

    provider._capture_certificate(  # pyright: ignore[reportPrivateUsage]
        httpx.Response(200, extensions={"network_stream": FakeStream(uploaded_der)})
    )
    assert provider.certificate_info["identity_verification"] == "EXACT_CERTIFICATE_PIN"
    with pytest.raises(ProviderTlsValidationError):
        provider._capture_certificate(  # pyright: ignore[reportPrivateUsage]
            httpx.Response(200, extensions={"network_stream": FakeStream(other_der)})
        )
    with pytest.raises(ProviderTlsValidationError):
        provider._capture_certificate(  # pyright: ignore[reportPrivateUsage]
            httpx.Response(200)
        )
    await provider.aclose()


@pytest.mark.asyncio
async def test_real_scc_uses_controlled_region_and_discovers_tenant() -> None:
    seen: list[str] = []
    scc_token = _test_credential("scc")

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        assert request.headers["Authorization"] == f"Bearer {scc_token}"
        if request.url.path.endswith("/v1/token"):
            return httpx.Response(
                200, json={"tenantUid": "tenant-1", "tenantName": "Example Tenant"}
            )
        if request.url.path.endswith("/info/serverversion"):
            return _collection([{"serverVersion": "cdFMC API 1.20.0"}])
        if request.url.path.endswith("/info/domain"):
            return _collection([{"uuid": "domain-1", "name": "Global"}])
        return _collection([])

    provider = RealSccProvider(
        region="eu",
        display_name="SCC — Europe",
        token=scc_token,
        capabilities=_capabilities(),
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
    )
    info = await provider.information()
    domains = await provider.domains(PageRequest(limit=100))

    assert info.writable is False
    assert provider.compatibility_scopes(domains.items)[0] == {
        "native_id": "tenant-1",
        "name": "Example Tenant",
        "scope_type": "TENANT",
    }
    assert all(url.startswith("https://api.eu.security.cisco.com/firewall/") for url in seen)
    await provider.aclose()


@pytest.mark.asyncio
async def test_real_scc_devices_use_scc_uid_for_deployment() -> None:
    scc_token = _test_credential("scc-devices")

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == f"Bearer {scc_token}"
        if request.url.path == "/firewall/v1/token":
            return httpx.Response(200, json={"tenantUid": "tenant-1"})
        if request.url.path.endswith("/devices/devicerecords/fmc-device-1"):
            return httpx.Response(
                200, json={"id": "fmc-device-1", "accessPolicy": {"id": "policy-1"}}
            )
        assert request.url.path == "/firewall/v1/inventory/devices"
        return _collection(
            [
                {
                    "uid": "scc-device-1",
                    "name": "Branch FTD",
                    "deviceType": "CDFMC_MANAGED_FTD",
                    "uidOnFmc": "fmc-device-1",
                    "modelNumber": "Cisco Secure Firewall 1210CP Threat Defense",
                }
            ]
        )

    provider = RealSccProvider(
        region="eu",
        display_name="SCC — Europe",
        token=scc_token,
        capabilities=_capabilities(),
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
    )
    devices = await provider.devices("domain-1", PageRequest(limit=100))

    assert devices.items[0].native_id == "scc-device-1"
    assert devices.items[0].native_metadata["fmc_native_id"] == "fmc-device-1"
    assert devices.items[0].model == "Cisco Secure Firewall 1210CP Threat Defense"
    await provider.aclose()


@pytest.mark.asyncio
async def test_real_scc_starts_and_polls_ftd_deployment() -> None:
    requests: list[httpx.Request] = []
    scc_token = _test_credential("scc-deployment")

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["Authorization"] == f"Bearer {scc_token}"
        if request.url.path.endswith("/deployment/deployabledevices"):
            return httpx.Response(200, json={"items": [], "paging": {"count": 0}})
        if request.method == "GET" and request.url.path.endswith("/v1/inventory/devices"):
            return httpx.Response(
                200,
                json={
                    "count": 3,
                    "items": [
                        {
                            "uid": "device-1",
                            "uidOnFmc": "fmc-device-1",
                            "deviceType": "CDFMC_MANAGED_FTD",
                        },
                        {
                            "uid": "device-2",
                            "uidOnFmc": "fmc-device-2",
                            "deviceType": "CDFMC_MANAGED_FTD",
                        },
                        {"uid": "onprem-device", "deviceType": "ONPREM_FMC_MANAGED_FTD"},
                    ],
                },
            )
        if request.method == "POST" and request.url.path.endswith("/deployment/rollbackrequests"):
            assert json.loads(request.content) == {
                "rollbackDeviceList": [
                    {"deploymentJobId": "deployment-run-1", "deviceList": ["fmc-device-1"]}
                ],
                "type": "RollbackRequest",
            }
            return httpx.Response(202, json={"metadata": {"task": {"id": "rollback-task-1"}}})
        if request.method == "POST":
            assert request.url.path == "/firewall/v1/inventory/devices/ftds/deploy"
            assert json.loads(request.content) == {
                "devices": [
                    {"uid": "device-1", "selectedPolicyTypes": ["FULL_DEPLOY"]},
                    {"uid": "device-2", "selectedPolicyTypes": ["FULL_DEPLOY"]},
                ],
                "ignoreWarnings": False,
            }
            return httpx.Response(202, json={"entityUid": "deployment-run-1"})
        assert request.method == "GET"
        if request.url.path.endswith("/runs/deployment-run-1"):
            return httpx.Response(
                200,
                json={
                    "uid": "deployment-run-1",
                    "deploymentRunStatus": "DEPLOY_COMPLETED",
                    "deviceDeploymentStatuses": [{"uid": "device-1", "status": "DONE"}],
                },
            )
        assert request.url.path.endswith("/job/taskstatuses/rollback-task-1")
        return httpx.Response(
            200,
            json={
                "status": "SUCCEEDED",
                "deviceResults": [{"deviceUUID": "fmc-device-1", "status": "SUCCEEDED"}],
            },
        )

    provider = RealSccProvider(
        region="eu",
        display_name="SCC — Europe",
        token=scc_token,
        capabilities={**_capabilities(), "pending_change_inspection": CapabilityStatus.SUPPORTED},
        transport=httpx.MockTransport(handler),
        validate_network_target=False,
        writable=True,
    )
    with pytest.raises(ProviderContractError) as refused:
        await provider.start_deployment(
            "tenant-1", ["policy-1"], ["device-1", "device-2", "onprem-device", "device-1"]
        )
    assert refused.value.details["code"] == "DEPLOYMENT_TARGET_UNAUTHORIZED"
    status = await provider.deployment_status("deployment-run-1")

    assert status["state"] == "DEPLOYED"
    assert status["provider_status"] == "DEPLOY_COMPLETED"
    assert status["devices"] == [{"uid": "device-1", "status": "DONE"}]
    rollback = await provider.rollback_deployment("domain-1", "deployment-run-1", ["device-1"])
    rollback_status = await provider.rollback_status(str(rollback["external_operation_id"]))
    assert rollback["external_operation_id"] == "domain-1:rollback-task-1"
    assert rollback_status["state"] == "ROLLED_BACK"
    assert not any(request.url.path.endswith("/ftds/deploy") for request in requests)
    assert sum(request.method == "POST" for request in requests) == 1  # native rollback only
    await provider.aclose()


def test_fmc_target_validation_rejects_unsafe_or_credentialed_urls() -> None:
    for value in (
        "http://fmc.example.test",
        "https://user:password@fmc.example.test",
        "https://169.254.169.254",
        "https://127.0.0.1",
        "https://fmc.example.test/arbitrary/path",
    ):
        with pytest.raises(ProviderConfigurationError):
            normalize_fmc_endpoint(value)
    assert normalize_fmc_endpoint("https://10.20.30.40:8443") == "https://10.20.30.40:8443"


@pytest.mark.asyncio
async def test_real_provider_refuses_redirects_instead_of_following_origins() -> None:
    async def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://attacker.example/token"})

    provider = RealFmcProvider(
        endpoint="https://fmc.example.test",
        display_name="FMC — Test",
        username="api-user",
        password=_test_credential("fmc"),
        capabilities=_capabilities(),
        transport=httpx.MockTransport(redirect),
        validate_network_target=False,
    )
    with pytest.raises(ProviderUnavailableError):
        await provider.information()
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["fmc", "scc"])
@pytest.mark.parametrize("pending", ["external", "ours", "empty", "unknown"])
async def test_deployment_refuses_unattributed_pending_changes(kind: str, pending: str) -> None:
    mutations = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and "generatetoken" in request.url.path:
            return httpx.Response(204, headers={"X-auth-access-token": "fixture"})
        if request.method != "GET":
            mutations.append(request.url.path)
            return httpx.Response(202, json={"id": "unexpected"})
        if request.url.path.endswith("pendingchanges"):
            return httpx.Response(
                200,
                json=(
                    {"items": []}
                    if pending == "empty"
                    else {
                        "items": [
                            {
                                "entityType": "AccessPolicy",
                                "lastUpdatedByUsers": [
                                    "firewall-policy-manager"
                                    if pending == "ours"
                                    else "someone-else"
                                ],
                            }
                        ]
                    }
                ),
            )
        return httpx.Response(200, json={"items": [{"id": "device-1"}], "paging": {"count": 1}})

    options = {
        "capabilities": {
            **_capabilities(),
            "pending_change_inspection": (
                CapabilityStatus.NOT_STARTED if pending == "unknown" else CapabilityStatus.SUPPORTED
            ),
        },
        "transport": httpx.MockTransport(handler),
        "validate_network_target": False,
        "writable": True,
        "display_name": "Test",
    }
    provider = (
        RealFmcProvider(
            endpoint="https://fmc.example.test",
            username="fixture",
            password=_test_credential("deploy"),
            **options,
        )
        if kind == "fmc"
        else RealSccProvider(region="eu", token=_test_credential("deploy"), **options)
    )
    with pytest.raises(ProviderContractError) as error:
        await provider.start_deployment("domain", ["policy"], ["device-1"])
    assert error.value.details["code"] in {
        "DEPLOYMENT_TARGET_UNAUTHORIZED",
        "DEPLOYMENT_TARGET_NOT_READY",
        "DEPLOYMENT_INSPECTION_UNAVAILABLE",
    }
    # Even a matching writer identity does not establish exact candidate ownership.
    # These incomplete legacy fixtures never establish deployable target evidence.
    assert mutations == []
    await provider.aclose()
