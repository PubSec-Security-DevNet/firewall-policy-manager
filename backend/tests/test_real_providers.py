"""Sanitized real-adapter parsing and hard read-only safety tests."""

from typing import Any

import httpx
import pytest

from firewall_manager.application.errors import (
    ProductionWriteDisabledError,
    ProviderConfigurationError,
    ProviderUnavailableError,
)
from firewall_manager.domain.models import CapabilityStatus, PageRequest, ProviderCapability
from firewall_manager.providers.fmc import RealFmcProvider
from firewall_manager.providers.real import normalize_fmc_endpoint
from firewall_manager.providers.scc import RealSccProvider


def _capabilities() -> dict[str, CapabilityStatus]:
    return {capability.value: CapabilityStatus.NOT_STARTED for capability in ProviderCapability}


def _test_credential(label: str) -> str:
    return f"sanitized-{label}-credential"


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
async def test_real_fmc_uses_token_auth_and_normalizes_read_only_inventory() -> None:
    requests: list[httpx.Request] = []
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
    assert objects.items[0].normalized_value == "10.0.0.0/24"
    assert zones.items[0].zone_type == "ROUTED"
    assert [request.method for request in requests].count("POST") == 1
    assert all(
        request.method == "GET" or request.url.path.endswith("/auth/generatetoken")
        for request in requests
    )


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


@pytest.mark.asyncio
async def test_real_scc_uses_controlled_region_and_discovers_tenant() -> None:
    seen: list[str] = []
    scc_token = _test_credential("scc")

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        assert request.headers["Authorization"] == f"Bearer {scc_token}"
        if request.url.path.endswith("/v1/token-info"):
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
