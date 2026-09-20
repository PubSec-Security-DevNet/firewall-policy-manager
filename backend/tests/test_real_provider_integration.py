"""Explicitly opted-in, non-production, read-only Cisco compatibility probes."""

import os

import pytest

from firewall_manager.domain.models import CapabilityStatus, PageRequest, ProviderCapability
from firewall_manager.providers.fmc import RealFmcProvider
from firewall_manager.providers.scc import RealSccProvider

pytestmark = pytest.mark.real_provider


def _capabilities() -> dict[str, CapabilityStatus]:
    return {capability.value: CapabilityStatus.NOT_STARTED for capability in ProviderCapability}


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        pytest.fail(f"{name} is required when the real-provider suite is enabled")
    return value


def _opted_in(flag: str) -> None:
    if os.getenv(flag, "").lower() != "true":
        pytest.skip(f"set {flag}=true to run this read-only compatibility probe")
    if os.getenv("REAL_PROVIDER_NON_PRODUCTION_ACK") != "non-production-read-only":
        pytest.fail(
            "REAL_PROVIDER_NON_PRODUCTION_ACK=non-production-read-only is required; "
            "never point this suite at production"
        )


@pytest.mark.asyncio
async def test_real_fmc_read_only_compatibility() -> None:
    _opted_in("RUN_REAL_FMC_TESTS")
    provider = RealFmcProvider(
        endpoint=_required("REAL_FMC_URL"),
        display_name="Opt-in non-production FMC",
        username=_required("REAL_FMC_USERNAME"),
        password=_required("REAL_FMC_PASSWORD"),
        ca_certificate=os.getenv("REAL_FMC_CA_CERTIFICATE") or None,
        capabilities=_capabilities(),
    )
    info = await provider.information()
    domains = await provider.domains(PageRequest(limit=10))
    assert info.writable is False
    assert info.provider_version
    for domain in domains.items:
        await provider.devices(domain.native_id, PageRequest(limit=1))
        policies = await provider.policies(domain.native_id, PageRequest(limit=10))
        await provider.objects(domain.native_id, PageRequest(limit=1))
        await provider.zones(domain.native_id, PageRequest(limit=1))
        for policy in policies.items:
            await provider.categories(policy.native_id, PageRequest(limit=1))
            await provider.rules(policy.native_id, PageRequest(limit=1))
    await provider.aclose()


@pytest.mark.asyncio
async def test_real_scc_read_only_compatibility() -> None:
    _opted_in("RUN_REAL_SCC_TESTS")
    provider = RealSccProvider(
        region=_required("REAL_SCC_REGION"),
        display_name="Opt-in non-production SCC",
        token=_required("REAL_SCC_TOKEN"),
        capabilities=_capabilities(),
    )
    info = await provider.information()
    domains = await provider.domains(PageRequest(limit=10))
    assert info.writable is False
    assert info.provider_version
    assert provider.tenant_info
    for domain in domains.items:
        await provider.devices(domain.native_id, PageRequest(limit=1))
        policies = await provider.policies(domain.native_id, PageRequest(limit=10))
        await provider.objects(domain.native_id, PageRequest(limit=1))
        await provider.zones(domain.native_id, PageRequest(limit=1))
        for policy in policies.items:
            await provider.categories(policy.native_id, PageRequest(limit=1))
            await provider.rules(policy.native_id, PageRequest(limit=1))
    await provider.aclose()
