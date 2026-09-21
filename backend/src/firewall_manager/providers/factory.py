"""Composition factory for real, configuration-read-only provider adapters."""

from firewall_manager.domain.models import CapabilityStatus, ProviderKind
from firewall_manager.providers.fmc import RealFmcProvider
from firewall_manager.providers.scc import RealSccProvider
from firewall_manager.providers.transactions import RealTransactionProvider


def build_real_provider(
    context: dict[str, object],
    credential: dict[str, str],
    capabilities: dict[str, str],
) -> RealTransactionProvider:
    """Build the same adapter for connection tests, manual sync, and scheduled sync."""
    typed_capabilities = {name: CapabilityStatus(status) for name, status in capabilities.items()}
    if ProviderKind(str(context["provider_type"])) is ProviderKind.FMC:
        return RealFmcProvider(
            endpoint=str(context["base_endpoint"]),
            display_name=str(context["display_name"]),
            username=credential["username"],
            password=credential["password"],
            ca_certificate=credential.get("ca_certificate"),
            capabilities=typed_capabilities,
            writable=bool(context.get("write_enabled", False)),
        )
    return RealSccProvider(
        region=str(context["region"]),
        display_name=str(context["display_name"]),
        token=credential["token"],
        capabilities=typed_capabilities,
        writable=bool(context.get("write_enabled", False)),
    )
