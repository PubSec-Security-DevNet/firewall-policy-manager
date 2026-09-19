"""FMC mock-compatible and real read-only adapter boundaries."""

import httpx

from firewall_manager.domain.models import CapabilityStatus, ProviderKind
from firewall_manager.providers.http_reader import HttpFirewallProvider
from firewall_manager.providers.real import CiscoReadOnlyProvider, normalize_fmc_endpoint


class FmcProviderReader(HttpFirewallProvider):
    """Read-only FMC adapter implementing the normalized provider contract."""

    kind = ProviderKind.FMC


class RealFmcProvider(CiscoReadOnlyProvider):
    """Direct FMC reader using short-lived tokens obtained from source credentials."""

    kind = ProviderKind.FMC

    def __init__(  # noqa: PLR0913 -- explicit security-sensitive connection inputs
        self,
        *,
        endpoint: str,
        display_name: str,
        username: str,
        password: str,
        capabilities: dict[str, CapabilityStatus],
        ca_certificate: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        validate_network_target: bool = True,
    ) -> None:
        super().__init__(
            endpoint=normalize_fmc_endpoint(endpoint),
            display_name=display_name,
            username=username,
            password=password,
            capabilities=capabilities,
            ca_certificate=ca_certificate,
            transport=transport,
            validate_network_target=validate_network_target,
        )
