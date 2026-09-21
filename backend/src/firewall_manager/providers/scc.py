"""SCC mock-compatible and real read-only adapter boundaries."""

import httpx

from firewall_manager.application.errors import ProviderConfigurationError
from firewall_manager.domain.models import CapabilityStatus, ProviderKind
from firewall_manager.providers.http_reader import HttpFirewallProvider
from firewall_manager.providers.real import SCC_ENDPOINTS, CiscoReadOnlyProvider


class SccProviderReader(HttpFirewallProvider):
    """Read-only SCC adapter implementing the normalized provider contract."""

    kind = ProviderKind.SCC


class RealSccProvider(CiscoReadOnlyProvider):
    """Regional SCC/cdFMC reader using an API-only identity bearer token."""

    kind = ProviderKind.SCC

    def __init__(  # noqa: PLR0913 -- explicit security-sensitive connection inputs
        self,
        *,
        region: str,
        display_name: str,
        token: str,
        capabilities: dict[str, CapabilityStatus],
        transport: httpx.AsyncBaseTransport | None = None,
        validate_network_target: bool = True,
        writable: bool = False,
    ) -> None:
        endpoint = SCC_ENDPOINTS.get(region)
        if endpoint is None:
            raise ProviderConfigurationError
        super().__init__(
            endpoint=endpoint,
            display_name=display_name,
            bearer_token=token,
            capabilities=capabilities,
            api_prefix="/v1/cdfmc",
            transport=transport,
            validate_network_target=validate_network_target,
            writable=writable,
        )
