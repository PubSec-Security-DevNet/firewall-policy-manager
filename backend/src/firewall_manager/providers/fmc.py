"""FMC read-only adapter boundary."""

from firewall_manager.domain.models import ProviderKind
from firewall_manager.providers.http_reader import HttpFirewallProvider


class FmcProviderReader(HttpFirewallProvider):
    """Read-only FMC adapter implementing the normalized provider contract."""

    kind = ProviderKind.FMC
