"""SCC read-only adapter boundary."""

from firewall_manager.domain.models import ProviderKind
from firewall_manager.providers.http_reader import HttpFirewallProvider


class SccProviderReader(HttpFirewallProvider):
    """Read-only SCC adapter implementing the normalized provider contract."""

    kind = ProviderKind.SCC
