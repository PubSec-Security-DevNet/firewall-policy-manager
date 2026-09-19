"""Read-only system overview use case shared by delivery interfaces."""

import asyncio
from dataclasses import asdict

from firewall_manager.application.authorization import require_action
from firewall_manager.application.errors import ResourceOutOfScopeError
from firewall_manager.application.ports import OverviewRepository, ProviderReader
from firewall_manager.domain.models import Action, Principal


class OverviewService:
    """Build a bounded overview after server-side authorization."""

    def __init__(
        self, repository: OverviewRepository, providers: tuple[ProviderReader, ...]
    ) -> None:
        self._repository = repository
        self._providers = providers

    async def get(self, principal: Principal) -> dict[str, object]:
        """Return normalized local and provider inventory for the principal's organization."""
        require_action(principal, Action.READ)
        organization = self._repository.organization_name(principal.organization_id)
        if organization is None:
            raise ResourceOutOfScopeError
        provider_inventory = await asyncio.gather(
            *(provider.discover() for provider in self._providers)
        )
        return {
            "organization": organization,
            "counts": self._repository.counts(principal.organization_id),
            "providers": [asdict(inventory) for inventory in provider_inventory],
        }
