"""Application-level readiness service."""

from firewall_manager.application.ports import HealthProbe


class HealthService:
    """Coordinate readiness checks through an infrastructure-neutral port."""

    def __init__(self, probe: HealthProbe) -> None:
        self._probe = probe

    async def check_readiness(self) -> None:
        """Raise the adapter's typed availability error when a dependency is unavailable."""
        await self._probe.check()
