"""Application overview behavior."""

from uuid import UUID

import pytest

from firewall_manager.application.overview import OverviewService
from firewall_manager.domain.models import Principal, ProviderInventory, ProviderKind


class FakeRepository:
    def organization_name(self, organization_id: UUID) -> str | None:
        return "Example Organization"

    def counts(self, organization_id: UUID) -> dict[str, int]:
        return {"managers": 2, "policies": 1, "rules": 1, "objects": 2, "change_sets": 2}

    def principal_by_email(self, email: str) -> Principal | None:
        return None


class FakeProvider:
    kind = ProviderKind.FMC

    async def discover(self) -> ProviderInventory:
        return ProviderInventory(self.kind, "Mock FMC", "mock-1", 1, 2, False)


@pytest.mark.asyncio
async def test_overview_is_bounded_and_read_only() -> None:
    principal = Principal(
        UUID("30000000-0000-0000-0000-000000000001"),
        UUID("10000000-0000-0000-0000-000000000001"),
        "viewer@example.test",
        "viewer",
    )
    result = await OverviewService(FakeRepository(), (FakeProvider(),)).get(principal)
    assert result["organization"] == "Example Organization"
    assert result["providers"] == [
        {
            "provider": ProviderKind.FMC,
            "display_name": "Mock FMC",
            "provider_version": "mock-1",
            "policy_count": 1,
            "object_count": 2,
            "writable": False,
        }
    ]
