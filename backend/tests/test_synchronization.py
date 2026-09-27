"""Synchronization completeness, isolation, missing, and drift behavior."""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from firewall_manager.application.synchronization import SynchronizationService
from firewall_manager.domain.models import (
    NativeResource,
    ProviderInfo,
    ProviderKind,
    ResourceState,
    SyncResult,
    SyncStatus,
)
from firewall_manager.providers.mock import DeterministicMockProvider, MockScenario


class FakeSyncRepository:
    """Behavioral fake retaining durable semantics relevant to the shared sync service."""

    def __init__(self, organization_id: UUID, manager_id: UUID, kind: ProviderKind) -> None:
        self.organization_id = organization_id
        self.manager_id = manager_id
        self.kind = kind
        self.runs: dict[UUID, dict[str, Any]] = {}
        self.resources: dict[tuple[str, str], dict[str, Any]] = {}
        self.drifts: list[tuple[str, str]] = []

    def manager_context(self, manager_id: UUID) -> tuple[UUID, ProviderKind] | None:
        return (self.organization_id, self.kind) if manager_id == self.manager_id else None

    def start_sync(self, organization_id: UUID, manager_id: UUID) -> UUID:
        assert organization_id == self.organization_id
        assert manager_id == self.manager_id
        run_id = uuid4()
        self.runs[run_id] = {"started_at": datetime.now(UTC)}
        return run_id

    def record_provider_info(self, manager_id: UUID, info: ProviderInfo) -> None:
        assert manager_id == self.manager_id
        assert info.provider is self.kind

    def _upsert(self, resource_type: str, run_id: UUID, item: NativeResource) -> UUID:
        key = (resource_type, item.native_id)
        existing: dict[str, Any] | None = self.resources.get(key)
        if existing is None:
            existing = {
                "id": uuid4(),
                "state": ResourceState.OBSERVED,
                "revision": 1,
                "organization_id": self.organization_id,
            }
            self.resources[key] = existing
        elif existing["fingerprint"] != item.fingerprint:
            existing["state"] = ResourceState.DRIFTED
            existing["revision"] += 1
            self.drifts.append(key)
        existing["fingerprint"] = item.fingerprint
        existing["run_id"] = run_id
        resource_id = existing["id"]
        assert isinstance(resource_id, UUID)
        return resource_id

    def upsert_domain(
        self, organization_id: UUID, manager_id: UUID, run_id: UUID, item: Any
    ) -> UUID:
        return self._upsert("domain", run_id, item)

    def upsert_device(
        self, organization_id: UUID, manager_id: UUID, domain_id: UUID, run_id: UUID, item: Any
    ) -> UUID:
        return self._upsert("device", run_id, item)

    def upsert_policy(
        self, organization_id: UUID, manager_id: UUID, domain_id: UUID, run_id: UUID, item: Any
    ) -> UUID:
        return self._upsert("policy", run_id, item)

    def upsert_category(
        self, organization_id: UUID, manager_id: UUID, policy_id: UUID, run_id: UUID, item: Any
    ) -> UUID:
        return self._upsert("category", run_id, item)

    def upsert_intrusion_policy(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: Any,
    ) -> UUID:
        return self._upsert("intrusion_policy", run_id, item)

    def upsert_variable_set(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: Any,
    ) -> UUID:
        return self._upsert("variable_set", run_id, item)

    def upsert_file_policy(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: Any,
    ) -> UUID:
        return self._upsert("file_policy", run_id, item)

    def upsert_rule(  # noqa: PLR0913, PLR0917
        self,
        organization_id: UUID,
        manager_id: UUID,
        policy_id: UUID,
        category_id: UUID | None,
        run_id: UUID,
        item: Any,
    ) -> UUID:
        return self._upsert("rule", run_id, item)

    def upsert_object(
        self, organization_id: UUID, manager_id: UUID, domain_id: UUID, run_id: UUID, item: Any
    ) -> UUID:
        return self._upsert("object", run_id, item)

    def upsert_zone(
        self, organization_id: UUID, manager_id: UUID, domain_id: UUID, run_id: UUID, item: Any
    ) -> UUID:
        return self._upsert("zone", run_id, item)

    def replace_rule_object_references(
        self,
        organization_id: UUID,
        manager_id: UUID,
        rule_id: UUID,
        references: Sequence[Any],
    ) -> None:
        pass

    def replace_rule_zone_references(
        self,
        organization_id: UUID,
        manager_id: UUID,
        rule_id: UUID,
        references: Sequence[Any],
    ) -> None:
        pass

    def refresh_rule_application_snapshot(self, organization_id: UUID, rule_id: UUID) -> None:
        pass

    def replace_object_references(
        self,
        organization_id: UUID,
        manager_id: UUID,
        source_object_id: UUID,
        object_native_ids: Sequence[str],
    ) -> None:
        pass

    def complete_sync(
        self,
        run_id: UUID,
        manager_id: UUID,
        resources_seen: int,
        applications_only: bool = False,
    ) -> SyncResult:
        for item in self.resources.values():
            if item["run_id"] != run_id:
                item["state"] = ResourceState.MISSING
                item["revision"] += 1
        return self._finish(run_id, SyncStatus.COMPLETED, resources_seen)

    def fail_sync(
        self, run_id: UUID, status: SyncStatus, resources_seen: int, error_code: str
    ) -> SyncResult:
        self.runs[run_id]["error"] = error_code
        return self._finish(run_id, status, resources_seen)

    def _finish(self, run_id: UUID, status: SyncStatus, seen: int) -> SyncResult:
        completed = datetime.now(UTC)
        self.runs[run_id].update(status=status, complete=status is SyncStatus.COMPLETED)
        return SyncResult(run_id, status, seen, self.runs[run_id]["started_at"], completed)


def repository(kind: ProviderKind = ProviderKind.FMC) -> FakeSyncRepository:
    return FakeSyncRepository(uuid4(), uuid4(), kind)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(ProviderKind))
async def test_initial_discovery_is_observed_and_complete_for_both_providers(
    kind: ProviderKind,
) -> None:
    repo = repository(kind)
    result = await SynchronizationService(repo, page_size=1).synchronize(
        repo.manager_id, DeterministicMockProvider(kind)
    )
    assert result.status is SyncStatus.COMPLETED
    assert result.resources_seen == 38
    assert {item["state"] for item in repo.resources.values()} == {ResourceState.OBSERVED}
    assert all("owner" not in item for item in repo.resources.values())
    assert len([key for key in repo.resources if key[0] == "zone"]) == 4


@pytest.mark.asyncio
async def test_incomplete_pagination_does_not_mark_previously_known_resource_missing() -> None:
    repo = repository()
    provider = DeterministicMockProvider(ProviderKind.FMC)
    await SynchronizationService(repo, page_size=2).synchronize(repo.manager_id, provider)
    known_rule = repo.resources[("rule", "fmc-rule-web")]
    provider.set_scenario(MockScenario.FAIL_SECOND_PAGE)
    result = await SynchronizationService(repo, page_size=2).synchronize(repo.manager_id, provider)
    assert result.status is SyncStatus.INCOMPLETE
    assert known_rule["state"] is ResourceState.OBSERVED


@pytest.mark.asyncio
async def test_complete_sync_marks_confirmed_deleted_resource_missing_and_detects_drift() -> None:
    repo = repository()
    provider = DeterministicMockProvider(ProviderKind.FMC)
    service = SynchronizationService(repo, page_size=2)
    await service.synchronize(repo.manager_id, provider)
    provider.simulate_rule_drift()
    drift_result = await service.synchronize(repo.manager_id, provider)
    assert drift_result.status is SyncStatus.COMPLETED
    assert repo.resources[("rule", "fmc-rule-web")]["state"] is ResourceState.DRIFTED
    assert ("rule", "fmc-rule-web") in repo.drifts

    provider.simulate_deleted_rule()
    provider.simulate_new_object()
    result = await service.synchronize(repo.manager_id, provider)
    assert result.status is SyncStatus.COMPLETED
    assert repo.resources[("rule", "fmc-rule-web")]["state"] is ResourceState.MISSING
    assert repo.resources[("object", "fmc-object-new")]["state"] is ResourceState.OBSERVED


@pytest.mark.asyncio
async def test_provider_resources_cannot_cross_manager_or_organization_context() -> None:
    first = repository(ProviderKind.FMC)
    second = repository(ProviderKind.SCC)
    await SynchronizationService(first).synchronize(
        first.manager_id, DeterministicMockProvider(ProviderKind.FMC)
    )
    await SynchronizationService(second).synchronize(
        second.manager_id, DeterministicMockProvider(ProviderKind.SCC)
    )
    assert {item["organization_id"] for item in first.resources.values()} == {first.organization_id}
    assert {item["organization_id"] for item in second.resources.values()} == {
        second.organization_id
    }
    assert set(first.resources).isdisjoint(second.resources)
