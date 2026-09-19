"""Provider-independent read-only discovery and reconciliation service."""

from collections.abc import Awaitable, Callable
from typing import TypeVar
from uuid import UUID

from firewall_manager.application.errors import (
    ProviderContractError,
    ProviderError,
    ProviderMismatchError,
    ProviderPaginationError,
    ResourceOutOfScopeError,
)
from firewall_manager.application.ports import FirewallProvider, SyncRepository
from firewall_manager.domain.models import (
    DiscoveredObject,
    DiscoveredRule,
    PageRequest,
    ProviderPage,
    SyncResult,
    SyncStatus,
)

T = TypeVar("T")


class SynchronizationService:
    """Synchronize provider observations without adopting or mutating provider resources."""

    def __init__(
        self,
        repository: SyncRepository,
        page_size: int = 50,
        max_pages_per_collection: int = 200,
    ) -> None:
        PageRequest(limit=page_size)
        self._repository = repository
        self._page_size = page_size
        self._max_pages_per_collection = max_pages_per_collection

    async def _all(self, fetch: Callable[[PageRequest], Awaitable[ProviderPage[T]]]) -> list[T]:
        items: list[T] = []
        cursor: str | None = None
        used_cursors: set[str] = set()
        for _page_number in range(self._max_pages_per_collection):
            page = await fetch(PageRequest(limit=self._page_size, cursor=cursor))
            items.extend(page.items)
            if page.next_cursor is None:
                return items
            if page.next_cursor in used_cursors or page.next_cursor == cursor:
                raise ProviderContractError
            used_cursors.add(page.next_cursor)
            cursor = page.next_cursor
        raise ProviderPaginationError(details={"code": "PROVIDER_PAGE_BOUND_EXCEEDED"})

    async def synchronize(  # noqa: PLR0912 -- explicit provider-scope orchestration
        self, manager_id: UUID, provider: FirewallProvider
    ) -> SyncResult:
        """Run one durable full-scope discovery, preserving incomplete-run semantics."""
        context = self._repository.manager_context(manager_id)
        if context is None:
            raise ResourceOutOfScopeError
        organization_id, expected_provider = context
        run_id = self._repository.start_sync(organization_id, manager_id)
        resources_seen = 0
        try:
            info = await provider.information()
            if info.provider is not expected_provider or provider.kind is not expected_provider:
                raise ProviderMismatchError
            self._repository.record_provider_info(manager_id, info)
            domains = await self._all(provider.domains)
            resources_seen += len(domains)
            policy_ids: dict[str, UUID] = {}
            category_ids: dict[str, UUID] = {}
            pending_rules: list[tuple[UUID, DiscoveredRule]] = []
            pending_objects: list[tuple[UUID, DiscoveredObject]] = []

            for domain in domains:
                domain_id = self._repository.upsert_domain(
                    organization_id, manager_id, run_id, domain
                )
                devices = await self._all(
                    lambda page, native_id=domain.native_id: provider.devices(native_id, page)
                )
                resources_seen += len(devices)
                for device in devices:
                    self._repository.upsert_device(
                        organization_id, manager_id, domain_id, run_id, device
                    )

                policies = await self._all(
                    lambda page, native_id=domain.native_id: provider.policies(native_id, page)
                )
                resources_seen += len(policies)
                for policy in policies:
                    policy_id = self._repository.upsert_policy(
                        organization_id, manager_id, domain_id, run_id, policy
                    )
                    policy_ids[policy.native_id] = policy_id

                zones = await self._all(
                    lambda page, native_id=domain.native_id: provider.zones(native_id, page)
                )
                resources_seen += len(zones)
                for zone in zones:
                    self._repository.upsert_zone(
                        organization_id, manager_id, domain_id, run_id, zone
                    )

                objects = await self._all(
                    lambda page, native_id=domain.native_id: provider.objects(native_id, page)
                )
                resources_seen += len(objects)
                for item in objects:
                    object_id = self._repository.upsert_object(
                        organization_id, manager_id, domain_id, run_id, item
                    )
                    pending_objects.append((object_id, item))

            for policy_native_id, policy_id in policy_ids.items():
                categories = await self._all(
                    lambda page, native_id=policy_native_id: provider.categories(native_id, page)
                )
                resources_seen += len(categories)
                for category in categories:
                    category_ids[category.native_id] = self._repository.upsert_category(
                        organization_id, manager_id, policy_id, run_id, category
                    )
                rules = await self._all(
                    lambda page, native_id=policy_native_id: provider.rules(native_id, page)
                )
                resources_seen += len(rules)
                for rule in rules:
                    rule_id = self._repository.upsert_rule(
                        organization_id,
                        manager_id,
                        policy_id,
                        category_ids.get(rule.category_native_id or ""),
                        run_id,
                        rule,
                    )
                    pending_rules.append((rule_id, rule))

            for object_id, item in pending_objects:
                self._repository.replace_object_references(
                    organization_id,
                    manager_id,
                    object_id,
                    item.referenced_object_native_ids,
                )
            for rule_id, rule in pending_rules:
                self._repository.replace_rule_object_references(
                    organization_id, manager_id, rule_id, rule.object_references
                )
                self._repository.replace_rule_zone_references(
                    organization_id, manager_id, rule_id, rule.zone_references
                )
            return self._repository.complete_sync(run_id, manager_id, resources_seen)
        except ProviderError as exc:
            status = SyncStatus.INCOMPLETE if resources_seen else SyncStatus.FAILED
            return self._repository.fail_sync(run_id, status, resources_seen, exc.code)
