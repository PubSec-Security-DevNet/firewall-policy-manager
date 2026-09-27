"""Shared HTTP transport adapter for normalized read-only providers."""

from collections.abc import Callable
from typing import Any, TypeVar

import httpx

from firewall_manager.application.errors import (
    ProviderContractError,
    ProviderPaginationError,
    ProviderUnavailableError,
)
from firewall_manager.domain.models import (
    CapabilityStatus,
    DiscoveredCategory,
    DiscoveredDevice,
    DiscoveredDomain,
    DiscoveredFilePolicy,
    DiscoveredIntrusionPolicy,
    DiscoveredObject,
    DiscoveredObjectReference,
    DiscoveredPolicy,
    DiscoveredRule,
    DiscoveredVariableSet,
    DiscoveredZone,
    DiscoveredZoneReference,
    PageRequest,
    ProviderEvidenceProfile,
    ProviderInfo,
    ProviderInventory,
    ProviderKind,
    ProviderPage,
)

T = TypeVar("T")


class HttpFirewallProvider:
    """Map mock/real adapter HTTP representations into provider-neutral DTOs."""

    kind: ProviderKind

    def __init__(self, base_url: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._transport = transport

    async def _get(self, path: str, params: dict[str, str | int] | None = None) -> Any:
        try:
            async with httpx.AsyncClient(timeout=3.0, transport=self._transport) as client:
                response = await client.get(f"{self._base_url}{path}", params=params)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 424:
                raise ProviderPaginationError from exc
            raise ProviderUnavailableError from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderUnavailableError from exc

    async def information(self) -> ProviderInfo:
        payload = await self._get("/api/v1/info")
        try:
            if payload["provider"] != self.kind.value:
                raise ProviderContractError
            return ProviderInfo(
                provider=self.kind,
                display_name=str(payload["display_name"]),
                provider_version=str(payload["provider_version"]),
                capabilities={
                    str(name): CapabilityStatus(status)
                    for name, status in payload["capabilities"].items()
                },
                evidence_profile=ProviderEvidenceProfile(payload["evidence_profile"]),
                writable=bool(payload["writable"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderContractError from exc

    async def discover(self) -> ProviderInventory:
        """Return a compatibility summary without leaking provider-native payloads."""
        payload = await self._get("/api/v1/discovery")
        try:
            if payload["provider"] != self.kind.value:
                raise ProviderUnavailableError
            return ProviderInventory(
                provider=self.kind,
                display_name=str(payload["display_name"]),
                provider_version=str(payload["provider_version"]),
                policy_count=int(payload["policy_count"]),
                object_count=int(payload["object_count"]),
                writable=bool(payload["writable"]),
                evidence_profile=ProviderEvidenceProfile(
                    str(payload.get("evidence_profile", ProviderEvidenceProfile.REAL.value))
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderUnavailableError from exc

    async def _page(
        self,
        resource: str,
        page: PageRequest,
        factory: Callable[..., T],
        parent: str | None = None,
        extra_params: dict[str, str | int] | None = None,
    ) -> ProviderPage[T]:
        params: dict[str, str | int] = {"limit": page.limit}
        if extra_params:
            params.update(extra_params)
        if page.cursor is not None:
            params["cursor"] = page.cursor
        if parent is not None:
            params["parent"] = parent
        payload = await self._get(f"/api/v1/resources/{resource}", params)
        try:
            items = tuple(factory(**item) for item in payload["items"])
            cursor = payload.get("next_cursor")
            if cursor is not None and not isinstance(cursor, str):
                raise TypeError
            return ProviderPage(items=items, next_cursor=cursor)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderContractError from exc

    async def domains(self, page: PageRequest) -> ProviderPage[DiscoveredDomain]:
        return await self._page("domains", page, DiscoveredDomain)

    async def devices(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredDevice]:
        return await self._page("devices", page, DiscoveredDevice, domain_native_id)

    async def policies(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredPolicy]:
        return await self._page("policies", page, DiscoveredPolicy, domain_native_id)

    async def categories(
        self, policy_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredCategory]:
        return await self._page("categories", page, DiscoveredCategory, policy_native_id)

    async def intrusion_policies(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredIntrusionPolicy]:
        return await self._page(
            "intrusion_policies", page, DiscoveredIntrusionPolicy, domain_native_id
        )

    async def variable_sets(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredVariableSet]:
        return await self._page("variable_sets", page, DiscoveredVariableSet, domain_native_id)

    async def file_policies(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredFilePolicy]:
        return await self._page("file_policies", page, DiscoveredFilePolicy, domain_native_id)

    async def rules(self, policy_native_id: str, page: PageRequest) -> ProviderPage[DiscoveredRule]:
        def rule_factory(**item: Any) -> DiscoveredRule:
            item["object_references"] = tuple(
                DiscoveredObjectReference(**reference)
                for reference in item.get("object_references", ())
            )
            item["zone_references"] = tuple(
                DiscoveredZoneReference(**reference)
                for reference in item.get("zone_references", ())
            )
            return DiscoveredRule(**item)

        return await self._page("rules", page, rule_factory, policy_native_id)

    async def objects(
        self,
        domain_native_id: str,
        page: PageRequest,
        *,
        applications_only: bool = False,
        include_applications: bool = True,
    ) -> ProviderPage[DiscoveredObject]:
        params: dict[str, str | int] = {
            "applications_only": int(applications_only),
            "include_applications": int(include_applications),
        }
        return await self._page(
            "objects", page, DiscoveredObject, domain_native_id, extra_params=params
        )

    async def zones(self, domain_native_id: str, page: PageRequest) -> ProviderPage[DiscoveredZone]:
        return await self._page("zones", page, DiscoveredZone, domain_native_id)
