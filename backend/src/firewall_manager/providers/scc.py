# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""SCC mock-compatible and real read-only adapter boundaries."""

from typing import Any

import httpx

from firewall_manager.application.errors import (
    ProviderConfigurationError,
)
from firewall_manager.domain.models import (
    CapabilityStatus,
    DiscoveredDevice,
    PageRequest,
    ProviderKind,
    ProviderPage,
)
from firewall_manager.providers.deployment_preflight import collection, refuse
from firewall_manager.providers.http_reader import HttpFirewallProvider
from firewall_manager.providers.real import (
    SCC_ENDPOINTS,
    CiscoReadOnlyProvider,
    _fingerprint,
    _metadata,
    _name,
    _version,
)


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

    async def devices(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredDevice]:
        """Discover SCC devices using SCC UIDs, not the nested FMC device UID.

        Local device identity remains the SCC UID. Selective deployment maps it to the
        cdFMC record ID; assignments are read from that record in the requested domain.
        """
        try:
            offset = int(page.cursor or "0")
        except ValueError as exc:
            raise ProviderConfigurationError from exc
        # SCC inventory rejects the shared FMC ``expanded`` parameter and caps
        # this collection at 100 records per request.
        payload = await self._get_with_params(
            "/v1/inventory/devices", {"offset": offset, "limit": min(page.limit, 100)}
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise ProviderConfigurationError
        items = [item for item in payload["items"] if isinstance(item, dict)]
        total = payload.get("count")
        next_cursor = (
            str(offset + len(items))
            if isinstance(total, int) and offset + len(items) < total and items
            else None
        )
        devices: list[DiscoveredDevice] = []
        for item in items:
            uid = item.get("uid")
            if not uid:
                continue
            metadata = _metadata(item)
            metadata["scc_device_type"] = str(item.get("deviceType") or "unknown")
            fmc_uid = item.get("uidOnFmc")
            if fmc_uid:
                metadata["fmc_native_id"] = str(fmc_uid)
                if (
                    item.get("deviceType") == "CDFMC_MANAGED_FTD"
                    and "access_policy_id" not in metadata
                ):
                    record = await self._get(
                        self._config_path(domain_native_id, f"devices/devicerecords/{fmc_uid}")
                    )
                    if not isinstance(record, dict):
                        refuse("DEPLOYMENT_POLICY_ASSIGNMENT_UNKNOWN")
                    metadata.update(_metadata(record))
            devices.append(
                DiscoveredDevice(
                    native_id=str(uid),
                    name=_name(item, str(uid)),
                    native_version=_version(item),
                    fingerprint=_fingerprint(item),
                    native_metadata=metadata,
                    domain_native_id=domain_native_id,
                    model=str(item.get("modelNumber") or item.get("hardwareModel"))
                    if item.get("modelNumber") or item.get("hardwareModel")
                    else None,
                )
            )
        return ProviderPage(tuple(devices), next_cursor)

    async def start_deployment(
        self,
        domain_id: str,
        policy_ids: list[str],
        device_ids: list[str],
        expected_mutations: list[dict[str, Any]] | None = None,
    ) -> dict[str, object]:
        """Translate SCC identities; use cdFMC's narrower selective deployment API.

        The documented SCC multi-device API deploys whole devices and has no policy-type
        selector. Do not send the undocumented selectedPolicyTypes payload formerly used here.
        """
        inventory = await self._get_with_params(
            "/v1/inventory/devices", {"offset": 0, "limit": 100}
        )
        if isinstance(inventory, dict) and "count" in inventory:
            inventory = {**inventory, "paging": {"count": inventory["count"]}}
        devices = collection(inventory)
        mapped = []
        for device_id in sorted(set(device_ids)):
            found = [d for d in devices if d.get("uid") == device_id]
            if (
                len(found) != 1
                or found[0].get("deviceType") != "CDFMC_MANAGED_FTD"
                or not found[0].get("uidOnFmc")
            ):
                refuse("DEPLOYMENT_TARGET_UNAUTHORIZED")
            mapped.append(str(found[0]["uidOnFmc"]))
        result = await super().start_deployment(domain_id, policy_ids, mapped, expected_mutations)
        result["scc_device_ids"] = sorted(set(device_ids))
        return result

    async def deployment_status(self, external_operation_id: str) -> dict[str, object]:
        """Poll an SCC deployment run and normalize its state for the worker."""
        if ":" in external_operation_id:
            return await super().deployment_status(external_operation_id)
        response = await self._get(
            f"/v1/inventory/devices/deployments/runs/{external_operation_id}"
        )
        if not isinstance(response, dict):
            raise ProviderConfigurationError
        status = str(response.get("deploymentRunStatus") or "UNKNOWN").upper()
        normalized = {
            "DEPLOY_COMPLETED": "DEPLOYED",
            "DEPLOY_FAILED": "FAILED",
        }.get(status, "DEPLOYING")
        return {
            "state": normalized,
            "provider_status": status,
            "provider": response,
            "devices": response.get("deviceDeploymentStatuses", []),
        }

    async def rollback_deployment(
        self, domain_id: str, deployment_operation_id: str, device_ids: list[str]
    ) -> dict[str, object]:
        """Request rollback through SCC's cdFMC deployment surface.

        SCC deployment runs use SCC device UIDs, while the cdFMC rollback request
        requires the nested FMC device IDs.
        """
        inventory = await self._get_with_params(
            "/v1/inventory/devices", {"offset": 0, "limit": 100}
        )
        if not isinstance(inventory, dict) or not isinstance(inventory.get("items"), list):
            raise ProviderConfigurationError
        fmc_ids = [
            str(item["uidOnFmc"])
            for item in inventory["items"]
            if isinstance(item, dict)
            and str(item.get("uid") or "") in set(device_ids)
            and item.get("uidOnFmc")
        ]
        if not fmc_ids:
            raise ProviderConfigurationError
        response = await self._mutate_json(
            "POST",
            f"/v1/cdfmc/api/fmc_config/v1/domain/{domain_id}/deployment/rollbackrequests",
            {
                "rollbackDeviceList": [
                    {"deploymentJobId": deployment_operation_id, "deviceList": fmc_ids}
                ],
                "type": "RollbackRequest",
            },
            ensure_identity=False,
        )
        metadata = response.get("metadata")
        task = metadata.get("task") if isinstance(metadata, dict) else None
        task_id = task.get("id") if isinstance(task, dict) else None
        task_id = task_id or response.get("taskId") or response.get("id")
        if not task_id:
            raise ProviderConfigurationError
        return {
            "external_operation_id": f"{domain_id}:{task_id}",
            "provider": dict(response),
        }

    async def rollback_status(self, external_operation_id: str) -> dict[str, object]:
        try:
            domain_id, task_id = external_operation_id.split(":", 1)
        except ValueError as exc:
            raise ProviderConfigurationError from exc
        response = await self._get(self._config_path(domain_id, f"job/taskstatuses/{task_id}"))
        if not isinstance(response, dict):
            raise ProviderConfigurationError
        status = str(response.get("status") or response.get("state") or "UNKNOWN").upper()
        normalized = {
            "COMPLETED": "ROLLED_BACK",
            "SUCCESS": "ROLLED_BACK",
            "SUCCEEDED": "ROLLED_BACK",
            "DEPLOYED": "ROLLED_BACK",
            "FAILED": "FAILED",
            "ERROR": "FAILED",
        }.get(status, "ROLLING_BACK")
        return {
            "state": normalized,
            "provider_status": status,
            "provider": response,
            "devices": response.get("deviceResults", []),
        }
