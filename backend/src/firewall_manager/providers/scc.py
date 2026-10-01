"""SCC mock-compatible and real read-only adapter boundaries."""

import httpx

from firewall_manager.application.errors import ProviderConfigurationError
from firewall_manager.domain.models import (
    CapabilityStatus,
    DiscoveredDevice,
    PageRequest,
    ProviderKind,
    ProviderPage,
)
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

        The cdFMC configuration proxy exposes ``uidOnFmc`` as the device record
        identifier.  Deployment APIs require the top-level SCC ``uid`` instead.
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
        self, _domain_id: str, _policy_ids: list[str], device_ids: list[str]
    ) -> dict[str, object]:
        """Start an SCC FTD deployment and return its deployment-run identifier."""
        if not device_ids:
            raise ProviderConfigurationError
        inventory = await self._get_with_params(
            "/v1/inventory/devices", {"offset": 0, "limit": 100}
        )
        if not isinstance(inventory, dict) or not isinstance(inventory.get("items"), list):
            raise ProviderConfigurationError
        deployable_ids = {
            str(item["uid"])
            for item in inventory["items"]
            if isinstance(item, dict)
            and item.get("uid")
            and str(item.get("deviceType") or "").upper() == "CDFMC_MANAGED_FTD"
        }
        selected_device_ids = [
            device_id for device_id in dict.fromkeys(device_ids) if device_id in deployable_ids
        ]
        if not selected_device_ids:
            raise ProviderConfigurationError
        response = await self._mutate_json(
            "POST",
            "/v1/inventory/devices/ftds/deploy",
            {
                "devices": [
                    {"uid": device_id, "selectedPolicyTypes": ["FULL_DEPLOY"]}
                    for device_id in selected_device_ids
                ],
                "ignoreWarnings": True,
            },
            ensure_identity=False,
        )
        operation_id = response.get("entityUid") or response.get("deploymentRunUid")
        if not operation_id:
            raise ProviderConfigurationError
        return {
            "external_operation_id": str(operation_id),
            "provider": dict(response),
        }

    async def deployment_status(self, external_operation_id: str) -> dict[str, object]:
        """Poll an SCC deployment run and normalize its state for the worker."""
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
