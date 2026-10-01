"""Shared Cisco FMC/cdFMC REST implementation with an explicit write gate."""

import asyncio
import hashlib
import ipaddress
import json
import socket
import ssl
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from firewall_manager.application.errors import (
    ProductionWriteDisabledError,
    ProviderAuthenticationError,
    ProviderConfigurationError,
    ProviderContractError,
    ProviderError,
    ProviderPermissionError,
    ProviderRateLimitedError,
    ProviderTlsValidationError,
    ProviderUnavailableError,
)
from firewall_manager.domain.models import (
    CapabilityStatus,
    ChangeOperationKind,
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
    FirewallObjectType,
    OperationStatus,
    PageRequest,
    ProviderCapability,
    ProviderEvidenceProfile,
    ProviderInfo,
    ProviderInventory,
    ProviderKind,
    ProviderPage,
    ProviderTransactionState,
    RuleObjectElement,
    ZoneElement,
)
from firewall_manager.providers.transactions import (
    ProviderExecutionResult,
    real_transaction_operation_id,
)

SCC_ENDPOINTS: Mapping[str, str] = {
    "us": "https://api.us.security.cisco.com/firewall",
    "eu": "https://api.eu.security.cisco.com/firewall",
    "apj": "https://api.apj.security.cisco.com/firewall",
    "au": "https://api.au.security.cisco.com/firewall",
    "in": "https://api.in.security.cisco.com/firewall",
    "uae": "https://api.uae.security.cisco.com/firewall",
    "fedramp": "https://manage.secure.cisco/api/rest",
    "il5": "https://manage.securitydod.cisco/api/rest",
}

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data.ec2.internal",
    }
)
_OBJECT_ENDPOINTS: tuple[tuple[str, FirewallObjectType], ...] = (
    ("networks", FirewallObjectType.NETWORK),
    ("hosts", FirewallObjectType.NETWORK),
    ("ranges", FirewallObjectType.NETWORK),
    ("networkgroups", FirewallObjectType.NETWORK_GROUP),
    ("protocolportobjects", FirewallObjectType.PORT_SERVICE),
    ("portobjectgroups", FirewallObjectType.PORT_SERVICE_GROUP),
    ("urls", FirewallObjectType.URL),
    ("urlgroups", FirewallObjectType.URL_GROUP),
    ("applicationtypes", FirewallObjectType.APPLICATION_FILTER),
    ("applicationrisks", FirewallObjectType.APPLICATION_FILTER),
    ("applicationproductivities", FirewallObjectType.APPLICATION_FILTER),
    ("applicationcategories", FirewallObjectType.APPLICATION_FILTER),
    ("applicationtags", FirewallObjectType.APPLICATION_FILTER),
    # Fetch filters before the large system application catalog.  A catalog
    # sync can be slow or retry, but filters must be available to rule forms
    # without waiting for thousands of application records to finish.
    ("applicationfilters", FirewallObjectType.APPLICATION_FILTER),
    ("applications", FirewallObjectType.APPLICATION),
)
_SYSTEM_APPLICATION_FILTER_ENDPOINTS = frozenset(
    {
        "applicationtypes",
        "applicationrisks",
        "applicationproductivities",
        "applicationcategories",
        "applicationtags",
    }
)
_SYSTEM_APPLICATION_FILTER_CRITERIA = {
    "applicationtypes": "type",
    "applicationrisks": "risk",
    "applicationproductivities": "productivity",
    "applicationcategories": "category",
    "applicationtags": "tag",
}


class _ProviderMutationConflictError(Exception):
    """A provider-side state or capability conflict known to be non-mutating."""

    def __init__(self, code: str, details: Mapping[str, object] | None = None) -> None:
        self.code = code
        self.details = dict(details or {})
        super().__init__(code)


class _AmbiguousMutationError(Exception):
    """The request may have reached the provider and must not be retried blindly."""

    def __init__(self, code: str, details: Mapping[str, object] | None = None) -> None:
        self.details = dict(details or {})
        self.code = code
        super().__init__(code)


def normalize_fmc_endpoint(value: str) -> str:
    """Validate a direct FMC origin while permitting legitimate private-address deployments."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ProviderConfigurationError from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.hostname.lower().rstrip(".") in _BLOCKED_HOSTNAMES
    ):
        raise ProviderConfigurationError
    if port is not None and not 1 <= port <= 65535:
        raise ProviderConfigurationError
    _reject_unsafe_ip_literal(parsed.hostname)
    netloc = parsed.hostname.lower()
    if ":" in netloc:
        netloc = f"[{netloc}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit(("https", netloc, "", "", ""))


def _reject_unsafe_ip_literal(hostname: str) -> None:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if _unsafe_address(address):
        raise ProviderConfigurationError


def _unsafe_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


async def validate_resolved_target(endpoint: str) -> None:
    """Reject metadata/link-local/rebinding-prone resolutions while allowing RFC1918 FMCs."""
    parsed = urlsplit(endpoint)
    hostname = parsed.hostname
    if hostname is None:
        raise ProviderConfigurationError
    try:
        rows = await asyncio.to_thread(
            socket.getaddrinfo,
            hostname,
            parsed.port or 443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ProviderUnavailableError from exc
    addresses = {ipaddress.ip_address(row[4][0]) for row in rows}
    if not addresses or any(_unsafe_address(address) for address in addresses):
        raise ProviderConfigurationError


def _fingerprint(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _native_id(payload: Mapping[str, Any]) -> str:
    value = payload.get("id") or payload.get("uuid")
    if not value:
        raise ProviderContractError
    return str(value)


def _reference_native_id(value: object) -> str | None:
    if isinstance(value, dict):
        candidate = value.get("id") or value.get("uuid")
        return str(candidate) if candidate is not None else None
    return str(value) if value is not None else None


def _first_reference_native_id(payload: Mapping[str, Any], *keys: str) -> str | None:
    """Read a provider reference using the field names used by FMC/cdFMC versions."""
    for key in keys:
        native_id = _reference_native_id(payload.get(key))
        if native_id is not None:
            return native_id
    return None


def _name(payload: Mapping[str, Any], fallback: str) -> str:
    return str(payload.get("name") or payload.get("hostname") or fallback)


def _version(payload: Mapping[str, Any]) -> str | None:
    value = payload.get("version")
    if value is not None:
        return str(value)
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        typed_metadata = cast("dict[str, Any]", metadata)
        if typed_metadata.get("timestamp") is not None:
            return str(typed_metadata["timestamp"])
    return None


def _metadata(payload: Mapping[str, Any]) -> dict[str, str]:
    result = {"type": str(payload.get("type", "unknown"))}
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        typed_metadata = cast("dict[str, Any]", metadata)
        read_only = typed_metadata.get("readOnly")
        if isinstance(read_only, dict):
            typed_read_only = cast("dict[str, Any]", read_only)
            if typed_read_only.get("state") is not None:
                result["provider_read_only"] = str(bool(typed_read_only["state"])).lower()
    return result


def _objects(container: object) -> list[Mapping[str, Any]]:
    if not isinstance(container, dict):
        return []
    typed_container = cast("dict[str, Any]", container)
    values = typed_container.get("objects", typed_container.get("applications", []))
    if not isinstance(values, list):
        return []
    return [cast("Mapping[str, Any]", item) for item in values if isinstance(item, dict)]


class CiscoReadOnlyProvider:
    """Normalized Cisco provider with connection-specific, default-deny writes."""

    kind: ProviderKind

    def __init__(  # noqa: PLR0913 -- explicit transport/auth/TLS boundary
        self,
        *,
        endpoint: str,
        display_name: str,
        capabilities: dict[str, CapabilityStatus],
        api_prefix: str = "",
        username: str | None = None,
        password: str | None = None,
        bearer_token: str | None = None,
        ca_certificate: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        validate_network_target: bool = True,
        writable: bool = False,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._display_name = display_name
        self._capabilities = capabilities
        self._api_prefix = api_prefix
        self._username = username
        self._password = password
        self._bearer_token = bearer_token
        self._transport = transport
        self._validate_network_target = validate_network_target
        self._target_validated = False
        self._writable = writable
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._policy_domains: dict[str, str] = {}
        self.certificate_info: dict[str, str] = {}
        self.tenant_info: dict[str, str] = {}
        self._custom_ca_certificate = ca_certificate
        self._exact_pin_fingerprints: set[bytes] = set()
        self._exact_pin_active = False
        self._ssl_context = ssl.create_default_context()
        if ca_certificate:
            try:
                self._ssl_context.load_verify_locations(cadata=ca_certificate)
                self._exact_pin_fingerprints = {
                    certificate.fingerprint(hashes.SHA256())
                    for certificate in x509.load_pem_x509_certificates(ca_certificate.encode())
                }
            except (ValueError, ssl.SSLError) as exc:
                raise ProviderConfigurationError from exc
        # One provider instance represents one bounded test/sync operation. Reusing its client
        # preserves verified TLS connection pooling; constructing a client per read made SCC tests
        # both unnecessarily slow and vulnerable to repeated handshake/read timeouts.
        self._client = self._build_client(self._ssl_context)

    def _build_client(self, ssl_context: ssl.SSLContext) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=ssl_context,
            timeout=httpx.Timeout(connect=5.0, read=120.0, write=10.0, pool=10.0),
            follow_redirects=False,
            transport=self._transport,
        )

    async def aclose(self) -> None:
        """Close the operation-scoped verified HTTP transport."""
        await self._client.aclose()

    async def inspect_pending_changes(self, domain_id: str, policy_id: str) -> dict[str, object]:
        """Return bounded provider evidence; incomplete provider scope fails closed."""
        warning = await self._pending_change_warning(domain_id, policy_id)
        return warning or {"pending_change_count": 0, "scope_known": True, "changes": []}

    async def start_deployment(
        self, domain_id: str, policy_ids: list[str], device_ids: list[str]
    ) -> dict[str, object]:
        # Deployment is intentionally gated by the connector's explicit write_enabled flag in
        # _mutate_json, not by stale capability evidence. Dev sources are used to establish that
        # evidence, so requiring prior evidence here would make first real deployment impossible.
        if not device_ids or not policy_ids:
            raise ProviderContractError
        deployable = await self._get_with_params(
            self._config_path(domain_id, "deployment/deployabledevices"),
            {"offset": 0, "limit": 1000, "expanded": True},
        )
        raw_items = deployable.get("items", []) if isinstance(deployable, dict) else []
        provider_device_ids: list[str] = []
        device_evidence: list[dict[str, object]] = []
        if isinstance(raw_items, list):
            for item in raw_items:
                if not isinstance(item, dict):
                    continue
                device_evidence.append(
                    {
                        "id": str(item.get("id") or ""),
                        "can_be_deployed": item.get("canBeDeployed"),
                        "is_deploying": item.get("isDeploying"),
                        "up_to_date": item.get("upToDate"),
                        "message": str(item.get("message") or "")[:300],
                    }
                )
                if item.get("canBeDeployed") is False or item.get("isDeploying") is True:
                    continue
                device = item.get("device")
                if isinstance(device, dict) and device.get("id"):
                    provider_device_ids.append(str(device["id"]))
                elif item.get("deviceId"):
                    provider_device_ids.append(str(item["deviceId"]))
                members = item.get("deviceMembers")
                if isinstance(members, list):
                    provider_device_ids.extend(
                        str(member["id"])
                        for member in members
                        if isinstance(member, dict) and member.get("id")
                    )
                if (
                    not isinstance(device, dict)
                    and not isinstance(members, list)
                    and item.get("id")
                ):
                    provider_device_ids.append(str(item["id"]))
        provider_device_ids = list(dict.fromkeys(provider_device_ids))
        if not provider_device_ids:
            raise ProviderContractError(
                details={
                    "code": "NO_DEPLOYABLE_DEVICES",
                    "provider_device_evidence": device_evidence[:20],
                    "provider_messages": [
                        {"message": "FMC reported no devices currently eligible for deployment."}
                    ],
                }
            )
        # FMC starts a full deployment through deploymentrequests.  The
        # deployabledevices collection is read-only; posting to its /deploy
        # subresource with a policyList is rejected by real FMC instances.
        response = await self._mutate_json(
            "POST",
            self._config_path(domain_id, "deployment/deploymentrequests"),
            {
                "deviceList": provider_device_ids,
                "forceDeploy": False,
                "ignoreWarning": True,
                "type": "DeploymentRequest",
                # 0 tells FMC to use the current pending-change timestamp.
                "version": "0",
            },
        )
        metadata = response.get("metadata")
        task = metadata.get("task") if isinstance(metadata, dict) else None
        task_id = task.get("id") if isinstance(task, dict) else None
        if not task_id:
            task_id = response.get("taskId") or response.get("id")
        if not task_id:
            raise ProviderContractError
        return {
            # Preserve the domain because FMC task status is domain-scoped.
            "external_operation_id": f"{domain_id}:{task_id}",
            "provider": response,
        }

    async def deployment_status(self, external_operation_id: str) -> dict[str, object]:
        # Status polling is read-only and must remain available while deployment evidence is being
        # collected; the connector lifecycle and provider response still determine the result.
        try:
            domain_id, task_id = external_operation_id.split(":", 1)
        except ValueError as exc:
            raise ProviderContractError from exc
        response = await self._get(self._config_path(domain_id, f"job/taskstatuses/{task_id}"))
        if not isinstance(response, dict):
            raise ProviderContractError
        status = str(response.get("status") or response.get("state") or "UNKNOWN").upper()
        normalized = {
            "COMPLETED": "DEPLOYED",
            "SUCCESS": "DEPLOYED",
            "SUCCEEDED": "DEPLOYED",
            "DEPLOYED": "DEPLOYED",
            "FAILED": "FAILED",
            "ERROR": "FAILED",
        }.get(status, "DEPLOYING")
        return {
            "state": normalized,
            "provider_status": status,
            "provider": response,
            "devices": response.get("deviceResults", []),
        }

    async def rollback_deployment(
        self, domain_id: str, deployment_operation_id: str, device_ids: list[str]
    ) -> dict[str, object]:
        """Request FMC rollback for the devices in a completed deployment task."""
        try:
            operation_domain, task_id = deployment_operation_id.split(":", 1)
        except ValueError as exc:
            raise ProviderContractError from exc
        if operation_domain != domain_id or not task_id or not device_ids:
            raise ProviderContractError
        response = await self._mutate_json(
            "POST",
            self._config_path(domain_id, "deployment/rollbackrequests"),
            {
                "rollbackDeviceList": [
                    {"deploymentJobId": task_id, "deviceList": list(dict.fromkeys(device_ids))}
                ],
                "type": "RollbackRequest",
            },
        )
        metadata = response.get("metadata")
        task = metadata.get("task") if isinstance(metadata, dict) else None
        rollback_task_id = task.get("id") if isinstance(task, dict) else None
        rollback_task_id = rollback_task_id or response.get("taskId") or response.get("id")
        if not rollback_task_id:
            raise ProviderContractError
        return {
            "external_operation_id": f"{domain_id}:{rollback_task_id}",
            "provider": response,
        }

    async def rollback_status(self, external_operation_id: str) -> dict[str, object]:
        result = await self.deployment_status(external_operation_id)
        state = result["state"]
        return {**result, "state": "ROLLED_BACK" if state == "DEPLOYED" else state}

    async def information(self) -> ProviderInfo:
        await self._ensure_identity()
        payload = await self._get(f"{self._api_prefix}/api/fmc_platform/v1/info/serverversion")
        item = self._first_item(payload)
        version = str(item.get("serverVersion") or item.get("version") or "unknown")
        return ProviderInfo(
            provider=self.kind,
            display_name=self._display_name,
            provider_version=version,
            capabilities=self._capabilities,
            evidence_profile=ProviderEvidenceProfile.REAL,
            writable=self._writable,
        )

    async def discover(self) -> ProviderInventory:
        info = await self.information()
        domains = await self.domains(PageRequest(limit=1))
        policy_count = 0
        object_count = 0
        if domains.items:
            domain_id = domains.items[0].native_id
            policy_count = len((await self.policies(domain_id, PageRequest(limit=100))).items)
            object_count = len((await self.objects(domain_id, PageRequest(limit=100))).items)
        return ProviderInventory(
            self.kind,
            info.display_name,
            info.provider_version,
            policy_count,
            object_count,
            self._writable,
            ProviderEvidenceProfile.REAL,
        )

    async def domains(self, page: PageRequest) -> ProviderPage[DiscoveredDomain]:
        payload, next_cursor = await self._page(
            f"{self._api_prefix}/api/fmc_platform/v1/info/domain", page
        )
        return ProviderPage(
            tuple(
                DiscoveredDomain(
                    native_id=_native_id(item),
                    name=_name(item, _native_id(item)),
                    native_version=_version(item),
                    fingerprint=_fingerprint(item),
                    native_metadata=_metadata(item),
                )
                for item in payload
            ),
            next_cursor,
        )

    async def devices(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredDevice]:
        items, next_cursor = await self._page(
            self._config_path(domain_native_id, "devices/devicerecords"), page
        )
        return ProviderPage(
            tuple(
                DiscoveredDevice(
                    native_id=_native_id(item),
                    name=_name(item, _native_id(item)),
                    native_version=_version(item),
                    fingerprint=_fingerprint(item),
                    native_metadata=_metadata(item),
                    domain_native_id=domain_native_id,
                    model=str(item["model"]) if item.get("model") is not None else None,
                )
                for item in items
            ),
            next_cursor,
        )

    async def policies(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredPolicy]:
        items, next_cursor = await self._page(
            self._config_path(domain_native_id, "policy/accesspolicies"), page
        )
        results: list[DiscoveredPolicy] = []
        for item in items:
            native_id = _native_id(item)
            self._policy_domains[native_id] = domain_native_id
            results.append(
                DiscoveredPolicy(
                    native_id=native_id,
                    name=_name(item, native_id),
                    native_version=_version(item),
                    fingerprint=_fingerprint(item),
                    native_metadata=_metadata(item),
                    domain_native_id=domain_native_id,
                )
            )
        return ProviderPage(tuple(results), next_cursor)

    async def categories(
        self, policy_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredCategory]:
        domain_id = self._policy_domain(policy_native_id)
        items, next_cursor = await self._page(
            self._config_path(domain_id, f"policy/accesspolicies/{policy_native_id}/categories"),
            page,
        )
        return ProviderPage(
            tuple(
                DiscoveredCategory(
                    native_id=_native_id(item),
                    name=_name(item, _native_id(item)),
                    native_version=_version(item),
                    fingerprint=_fingerprint(item),
                    native_metadata=_metadata(item),
                    policy_native_id=policy_native_id,
                    position=self._position(item),
                )
                for item in items
            ),
            next_cursor,
        )

    async def intrusion_policies(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredIntrusionPolicy]:
        items, next_cursor = await self._page(
            self._config_path(domain_native_id, "policy/intrusionpolicies"), page
        )
        return ProviderPage(
            tuple(
                DiscoveredIntrusionPolicy(
                    native_id=_native_id(item),
                    name=_name(item, _native_id(item)),
                    native_version=_version(item),
                    fingerprint=_fingerprint(item),
                    native_metadata=_metadata(item),
                    domain_native_id=domain_native_id,
                    default_variable_set_native_id=_reference_native_id(
                        item.get("defaultVariableSet") or item.get("variableSet")
                    ),
                )
                for item in items
            ),
            next_cursor,
        )

    async def variable_sets(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredVariableSet]:
        items, next_cursor = await self._page(
            self._config_path(domain_native_id, "object/variablesets"), page
        )
        return ProviderPage(
            tuple(
                DiscoveredVariableSet(
                    native_id=_native_id(item),
                    name=_name(item, _native_id(item)),
                    native_version=_version(item),
                    fingerprint=_fingerprint(item),
                    native_metadata=_metadata(item),
                    domain_native_id=domain_native_id,
                    is_default=bool(
                        item.get("isDefault")
                        or item.get("defaultVariableSet")
                        or str(item.get("name", "")).lower() in {"default", "default set"}
                    ),
                )
                for item in items
            ),
            next_cursor,
        )

    async def file_policies(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredFilePolicy]:
        items, next_cursor = await self._page(
            self._config_path(domain_native_id, "policy/filepolicies"), page
        )
        return ProviderPage(
            tuple(
                DiscoveredFilePolicy(
                    native_id=_native_id(item),
                    name=_name(item, _native_id(item)),
                    native_version=_version(item),
                    fingerprint=_fingerprint(item),
                    native_metadata=_metadata(item),
                    domain_native_id=domain_native_id,
                )
                for item in items
            ),
            next_cursor,
        )

    async def rules(self, policy_native_id: str, page: PageRequest) -> ProviderPage[DiscoveredRule]:
        domain_id = self._policy_domain(policy_native_id)
        items, next_cursor = await self._page(
            self._config_path(domain_id, f"policy/accesspolicies/{policy_native_id}/accessrules"),
            page,
        )
        return ProviderPage(
            tuple(self._rule(item, policy_native_id) for item in items), next_cursor
        )

    async def objects(
        self,
        domain_native_id: str,
        page: PageRequest,
        *,
        applications_only: bool = False,
        include_applications: bool = True,
    ) -> ProviderPage[DiscoveredObject]:
        endpoint_index, offset = self._object_cursor(page.cursor)
        while endpoint_index < len(_OBJECT_ENDPOINTS):
            endpoint, object_type = _OBJECT_ENDPOINTS[endpoint_index]
            is_application = object_type is FirewallObjectType.APPLICATION
            is_application_catalog = object_type in {
                FirewallObjectType.APPLICATION,
                FirewallObjectType.APPLICATION_FILTER,
            }
            if (applications_only and not is_application_catalog) or (
                not applications_only and not include_applications and is_application
            ):
                endpoint_index += 1
                offset = 0
                continue
            break
        if endpoint_index >= len(_OBJECT_ENDPOINTS):
            return ProviderPage((), None)
        page_params: dict[str, str | int | bool] = {}
        if endpoint == "applicationfilters":
            # FMC/SCC do not include the system-maintained filter catalog in
            # the default application-filter listing.  Request it explicitly
            # so rule forms can offer the provider's built-in filters.
            page_params["filter"] = "issystemdefined:true"
        items, native_next = await self._page(
            self._config_path(domain_native_id, f"object/{endpoint}"),
            PageRequest(limit=page.limit, cursor=str(offset)),
            extra_params=page_params,
        )
        if endpoint in _SYSTEM_APPLICATION_FILTER_ENDPOINTS:
            items = [self._system_filter_item(item, endpoint) for item in items]
        if native_next is not None:
            next_cursor = f"{endpoint_index}:{native_next}"
        elif endpoint_index + 1 < len(_OBJECT_ENDPOINTS):
            next_cursor = f"{endpoint_index + 1}:0"
        else:
            next_cursor = None
        return ProviderPage(
            tuple(self._object(item, domain_native_id, object_type) for item in items),
            next_cursor,
        )

    async def zones(self, domain_native_id: str, page: PageRequest) -> ProviderPage[DiscoveredZone]:
        items, next_cursor = await self._page(
            self._config_path(domain_native_id, "object/securityzones"), page
        )
        return ProviderPage(
            tuple(
                DiscoveredZone(
                    native_id=_native_id(item),
                    name=_name(item, _native_id(item)),
                    native_version=_version(item),
                    fingerprint=_fingerprint(item),
                    native_metadata=_metadata(item),
                    domain_native_id=domain_native_id,
                    zone_type=str(item.get("interfaceMode", "SECURITY")),
                )
                for item in items
            ),
            next_cursor,
        )

    async def execute_transaction(  # noqa: PLR0912, PLR0915 -- explicit provider outcome mapping
        self,
        change_set_id: UUID,
        manager_id: UUID,
        operations: list[dict[str, object]],
    ) -> ProviderExecutionResult:
        """Execute one already-authorized normalized transaction without unsafe retries."""
        if not self._writable:
            raise ProductionWriteDisabledError
        transaction_id = real_transaction_operation_id(change_set_id, manager_id)
        results: list[dict[str, object]] = []
        checked_pending_scopes: set[tuple[str, str]] = set()
        checked_move_categories: set[tuple[str, str, str]] = set()
        resolved_categories: dict[str, str] = {}
        mutation_seen = False
        ambiguous = False
        for operation in operations:
            operation_id = str(operation.get("id", ""))
            operation_warnings: list[dict[str, object]] = []
            if ambiguous:
                results.append(self._operation_result(operation_id, OperationStatus.NOT_ATTEMPTED))
                continue
            try:
                payload = operation.get("provider_payload")
                if not isinstance(payload, dict):
                    raise ProviderContractError
                typed_payload = cast("dict[str, object]", payload)
                category_name = typed_payload.get("category_provider_name")
                if category_name and not typed_payload.get("category_native_id"):
                    native_category = resolved_categories.get(str(category_name))
                    if native_category:
                        typed_payload = {**typed_payload, "category_native_id": native_category}
                kind = ChangeOperationKind(str(operation["kind"]))
                if kind is ChangeOperationKind.MOVE_RULE and typed_payload.get(
                    "category_native_id"
                ):
                    category_scope = (
                        str(typed_payload.get("domain_native_id", "")),
                        str(typed_payload.get("policy_native_id", "")),
                        str(typed_payload["category_native_id"]),
                    )
                    if category_scope in checked_move_categories:
                        typed_payload = {**typed_payload, "expected_category_version": None}
                    else:
                        checked_move_categories.add(category_scope)
                if (
                    kind is ChangeOperationKind.CREATE_RULE
                    and category_name
                    and not typed_payload.get("category_native_id")
                ):
                    results.append(
                        self._operation_result(
                            operation_id,
                            OperationStatus.NOT_ATTEMPTED,
                            failure={"code": "CATEGORY_DEPENDENCY_FAILED", "retry_safe": True},
                        )
                    )
                    continue
                resource, mutated = await self._execute_operation(
                    kind,
                    typed_payload,
                    checked_pending_scopes,
                    operation_warnings,
                )
                if kind is ChangeOperationKind.ENSURE_RULE_CATEGORY:
                    provider_name = typed_payload.get("provider_name")
                    native_id = resource.get("native_id")
                    if provider_name and native_id:
                        resolved_categories[str(provider_name)] = str(native_id)
                mutation_seen = mutation_seen or mutated
                results.append(
                    self._operation_result(
                        operation_id,
                        OperationStatus.SUCCEEDED,
                        mutated=mutated,
                        resource=resource,
                        warnings=operation_warnings,
                    )
                )
            except _AmbiguousMutationError as exc:
                ambiguous = True
                results.append(
                    self._operation_result(
                        operation_id,
                        OperationStatus.AMBIGUOUS,
                        mutated="unknown",
                        failure={
                            "code": exc.code,
                            "retry_safe": False,
                            "reconciliation_required": True,
                        },
                        warnings=operation_warnings,
                    )
                )
            except _ProviderMutationConflictError as exc:
                results.append(
                    self._operation_result(
                        operation_id,
                        OperationStatus.CONFLICT,
                        failure={
                            "code": exc.code,
                            "retry_safe": False,
                            **exc.details,
                        },
                        warnings=operation_warnings,
                    )
                )
            except ProviderError as exc:
                results.append(
                    self._operation_result(
                        operation_id,
                        OperationStatus.FAILED,
                        failure={"code": exc.code, "retry_safe": False},
                        warnings=operation_warnings,
                    )
                )
            except (KeyError, TypeError, ValueError):
                results.append(
                    self._operation_result(
                        operation_id,
                        OperationStatus.FAILED,
                        failure={"code": "PROVIDER_CONTRACT_ERROR", "retry_safe": False},
                        warnings=operation_warnings,
                    )
                )
        statuses = {str(item["status"]) for item in results}
        if ambiguous:
            state = ProviderTransactionState.RECONCILIATION_REQUIRED
        elif OperationStatus.CONFLICT.value in statuses and not mutation_seen:
            state = ProviderTransactionState.CONFLICT
        elif statuses == {OperationStatus.SUCCEEDED.value}:
            state = ProviderTransactionState.SUCCEEDED
        elif mutation_seen:
            state = ProviderTransactionState.PARTIALLY_SUCCEEDED
        else:
            state = ProviderTransactionState.FAILED
        failures = [item for item in results if item["status"] != OperationStatus.SUCCEEDED.value]
        return ProviderExecutionResult(
            state=state,
            operation_results=results,
            failure_info={"operation_failures": failures} if failures else {},
            reconciliation_required=ambiguous,
            external_operation_id=transaction_id,
        )

    async def _execute_operation(  # noqa: PLR0912, PLR0915 -- explicit mutation routing
        self,
        kind: ChangeOperationKind,
        payload: dict[str, object],
        checked_pending_scopes: set[tuple[str, str]],
        warnings: list[dict[str, object]],
    ) -> tuple[dict[str, object], bool]:
        required = self._mutation_capability(kind, payload)
        if self._capabilities.get(required.value) is not CapabilityStatus.SUPPORTED:
            raise _ProviderMutationConflictError("PROVIDER_CAPABILITY_UNAVAILABLE")
        domain_id = self._required(payload, "domain_native_id")
        policy_id = self._required(payload, "policy_native_id")
        pending_scope = (domain_id, policy_id)
        if pending_scope not in checked_pending_scopes:
            await self._assert_current(
                self._config_path(domain_id, f"policy/accesspolicies/{policy_id}"),
                payload.get("expected_policy_version"),
            )
            pending_warning = await self._pending_change_warning(domain_id, policy_id)
            if pending_warning:
                warnings.append(pending_warning)
            checked_pending_scopes.add(pending_scope)
        if kind is ChangeOperationKind.ENSURE_RULE_CATEGORY:
            category_id = payload.get("category_native_id")
            if category_id:
                current = await self._assert_current(
                    self._config_path(
                        domain_id,
                        f"policy/accesspolicies/{policy_id}/categories/{category_id}",
                    ),
                    payload.get("expected_category_version"),
                )
                if _name(current, "") != self._required(payload, "provider_name"):
                    raise _ProviderMutationConflictError("PROVIDER_CATEGORY_MAPPING_CONFLICT")
                return self._provider_resource(current), False
            categories = await self._get_with_params(
                self._config_path(domain_id, f"policy/accesspolicies/{policy_id}/categories"),
                {"offset": 0, "limit": 1000, "expanded": True},
            )
            typed_categories = (
                cast("dict[str, object]", categories) if isinstance(categories, dict) else {}
            )
            items = typed_categories.get("items", [])
            if not isinstance(items, list):
                raise _ProviderMutationConflictError("CATEGORY_STATE_UNKNOWN")
            typed_items = cast("list[object]", items)
            paging = typed_categories.get("paging", {})
            typed_paging = cast("dict[str, object]", paging) if isinstance(paging, dict) else {}
            if int(str(typed_paging.get("count", len(typed_items)))) > len(typed_items):
                raise _ProviderMutationConflictError("CATEGORY_STATE_INCOMPLETE")
            if any(
                isinstance(item, dict)
                and _name(cast("Mapping[str, Any]", item), "")
                == self._required(payload, "provider_name")
                for item in typed_items
            ):
                raise _ProviderMutationConflictError("PROVIDER_CATEGORY_NAME_CONFLICT")
            access_rules = await self._get_with_params(
                self._config_path(domain_id, f"policy/accesspolicies/{policy_id}/accessrules"),
                {"offset": 0, "limit": 1000, "expanded": True},
            )
            typed_rules = (
                cast("dict[str, object]", access_rules) if isinstance(access_rules, dict) else {}
            )
            rules = typed_rules.get("items", [])
            if not isinstance(rules, list):
                raise _ProviderMutationConflictError("RULE_STATE_UNKNOWN")
            typed_rules_list = cast("list[object]", rules)
            rule_paging = typed_rules.get("paging", {})
            typed_rule_paging = (
                cast("dict[str, object]", rule_paging) if isinstance(rule_paging, dict) else {}
            )
            if int(str(typed_rule_paging.get("count", len(typed_rules_list)))) > len(
                typed_rules_list
            ):
                raise _ProviderMutationConflictError("RULE_STATE_INCOMPLETE")
            default_indexes: list[int] = []
            for rule in typed_rules_list:
                if not isinstance(rule, dict):
                    raise _ProviderMutationConflictError("RULE_STATE_UNKNOWN")
                metadata = rule.get("metadata")
                if not isinstance(metadata, dict):
                    continue
                typed_metadata = cast("dict[str, object]", metadata)
                if str(typed_metadata.get("section", "")).casefold() != "default":
                    continue
                if typed_metadata.get("ruleIndex") is not None:
                    default_indexes.append(int(str(typed_metadata["ruleIndex"])))
            default_categories: list[tuple[int, str]] = []
            for item in typed_items:
                if not isinstance(item, dict) or not item.get("name"):
                    continue
                metadata = item.get("metadata")
                if not isinstance(metadata, dict):
                    continue
                typed_metadata = cast("dict[str, object]", metadata)
                if str(typed_metadata.get("section", "")).casefold() != "default":
                    continue
                if typed_metadata.get("startIndex") is not None:
                    typed_item = cast("dict[str, object]", item)
                    default_categories.append(
                        (int(str(typed_metadata["startIndex"])), str(typed_item["name"]))
                    )
            if default_categories:
                placement: dict[str, str | int | bool] = {
                    "aboveCategory": min(default_categories)[1]
                }
            elif default_indexes:
                placement = {"insertBefore": str(min(default_indexes))}
            else:
                placement = {"section": "default"}
            response = await self._mutate_json(
                "POST",
                self._config_path(domain_id, f"policy/accesspolicies/{policy_id}/categories"),
                {"name": self._required(payload, "provider_name"), "type": "Category"},
                params=placement,
            )
            return self._provider_resource(response), True
        if kind in {
            ChangeOperationKind.CREATE_OBJECT,
            ChangeOperationKind.MODIFY_OBJECT,
            ChangeOperationKind.DELETE_OBJECT,
        }:
            return await self._execute_object(kind, domain_id, payload)
        return await self._execute_rule(kind, domain_id, policy_id, payload)

    async def _execute_rule(  # noqa: PLR0912, PLR0915 -- explicit Cisco payload mapping
        self,
        kind: ChangeOperationKind,
        domain_id: str,
        policy_id: str,
        payload: dict[str, object],
    ) -> tuple[dict[str, object], bool]:
        base = self._config_path(domain_id, f"policy/accesspolicies/{policy_id}/accessrules")
        if kind is ChangeOperationKind.CREATE_RULE:
            if payload.get("category_provider_name") and not payload.get("category_native_id"):
                raise _ProviderMutationConflictError("PROVIDER_RULE_CATEGORY_NOT_RESOLVED")
            existing = await self._get_with_params(
                base, {"offset": 0, "limit": 1000, "expanded": True}
            )
            typed_existing = (
                cast("dict[str, object]", existing) if isinstance(existing, dict) else {}
            )
            items = typed_existing.get("items", [])
            if not isinstance(items, list):
                raise _ProviderMutationConflictError("RULE_STATE_UNKNOWN")
            typed_existing_items = cast("list[object]", items)
            paging = typed_existing.get("paging", {})
            typed_paging = cast("dict[str, object]", paging) if isinstance(paging, dict) else {}
            if int(str(typed_paging.get("count", len(typed_existing_items)))) > len(
                typed_existing_items
            ):
                raise _ProviderMutationConflictError("RULE_STATE_INCOMPLETE")
            requested_name = str(payload.get("name", ""))
            matching_name = next(
                (
                    cast("Mapping[str, Any]", item)
                    for item in typed_existing_items
                    if isinstance(item, dict)
                    and _name(cast("Mapping[str, Any]", item), "") == requested_name
                ),
                None,
            )
            if matching_name is not None:
                if self._rule_create_matches(matching_name, payload):
                    return self._provider_resource(matching_name), False
                raise _ProviderMutationConflictError("PROVIDER_RULE_NAME_CONFLICT")
            # Cisco rejects empty match containers on rule creation.  Omit optional
            # criteria that the caller did not select; an omitted criterion means Any.
            body = self._rule_payload(payload)
            body.pop("category", None)
            params: dict[str, str | int | bool] = {
                "category": self._required(payload, "category_provider_name")
            }
            if payload.get("position") is not None:
                position = int(str(payload["position"]))
                anchor_native_id = payload.get("anchor_rule_native_id")
                if anchor_native_id:
                    anchor = await self._assert_current(f"{base}/{anchor_native_id}", None)
                    if not self._rule_category_matches(
                        anchor,
                        str(payload.get("category_native_id", "")),
                        str(payload.get("category_provider_name", "")),
                    ):
                        raise _ProviderMutationConflictError("PROVIDER_OWNERSHIP_CATEGORY_CONFLICT")
                    position = self._position(anchor)
                placement = str(payload.get("placement", "BEFORE")).upper()
                params["insertAfter" if placement == "AFTER" else "insertBefore"] = str(position)
            response = await self._mutate_json(
                "POST",
                base,
                body,
                params=params,
            )
            return self._provider_resource(response), True
        rule_id = self._required(payload, "rule_native_id")
        current = await self._assert_current(
            f"{base}/{rule_id}", payload.get("expected_rule_version")
        )
        if _name(current, "") != self._required(payload, "expected_rule_name"):
            raise _ProviderMutationConflictError("PROVIDER_OWNERSHIP_NAME_CONFLICT")
        current_action = str(current.get("action", "")).upper()
        expected_action = str(payload.get("expected_rule_action", "")).upper()
        if expected_action and current_action != expected_action:
            raise _ProviderMutationConflictError("STALE_PROVIDER_REVISION")
        if kind is ChangeOperationKind.DELETE_RULE:
            await self._mutate_json("DELETE", f"{base}/{rule_id}", None)
            return self._provider_resource(current), True
        if kind is ChangeOperationKind.MOVE_RULE:
            category = payload.get("category_native_id")
            if not category:
                raise _ProviderMutationConflictError("PROVIDER_RULE_CATEGORY_NOT_RESOLVED")
            current_category = await self._assert_current(
                self._config_path(
                    domain_id,
                    f"policy/accesspolicies/{policy_id}/categories/{category}",
                ),
                payload.get("expected_category_version"),
            )
            expected_category_name = payload.get("expected_category_name")
            if expected_category_name and _name(current_category, "") != str(
                expected_category_name
            ):
                raise _ProviderMutationConflictError("PROVIDER_CATEGORY_MAPPING_CONFLICT")
            if not self._rule_category_matches(
                current,
                str(category),
                _name(current_category, ""),
            ):
                raise _ProviderMutationConflictError("PROVIDER_OWNERSHIP_CATEGORY_CONFLICT")
            metadata = current_category.get("metadata")
            typed_metadata = (
                cast("dict[str, object]", metadata) if isinstance(metadata, dict) else {}
            )
            start = typed_metadata.get("startIndex")
            end = typed_metadata.get("endIndex")
            target_position = int(str(payload["position"]))
            if (
                start is not None
                and end is not None
                and not (int(str(start)) <= target_position <= int(str(end)))
            ):
                raise _ProviderMutationConflictError("RULE_ORDERING_BOUNDARY_VIOLATION")
            # FMC's update endpoint does not expose rule ordering. Recreate the same rule at the
            # requested index, preserving its configuration while treating any post-delete failure
            # as ambiguous so reconciliation—not a blind retry—repairs the local/native ID mapping.
            body = dict(current)
            for field in (
                "id",
                "links",
                "metadata",
                "version",
                "ruleIndex",
                "position",
                "startIndex",
                "endIndex",
                "section",
            ):
                body.pop(field, None)
            await self._mutate_json("DELETE", f"{base}/{rule_id}", None)
            try:
                response = await self._mutate_json(
                    "POST",
                    base,
                    body,
                    params={
                        "category": _name(current_category, ""),
                        "insertBefore": str(target_position),
                    },
                )
            except (_ProviderMutationConflictError, _AmbiguousMutationError, ProviderError) as exc:
                raise _AmbiguousMutationError("RULE_REORDER_RECONCILIATION_REQUIRED") from exc
            return self._provider_resource(response), True
        # Build the PUT body from normalized ChangeSet intent instead of copying the provider's
        # read representation. FMC read objects contain response-only fields and nested shapes
        # (for example metadata.ruleIndex and some objects containers) that PUT rejects.
        body = self._rule_payload(payload, include_empty=True)
        body["id"] = rule_id
        # Keep FMC's normal rule-reference containers (for example
        # {"objects": [{"id": ...}]}). Flattening them changes this into a bulk-style
        # payload and causes FMC to reject the request even when bulk=true is supplied.
        response = await self._mutate_json("PUT", f"{base}/{rule_id}", body)
        return self._provider_resource(response), True

    async def _execute_object(
        self, kind: ChangeOperationKind, domain_id: str, payload: dict[str, object]
    ) -> tuple[dict[str, object], bool]:
        resolution = payload.get("resolution")
        if kind is ChangeOperationKind.CREATE_OBJECT and isinstance(resolution, dict):
            existing = cast("dict[str, object]", resolution).get("existing_object_native_id")
            if existing:
                return {"native_id": str(existing), "fingerprint": "reused"}, False
        endpoint, body = self._object_payload(payload)
        base = self._config_path(domain_id, f"object/{endpoint}")
        if kind is ChangeOperationKind.CREATE_OBJECT:
            existing = await self._get_with_params(
                base, {"offset": 0, "limit": 1000, "expanded": True}
            )
            typed_existing = (
                cast("dict[str, object]", existing) if isinstance(existing, dict) else {}
            )
            items = typed_existing.get("items", [])
            if not isinstance(items, list):
                raise _ProviderMutationConflictError("OBJECT_STATE_UNKNOWN")
            typed_items = cast("list[object]", items)
            paging = typed_existing.get("paging", {})
            typed_paging = cast("dict[str, object]", paging) if isinstance(paging, dict) else {}
            if int(str(typed_paging.get("count", len(typed_items)))) > len(typed_items):
                raise _ProviderMutationConflictError("OBJECT_STATE_INCOMPLETE")
            for item in typed_items:
                if not isinstance(item, dict):
                    raise _ProviderMutationConflictError("OBJECT_STATE_UNKNOWN")
                candidate = cast("Mapping[str, Any]", item)
                if _name(candidate, "") == str(body["name"]):
                    if self._object_payload_matches(candidate, body):
                        # A prior attempt may have committed at the provider and failed
                        # before local reconciliation. Re-adopt the matching resource.
                        return self._provider_resource(candidate), True
                    raise _ProviderMutationConflictError("PROVIDER_OBJECT_NAME_CONFLICT")
            response = await self._mutate_json("POST", base, body)
            return self._provider_resource(response), True
        native_id = self._required(payload, "object_native_id")
        current = await self._assert_current(
            f"{base}/{native_id}", payload.get("expected_object_version")
        )
        if _name(current, "") != self._required(payload, "expected_provider_name"):
            raise _ProviderMutationConflictError("PROVIDER_OWNERSHIP_NAME_CONFLICT")
        if kind is ChangeOperationKind.DELETE_OBJECT:
            await self._mutate_json("DELETE", f"{base}/{native_id}", None)
            return self._provider_resource(current), True
        body["id"] = native_id
        response = await self._mutate_json("PUT", f"{base}/{native_id}", body)
        return self._provider_resource(response), True

    async def _pending_change_warning(
        self, domain_id: str, _policy_id: str
    ) -> dict[str, object] | None:
        if (
            self._capabilities.get(ProviderCapability.PENDING_CHANGE_INSPECTION.value)
            is not CapabilityStatus.SUPPORTED
        ):
            raise _ProviderMutationConflictError("PENDING_CHANGE_INSPECTION_UNAVAILABLE")
        payload = await self._get_with_params(
            self._config_path(domain_id, "deployment/deployabledevices"),
            {"offset": 0, "limit": 1000, "expanded": True},
        )
        raw_items = payload.get("items", []) if isinstance(payload, dict) else []
        if not isinstance(raw_items, list):
            raise _ProviderMutationConflictError("PENDING_CHANGE_STATE_UNKNOWN")
        items = cast("list[object]", raw_items)
        raw_paging = payload.get("paging", {}) if isinstance(payload, dict) else {}
        paging = cast("dict[str, object]", raw_paging) if isinstance(raw_paging, dict) else {}
        count = paging.get("count", len(items))
        if int(str(count)) > len(items):
            raise _ProviderMutationConflictError("PENDING_CHANGE_STATE_INCOMPLETE")
        pending_changes: list[Mapping[str, Any]] = []
        for item in items:
            if not isinstance(item, dict) or not item.get("id"):
                raise _ProviderMutationConflictError("PENDING_CHANGE_STATE_UNKNOWN")
            pending = await self._get(
                self._config_path(
                    domain_id,
                    f"deployment/deployabledevices/{item['id']}/pendingchanges",
                )
            )
            pending_items = pending.get("items", []) if isinstance(pending, dict) else []
            if not isinstance(pending_items, list):
                raise _ProviderMutationConflictError("PENDING_CHANGE_STATE_UNKNOWN")
            if not all(isinstance(change, dict) for change in pending_items):
                raise _ProviderMutationConflictError("PENDING_CHANGE_STATE_UNKNOWN")
            pending_changes.extend(cast("Mapping[str, Any]", change) for change in pending_items)
        if not pending_changes:
            return None
        actors: set[str] = set()
        entity_types: set[str] = set()
        for item in pending_changes:
            entity_type = str(item.get("entityType", "")).strip()
            if entity_type:
                entity_types.add(entity_type)
            raw_actors = item.get("lastUpdatedByUsers", [])
            if isinstance(raw_actors, list):
                actors.update(
                    str(actor).strip()
                    for actor in cast("list[object]", raw_actors)
                    if str(actor).strip()
                )
        return {
            "code": "OTHER_PENDING_CHANGES_PRESENT",
            "pending_change_count": len(pending_changes),
            "entity_types": sorted(entity_types),
            "actors": sorted(actors),
            "deployment_notice": (
                "Deployment is separate and may include provider changes outside this ChangeSet."
            ),
        }

    async def _assert_current(self, path: str, expected_version: object) -> Mapping[str, Any]:
        payload = await self._get(path)
        if not isinstance(payload, dict):
            raise ProviderContractError
        current = cast("Mapping[str, Any]", payload)
        if expected_version is not None and str(expected_version) != str(_version(current)):
            raise _ProviderMutationConflictError("STALE_PROVIDER_REVISION")
        return current

    async def _mutate_json(  # noqa: PLR0913 -- transport retry controls are explicit
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None,
        *,
        params: dict[str, str | int | bool] | None = None,
        ensure_identity: bool = True,
        retry_auth: bool = True,
    ) -> Mapping[str, Any]:
        """Send a mutation exactly once; transport/5xx outcomes are always ambiguous."""
        await self._ensure_target_safe()
        if ensure_identity:
            await self._ensure_identity()
        headers = (
            {"X-auth-access-token": self._access_token or ""}
            if self.kind is ProviderKind.FMC
            else {"Authorization": f"Bearer {self._bearer_token or ''}"}
        )
        try:
            response = await self._client.request(
                method,
                f"{self._endpoint}{path}",
                headers=headers,
                json=payload,
                params=params,
            )
            self._capture_certificate(response)
        except httpx.TransportError as exc:
            if self._is_tls_error(exc):
                raise ProviderTlsValidationError from exc
            raise _AmbiguousMutationError("MUTATION_TRANSPORT_RESULT_UNKNOWN") from exc
        if response.status_code >= 500 or response.status_code == 429:
            raise _AmbiguousMutationError(
                "MUTATION_PROVIDER_RESULT_UNKNOWN",
                self._provider_validation_details(response),
            )
        if response.status_code in {409, 412}:
            raise _ProviderMutationConflictError("STALE_PROVIDER_REVISION")
        if response.status_code == 401 and self.kind is ProviderKind.FMC and retry_auth:
            self._access_token = None
            await self._authenticate_fmc()
            return await self._mutate_json(
                method,
                path,
                payload,
                params=params,
                ensure_identity=False,
                retry_auth=False,
            )
        if response.status_code in {400, 422}:
            raise _ProviderMutationConflictError(
                "PROVIDER_VALIDATION_ERROR",
                self._provider_validation_details(response),
            )
        self._raise_for_status(response)
        if method == "DELETE" or not response.content:
            return {}
        try:
            value = response.json()
        except ValueError as exc:
            raise _AmbiguousMutationError("MUTATION_RESPONSE_INVALID") from exc
        if not isinstance(value, dict):
            raise _AmbiguousMutationError("MUTATION_RESPONSE_INVALID")
        return cast("Mapping[str, Any]", value)

    @staticmethod
    def _provider_validation_details(  # noqa: PLR0912 -- normalize version-specific error envelopes
        response: httpx.Response,
    ) -> dict[str, object]:
        """Retain only bounded, user-actionable fields from a provider error response."""
        details: dict[str, object] = {"provider_status": response.status_code}
        try:
            payload = response.json()
        except ValueError:
            text = response.text.strip()
            if text:
                details["provider_messages"] = [{"message": text[:500]}]
            return details
        if not isinstance(payload, dict):
            try:
                serialized = json.dumps(payload, default=str)
            except (TypeError, ValueError):
                serialized = str(payload)
            if serialized.strip():
                details["provider_messages"] = [{"message": serialized[:1000]}]
            return details
        messages = payload.get("messages")
        if not isinstance(messages, list):
            messages = payload.get("errors")
        if not isinstance(messages, list):
            messages = [payload]
        safe_messages: list[dict[str, str]] = []
        for message in messages[:3]:
            if not isinstance(message, dict):
                continue
            safe_message: dict[str, str] = {}
            for field in (
                "errorCode",
                "code",
                "description",
                "details",
                "location",
                "message",
                "error",
                "reason",
                "field",
                "messages",
                "error_description",
                "validationErrors",
                "validation_errors",
                "title",
                "status",
                "type",
                "path",
            ):
                value = message.get(field)
                if isinstance(value, (str, int, float)) and str(value).strip():
                    safe_message[field] = str(value).strip()[:500]
            if safe_message:
                safe_messages.append(safe_message)
        if not safe_messages and isinstance(payload, dict):
            # Cisco responses differ across FMC/SCC versions. Preserve bounded scalar fields when
            # the response does not use the documented messages/errors envelope.
            for field, value in list(payload.items())[:12]:
                if isinstance(value, (str, int, float, bool)) and str(value).strip():
                    safe_messages.append({str(field)[:80]: str(value)[:500]})

        # Some FMC/SCC versions wrap the useful message several levels deep. Include bounded
        # scalar paths so the UI can show the actual rejection without retaining arbitrary JSON.
        def collect_nested(value: object, path: str = "", depth: int = 0) -> None:
            if len(safe_messages) >= 10 or depth > 4:
                return
            if isinstance(value, dict):
                for key, nested in list(value.items())[:20]:
                    lowered = str(key).lower()
                    if any(secret in lowered for secret in ("password", "token", "secret", "auth")):
                        continue
                    collect_nested(nested, f"{path}.{key}".strip("."), depth + 1)
            elif isinstance(value, list):
                for index, nested in enumerate(value[:10]):
                    collect_nested(nested, f"{path}[{index}]", depth + 1)
            elif isinstance(value, (str, int, float, bool)) and str(value).strip():
                candidate = f"{path}: {str(value).strip()[:500]}"
                if not any(item.get("message") == candidate for item in safe_messages):
                    safe_messages.append({"message": candidate})

        collect_nested(payload)
        if safe_messages:
            details["provider_messages"] = safe_messages
        return details

    @staticmethod
    def _mutation_capability(
        kind: ChangeOperationKind, payload: dict[str, object]
    ) -> ProviderCapability:
        direct = {
            ChangeOperationKind.CREATE_RULE: ProviderCapability.ACCESS_RULE_CREATE,
            ChangeOperationKind.MODIFY_RULE: ProviderCapability.ACCESS_RULE_UPDATE,
            ChangeOperationKind.DELETE_RULE: ProviderCapability.ACCESS_RULE_DELETE,
            ChangeOperationKind.MOVE_RULE: ProviderCapability.RULE_ORDERING,
            ChangeOperationKind.ENSURE_RULE_CATEGORY: ProviderCapability.RULE_CATEGORY_MUTATION,
        }
        if kind in direct:
            return direct[kind]
        object_type = FirewallObjectType(str(payload["object_type"]))
        if kind is ChangeOperationKind.CREATE_OBJECT:
            return {
                FirewallObjectType.NETWORK: ProviderCapability.NETWORK_OBJECT_CREATE,
                FirewallObjectType.NETWORK_GROUP: ProviderCapability.NETWORK_OBJECT_CREATE,
                FirewallObjectType.PORT_SERVICE: ProviderCapability.PORT_SERVICE_OBJECT_CREATE,
                FirewallObjectType.PORT_SERVICE_GROUP: (
                    ProviderCapability.PORT_SERVICE_OBJECT_CREATE
                ),
                FirewallObjectType.URL: ProviderCapability.URL_OBJECT_CREATE,
                FirewallObjectType.URL_GROUP: ProviderCapability.URL_OBJECT_CREATE,
            }.get(object_type, ProviderCapability.APPLICATION_OBJECT_CREATE)
        return {
            FirewallObjectType.NETWORK: ProviderCapability.NETWORK_OBJECT_MUTATION,
            FirewallObjectType.NETWORK_GROUP: ProviderCapability.NETWORK_OBJECT_MUTATION,
            FirewallObjectType.PORT_SERVICE: ProviderCapability.PORT_SERVICE_OBJECT_MUTATION,
            FirewallObjectType.PORT_SERVICE_GROUP: (
                ProviderCapability.PORT_SERVICE_OBJECT_MUTATION
            ),
            FirewallObjectType.URL: ProviderCapability.URL_OBJECT_MUTATION,
            FirewallObjectType.URL_GROUP: ProviderCapability.URL_OBJECT_MUTATION,
        }.get(object_type, ProviderCapability.APPLICATION_OBJECT_MUTATION)

    @staticmethod
    def _required(payload: dict[str, object], key: str) -> str:
        value = payload.get(key)
        if value is None or not str(value):
            raise ProviderContractError(details={"code": f"MISSING_{key.upper()}"})
        return str(value)

    @staticmethod
    def _rule_payload(
        payload: dict[str, object], *, include_empty: bool = False
    ) -> dict[str, object]:
        body: dict[str, object] = {
            "type": "AccessRule",
            "name": str(payload.get("name", "delegated rule")),
            "action": str(payload.get("action", "ALLOW")),
            "enabled": bool(payload.get("enabled", True)),
        }
        logging_mode = str(payload.get("logging", "NONE")).upper()
        body["logBegin"] = logging_mode == "BEGIN"
        body["logEnd"] = logging_mode == "END"
        category = payload.get("category_native_id")
        if category:
            body["category"] = {"id": str(category), "type": "Category"}
        intrusion_policy = payload.get("intrusion_policy_native_id")
        if intrusion_policy:
            body["ipsPolicy"] = {"id": str(intrusion_policy), "type": "IntrusionPolicy"}
        variable_set = payload.get("variable_set_native_id")
        if variable_set:
            body["variableSet"] = {"id": str(variable_set), "type": "VariableSet"}
        file_policy = payload.get("file_policy_native_id")
        if file_policy:
            body["filePolicy"] = {"id": str(file_policy), "type": "FilePolicy"}
        for source, target in (
            ("source_zone_native_ids", "sourceZones"),
            ("destination_zone_native_ids", "destinationZones"),
            ("source_object_native_ids", "sourceNetworks"),
            ("destination_object_native_ids", "destinationNetworks"),
            ("port_object_native_ids", "destinationPorts"),
            ("source_port_object_native_ids", "sourcePorts"),
            ("destination_port_object_native_ids", "destinationPorts"),
            ("url_object_native_ids", "urls"),
        ):
            values = payload.get(source)
            if isinstance(values, list) and (values or include_empty):
                body[target] = {
                    "objects": [
                        _provider_reference_payload(item) for item in cast("list[object]", values)
                    ]
                }
        application_values = payload.get("application_object_native_ids")
        if isinstance(application_values, list) and (application_values or include_empty):
            application_objects: list[dict[str, object]] = []
            application_filters: list[dict[str, object]] = []
            for value in cast("list[object]", application_values):
                reference = CiscoReadOnlyProvider._application_reference_payload(value)
                if reference.get("type") == "ApplicationFilter":
                    application_filters.append(reference)
                else:
                    application_objects.append(reference)
            body["applications"] = {
                # FMC calls this member `applications`; `objects` is not a valid
                # field in the AccessRule application container.
                "applications": application_objects,
                "applicationFilters": application_filters,
            }
        return body

    @staticmethod
    def _application_reference_payload(value: object) -> dict[str, object]:
        """Build FMC's split application/application-filter rule container entries."""
        reference = _provider_reference_payload(value)
        if reference.get("type") != "ApplicationFilter":
            return reference
        raw_value = value.get("normalized_value") if isinstance(value, dict) else None
        if isinstance(raw_value, str):
            try:
                criterion = json.loads(raw_value)
            except ValueError:
                criterion = None
            if isinstance(criterion, dict) and criterion.get("criterion"):
                key = {
                    "type": "applicationTypes",
                    "risk": "risks",
                    "productivity": "productivities",
                    "category": "categories",
                    "tag": "tags",
                }.get(str(criterion["criterion"]))
                if key:
                    return {
                        "appConditions": [
                            {
                                key: [
                                    {
                                        "id": str(criterion.get("id", "")),
                                        "name": str(criterion.get("name", "")),
                                    }
                                ]
                            }
                        ]
                    }
        return reference

    @staticmethod
    def _object_payload(  # noqa: PLR0911 -- one provider payload per object type
        payload: dict[str, object],
    ) -> tuple[str, dict[str, object]]:
        object_type = FirewallObjectType(str(payload["object_type"]))
        value = str(payload.get("normalized_value", ""))
        name = str(payload.get("provider_name") or payload.get("expected_provider_name") or "")
        member_references = payload.get("member_object_references")
        if not isinstance(member_references, list):
            member_references = [
                {"id": str(item)} for item in payload.get("member_object_native_ids", [])
            ]
        if object_type is FirewallObjectType.NETWORK:
            if value.count("-") == 1:
                start, end = value.split("-", 1)
                # Naming normalization has already verified ordering and address-family equality.
                canonical_range = f"{ipaddress.ip_address(start)}-{ipaddress.ip_address(end)}"
                return "ranges", {"type": "Range", "name": name, "value": canonical_range}
            parsed = ipaddress.ip_network(value, strict=False)
            if parsed.prefixlen == parsed.max_prefixlen:
                return "hosts", {"type": "Host", "name": name, "value": str(parsed.network_address)}
            return "networks", {"type": "Network", "name": name, "value": str(parsed)}
        if object_type is FirewallObjectType.NETWORK_GROUP:
            return "networkgroups", {
                "type": "NetworkGroup",
                "name": name,
                "objects": [_provider_reference_payload(item) for item in member_references],
            }
        if object_type is FirewallObjectType.PORT_SERVICE:
            protocol, port = value.split("/", maxsplit=1)
            return "protocolportobjects", {
                "type": "ProtocolPortObject",
                "name": name,
                "protocol": protocol.upper(),
                "port": port,
            }
        if object_type is FirewallObjectType.PORT_SERVICE_GROUP:
            return "portobjectgroups", {
                "type": "PortObjectGroup",
                "name": name,
                "objects": [_provider_reference_payload(item) for item in member_references],
            }
        if object_type is FirewallObjectType.URL:
            return "urls", {"type": "Url", "name": name, "url": value}
        if object_type is FirewallObjectType.URL_GROUP:
            return "urlgroups", {
                "type": "UrlGroup",
                "name": name,
                "objects": [_provider_reference_payload(item) for item in member_references],
            }
        raise _ProviderMutationConflictError("PROVIDER_CAPABILITY_UNAVAILABLE")

    @staticmethod
    def _provider_resource(value: Mapping[str, Any]) -> dict[str, object]:
        native_id = _native_id(value) if value else "deleted"
        return {
            "native_id": native_id,
            "native_version": _version(value) or "",
            "fingerprint": (
                _fingerprint(value) if value else hashlib.sha256(native_id.encode()).hexdigest()
            ),
            "position": CiscoReadOnlyProvider._position(value) if value else 0,
        }

    @staticmethod
    def _object_payload_matches(candidate: Mapping[str, Any], desired: Mapping[str, Any]) -> bool:
        """Compare a discovered provider object with a retry's intended payload."""
        if str(candidate.get("type", "")) != str(desired.get("type", "")):
            return False
        object_type = str(desired.get("type", ""))
        if object_type in {"NetworkGroup", "PortObjectGroup", "UrlGroup"}:

            def ids(value: object) -> set[str]:
                if not isinstance(value, list):
                    return set()
                return {
                    str(item.get("id") or item.get("uuid"))
                    for item in value
                    if isinstance(item, dict) and (item.get("id") or item.get("uuid"))
                }

            return ids(candidate.get("objects", candidate.get("members", []))) == ids(
                desired.get("objects", desired.get("members", []))
            )
        for key in ("value", "url", "protocol", "port"):
            if key in desired and str(candidate.get(key, "")) != str(desired.get(key, "")):
                return False
        return True

    @staticmethod
    def _operation_result(  # noqa: PLR0913 -- normalized provider-result constructor
        operation_id: str,
        status: OperationStatus,
        *,
        mutated: bool | str = False,
        resource: dict[str, object] | None = None,
        failure: dict[str, object] | None = None,
        warnings: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "operation_id": operation_id,
            "status": status.value,
            "mutated": mutated,
            "failure": failure or {},
        }
        if resource:
            value["provider_resource"] = resource
            value["provider_resource_id"] = resource.get("native_id")
        if warnings:
            value["warnings"] = warnings
        return value

    async def _ensure_identity(self) -> None:
        if self.kind is ProviderKind.FMC:
            if self._access_token is None:
                await self._authenticate_fmc()
            return
        if not self._bearer_token:
            raise ProviderConfigurationError
        if not self.tenant_info:
            payload = await self._get("/v1/token")
            if not isinstance(payload, dict):
                raise ProviderContractError
            typed_payload = cast("dict[str, Any]", payload)
            tenant_id = typed_payload.get("tenantUid") or typed_payload.get("parentId")
            self.tenant_info = {
                "native_id": str(tenant_id or "tenant"),
                "name": str(typed_payload.get("tenantName") or "SCC tenant"),
                "scope_type": "TENANT",
            }

    async def _authenticate_fmc(self) -> None:
        if not self._username or not self._password:
            raise ProviderConfigurationError
        await self._ensure_target_safe()
        response = await self._send(
            "POST",
            "/api/fmc_platform/v1/auth/generatetoken",
            auth=httpx.BasicAuth(self._username, self._password),
            allow_auth_post=True,
        )
        access_token = response.headers.get("x-auth-access-token")
        if not access_token:
            raise ProviderContractError
        self._access_token = access_token
        self._refresh_token = response.headers.get("x-auth-refresh-token")

    async def _get(self, path: str, *, retry_auth: bool = True) -> Any:
        await self._ensure_target_safe()
        headers: dict[str, str]
        if self.kind is ProviderKind.FMC:
            if self._access_token is None:
                await self._authenticate_fmc()
            headers = {"X-auth-access-token": self._access_token or ""}
        else:
            headers = {"Authorization": f"Bearer {self._bearer_token or ''}"}
        try:
            response = await self._send("GET", path, headers=headers)
        except ProviderAuthenticationError:
            if self.kind is ProviderKind.FMC and retry_auth:
                self._access_token = None
                await self._authenticate_fmc()
                return await self._get(path, retry_auth=False)
            raise
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderContractError from exc

    async def _send(  # noqa: PLR0913 -- explicit safe transport controls
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        auth: httpx.Auth | None = None,
        params: dict[str, str | int | bool] | None = None,
        allow_auth_post: bool = False,
    ) -> httpx.Response:
        if method != "GET" and not (allow_auth_post and method == "POST"):
            raise ProductionWriteDisabledError
        attempts = (3 if method == "GET" else 1) + bool(self._exact_pin_fingerprints)
        for attempt in range(attempts):
            try:
                response = await self._client.request(
                    method,
                    f"{self._endpoint}{path}",
                    headers=headers,
                    auth=auth,
                    params=params,
                )
                self._capture_certificate(response)
            except httpx.TransportError as exc:
                if self._is_tls_error(exc):
                    if await self._activate_exact_certificate_pin():
                        continue
                    raise ProviderTlsValidationError from exc
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.1 * (2**attempt))
                    continue
                raise ProviderUnavailableError from exc
            if response.status_code in {429, 502, 503, 504} and attempt + 1 < attempts:
                retry_after = response.headers.get("retry-after")
                delay = (
                    min(float(retry_after), 2.0)
                    if retry_after and retry_after.isdigit()
                    else 0.1 * (2**attempt)
                )
                await asyncio.sleep(delay)
                continue
            self._raise_for_status(response)
            return response
        raise ProviderUnavailableError

    async def _activate_exact_certificate_pin(self) -> bool:
        """Replace hostname identity with an exact uploaded leaf pin after verified preflight."""
        if self._exact_pin_active or not self._exact_pin_fingerprints:
            return False
        parsed = urlsplit(self._endpoint)
        hostname = parsed.hostname
        if hostname is None or self._custom_ca_certificate is None:
            raise ProviderTlsValidationError
        pin_context = ssl.create_default_context()
        try:
            pin_context.load_verify_locations(cadata=self._custom_ca_certificate)
            pin_context.check_hostname = False
            _reader, writer = await asyncio.open_connection(
                hostname,
                parsed.port or 443,
                ssl=pin_context,
                server_hostname=hostname,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = (
                ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
            )
            writer.close()
            await writer.wait_closed()
        except (OSError, ssl.SSLError) as exc:
            raise ProviderTlsValidationError from exc
        if not certificate or not self._certificate_is_exactly_pinned(certificate):
            raise ProviderTlsValidationError
        await self._client.aclose()
        self._ssl_context = pin_context
        self._client = self._build_client(pin_context)
        self._exact_pin_active = True
        return True

    def _certificate_is_exactly_pinned(self, certificate: bytes) -> bool:
        parsed = x509.load_der_x509_certificate(certificate)
        return parsed.fingerprint(hashes.SHA256()) in self._exact_pin_fingerprints

    async def _page(
        self,
        path: str,
        page: PageRequest,
        extra_params: dict[str, str | int | bool] | None = None,
    ) -> tuple[list[Mapping[str, Any]], str | None]:
        try:
            offset = int(page.cursor or "0")
        except ValueError as exc:
            raise ProviderContractError from exc
        if offset < 0 or offset > 100_000:
            raise ProviderContractError
        await self._ensure_identity()
        params: dict[str, str | int | bool] = {
            "offset": offset,
            "limit": page.limit,
            "expanded": True,
        }
        if extra_params:
            params.update(extra_params)
        payload = await self._get_with_params(path, params)
        if not isinstance(payload, dict):
            raise ProviderContractError
        items = payload.get("items", [])
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise ProviderContractError
        typed_items = [cast("Mapping[str, Any]", item) for item in items]
        paging = payload.get("paging", {})
        total = paging.get("count") if isinstance(paging, dict) else None
        if isinstance(total, int):
            has_more = offset + len(typed_items) < total
        else:
            has_more = len(typed_items) == page.limit
        return (
            typed_items,
            str(offset + len(typed_items)) if has_more and typed_items else None,
        )

    async def _get_with_params(
        self,
        path: str,
        params: dict[str, str | int | bool],
        *,
        retry_auth: bool = True,
    ) -> Any:
        await self._ensure_target_safe()
        if self.kind is ProviderKind.FMC and self._access_token is None:
            await self._authenticate_fmc()
        headers = (
            {"X-auth-access-token": self._access_token or ""}
            if self.kind is ProviderKind.FMC
            else {"Authorization": f"Bearer {self._bearer_token or ''}"}
        )
        try:
            response = await self._send("GET", path, headers=headers, params=params)
        except ProviderAuthenticationError:
            if self.kind is ProviderKind.FMC and retry_auth:
                self._access_token = None
                await self._authenticate_fmc()
                return await self._get_with_params(path, params, retry_auth=False)
            raise
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderContractError from exc

    async def _ensure_target_safe(self) -> None:
        if self._target_validated or not self._validate_network_target:
            return
        await validate_resolved_target(self._endpoint)
        self._target_validated = True

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if 200 <= response.status_code < 300:
            return
        if response.status_code in {301, 302, 303, 307, 308}:
            raise ProviderUnavailableError(details={"code": "CROSS_ORIGIN_REDIRECT_REFUSED"})
        if response.status_code == 401:
            raise ProviderAuthenticationError(
                details={
                    "http_status": response.status_code,
                    "provider_status": response.reason_phrase,
                }
            )
        if response.status_code == 403:
            raise ProviderPermissionError
        if response.status_code == 429:
            raise ProviderRateLimitedError
        raise ProviderUnavailableError

    @staticmethod
    def _is_tls_error(exc: httpx.TransportError) -> bool:
        current: BaseException | None = exc
        while current is not None:
            if isinstance(
                current, ssl.SSLCertVerificationError
            ) or "CERTIFICATE_VERIFY_FAILED" in str(current):
                return True
            current = current.__cause__
        return False

    def _capture_certificate(self, response: httpx.Response) -> None:
        stream = response.extensions.get("network_stream")
        ssl_object = stream.get_extra_info("ssl_object") if stream is not None else None
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if not certificate:
            if self._exact_pin_active:
                raise ProviderTlsValidationError
            return
        parsed = x509.load_der_x509_certificate(certificate)
        if self._exact_pin_active and not self._certificate_is_exactly_pinned(certificate):
            raise ProviderTlsValidationError
        self.certificate_info = {
            "subject": parsed.subject.rfc4514_string(),
            "issuer": parsed.issuer.rfc4514_string(),
            "not_valid_before": parsed.not_valid_before_utc.astimezone(UTC).isoformat(),
            "not_valid_after": parsed.not_valid_after_utc.astimezone(UTC).isoformat(),
            "sha256_fingerprint": parsed.fingerprint(hashes.SHA256()).hex(),
            "identity_verification": (
                "EXACT_CERTIFICATE_PIN" if self._exact_pin_active else "HOSTNAME"
            ),
        }

    def _config_path(self, domain_id: str, suffix: str) -> str:
        return f"{self._api_prefix}/api/fmc_config/v1/domain/{domain_id}/{suffix}"

    def _policy_domain(self, policy_id: str) -> str:
        domain_id = self._policy_domains.get(policy_id)
        if domain_id is None:
            raise ProviderContractError(details={"code": "POLICY_DOMAIN_CONTEXT_MISSING"})
        return domain_id

    @staticmethod
    def _first_item(payload: object) -> Mapping[str, Any]:
        if not isinstance(payload, dict):
            raise ProviderContractError
        items = payload.get("items")
        if isinstance(items, list) and items and isinstance(items[0], dict):
            return items[0]
        if payload:
            return payload
        raise ProviderContractError

    @staticmethod
    def _position(item: Mapping[str, Any]) -> int:
        metadata = item.get("metadata")
        if isinstance(metadata, dict):
            typed_metadata = cast("dict[str, Any]", metadata)
            for key in ("position", "ruleIndex", "startIndex"):
                if typed_metadata.get(key) is not None:
                    try:
                        return int(str(typed_metadata[key]))
                    except (TypeError, ValueError):
                        pass
        try:
            return int(item.get("position", 0))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _object_cursor(cursor: str | None) -> tuple[int, int]:
        if cursor is None:
            return 0, 0
        try:
            endpoint, offset = (int(value) for value in cursor.split(":", maxsplit=1))
        except (ValueError, TypeError) as exc:
            raise ProviderContractError from exc
        if not 0 <= endpoint < len(_OBJECT_ENDPOINTS) or offset < 0:
            raise ProviderContractError
        return endpoint, offset

    def _rule(self, item: Mapping[str, Any], policy_id: str) -> DiscoveredRule:  # noqa: PLR0912 -- provider payload compatibility branches
        object_references: list[DiscoveredObjectReference] = []
        for field, element in (
            ("sourceNetworks", RuleObjectElement.SOURCE_NETWORK),
            ("destinationNetworks", RuleObjectElement.DESTINATION_NETWORK),
            ("sourcePorts", RuleObjectElement.SOURCE_PORT),
            ("destinationPorts", RuleObjectElement.DESTINATION_PORT),
            ("applications", RuleObjectElement.APPLICATION),
            ("urls", RuleObjectElement.URL),
        ):
            object_references.extend(
                DiscoveredObjectReference(_native_id(reference), element)
                for reference in _objects(item.get(field))
                if reference.get("id") or reference.get("uuid")
            )
        application_container = item.get("applications")
        if isinstance(application_container, dict):
            filter_references = application_container.get("applicationFilters", [])
            if isinstance(filter_references, list):
                object_references.extend(
                    DiscoveredObjectReference(_native_id(reference), RuleObjectElement.APPLICATION)
                    for reference in filter_references
                    if isinstance(reference, Mapping)
                    and (reference.get("id") or reference.get("uuid"))
                )
        zone_references: list[DiscoveredZoneReference] = []
        for field, element in (
            ("sourceZones", ZoneElement.SOURCE),
            ("destinationZones", ZoneElement.DESTINATION),
        ):
            zone_references.extend(
                DiscoveredZoneReference(_native_id(reference), element)
                for reference in _objects(item.get(field))
                if reference.get("id") or reference.get("uuid")
            )
        category = item.get("category")
        metadata = item.get("metadata")
        if not isinstance(category, dict) and isinstance(metadata, dict):
            category = cast("dict[str, Any]", metadata).get("category")
        typed_category = cast("Mapping[str, Any]", category) if isinstance(category, dict) else None
        category_id = (
            _native_id(typed_category)
            if typed_category is not None
            and (typed_category.get("id") or typed_category.get("uuid"))
            else None
        )
        category_name: str | None = None
        if isinstance(typed_category, Mapping):
            raw_category_name = typed_category.get("name")
            if raw_category_name is not None:
                category_name = str(raw_category_name)
        elif isinstance(category, str):
            category_name = category
        if category_name is None:
            for key in ("categoryName", "category_name"):
                raw_category_name = item.get(key)
                if raw_category_name is not None:
                    category_name = str(raw_category_name)
                    break
        if category_name is None and isinstance(metadata, dict):
            metadata_category = cast("dict[str, Any]", metadata).get("category")
            if isinstance(metadata_category, dict):
                raw_category_name = cast("dict[str, Any]", metadata_category).get("name")
                if raw_category_name is not None:
                    category_name = str(raw_category_name)
            elif isinstance(metadata_category, str):
                category_name = metadata_category
        native_id = _native_id(item)
        return DiscoveredRule(
            native_id=native_id,
            name=_name(item, native_id),
            native_version=_version(item),
            fingerprint=_fingerprint(item),
            native_metadata=_metadata(item),
            policy_native_id=policy_id,
            category_native_id=category_id,
            category_name=category_name,
            action=str(item.get("action", "UNKNOWN")),
            enabled=bool(item.get("enabled", True)),
            log_begin=bool(item.get("logBegin", False)),
            log_end=bool(item.get("logEnd", False)),
            # FMC calls the IPS attachment ``ipsPolicy``.  Keep the older
            # ``intrusionPolicy`` spelling as a compatibility fallback for
            # older FMC/cdFMC responses and the mock adapter.
            intrusion_policy_native_id=_first_reference_native_id(
                item, "ipsPolicy", "intrusionPolicy", "ips_policy", "intrusion_policy"
            ),
            variable_set_native_id=_first_reference_native_id(item, "variableSet", "variable_set"),
            file_policy_native_id=_first_reference_native_id(item, "filePolicy", "file_policy"),
            position=self._position(item),
            object_references=tuple(object_references),
            zone_references=tuple(zone_references),
        )

    @staticmethod
    def _rule_category_matches(
        item: Mapping[str, Any], category_id: str, category_name: str
    ) -> bool:
        """Match both UUID references and FMC's metadata.category name representation."""
        category = item.get("category")
        metadata = item.get("metadata")
        if category is None and isinstance(metadata, dict):
            category = cast("dict[str, Any]", metadata).get("category")
        if isinstance(category, dict):
            typed_category = cast("Mapping[str, Any]", category)
            native_id = typed_category.get("id") or typed_category.get("uuid")
            if native_id is not None and str(native_id) == category_id:
                return True
            name = typed_category.get("name")
            return name is not None and str(name) == category_name
        return isinstance(category, str) and category == category_name

    @classmethod
    def _rule_create_matches(  # noqa: PLR0911 -- exact provider duplicate matching
        cls, item: Mapping[str, Any], payload: dict[str, object]
    ) -> bool:
        """Recognize an exact prior create after a duplicate worker delivery."""
        if str(item.get("action", "")).upper() != str(payload.get("action", "")).upper():
            return False
        if bool(item.get("enabled", True)) != bool(payload.get("enabled", True)):
            return False
        logging_mode = str(payload.get("logging", "NONE")).upper()
        if bool(item.get("logBegin", False)) != (logging_mode == "BEGIN"):
            return False
        if bool(item.get("logEnd", False)) != (logging_mode == "END"):
            return False
        if not cls._rule_category_matches(
            item,
            str(payload.get("category_native_id", "")),
            str(payload.get("category_provider_name", "")),
        ):
            return False

        for source, target in (
            ("source_zone_native_ids", "sourceZones"),
            ("destination_zone_native_ids", "destinationZones"),
            ("source_object_native_ids", "sourceNetworks"),
            ("destination_object_native_ids", "destinationNetworks"),
            ("source_port_object_native_ids", "sourcePorts"),
            ("destination_port_object_native_ids", "destinationPorts"),
            ("application_object_native_ids", "applications"),
            ("url_object_native_ids", "urls"),
        ):
            requested = payload.get(source)
            if not isinstance(requested, list):
                continue
            requested_ids = {
                _provider_reference_id(value) for value in cast("list[object]", requested)
            }
            container = item.get(target)
            values: object = []
            if isinstance(container, dict):
                typed_container = cast("dict[str, object]", container)
                values = typed_container.get("objects", typed_container.get("applications", []))
            existing_ids = (
                {
                    _provider_reference_id(value)
                    for value in cast("list[object]", values)
                    if _provider_reference_has_id(value)
                }
                if isinstance(values, list)
                else set()
            )
            if existing_ids != requested_ids:
                return False
        return True

    @staticmethod
    def _object(
        item: Mapping[str, Any], domain_id: str, object_type: FirewallObjectType
    ) -> DiscoveredObject:
        native_id = _native_id(item)
        referenced_ids: list[str] = []
        for key in ("objects", "members", "applications"):
            values = item.get(key)
            if isinstance(values, list):
                referenced_ids.extend(
                    reference_id
                    for value in values
                    if (reference_id := _reference_native_id(value)) is not None
                )
        value = item.get("value")
        if object_type is FirewallObjectType.PORT_SERVICE:
            protocol = item.get("protocol")
            port = item.get("port")
            value = (
                f"{str(protocol).lower()}/{port}"
                if protocol is not None and port is not None
                else None
            )
        elif object_type is FirewallObjectType.URL:
            value = item.get("url", value)
        return DiscoveredObject(
            native_id=native_id,
            name=_name(item, native_id),
            native_version=_version(item),
            fingerprint=_fingerprint(item),
            native_metadata=_metadata(item),
            domain_native_id=domain_id,
            object_type=object_type,
            normalized_value=str(value) if value is not None else None,
            sharing_mode="provider",
            referenced_object_native_ids=tuple(referenced_ids),
        )

    @staticmethod
    def _system_filter_item(item: Mapping[str, Any], endpoint: str) -> Mapping[str, Any]:
        """Normalize a Cisco system criterion as a read-only selectable filter."""
        native_id = _native_id(item)
        criterion = _SYSTEM_APPLICATION_FILTER_CRITERIA[endpoint]
        return {
            **item,
            "id": f"system-filter:{criterion}:{native_id}",
            "name": f"{criterion.title()}: {_name(item, native_id)}",
            "value": json.dumps(
                {
                    "criterion": criterion,
                    "id": native_id,
                    "name": _name(item, native_id),
                },
                separators=(",", ":"),
            ),
        }

    def compatibility_scopes(self, domains: tuple[DiscoveredDomain, ...]) -> list[dict[str, str]]:
        scopes = [
            {"native_id": item.native_id, "name": item.name, "scope_type": "DOMAIN"}
            for item in domains
        ]
        if self.tenant_info:
            scopes.insert(0, dict(self.tenant_info))
        return scopes


def connection_test_timestamp() -> str:
    """Small deterministic-format helper used in safe evidence summaries."""
    return datetime.now(UTC).isoformat()


def _provider_reference_id(value: object) -> str:
    if isinstance(value, dict):
        return str(cast("dict[str, object]", value).get("id"))
    return str(value)


def _provider_reference_payload(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {"id": str(value)}
    item = cast("dict[str, object]", value)
    return {
        key: str(item[key])
        for key in ("id", "name", "type", "object_type", "normalized_value")
        if key in item
    }


def _provider_reference_has_id(value: object) -> bool:
    return isinstance(value, dict) and cast("dict[str, object]", value).get("id") is not None
