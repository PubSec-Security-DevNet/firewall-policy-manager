"""Shared, configuration-read-only Cisco FMC/cdFMC REST implementation."""

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

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from firewall_manager.application.errors import (
    ProductionWriteDisabledError,
    ProviderAuthenticationError,
    ProviderConfigurationError,
    ProviderContractError,
    ProviderPermissionError,
    ProviderRateLimitedError,
    ProviderTlsValidationError,
    ProviderUnavailableError,
)
from firewall_manager.domain.models import (
    CapabilityStatus,
    DiscoveredCategory,
    DiscoveredDevice,
    DiscoveredDomain,
    DiscoveredObject,
    DiscoveredObjectReference,
    DiscoveredPolicy,
    DiscoveredRule,
    DiscoveredZone,
    DiscoveredZoneReference,
    FirewallObjectType,
    PageRequest,
    ProviderEvidenceProfile,
    ProviderInfo,
    ProviderInventory,
    ProviderKind,
    ProviderPage,
    RuleObjectElement,
    ZoneElement,
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
    ("urls", FirewallObjectType.URL),
)


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
    values = cast("dict[str, Any]", container).get("objects", [])
    if not isinstance(values, list):
        return []
    return [cast("Mapping[str, Any]", item) for item in values if isinstance(item, dict)]


class CiscoReadOnlyProvider:
    """Normalized FMC-compatible reader with an operation-layer write safety envelope."""

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
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=5.0, pool=5.0),
            follow_redirects=False,
            transport=self._transport,
        )

    async def aclose(self) -> None:
        """Close the operation-scoped verified HTTP transport."""
        await self._client.aclose()

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
            writable=False,
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
            False,
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
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredObject]:
        endpoint_index, offset = self._object_cursor(page.cursor)
        endpoint, object_type = _OBJECT_ENDPOINTS[endpoint_index]
        items, native_next = await self._page(
            self._config_path(domain_native_id, f"object/{endpoint}"),
            PageRequest(limit=page.limit, cursor=str(offset)),
        )
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
        self, path: str, page: PageRequest
    ) -> tuple[list[Mapping[str, Any]], str | None]:
        try:
            offset = int(page.cursor or "0")
        except ValueError as exc:
            raise ProviderContractError from exc
        if offset < 0 or offset > 100_000:
            raise ProviderContractError
        await self._ensure_identity()
        payload = await self._get_with_params(
            path, {"offset": offset, "limit": page.limit, "expanded": True}
        )
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
            raise ProviderAuthenticationError
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

    def _rule(self, item: Mapping[str, Any], policy_id: str) -> DiscoveredRule:
        object_references: list[DiscoveredObjectReference] = []
        for field, element in (
            ("sourceNetworks", RuleObjectElement.SOURCE_NETWORK),
            ("destinationNetworks", RuleObjectElement.DESTINATION_NETWORK),
            ("sourcePorts", RuleObjectElement.PORT_SERVICE),
            ("destinationPorts", RuleObjectElement.PORT_SERVICE),
            ("applications", RuleObjectElement.APPLICATION),
            ("urls", RuleObjectElement.URL),
        ):
            object_references.extend(
                DiscoveredObjectReference(_native_id(reference), element)
                for reference in _objects(item.get(field))
                if reference.get("id") or reference.get("uuid")
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
        native_id = _native_id(item)
        return DiscoveredRule(
            native_id=native_id,
            name=_name(item, native_id),
            native_version=_version(item),
            fingerprint=_fingerprint(item),
            native_metadata=_metadata(item),
            policy_native_id=policy_id,
            category_native_id=category_id,
            action=str(item.get("action", "UNKNOWN")),
            position=self._position(item),
            object_references=tuple(object_references),
            zone_references=tuple(zone_references),
        )

    @staticmethod
    def _object(
        item: Mapping[str, Any], domain_id: str, object_type: FirewallObjectType
    ) -> DiscoveredObject:
        native_id = _native_id(item)
        referenced_ids: list[str] = []
        for key in ("objects", "members"):
            values = item.get(key)
            if isinstance(values, list):
                referenced_ids.extend(
                    _native_id(cast("Mapping[str, Any]", value))
                    for value in values
                    if isinstance(value, dict) and (value.get("id") or value.get("uuid"))
                )
        value = item.get("value")
        if object_type is FirewallObjectType.PORT_SERVICE:
            protocol = item.get("protocol")
            port = item.get("port")
            value = f"{protocol}:{port}" if protocol is not None and port is not None else None
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
