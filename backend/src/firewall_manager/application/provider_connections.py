"""Authorized provider-connection lifecycle and read-only compatibility validation."""

import asyncio
from collections.abc import Awaitable, Callable
from typing import cast
from uuid import UUID, uuid4

from firewall_manager.application.authorization import AuthorizationService
from firewall_manager.application.errors import (
    InvalidInputError,
    ProviderConfigurationError,
    ProviderError,
    ResourceOutOfScopeError,
)
from firewall_manager.application.ports import (
    AuthorizationRepository,
    ConnectionTestProvider,
    ProviderConnectionRepository,
    ProviderFactory,
    SecretStore,
)
from firewall_manager.domain.models import (
    CapabilityStatus,
    DiscoveredPolicy,
    PageRequest,
    Principal,
    ProviderCapability,
    ProviderConnectionLifecycle,
    ProviderConnectionStatus,
    ProviderEvidenceProfile,
    ProviderKind,
    ProviderPage,
    TlsTrustMode,
)
from firewall_manager.providers.capabilities import (
    default_capability_path,
    load_capabilities,
)
from firewall_manager.providers.real import (
    SCC_ENDPOINTS,
    normalize_fmc_endpoint,
)

_READ_CAPABILITIES = {
    ProviderCapability.AUTHENTICATION_SESSION,
    ProviderCapability.MANAGER_TENANT_DISCOVERY,
    ProviderCapability.DEVICE_DISCOVERY,
    ProviderCapability.ACCESS_POLICY_DISCOVERY,
    ProviderCapability.RULE_CATEGORY_READ,
    ProviderCapability.ACCESS_RULE_READ,
    ProviderCapability.NETWORK_OBJECT_READ,
    ProviderCapability.SECURITY_ZONE_READ,
}

PROVIDER_SETUP_GUIDANCE: dict[str, dict[str, object]] = {
    "fmc": {
        "title": "Dedicated FMC API service account",
        "capability_target": "READ-ONLY DISCOVERY",
        "steps": [
            "Create a dedicated API/service account; do not reuse a human administrator account.",
            "Enable FMC REST API access and grant only the permissions required by the read "
            "endpoints below.",
            "Use System > Domains for domain discovery. Verify each additional read operation "
            "on the target FMC version.",
            "Do not grant configuration, deployment, or broad administrator privileges unless "
            "a separately approved future capability requires them.",
        ],
        "permission_note": (
            "Cisco documents System > Domains for domain discovery. The exact RBAC labels for all "
            "configuration-read endpoints vary by FMC version and must be verified in that "
            "version's API Explorer; "
            "this application validates access by performing only the required safe reads."
        ),
        "operations": [
            {
                "operation": "server/domain discovery",
                "method": "GET",
                "permission": (
                    "System > Domains (domain endpoint); server-version permission is not named "
                    "in the 7.6 guide"
                ),
            },
            {
                "operation": "device discovery",
                "method": "GET",
                "permission": "Verify in the target-version FMC API Explorer",
            },
            {
                "operation": "policy/rule/category discovery",
                "method": "GET",
                "permission": "Verify in the target-version FMC API Explorer",
            },
            {
                "operation": "object/zone discovery",
                "method": "GET",
                "permission": "Verify in the target-version FMC API Explorer",
            },
        ],
        "official_references": [
            {
                "label": (
                    "FMC REST API Quick Start Guide 7.6 — authentication and endpoint permissions"
                ),
                "url": "https://www.cisco.com/c/en/us/td/docs/security/firepower/760/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_760.html",
            },
            {
                "label": "FMC REST API Quick Start Guide 7.7 — endpoint catalog and rate limits",
                "url": "https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770.html",
            },
        ],
    },
    "scc": {
        "title": "Dedicated SCC API-only identity",
        "capability_target": "READ-ONLY DISCOVERY",
        "steps": [
            "Create an API-only user in Security Cloud Control User Management.",
            "Select ROLE_READ_ONLY for this milestone when the required cdFMC read endpoints "
            "permit it.",
            "Generate and copy the API token when Cisco displays it, then store it only in this "
            "write-only credential flow.",
            "Do not use Admin or Super Admin for read-only discovery. Rotate or upgrade the "
            "credential later if an approved capability requires it.",
        ],
        "permission_note": (
            "Cisco defines ROLE_READ_ONLY as unable to make configuration changes. Endpoint "
            "access is validated using the actual required reads rather than inferred only from "
            "the token role."
        ),
        "operations": [
            {
                "operation": "token and tenant discovery",
                "method": "GET",
                "permission": "API token for an API-only user",
            },
            {
                "operation": "cdFMC policy/rule/object/zone discovery",
                "method": "GET",
                "permission": "ROLE_READ_ONLY where accepted by the endpoint",
            },
        ],
        "official_references": [
            {
                "label": "SCC Firewall Manager API — authentication and roles (API 1.20.0)",
                "url": "https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/authentication/",
            },
            {
                "label": "SCC Firewall Manager API — getting started and production regions",
                "url": "https://developer.cisco.com/docs/cisco-security-cloud-control-firewall-manager/getting-started/",
            },
        ],
    },
}


class _ProbeFailureError(Exception):
    """Bind a concurrent provider failure to the capability being exercised."""

    def __init__(
        self,
        capability: ProviderCapability,
        error: ProviderError | ProviderConfigurationError,
    ) -> None:
        super().__init__(error.safe_message)
        self.capability = capability
        self.error = error


class ProviderConnectionService:
    """Manage independent real-provider connections without exposing credential plaintext."""

    def __init__(
        self,
        authorization_repository: AuthorizationRepository,
        repository: ProviderConnectionRepository,
        secret_store: SecretStore,
        provider_factory: ProviderFactory | None = None,
    ) -> None:
        self._authorization = AuthorizationService(authorization_repository)
        self._repository = repository
        self._secret_store = secret_store
        self._provider_factory = provider_factory

    def list(
        self, principal: Principal, offset: int = 0, limit: int = 100
    ) -> tuple[list[dict[str, object]], int]:
        self._require_admin(principal)
        return self._repository.list_connections(principal.organization_id, offset, limit)

    def get(self, principal: Principal, connection_id: UUID) -> dict[str, object]:
        self._require_admin(principal)
        context = self._repository.connection_context(principal.organization_id, connection_id)
        if context is None:
            raise ResourceOutOfScopeError
        return self._public(context)

    def create(self, principal: Principal, values: dict[str, object]) -> dict[str, object]:
        self._require_admin(principal)
        connection_id = uuid4()
        provider = ProviderKind(str(values["provider_type"]))
        normalized, credential = self._validated_create_values(provider, values)
        purpose = self._secret_purpose(connection_id)
        credential_reference = self._secret_store.create(
            principal.organization_id, purpose, credential
        )
        capabilities = self._baseline_capabilities(provider)
        result = self._repository.create_connection(
            principal.organization_id,
            principal.user_id,
            connection_id,
            credential_reference,
            normalized,
            capabilities,
        )
        return self._public(result)

    def update(
        self,
        principal: Principal,
        connection_id: UUID,
        expected_revision: int,
        values: dict[str, object],
    ) -> dict[str, object]:
        self._require_admin(principal)
        context = self._context(principal, connection_id)
        provider = ProviderKind(str(context["provider_type"]))
        update = self._validated_update_values(provider, values)
        if update.get("tls_mode") == TlsTrustMode.CUSTOM_CA.value:
            credential = self._credential(principal, connection_id, context)
            if not credential.get("ca_certificate"):
                raise ProviderConfigurationError
        result = self._repository.update_connection(
            principal.organization_id,
            principal.user_id,
            connection_id,
            expected_revision,
            update,
        )
        return self._public(result)

    def rotate_credentials(
        self,
        principal: Principal,
        connection_id: UUID,
        expected_revision: int,
        values: dict[str, str],
    ) -> dict[str, object]:
        self._require_admin(principal)
        context = self._context(principal, connection_id)
        credential = self._credential(principal, connection_id, context)
        provider = ProviderKind(str(context["provider_type"]))
        if provider is ProviderKind.FMC:
            username = values.get("username") or credential.get("username")
            password = values.get("password")
            if not username or not password:
                raise InvalidInputError
            credential.update({"username": username, "password": password})
            if "ca_certificate" in values:
                credential["ca_certificate"] = values["ca_certificate"]
        else:
            username = None
            token = values.get("token")
            if not token:
                raise InvalidInputError
            credential = {"token": token}
        result = self._repository.record_credential_rotation(
            principal.organization_id,
            principal.user_id,
            connection_id,
            expected_revision,
            username,
        )
        self._secret_store.replace(
            principal.organization_id,
            UUID(str(context["credential_reference"])),
            self._secret_purpose(connection_id),
            credential,
        )
        return self._public(result)

    async def test(
        self, principal: Principal, connection_id: UUID, correlation_id: str | None
    ) -> dict[str, object]:
        self._require_admin(principal, correlation_id)
        context = self._context(principal, connection_id)
        capabilities = self._baseline_capabilities(ProviderKind(str(context["provider_type"])))
        current_probe = ProviderCapability.AUTHENTICATION_SESSION.value
        provider: ConnectionTestProvider | None = None
        try:
            provider = self._provider(principal, connection_id, context, capabilities)
            info = await provider.information()
            capabilities[current_probe] = CapabilityStatus.READ_ONLY.value
            current_probe = ProviderCapability.MANAGER_TENANT_DISCOVERY.value
            domain_page = await provider.domains(PageRequest(limit=100))
            capabilities[current_probe] = CapabilityStatus.READ_ONLY.value
            if domain_page.items:
                # Test representative endpoints rather than exhaustively enumerating every scope.
                # Full pagination belongs to queued synchronization; the interactive test remains
                # bounded and uses modest concurrency to tolerate high-latency SCC regions.
                domain = domain_page.items[0]
                domain_results = await self._run_probe_phase(
                    capabilities,
                    {
                        ProviderCapability.DEVICE_DISCOVERY: provider.devices(
                            domain.native_id, PageRequest(limit=1)
                        ),
                        ProviderCapability.ACCESS_POLICY_DISCOVERY: provider.policies(
                            domain.native_id, PageRequest(limit=1)
                        ),
                        ProviderCapability.SECURITY_ZONE_READ: provider.zones(
                            domain.native_id, PageRequest(limit=1)
                        ),
                        ProviderCapability.NETWORK_OBJECT_READ: provider.objects(
                            domain.native_id, PageRequest(limit=1)
                        ),
                    },
                )
                policies = cast(
                    "ProviderPage[DiscoveredPolicy]",
                    domain_results[ProviderCapability.ACCESS_POLICY_DISCOVERY],
                )
                policy_items = policies.items
                if policy_items:
                    policy = policy_items[0]
                    await self._run_probe_phase(
                        capabilities,
                        {
                            ProviderCapability.RULE_CATEGORY_READ: provider.categories(
                                policy.native_id, PageRequest(limit=1)
                            ),
                            ProviderCapability.ACCESS_RULE_READ: provider.rules(
                                policy.native_id, PageRequest(limit=1)
                            ),
                        },
                    )
            scopes = provider.compatibility_scopes(domain_page.items)
            result: dict[str, object] = {
                "status": ProviderConnectionStatus.CONNECTED.value,
                "provider_version": info.provider_version,
                "certificate_info": provider.certificate_info,
                "tested_capabilities": sorted(
                    name for name, status in capabilities.items() if status == "READ_ONLY"
                ),
                "unverified_capabilities": sorted(
                    capability.value
                    for capability in _READ_CAPABILITIES
                    if capabilities.get(capability.value) != "READ_ONLY"
                ),
                "correlation_id": correlation_id,
            }
        except _ProbeFailureError as failure:
            current_probe = failure.capability.value
            exc = failure.error
            status = (
                exc.code
                if exc.code in {item.value for item in ProviderConnectionStatus}
                else ProviderConnectionStatus.PROVIDER_UNAVAILABLE.value
            )
            result = {
                "status": status,
                "error_code": exc.code,
                "safe_message": exc.safe_message,
                "missing_capability": current_probe
                if exc.code == "INSUFFICIENT_PRIVILEGES"
                else None,
                "correlation_id": correlation_id,
            }
            scopes = []
        except (ProviderError, ProviderConfigurationError) as exc:
            status = (
                exc.code
                if exc.code in {item.value for item in ProviderConnectionStatus}
                else ProviderConnectionStatus.PROVIDER_UNAVAILABLE.value
            )
            result = {
                "status": status,
                "error_code": exc.code,
                "safe_message": exc.safe_message,
                "missing_capability": current_probe
                if exc.code == "INSUFFICIENT_PRIVILEGES"
                else None,
                "correlation_id": correlation_id,
            }
            scopes = []
        finally:
            if provider is not None:
                await provider.aclose()
        saved = self._repository.record_connection_test(
            principal.organization_id,
            principal.user_id,
            connection_id,
            result,
            capabilities,
            scopes,
        )
        return {**result, "connection": self._public(saved)}

    @staticmethod
    async def _run_probe_phase(
        capabilities: dict[str, str],
        probes: dict[ProviderCapability, Awaitable[object]],
    ) -> dict[ProviderCapability, object]:
        async def run(
            capability: ProviderCapability, operation: Awaitable[object]
        ) -> tuple[ProviderCapability, object]:
            try:
                return capability, await operation
            except (ProviderError, ProviderConfigurationError) as exc:
                raise _ProbeFailureError(capability, exc) from exc

        results = await asyncio.gather(
            *(run(capability, operation) for capability, operation in probes.items()),
            return_exceptions=True,
        )
        values: dict[ProviderCapability, object] = {}
        for result in results:
            if isinstance(result, BaseException):
                raise result
            capability, value = result
            capabilities[capability.value] = CapabilityStatus.READ_ONLY.value
            values[capability] = value
        return values

    def set_lifecycle(
        self,
        principal: Principal,
        connection_id: UUID,
        expected_revision: int,
        lifecycle: str,
    ) -> dict[str, object]:
        self._require_admin(principal)
        parsed = ProviderConnectionLifecycle(lifecycle)
        result = self._repository.set_lifecycle(
            principal.organization_id,
            principal.user_id,
            connection_id,
            expected_revision,
            parsed.value,
        )
        return self._public(result)

    def set_write_enabled(  # noqa: PLR0913, PLR0917 -- explicit gate acknowledgements
        self,
        principal: Principal,
        connection_id: UUID,
        expected_revision: int,
        enabled: bool,
        acknowledged: bool,
        allow_unvalidated_non_production: bool = False,
    ) -> dict[str, object]:
        """Apply the explicit administrator acknowledgement and independent write gate."""
        self._require_admin(principal)
        if enabled and not acknowledged:
            raise InvalidInputError(
                details={"code": "CONFIGURATION_MUTATION_ACKNOWLEDGEMENT_REQUIRED"}
            )
        result = self._repository.set_write_enabled(
            principal.organization_id,
            principal.user_id,
            connection_id,
            expected_revision,
            enabled,
            allow_unvalidated_non_production,
        )
        return self._public(result)

    def request_sync(
        self,
        principal: Principal,
        connection_id: UUID,
        dispatch: Callable[[UUID], object],
    ) -> None:
        self._require_admin(principal)
        self._repository.request_sync(principal.organization_id, principal.user_id, connection_id)
        dispatch(connection_id)

    @staticmethod
    def guidance(provider: ProviderKind) -> dict[str, object]:
        return PROVIDER_SETUP_GUIDANCE[provider.value]

    def _provider(
        self,
        principal: Principal,
        connection_id: UUID,
        context: dict[str, object],
        capabilities: dict[str, str],
    ) -> ConnectionTestProvider:
        if self._provider_factory is None:
            raise ProviderConfigurationError
        credential = self._credential(principal, connection_id, context)
        return self._provider_factory(context, credential, capabilities)

    def _credential(
        self, principal: Principal, connection_id: UUID, context: dict[str, object]
    ) -> dict[str, str]:
        return self._secret_store.retrieve(
            principal.organization_id,
            UUID(str(context["credential_reference"])),
            self._secret_purpose(connection_id),
        )

    def _context(self, principal: Principal, connection_id: UUID) -> dict[str, object]:
        context = self._repository.connection_context(principal.organization_id, connection_id)
        if context is None:
            raise ResourceOutOfScopeError
        return context

    def _require_admin(self, principal: Principal, correlation_id: str | None = None) -> None:
        decision = self._authorization.authorize_provider_administration(
            principal, interface="rest", correlation_id=correlation_id
        )
        if not decision.allowed:
            raise ResourceOutOfScopeError

    @staticmethod
    def _public(value: dict[str, object]) -> dict[str, object]:
        return {key: item for key, item in value.items() if key != "credential_reference"}

    @staticmethod
    def _secret_purpose(connection_id: UUID) -> str:
        return f"provider-connection:{connection_id}"

    @staticmethod
    def _baseline_capabilities(provider: ProviderKind) -> dict[str, str]:
        values = load_capabilities(default_capability_path()).for_provider(
            provider, profile=ProviderEvidenceProfile.REAL
        )
        return {name: status.value for name, status in values.items()}

    @staticmethod
    def _validated_create_values(
        provider: ProviderKind, values: dict[str, object]
    ) -> tuple[dict[str, object], dict[str, str]]:
        display_name = str(values.get("display_name", "")).strip()
        if not display_name or len(display_name) > 200:
            raise InvalidInputError
        interval = int(str(values.get("sync_interval_minutes", 60)))
        if not 5 <= interval <= 10080:
            raise InvalidInputError
        if provider is ProviderKind.FMC:
            endpoint = normalize_fmc_endpoint(str(values.get("base_endpoint", "")))
            username = str(values.get("username", "")).strip()
            password = str(values.get("password", ""))
            tls_mode = TlsTrustMode(str(values.get("tls_mode", TlsTrustMode.SYSTEM.value)))
            ca_certificate = str(values.get("ca_certificate", ""))
            if (
                not username
                or not password
                or (tls_mode is TlsTrustMode.CUSTOM_CA and not ca_certificate)
            ):
                raise InvalidInputError
            credential = {"username": username, "password": password}
            if ca_certificate:
                credential["ca_certificate"] = ca_certificate
            return (
                {
                    "provider_type": provider.value,
                    "display_name": display_name,
                    "connection_mode": "DIRECT",
                    "base_endpoint": endpoint,
                    "region": None,
                    "tls_mode": tls_mode.value,
                    "credential_type": "USERNAME_PASSWORD",
                    "credential_username": username,
                    "sync_interval_minutes": interval,
                },
                credential,
            )
        region = str(values.get("region", ""))
        token = str(values.get("token", ""))
        if region not in SCC_ENDPOINTS or not token:
            raise InvalidInputError
        return (
            {
                "provider_type": provider.value,
                "display_name": display_name,
                "connection_mode": "REGIONAL_API",
                "base_endpoint": SCC_ENDPOINTS[region],
                "region": region,
                "tls_mode": TlsTrustMode.SYSTEM.value,
                "credential_type": "BEARER_TOKEN",
                "credential_username": None,
                "sync_interval_minutes": interval,
            },
            {"token": token},
        )

    @staticmethod
    def _validated_update_values(
        provider: ProviderKind, values: dict[str, object]
    ) -> dict[str, object]:
        allowed = {"display_name", "sync_interval_minutes"}
        if provider is ProviderKind.FMC:
            allowed.update({"base_endpoint", "tls_mode"})
        else:
            allowed.add("region")
        if set(values) - allowed:
            raise InvalidInputError
        result = dict(values)
        if "display_name" in result:
            result["display_name"] = str(result["display_name"]).strip()
            if not result["display_name"]:
                raise InvalidInputError
        if "sync_interval_minutes" in result:
            interval = int(str(result["sync_interval_minutes"]))
            if not 5 <= interval <= 10080:
                raise InvalidInputError
            result["sync_interval_minutes"] = interval
        if "base_endpoint" in result:
            result["base_endpoint"] = normalize_fmc_endpoint(str(result["base_endpoint"]))
        if "tls_mode" in result:
            result["tls_mode"] = TlsTrustMode(str(result["tls_mode"])).value
        if "region" in result:
            region = str(result["region"])
            if region not in SCC_ENDPOINTS:
                raise InvalidInputError
            result["region"] = region
            result["base_endpoint"] = SCC_ENDPOINTS[region]
        return result
