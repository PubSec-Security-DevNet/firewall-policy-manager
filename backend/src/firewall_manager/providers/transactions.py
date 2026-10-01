"""Provider transaction adapters used by the ChangeSet application service."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid5

import httpx

from firewall_manager.application.errors import (
    ProductionWriteDisabledError,
    ProviderContractError,
    ProviderUnavailableError,
)
from firewall_manager.application.ports import ConnectionTestProvider
from firewall_manager.domain.models import ProviderKind, ProviderTransactionState


@dataclass(frozen=True, slots=True)
class ProviderExecutionResult:
    """Independent provider transaction and operation outcomes."""

    state: ProviderTransactionState
    operation_results: list[dict[str, object]]
    failure_info: dict[str, object]
    reconciliation_required: bool
    external_operation_id: str

    @classmethod
    def from_dict(cls, payload: object) -> "ProviderExecutionResult":
        """Validate the small provider-neutral transaction result envelope."""
        if not isinstance(payload, dict):
            raise ProviderContractError
        value = cast("dict[str, object]", payload)
        operation_results = value.get("operation_results")
        failure_info = value.get("failure_info")
        if not isinstance(operation_results, list) or not all(
            isinstance(item, dict) for item in operation_results
        ):
            raise ProviderContractError
        if not isinstance(failure_info, dict):
            raise ProviderContractError
        try:
            return cls(
                state=ProviderTransactionState(str(value["state"])),
                operation_results=cast("list[dict[str, object]]", operation_results),
                failure_info=cast("dict[str, object]", failure_info),
                reconciliation_required=bool(value["reconciliation_required"]),
                external_operation_id=str(value["external_operation_id"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderContractError from exc

    def to_dict(self) -> dict[str, object]:
        """Return an HTTP-safe provider result."""
        return {
            "state": self.state.value,
            "operation_results": self.operation_results,
            "failure_info": self.failure_info,
            "reconciliation_required": self.reconciliation_required,
            "external_operation_id": self.external_operation_id,
        }


def real_transaction_operation_id(change_set_id: UUID, manager_id: UUID) -> str:
    """Return the stable application operation ID persisted before a real mutation."""
    return str(uuid5(NAMESPACE_URL, f"real:{manager_id}:{change_set_id}"))


class MockTransactionProvider(Protocol):
    """Mutation portion of the deterministic mock provider contract."""

    kind: ProviderKind

    async def execute_transaction(
        self,
        change_set_id: UUID,
        manager_id: UUID,
        operations: list[dict[str, object]],
    ) -> ProviderExecutionResult: ...


class RealTransactionProvider(ConnectionTestProvider, MockTransactionProvider, Protocol):
    """Guarded real provider mutation surface; no native request escape hatch."""

    async def aclose(self) -> None: ...


class TransactionSecretStore(Protocol):
    """Minimal credential retrieval needed at the provider execution boundary."""

    def retrieve(self, organization_id: UUID, secret_id: UUID, purpose: str) -> dict[str, str]: ...


class ProviderTransactionExecutor(Protocol):
    """Application-facing adapter for exactly one provider transaction."""

    async def execute(
        self,
        target: dict[str, object],
        change_set_id: UUID,
        manager_id: UUID,
        operations: list[dict[str, object]],
    ) -> ProviderExecutionResult: ...


class ProviderDeploymentAdapter(Protocol):
    """Provider-native deployment surface; configuration writes never imply deployment."""

    async def inspect_pending_changes(
        self, domain_id: str, policy_id: str
    ) -> dict[str, object]: ...

    async def start_deployment(
        self, domain_id: str, policy_ids: list[str], device_ids: list[str]
    ) -> dict[str, object]: ...

    async def deployment_status(self, external_operation_id: str) -> dict[str, object]: ...

    async def rollback_deployment(
        self, domain_id: str, deployment_operation_id: str, device_ids: list[str]
    ) -> dict[str, object]: ...

    async def rollback_status(self, external_operation_id: str) -> dict[str, object]: ...


class DeterministicMockTransactionExecutor:
    """In-process contract adapter used by provider and ChangeSet behavior tests."""

    def __init__(self, provider: MockTransactionProvider) -> None:
        self._provider = provider

    async def execute(
        self,
        target: dict[str, object],
        change_set_id: UUID,
        manager_id: UUID,
        operations: list[dict[str, object]],
    ) -> ProviderExecutionResult:
        if target.get("is_mock") is not True or target.get("provider") != self._provider.kind.value:
            raise ProviderContractError(details={"code": "MOCK_PROVIDER_TARGET_MISMATCH"})
        return await self._provider.execute_transaction(change_set_id, manager_id, operations)


class HttpMockTransactionExecutor:
    """HTTP adapter that reaches the same mock provider process used for discovery."""

    async def execute(
        self,
        target: dict[str, object],
        change_set_id: UUID,
        manager_id: UUID,
        operations: list[dict[str, object]],
    ) -> ProviderExecutionResult:
        if target.get("is_mock") is not True:
            raise ProviderContractError(details={"code": "MOCK_PROVIDER_REQUIRED"})
        base_url = target.get("base_url")
        if not isinstance(base_url, str) or not base_url:
            raise ProviderContractError(details={"code": "MOCK_PROVIDER_URL_MISSING"})
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    f"{base_url.rstrip('/')}/api/v1/transactions",
                    json={
                        "change_set_id": str(change_set_id),
                        "manager_id": str(manager_id),
                        "operations": operations,
                    },
                )
                response.raise_for_status()
                return ProviderExecutionResult.from_dict(response.json())
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 422:
                raise ProviderContractError from exc
            raise ProviderUnavailableError from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ProviderUnavailableError from exc


class GuardedProviderTransactionExecutor:
    """Dispatch mock or explicitly enabled real writes through one normalized boundary."""

    def __init__(
        self,
        secret_store: TransactionSecretStore,
        provider_factory: Callable[
            [dict[str, object], dict[str, str], dict[str, str]], RealTransactionProvider
        ],
    ) -> None:
        self._mock = HttpMockTransactionExecutor()
        self._secrets = secret_store
        self._provider_factory = provider_factory

    async def execute(
        self,
        target: dict[str, object],
        change_set_id: UUID,
        manager_id: UUID,
        operations: list[dict[str, object]],
    ) -> ProviderExecutionResult:
        if target.get("is_mock") is True:
            return await self._mock.execute(target, change_set_id, manager_id, operations)
        if (
            target.get("write_enabled") is not True
            or target.get("read_only") is not False
            or target.get("lifecycle") != "ACTIVE"
            or target.get("connection_status") != "CONNECTED"
            or not target.get("provider_version")
        ):
            raise ProductionWriteDisabledError
        organization_id = UUID(str(target["organization_id"]))
        connection_id = UUID(str(target["provider_connection_id"]))
        credential = self._secrets.retrieve(
            organization_id,
            UUID(str(target["credential_reference"])),
            f"provider-connection:{connection_id}",
        )
        raw_capabilities = target.get("capabilities", {})
        if not isinstance(raw_capabilities, dict):
            raise ProviderContractError
        capabilities = {
            str(key): str(value)
            for key, value in cast("dict[object, object]", raw_capabilities).items()
        }
        provider = self._provider_factory(target, credential, capabilities)
        try:
            return await provider.execute_transaction(change_set_id, manager_id, operations)
        finally:
            await provider.aclose()
