"""Ports required by application services."""

# ruff: noqa: PLR0913, PLR0917 -- persistence ports retain explicit security context.

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from firewall_manager.domain.models import (
    AuthorizationDecision,
    DiscoveredCategory,
    DiscoveredDevice,
    DiscoveredDomain,
    DiscoveredObject,
    DiscoveredObjectReference,
    DiscoveredPolicy,
    DiscoveredRule,
    DiscoveredZone,
    DiscoveredZoneReference,
    PageRequest,
    Principal,
    ProviderInfo,
    ProviderInventory,
    ProviderKind,
    ProviderPage,
    SyncResult,
    SyncStatus,
)


class AuthorizationRepository(Protocol):
    """Current-state persistence reads used by the authorization boundary."""

    def user_state(self, user_id: UUID, organization_id: UUID) -> tuple[bool, int] | None: ...

    def membership_state(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> tuple[bool, int] | None: ...

    def policy_state(
        self, policy_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, int] | None: ...

    def policy_capabilities(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[set[str], int, bool]: ...

    def object_grant_state(
        self, group_id: UUID, policy_id: UUID, object_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, set[str], int] | None: ...

    def object_mutation_state(
        self, group_id: UUID, policy_id: UUID, object_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None: ...

    def zone_grant_state(
        self, group_id: UUID, policy_id: UUID, zone_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, set[str], int] | None: ...

    def ip_range_grants(
        self, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[list[str], int]: ...

    def object_create_grant_state(
        self, group_id: UUID, policy_id: UUID, object_type: str, organization_id: UUID
    ) -> tuple[UUID, dict[str, str], int] | None: ...

    def equivalent_object_id(
        self, manager_id: UUID, object_type: str, normalized_value: str, organization_id: UUID
    ) -> UUID | None: ...

    def rule_owner_state(
        self, rule_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[UUID | None, str, int] | None: ...

    def category_mapping_state(
        self, group_id: UUID, policy_id: UUID, category_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, int] | None: ...

    def record_authorization_decision(
        self, decision: AuthorizationDecision, *, interface: str, correlation_id: str | None
    ) -> None: ...

    def active_groups_for_user(
        self, user_id: UUID, organization_id: UUID
    ) -> list[dict[str, object]]: ...

    def default_context_for_user(
        self, user_id: UUID, organization_id: UUID
    ) -> tuple[UUID | None, UUID | None]: ...

    def set_default_context_for_user(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> bool: ...

    def delegated_context_view(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None: ...

    def delegated_policies(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> list[dict[str, object]]: ...


class AdministrationRepository(Protocol):
    """Persistence writes for the bounded Milestone 2 administration surface."""

    def authorization_snapshot(self, organization_id: UUID) -> dict[str, object]: ...

    def create_user(
        self, organization_id: UUID, actor_user_id: UUID, values: dict[str, object]
    ) -> dict[str, object]: ...

    def create_group(
        self, organization_id: UUID, actor_user_id: UUID, values: dict[str, object]
    ) -> dict[str, object]: ...

    def update_enabled(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        resource: str,
        resource_id: UUID,
        enabled: bool,
        expected_revision: int,
    ) -> dict[str, object]: ...

    def update_user_role(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        user_id: UUID,
        role: str,
        expected_revision: int,
    ) -> dict[str, object]: ...

    def upsert_authorization_resource(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        resource: str,
        values: dict[str, object],
        expected_revision: int | None,
    ) -> dict[str, object]: ...

    def revoke_authorization_resource(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        resource: str,
        resource_id: UUID,
        expected_revision: int,
    ) -> None: ...


class SecretStore(Protocol):
    """Write-only-at-interface credential storage with organization-bound retrieval."""

    def create(self, organization_id: UUID, purpose: str, value: dict[str, str]) -> UUID: ...

    def retrieve(self, organization_id: UUID, secret_id: UUID, purpose: str) -> dict[str, str]: ...

    def replace(
        self, organization_id: UUID, secret_id: UUID, purpose: str, value: dict[str, str]
    ) -> None: ...


class ProviderConnectionRepository(Protocol):
    """Organization-scoped persistence for provider connection administration."""

    def list_connections(
        self, organization_id: UUID, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]: ...

    def connection_context(
        self, organization_id: UUID, connection_id: UUID
    ) -> dict[str, object] | None: ...

    def create_connection(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        credential_reference: UUID,
        values: dict[str, object],
        capabilities: dict[str, str],
    ) -> dict[str, object]: ...

    def update_connection(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        expected_revision: int,
        values: dict[str, object],
    ) -> dict[str, object]: ...

    def record_credential_rotation(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        expected_revision: int,
        username: str | None,
    ) -> dict[str, object]: ...

    def record_connection_test(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        result: dict[str, object],
        capabilities: dict[str, str],
        scopes: list[dict[str, str]],
    ) -> dict[str, object]: ...

    def set_lifecycle(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        expected_revision: int,
        lifecycle: str,
    ) -> dict[str, object]: ...

    def set_write_enabled(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        expected_revision: int,
        enabled: bool,
        allow_unvalidated_non_production: bool,
    ) -> dict[str, object]: ...

    def request_sync(
        self, organization_id: UUID, actor_user_id: UUID, connection_id: UUID
    ) -> None: ...


class ChangeSetRepository(Protocol):
    """Durable ChangeSet, revision, transaction, and audit persistence boundary."""

    def create_change_set(
        self,
        principal: Principal,
        group_id: UUID,
        policy_id: UUID,
        title: str,
        description: str,
        audit_metadata: dict[str, object],
    ) -> dict[str, object]: ...

    def list_change_sets(self, principal: Principal, group_id: UUID) -> list[dict[str, object]]: ...

    def get_change_set(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> dict[str, object] | None: ...

    def update_change_set_metadata(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        title: str,
        description: str,
        expected_revision: int,
    ) -> dict[str, object]: ...

    def add_operation(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        kind: str,
        payload: dict[str, object],
    ) -> dict[str, object]: ...

    def update_operation(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        operation_id: UUID,
        payload: dict[str, object],
        expected_revision: int,
    ) -> dict[str, object]: ...

    def remove_operation(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        operation_id: UUID,
    ) -> None: ...

    def save_preflight(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        operation_results: list[dict[str, object]],
        state: str,
        provider_snapshot: dict[str, object],
    ) -> dict[str, object]: ...

    def current_revision_snapshot(
        self, operation: dict[str, object], organization_id: UUID
    ) -> dict[str, str]: ...

    def naming_context(
        self, policy_id: UUID, group_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None: ...

    def object_mutation_context(
        self, object_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None: ...

    def object_equivalent_id(
        self,
        manager_id: UUID,
        object_type: str,
        normalized_value: str,
        excluded_object_id: UUID,
        organization_id: UUID,
    ) -> UUID | None: ...

    def category_ensure_context(
        self, policy_id: UUID, group_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None: ...

    def set_execution_state(
        self,
        principal: Principal,
        group_id: UUID,
        change_set_id: UUID,
        state: str,
        execution_results: dict[str, object],
        failure_info: dict[str, object],
    ) -> dict[str, object]: ...

    def upsert_provider_transaction(
        self,
        change_set: dict[str, object],
        manager_id: UUID,
        state: str,
        operation_results: list[dict[str, object]],
        failure_info: dict[str, object],
        reconciliation_required: bool,
        external_operation_id: str | None,
    ) -> dict[str, object]: ...

    def commit_provider_transaction_intent(self) -> None: ...

    def queue_execution(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]: ...

    def commit_change_set_queue(self) -> None: ...

    def claim_queued_execution(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> bool: ...

    def manager_execution_target(
        self, manager_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None: ...

    def provider_capability_state(
        self, manager_id: UUID, capability: str, organization_id: UUID
    ) -> str | None: ...

    def rule_ordering_bounds(
        self,
        group_id: UUID,
        policy_id: UUID,
        category_id: UUID,
        organization_id: UUID,
    ) -> tuple[int, int] | None: ...

    def prepare_provider_operations(
        self, operations: list[dict[str, object]], organization_id: UUID
    ) -> list[dict[str, object]]: ...

    def reconcile_successful_operations(
        self,
        change_set: dict[str, object],
        principal: Principal,
        group_id: UUID,
        operations: list[dict[str, object]],
        operation_results: list[dict[str, object]],
    ) -> None: ...

    def record_successful_write_evidence(
        self,
        change_set: dict[str, object],
        principal: Principal,
        manager_id: UUID,
        operations: list[dict[str, object]],
        operation_results: list[dict[str, object]],
    ) -> set[str]: ...

    def group_provider_slug(self, group_id: UUID, organization_id: UUID) -> str | None: ...

    def cancel_change_set(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]: ...

    def delete_change_set(
        self, principal: Principal, group_id: UUID, change_set_id: UUID
    ) -> None: ...

    def record_change_event(
        self,
        principal: Principal,
        group_id: UUID,
        policy_id: UUID,
        change_set_id: UUID,
        action: str,
        result: str,
        details: dict[str, object],
    ) -> None: ...


class OverviewRepository(Protocol):
    """Read-only persistence contract for the overview use case."""

    def principal_by_email(self, email: str) -> Principal | None: ...

    def organization_name(self, organization_id: UUID) -> str | None: ...

    def counts(self, organization_id: UUID) -> dict[str, int]: ...


class DevelopmentIdentityRepository(Protocol):
    """Read model exposed only by the conditionally mounted development-auth route."""

    def development_identities(self) -> list[dict[str, object]]: ...


class HealthProbe(Protocol):
    """Infrastructure readiness checks exposed without leaking implementation details."""

    async def check(self) -> None: ...


class ProviderReader(Protocol):
    """Compatibility summary port retained for the overview."""

    kind: ProviderKind

    async def discover(self) -> ProviderInventory: ...


class FirewallProvider(ProviderReader, Protocol):
    """Typed, read-only provider contract implemented equally by FMC and SCC."""

    async def information(self) -> ProviderInfo: ...

    async def domains(self, page: PageRequest) -> ProviderPage[DiscoveredDomain]: ...

    async def devices(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredDevice]: ...

    async def policies(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredPolicy]: ...

    async def categories(
        self, policy_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredCategory]: ...

    async def rules(
        self, policy_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredRule]: ...

    async def objects(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredObject]: ...

    async def zones(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredZone]: ...


class ConnectionTestProvider(FirewallProvider, Protocol):
    """Read provider plus safe compatibility metadata used by connection validation."""

    certificate_info: dict[str, str]

    async def aclose(self) -> None:
        """Release provider transport resources after one test or synchronization run."""
        ...

    def compatibility_scopes(
        self, domains: tuple[DiscoveredDomain, ...]
    ) -> list[dict[str, str]]: ...


class ProviderFactory(Protocol):
    """Infrastructure factory injected into application connection testing."""

    def __call__(
        self,
        context: dict[str, object],
        credential: dict[str, str],
        capabilities: dict[str, str],
    ) -> ConnectionTestProvider: ...


class ProviderSyncDispatcher(Protocol):
    """Queue publisher injected at the delivery composition boundary."""

    def __call__(self, connection_id: UUID) -> object: ...


class ChangeSetExecutionDispatcher(Protocol):
    """Queue publisher for one immutable ChangeSet security context."""

    def __call__(
        self, change_set_id: UUID, principal_id: UUID, group_id: UUID, organization_id: UUID
    ) -> object: ...


class SyncRepository(Protocol):
    """Durable unit-of-work contract used by the provider-independent sync service."""

    def manager_context(self, manager_id: UUID) -> tuple[UUID, ProviderKind] | None: ...

    def start_sync(self, organization_id: UUID, manager_id: UUID) -> UUID: ...

    def record_provider_info(self, manager_id: UUID, info: ProviderInfo) -> None: ...

    def upsert_domain(
        self, organization_id: UUID, manager_id: UUID, run_id: UUID, item: DiscoveredDomain
    ) -> UUID: ...

    def upsert_device(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredDevice,
    ) -> UUID: ...

    def upsert_policy(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredPolicy,
    ) -> UUID: ...

    def upsert_category(
        self,
        organization_id: UUID,
        manager_id: UUID,
        policy_id: UUID,
        run_id: UUID,
        item: DiscoveredCategory,
    ) -> UUID: ...

    def upsert_rule(
        self,
        organization_id: UUID,
        manager_id: UUID,
        policy_id: UUID,
        category_id: UUID | None,
        run_id: UUID,
        item: DiscoveredRule,
    ) -> UUID: ...

    def upsert_object(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredObject,
    ) -> UUID: ...

    def upsert_zone(
        self,
        organization_id: UUID,
        manager_id: UUID,
        domain_id: UUID,
        run_id: UUID,
        item: DiscoveredZone,
    ) -> UUID: ...

    def replace_rule_object_references(
        self,
        organization_id: UUID,
        manager_id: UUID,
        rule_id: UUID,
        references: Sequence[DiscoveredObjectReference],
    ) -> None: ...

    def replace_rule_zone_references(
        self,
        organization_id: UUID,
        manager_id: UUID,
        rule_id: UUID,
        references: Sequence[DiscoveredZoneReference],
    ) -> None: ...

    def replace_object_references(
        self,
        organization_id: UUID,
        manager_id: UUID,
        source_object_id: UUID,
        object_native_ids: Sequence[str],
    ) -> None: ...

    def complete_sync(self, run_id: UUID, manager_id: UUID, resources_seen: int) -> SyncResult: ...

    def fail_sync(
        self, run_id: UUID, status: SyncStatus, resources_seen: int, error_code: str
    ) -> SyncResult: ...


class InventoryRepository(OverviewRepository, Protocol):
    """Organization-scoped read model for REST and UI inventory browsing."""

    def list_managers(
        self, organization_id: UUID, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]: ...

    def list_policies(
        self, organization_id: UUID, manager_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]: ...

    def list_rules(
        self, organization_id: UUID, policy_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]: ...

    def list_objects(
        self, organization_id: UUID, manager_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]: ...

    def provider_status(self, organization_id: UUID) -> list[dict[str, object]]: ...
