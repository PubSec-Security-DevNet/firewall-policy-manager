"""Milestone 3 authorization, drift, naming, and mock transaction invariants."""

# ruff: noqa: PLR0913, PLR0917 -- fake preserves the explicit production port.
# pyright: reportArgumentType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportReturnType=false
# pyright: reportIndexIssue=false
# pyright: reportGeneralTypeIssues=false

from copy import deepcopy
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import pytest

from firewall_manager.application.changesets import ChangeSetService
from firewall_manager.application.errors import (
    ChangeSetConflictError,
    InvalidChangeSetStateError,
    ProductionWriteDisabledError,
    ResourceOutOfScopeError,
)
from firewall_manager.application.naming import ObjectCandidate, ProviderObjectNamingService
from firewall_manager.domain.models import (
    AuthorizationDecision,
    ChangeOperationKind,
    NamingResolutionKind,
    PageRequest,
    Principal,
    ProviderKind,
)
from firewall_manager.providers.mock import DeterministicMockProvider
from firewall_manager.providers.transactions import DeterministicMockTransactionExecutor

ORG = UUID("10000000-0000-0000-0000-000000000001")
USER = UUID("30000000-0000-0000-0000-000000000001")
FINANCE = UUID("20000000-0000-0000-0000-000000000001")
ENGINEERING = UUID("20000000-0000-0000-0000-000000000002")
POLICY = UUID("50000000-0000-0000-0000-000000000001")
MANAGER = UUID("40000000-0000-0000-0000-000000000001")
CATEGORY = UUID("51000000-0000-0000-0000-000000000001")
ZONE = UUID("70000000-0000-0000-0000-000000000001")
FINANCE_OBJECT = UUID("60000000-0000-0000-0000-000000000001")
ENGINEERING_OBJECT = UUID("60000000-0000-0000-0000-000000000002")
ADMIN_CATEGORY = UUID("51000000-0000-0000-0000-000000000099")
OTHER_POLICY = UUID("50000000-0000-0000-0000-000000000099")


def principal(role: str = "editor") -> Principal:
    return Principal(USER, ORG, f"{role}@example.test", role)


class MemoryChangeSetRepository:
    """Small durable-style fake that exposes revocation/drift controls to tests."""

    def __init__(self) -> None:
        self.change_sets: dict[UUID, dict[str, object]] = {}
        self.user_enabled = True
        self.memberships = {FINANCE}
        self.capabilities = {"view", "create_rule", "modify_rule", "delete_rule", "reorder_rule"}
        self.object_grants = {FINANCE_OBJECT}
        self.zone_grants = {ZONE}
        self.revision_marker = "policy-v1"
        self.ordering_marker = "order-v1"
        self.is_mock = True
        self.decisions: list[AuthorizationDecision] = []
        self.provider_kind = ProviderKind.FMC
        self.provider_capabilities = {
            "access_rule_create": "SUPPORTED",
            "access_rule_update": "SUPPORTED",
            "access_rule_delete": "SUPPORTED",
            "rule_ordering": "SUPPORTED",
            "network_object_create": "SUPPORTED",
            "port_service_object_create": "SUPPORTED",
            "url_object_create": "SUPPORTED",
            "application_object_create": "PARTIAL",
        }
        self.provider = DeterministicMockProvider(self.provider_kind)

    # Authorization port
    def user_state(self, user_id: UUID, organization_id: UUID) -> tuple[bool, int] | None:
        return (self.user_enabled, 1) if (user_id, organization_id) == (USER, ORG) else None

    def membership_state(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> tuple[bool, int] | None:
        return (
            (True, 1)
            if user_id == USER and organization_id == ORG and group_id in self.memberships
            else None
        )

    def policy_state(self, policy_id: UUID, organization_id: UUID) -> tuple[UUID, str, int] | None:
        return (MANAGER, "OBSERVED", 1) if policy_id == POLICY and organization_id == ORG else None

    def policy_capabilities(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[set[str], int, bool]:
        delegated = group_id == FINANCE and policy_id == POLICY and organization_id == ORG
        return set(self.capabilities) if delegated else set(), 1, delegated

    def object_grant_state(
        self, group_id: UUID, policy_id: UUID, object_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, set[str], int] | None:
        if group_id == FINANCE and policy_id == POLICY and object_id in self.object_grants:
            return MANAGER, "OBSERVED", {"use"}, 1
        return None

    def zone_grant_state(
        self, group_id: UUID, policy_id: UUID, zone_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, set[str], int] | None:
        if group_id == FINANCE and policy_id == POLICY and zone_id in self.zone_grants:
            return MANAGER, "OBSERVED", {"BOTH"}, 1
        return None

    def ip_range_grants(
        self, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[list[str], int]:
        return (["10.20.0.0/16"], 1) if group_id == FINANCE else ([], 0)

    def object_create_grant_state(
        self, group_id: UUID, policy_id: UUID, object_type: str, organization_id: UUID
    ) -> tuple[UUID, dict[str, str], int] | None:
        capability = {
            "NETWORK": "network_object_create",
            "PORT_SERVICE": "port_service_object_create",
            "URL": "url_object_create",
            "APPLICATION": "application_object_create",
            "APPLICATION_FILTER": "application_object_create",
        }.get(object_type)
        if group_id == FINANCE and capability:
            return MANAGER, {capability: self.provider_capabilities[capability]}, 1
        return None

    def equivalent_object_id(
        self, manager_id: UUID, object_type: str, normalized_value: str, organization_id: UUID
    ) -> UUID | None:
        return None

    def rule_owner_state(
        self, rule_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[UUID | None, str, int] | None:
        return FINANCE, "MANAGED", 1

    def category_mapping_state(
        self, group_id: UUID, policy_id: UUID, category_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, int] | None:
        if (group_id, policy_id, category_id, organization_id) == (FINANCE, POLICY, CATEGORY, ORG):
            return MANAGER, "OBSERVED", 1
        return None

    def record_authorization_decision(
        self, decision: AuthorizationDecision, *, interface: str, correlation_id: str | None
    ) -> None:
        self.decisions.append(decision)

    def active_groups_for_user(
        self, user_id: UUID, organization_id: UUID
    ) -> list[dict[str, object]]:
        return []

    def delegated_context_view(self, *args: object) -> None:
        return None

    def delegated_policies(self, *args: object) -> list[dict[str, object]]:
        return []

    # ChangeSet port
    def create_change_set(
        self,
        actor: Principal,
        group_id: UUID,
        policy_id: UUID,
        title: str,
        description: str,
        audit_metadata: dict[str, object],
    ) -> dict[str, object]:
        identifier = uuid4()
        now = datetime.now(UTC)
        row: dict[str, object] = {
            "id": identifier,
            "organization_id": ORG,
            "creator_id": actor.user_id,
            "active_group_id": group_id,
            "access_policy_id": policy_id,
            "target_policy_ids": [str(policy_id)],
            "title": title,
            "description": description,
            "state": "DRAFT",
            "revision": 1,
            "validated_revision": None,
            "provider_revision_snapshot": {},
            "validation_results": [],
            "execution_results": {},
            "failure_info": {},
            "audit_metadata": audit_metadata,
            "created_at": now,
            "updated_at": now,
            "operations": [],
            "transactions": [],
        }
        self.change_sets[identifier] = row
        return deepcopy(row)

    def list_change_sets(self, actor: Principal, group_id: UUID) -> list[dict[str, object]]:
        return [
            deepcopy(item)
            for item in self.change_sets.values()
            if item["active_group_id"] == group_id
        ]

    def get_change_set(
        self, actor: Principal, group_id: UUID, change_set_id: UUID
    ) -> dict[str, object] | None:
        row = self.change_sets.get(change_set_id)
        return deepcopy(row) if row and row["active_group_id"] == group_id else None

    def update_change_set_metadata(self, *args: object) -> dict[str, object]:
        raise NotImplementedError

    def add_operation(
        self,
        actor: Principal,
        group_id: UUID,
        change_set_id: UUID,
        kind: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        row = self.change_sets[change_set_id]
        operation = {
            "id": uuid4(),
            "change_set_id": change_set_id,
            "manager_id": MANAGER,
            "access_policy_id": UUID(str(payload.get("policy_id", POLICY))),
            "sequence": len(row["operations"]) + 1,  # type: ignore[arg-type]
            "kind": kind,
            "payload": deepcopy(payload),
            "expected_revisions": {},
            "status": "DRAFT",
            "validation_results": [],
            "resolution": {},
            "execution_result": {},
            "failure_info": {},
            "revision": 1,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        row["operations"].append(operation)  # type: ignore[union-attr]
        row["state"] = "DRAFT"
        row["revision"] = int(row["revision"]) + 1
        row["validated_revision"] = None
        return deepcopy(operation)

    def update_operation(
        self,
        actor: Principal,
        group_id: UUID,
        change_set_id: UUID,
        operation_id: UUID,
        payload: dict[str, object],
        expected_revision: int,
    ) -> dict[str, object]:
        row = self.change_sets[change_set_id]
        operation = next(item for item in row["operations"] if item["id"] == operation_id)  # type: ignore[union-attr]
        operation["payload"] = payload
        operation["revision"] = int(operation["revision"]) + 1
        row["state"] = "DRAFT"
        row["revision"] = int(row["revision"]) + 1
        row["validated_revision"] = None
        return deepcopy(operation)

    def remove_operation(self, *args: object) -> None:
        raise NotImplementedError

    def save_preflight(
        self,
        actor: Principal,
        group_id: UUID,
        change_set_id: UUID,
        operation_results: list[dict[str, object]],
        state: str,
        provider_snapshot: dict[str, object],
    ) -> dict[str, object]:
        row = self.change_sets[change_set_id]
        by_id = {UUID(str(item["operation_id"])): item for item in operation_results}
        for operation in row["operations"]:  # type: ignore[union-attr]
            result = by_id[operation["id"]]
            operation["status"] = result["status"]
            operation["validation_results"] = result["checks"]
            operation["expected_revisions"] = result["expected_revisions"]
            operation["resolution"] = result["resolution"]
        row["state"] = state
        row["validation_results"] = deepcopy(operation_results)
        row["provider_revision_snapshot"] = provider_snapshot
        row["revision"] = int(row["revision"]) + 1
        row["validated_revision"] = row["revision"]
        return deepcopy(row)

    def current_revision_snapshot(
        self, operation: dict[str, object], organization_id: UUID
    ) -> dict[str, str]:
        result = {"policy": self.revision_marker}
        if operation["kind"] == "MOVE_RULE":
            result["rule_ordering"] = self.ordering_marker
        return result

    def naming_context(self, *args: object) -> dict[str, object]:
        return {
            "manager_id": MANAGER,
            "provider": self.provider_kind.value,
            "is_mock": self.is_mock,
            "group_slug": "FINANCE",
            "objects": [],
            "policy_revision": self.revision_marker,
        }

    def set_execution_state(
        self,
        actor: Principal,
        group_id: UUID,
        change_set_id: UUID,
        state: str,
        execution_results: dict[str, object],
        failure_info: dict[str, object],
    ) -> dict[str, object]:
        row = self.change_sets[change_set_id]
        row["state"] = state
        row["execution_results"] = deepcopy(execution_results)
        row["failure_info"] = deepcopy(failure_info)
        row["revision"] = int(row["revision"]) + 1
        results = {
            item["operation_id"]: item
            for transaction in execution_results.get("transactions", [])
            for item in transaction["operation_results"]
        }
        for operation in row["operations"]:  # type: ignore[union-attr]
            if str(operation["id"]) in results:
                operation["status"] = results[str(operation["id"])]["status"]
        return deepcopy(row)

    def upsert_provider_transaction(
        self,
        change_set: dict[str, object],
        manager_id: UUID,
        state: str,
        operation_results: list[dict[str, object]],
        failure_info: dict[str, object],
        reconciliation_required: bool,
        external_operation_id: str | None,
    ) -> dict[str, object]:
        result = {
            "id": uuid4(),
            "manager_id": manager_id,
            "state": state,
            "operation_results": operation_results,
            "failure_info": failure_info,
            "reconciliation_required": reconciliation_required,
            "external_operation_id": external_operation_id,
            "revision": 1,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        self.change_sets[UUID(str(change_set["id"]))]["transactions"].append(result)  # type: ignore[union-attr]
        return deepcopy(result)

    def manager_execution_target(self, *args: object) -> dict[str, object]:
        return {
            "id": MANAGER,
            "provider": self.provider_kind.value,
            "is_mock": self.is_mock,
        }

    def provider_capability_state(self, *args: object) -> str:
        capability = str(args[1])
        return self.provider_capabilities.get(capability, "NOT_STARTED")

    def rule_ordering_bounds(self, *args: object) -> tuple[int, int]:
        return (10, 19)

    def prepare_provider_operations(
        self, operations: list[dict[str, object]], organization_id: UUID
    ) -> list[dict[str, object]]:
        prepared = []
        prefix = self.provider_kind.value
        for operation in operations:
            payload = cast("dict[str, object]", deepcopy(operation["payload"]))
            payload["policy_native_id"] = f"{prefix}-policy-edge"
            payload["expected_policy_version"] = "3"
            if payload.get("category_id"):
                payload["category_native_id"] = f"{prefix}-category-finance"
            if payload.get("rule_id"):
                payload["rule_native_id"] = f"{prefix}-rule-web"
                payload["expected_rule_version"] = "4"
            payload["source_zone_native_ids"] = [f"{prefix}-zone-inside"]
            payload["source_object_native_ids"] = [f"{prefix}-object-app"]
            if operation["kind"] == "CREATE_OBJECT":
                resolution = cast("dict[str, object]", deepcopy(operation["resolution"]))
                payload["provider_name"] = resolution.get("provider_name")
                payload["normalized_value"] = resolution.get("normalized_value")
                payload["resolution"] = resolution
            prepared.append(
                {
                    "id": str(operation["id"]),
                    "kind": str(operation["kind"]),
                    "provider_payload": payload,
                }
            )
        return prepared

    def group_provider_slug(self, *args: object) -> str:
        return "FINANCE"

    def cancel_change_set(self, *args: object) -> dict[str, object]:
        raise NotImplementedError

    def delete_change_set(self, *args: object) -> None:
        raise NotImplementedError

    def record_change_event(self, *args: object) -> None:
        pass


def valid_rule(*, object_id: UUID = FINANCE_OBJECT, behavior: str = "success") -> dict[str, object]:
    return {
        "name": "Allow delegated application",
        "action": "ALLOW",
        "category_id": str(CATEGORY),
        "source_zone_ids": [str(ZONE)],
        "source_object_ids": [str(object_id)],
        "manual_destination_networks": ["10.20.30.0/24"],
        "manual_ports": ["tcp/443"],
        "mock_behavior": behavior,
    }


def valid_move(*, category_id: UUID = CATEGORY, position: int = 11) -> dict[str, object]:
    return {
        "rule_id": str(uuid4()),
        "category_id": str(category_id),
        "position": position,
    }


def service_and_change(
    kind: ProviderKind = ProviderKind.FMC,
) -> tuple[MemoryChangeSetRepository, ChangeSetService, dict[str, object]]:
    repository = MemoryChangeSetRepository()
    repository.provider_kind = kind
    repository.provider = DeterministicMockProvider(kind)
    service = ChangeSetService(
        repository,
        repository,
        DeterministicMockTransactionExecutor(repository.provider),
    )
    change_set = service.create(principal(), FINANCE, POLICY, "Test", "")
    return repository, service, change_set


def test_every_rule_element_is_preflighted_and_denied_ids_are_redacted() -> None:
    _repository, service, change_set = service_and_change()
    result = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(object_id=ENGINEERING_OBJECT),
    )
    assert result["state"] == "VALIDATION_FAILED"
    checks = result["operations"][0]["validation_results"]
    denied = next(item for item in checks if item["element_type"] == "source_network")
    assert denied["allowed"] is False
    assert denied["element"] == "NOT_DISCLOSED"
    assert {item["element_type"] for item in checks} >= {
        "access_policy",
        "rule_category",
        "zone",
        "source_network",
        "manual_destination_network",
        "manual_port",
        "rule_action",
    }


def test_cross_group_changeset_access_and_permissions_never_union() -> None:
    repository, service, change_set = service_and_change()
    repository.memberships.add(ENGINEERING)
    with pytest.raises(ResourceOutOfScopeError):
        service.get(principal(), ENGINEERING, UUID(str(change_set["id"])))


def test_rule_ordering_preflight_enforces_authoritative_category_boundaries() -> None:
    _repository, service, change_set = service_and_change()
    within = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MOVE_RULE,
        valid_move(position=11),
    )
    assert within["state"] == "READY"

    _repository, service, change_set = service_and_change()
    crossing = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MOVE_RULE,
        valid_move(position=20),
    )
    assert crossing["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == "RULE_ORDERING_BOUNDARY_VIOLATION"
        for item in crossing["operations"][0]["validation_results"]
    )

    _repository, service, change_set = service_and_change()
    administrator_category = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MOVE_RULE,
        valid_move(category_id=ADMIN_CATEGORY, position=30),
    )
    assert administrator_category["state"] == "VALIDATION_FAILED"
    category_check = next(
        item
        for item in administrator_category["operations"][0]["validation_results"]
        if item["element_type"] == "rule_category"
    )
    assert category_check["allowed"] is False
    assert category_check["element"] == "NOT_DISCLOSED"

    _repository, service, change_set = service_and_change()
    cross_policy = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MOVE_RULE,
        {**valid_move(), "policy_id": str(OTHER_POLICY)},
    )
    assert cross_policy["state"] == "VALIDATION_FAILED"


def test_unadvertised_provider_operation_fails_preflight() -> None:
    repository, service, change_set = service_and_change()
    repository.provider_capabilities["access_rule_create"] = "NOT_STARTED"
    result = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(),
    )
    assert result["state"] == "VALIDATION_FAILED"
    capability = next(
        item
        for item in result["operations"][0]["validation_results"]
        if item["element_type"] == "provider_capability"
    )
    assert capability["reason"] == "PROVIDER_CAPABILITY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_execute_reauthorizes_and_permission_removal_fails_closed() -> None:
    repository, service, change_set = service_and_change()
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(),
    )
    assert ready["state"] == "READY"
    repository.object_grants.clear()
    with pytest.raises(ResourceOutOfScopeError):
        await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))
    assert repository.change_sets[UUID(str(change_set["id"]))]["state"] == "VALIDATION_FAILED"


@pytest.mark.asyncio
async def test_stale_revision_and_post_preflight_edit_are_rejected() -> None:
    repository, service, change_set = service_and_change()
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(),
    )
    repository.revision_marker = "policy-v2"
    with pytest.raises(ChangeSetConflictError):
        await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))
    assert repository.change_sets[UUID(str(change_set["id"]))]["state"] == "CONFLICT"

    repository, service, change_set = service_and_change()
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(),
    )
    operation = ready["operations"][0]
    service.update_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        UUID(str(operation["id"])),
        valid_rule(),
        int(operation["revision"]),
    )
    with pytest.raises(InvalidChangeSetStateError):
        await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))


@pytest.mark.asyncio
async def test_stale_provider_order_is_rejected_before_mock_mutation() -> None:
    repository, service, change_set = service_and_change()
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MOVE_RULE,
        valid_move(),
    )
    assert ready["state"] == "READY"
    repository.ordering_marker = "order-v2"
    with pytest.raises(ChangeSetConflictError):
        await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_kind", list(ProviderKind))
@pytest.mark.parametrize(
    "operation_kind",
    [
        ChangeOperationKind.CREATE_RULE,
        ChangeOperationKind.MODIFY_RULE,
        ChangeOperationKind.DELETE_RULE,
        ChangeOperationKind.MOVE_RULE,
    ],
)
async def test_supported_rule_operations_follow_changeset_to_provider_path(
    provider_kind: ProviderKind, operation_kind: ChangeOperationKind
) -> None:
    repository, service, change_set = service_and_change(provider_kind)
    payload = {
        ChangeOperationKind.CREATE_RULE: valid_rule(),
        ChangeOperationKind.MODIFY_RULE: {
            "rule_id": str(uuid4()),
            "name": "Updated delegated rule",
            "action": "BLOCK",
            "category_id": str(CATEGORY),
        },
        ChangeOperationKind.DELETE_RULE: {"rule_id": str(uuid4())},
        ChangeOperationKind.MOVE_RULE: valid_move(),
    }[operation_kind]
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        operation_kind,
        payload,
    )
    assert ready["state"] == "READY"
    result = await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))
    assert result["state"] == "SUCCEEDED"
    assert result["transactions"][0]["state"] == "SUCCEEDED"
    rules = await repository.provider.rules(f"{provider_kind.value}-policy-edge", PageRequest())
    if operation_kind is ChangeOperationKind.CREATE_RULE:
        assert any(item.name == "Allow delegated application" for item in rules.items)
    elif operation_kind is ChangeOperationKind.MODIFY_RULE:
        assert any(item.name == "Updated delegated rule" for item in rules.items)
    elif operation_kind is ChangeOperationKind.DELETE_RULE:
        assert all(item.native_id != f"{provider_kind.value}-rule-web" for item in rules.items)
    else:
        moved = next(
            item for item in rules.items if item.native_id == f"{provider_kind.value}-rule-web"
        )
        assert moved.position == 11


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_kind", list(ProviderKind))
@pytest.mark.parametrize(
    ("object_type", "value"),
    [
        ("NETWORK", "10.20.77.0/24"),
        ("PORT_SERVICE", "tcp/8443"),
        ("URL", "delegated.example.test"),
    ],
)
async def test_supported_object_create_follows_changeset_to_provider_path(
    provider_kind: ProviderKind, object_type: str, value: str
) -> None:
    repository, service, change_set = service_and_change(provider_kind)
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_OBJECT,
        {"object_type": object_type, "name": f"created-{object_type.lower()}", "value": value},
    )
    assert ready["state"] == "READY"
    result = await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))
    assert result["state"] == "SUCCEEDED"
    objects = await repository.provider.objects(f"{provider_kind.value}-domain-main", PageRequest())
    assert any(item.name == f"FINANCE__created-{object_type.lower()}" for item in objects.items)


def test_partial_application_object_capability_is_not_treated_as_supported() -> None:
    _repository, service, change_set = service_and_change()
    result = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_OBJECT,
        {"object_type": "APPLICATION", "name": "app", "value": "example-app"},
    )
    assert result["state"] == "VALIDATION_FAILED"


@pytest.mark.asyncio
async def test_production_target_is_explicitly_blocked() -> None:
    repository, service, change_set = service_and_change()
    service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(),
    )
    repository.is_mock = False
    with pytest.raises(ProductionWriteDisabledError):
        await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))


@pytest.mark.parametrize(
    ("behavior", "transaction_state"),
    [
        ("success", "SUCCEEDED"),
        ("provider_failure", "FAILED"),
        ("rate_limit", "FAILED"),
        ("timeout_before_mutation", "FAILED"),
        ("timeout_after_mutation", "RECONCILIATION_REQUIRED"),
        ("partial_failure", "FAILED"),
    ],
)
@pytest.mark.asyncio
async def test_mock_transaction_fault_matrix(behavior: str, transaction_state: str) -> None:
    provider = DeterministicMockProvider(ProviderKind.FMC)
    operation = {
        "id": str(uuid4()),
        "kind": "CREATE_RULE",
        "provider_payload": {
            **valid_rule(behavior=behavior),
            "policy_native_id": "fmc-policy-edge",
            "expected_policy_version": "3",
            "category_native_id": "fmc-category-finance",
            "position": 11,
        },
    }
    result = await DeterministicMockTransactionExecutor(provider).execute(
        {"is_mock": True, "provider": "fmc"}, uuid4(), MANAGER, [operation]
    )
    assert result.state.value == transaction_state
    if behavior == "timeout_after_mutation":
        assert result.reconciliation_required is True
        assert result.operation_results[0]["status"] == "AMBIGUOUS"


@pytest.mark.asyncio
async def test_partial_success_preserves_each_operation_result() -> None:
    provider = DeterministicMockProvider(ProviderKind.FMC)
    operations = [
        {
            "id": str(uuid4()),
            "kind": "CREATE_RULE",
            "provider_payload": {
                **valid_rule(),
                "policy_native_id": "fmc-policy-edge",
                "expected_policy_version": "3",
                "category_native_id": "fmc-category-finance",
                "position": 11,
            },
        },
        {
            "id": str(uuid4()),
            "kind": "CREATE_RULE",
            "provider_payload": {
                **valid_rule(behavior="provider_failure"),
                "policy_native_id": "fmc-policy-edge",
                "expected_policy_version": "3",
                "category_native_id": "fmc-category-finance",
                "position": 12,
            },
        },
    ]
    result = await DeterministicMockTransactionExecutor(provider).execute(
        {"is_mock": True, "provider": "fmc"}, uuid4(), MANAGER, operations
    )
    assert result.state.value == "PARTIALLY_SUCCEEDED"
    assert [item["status"] for item in result.operation_results] == ["SUCCEEDED", "FAILED"]


def test_centralized_naming_distinguishes_reuse_and_conflicts() -> None:
    naming = ProviderObjectNamingService()
    candidate = ObjectCandidate(FINANCE_OBJECT, "FINANCE__servers", "NETWORK", "10.20.30.0/24")
    exact = naming.resolve(
        provider=ProviderKind.FMC,
        group_slug="FINANCE",
        requested_name="servers",
        object_type="NETWORK",
        value="10.20.30.4/24",
        candidates=[candidate],
    )
    conflict = naming.resolve(
        provider=ProviderKind.FMC,
        group_slug="FINANCE",
        requested_name="servers",
        object_type="NETWORK",
        value="10.20.40.0/24",
        candidates=[candidate],
    )
    equivalent = naming.resolve(
        provider=ProviderKind.FMC,
        group_slug="FINANCE",
        requested_name="alternate",
        object_type="NETWORK",
        value="10.20.30.0/24",
        candidates=[candidate],
    )
    assert exact.kind is NamingResolutionKind.EXACT_REUSE
    assert conflict.kind is NamingResolutionKind.NAMING_CONFLICT
    assert equivalent.kind is NamingResolutionKind.EQUIVALENT_REUSE


@pytest.mark.parametrize("role", ["viewer", "editor", "approver", "admin"])
def test_defined_roles_do_not_bypass_current_group_policy_grants(role: str) -> None:
    repository = MemoryChangeSetRepository()
    repository.capabilities = {"view"}
    service = ChangeSetService(
        repository,
        repository,
        DeterministicMockTransactionExecutor(DeterministicMockProvider(ProviderKind.FMC)),
    )
    change_set = service.create(principal(role), FINANCE, POLICY, "Role matrix", "")
    result = service.add_operation(
        principal(role),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(),
    )
    assert result["state"] == "VALIDATION_FAILED"
