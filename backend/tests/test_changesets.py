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
OTHER_FINANCE_USER = UUID("30000000-0000-0000-0000-000000000002")
FINANCE = UUID("20000000-0000-0000-0000-000000000001")
ENGINEERING = UUID("20000000-0000-0000-0000-000000000002")
POLICY = UUID("50000000-0000-0000-0000-000000000001")
MANAGER = UUID("40000000-0000-0000-0000-000000000001")
CATEGORY = UUID("51000000-0000-0000-0000-000000000001")
ZONE = UUID("70000000-0000-0000-0000-000000000001")
FINANCE_OBJECT = UUID("60000000-0000-0000-0000-000000000001")
ENGINEERING_OBJECT = UUID("60000000-0000-0000-0000-000000000002")
PORT_OBJECT = UUID("60000000-0000-0000-0000-000000000003")
URL_OBJECT = UUID("60000000-0000-0000-0000-000000000004")
ADMIN_CATEGORY = UUID("51000000-0000-0000-0000-000000000099")
OTHER_POLICY = UUID("50000000-0000-0000-0000-000000000099")


def principal(role: str = "editor") -> Principal:
    return Principal(USER, ORG, f"{role}@example.test", role)


def other_finance_principal() -> Principal:
    return Principal(OTHER_FINANCE_USER, ORG, "other-editor@example.test", "editor")


class MemoryChangeSetRepository:
    """Small durable-style fake that exposes revocation/drift controls to tests."""

    def __init__(self) -> None:
        self.change_sets: dict[UUID, dict[str, object]] = {}
        self.user_enabled = True
        self.users = {USER, OTHER_FINANCE_USER}
        self.memberships = {FINANCE}
        self.capabilities = {
            "view",
            "create_rule",
            "modify_rule",
            "delete_rule",
            "reorder_rule",
            "modify_object",
            "delete_object",
        }
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
            "network_object_mutation": "SUPPORTED",
            "port_service_object_mutation": "SUPPORTED",
            "url_object_mutation": "SUPPORTED",
            "application_object_mutation": "NOT_STARTED",
            "rule_category_mutation": "SUPPORTED",
        }
        self.provider = DeterministicMockProvider(self.provider_kind)
        self.object_states: dict[UUID, dict[str, object]] = {
            FINANCE_OBJECT: {
                "owner_group_id": FINANCE,
                "owner_policy_id": POLICY,
                "object_type": "NETWORK",
                "name": "FINANCE__APP-SUBNET",
                "native_id": "object-finance-servers",
                "normalized_value": "10.20.10.0/24",
                "dependency_state": "UNREFERENCED",
                "management_state": "MANAGED",
                "provider_version": "1",
                "provider_name_matches": True,
            },
            ENGINEERING_OBJECT: {
                "owner_group_id": ENGINEERING,
                "owner_policy_id": POLICY,
                "object_type": "NETWORK",
                "name": "ENGINEERING__BUILD-SERVERS",
                "native_id": "object-engineering-servers",
                "normalized_value": "172.16.10.0/24",
                "dependency_state": "UNREFERENCED",
                "management_state": "MANAGED",
                "provider_version": "1",
                "provider_name_matches": True,
            },
            PORT_OBJECT: {
                "owner_group_id": FINANCE,
                "owner_policy_id": POLICY,
                "object_type": "PORT_SERVICE",
                "name": "FINANCE__API-SERVICE",
                "native_id": "object-finance-service",
                "normalized_value": "tcp/9443",
                "dependency_state": "UNREFERENCED",
                "management_state": "MANAGED",
                "provider_version": "1",
                "provider_name_matches": True,
            },
            URL_OBJECT: {
                "owner_group_id": FINANCE,
                "owner_policy_id": POLICY,
                "object_type": "URL",
                "name": "FINANCE__PORTAL",
                "native_id": "object-finance-url",
                "normalized_value": "finance.example.test",
                "dependency_state": "UNREFERENCED",
                "management_state": "MANAGED",
                "provider_version": "1",
                "provider_name_matches": True,
            },
        }
        self.reconciled_objects: list[dict[str, object]] = []
        self.category_mapping_exists = True
        self.category_name_collision = False
        self.category_slug = "FINANCE"
        self.category_revision_marker = "categories-v1"
        self.equivalent_mutation_id: UUID | None = None

    # Authorization port
    def user_state(self, user_id: UUID, organization_id: UUID) -> tuple[bool, int] | None:
        return (self.user_enabled, 1) if user_id in self.users and organization_id == ORG else None

    def membership_state(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> tuple[bool, int] | None:
        return (
            (True, 1)
            if user_id in self.users and organization_id == ORG and group_id in self.memberships
            else None
        )

    def policy_state(self, policy_id: UUID, organization_id: UUID) -> tuple[UUID, str, int] | None:
        return (MANAGER, "OBSERVED", 1) if policy_id == POLICY and organization_id == ORG else None

    def policy_capabilities(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[set[str], int, bool]:
        delegated = group_id in self.memberships and policy_id == POLICY and organization_id == ORG
        return set(self.capabilities) if delegated else set(), 1, delegated

    def object_grant_state(
        self, group_id: UUID, policy_id: UUID, object_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, set[str], int] | None:
        if group_id == FINANCE and policy_id == POLICY and object_id in self.object_grants:
            return MANAGER, "OBSERVED", {"use"}, 1
        return None

    def object_mutation_state(
        self, group_id: UUID, policy_id: UUID, object_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None:
        state = self.object_states.get(object_id)
        if state is None or policy_id != POLICY or organization_id != ORG:
            return None
        return {"manager_id": MANAGER, "revision": 1, **state}

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
        if operation["kind"] == "ENSURE_RULE_CATEGORY":
            result["category_inventory"] = self.category_revision_marker
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

    def object_mutation_context(
        self, object_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None:
        state = self.object_states.get(object_id)
        return (
            {"manager_id": MANAGER, **deepcopy(state)}
            if state and policy_id == POLICY and organization_id == ORG
            else None
        )

    def object_equivalent_id(self, *args: object) -> UUID | None:
        return self.equivalent_mutation_id

    def category_ensure_context(self, *args: object) -> dict[str, object]:
        group_id = UUID(str(args[1]))
        slug = self.category_slug if group_id == FINANCE else "ENGINEERING"
        categories: list[dict[str, object]] = [
            {
                "id": CATEGORY,
                "native_id": f"{self.provider_kind.value}-category-finance",
                "name": "FINANCE__RULES",
                "provider_version": "2",
                "management_state": "OBSERVED",
                "position": 10,
            }
        ]
        if self.category_name_collision and not self.category_mapping_exists:
            categories.append(
                {
                    "id": uuid4(),
                    "native_id": f"{self.provider_kind.value}-category-collision",
                    "name": f"{slug}__RULES",
                    "provider_version": "1",
                    "management_state": "OBSERVED",
                    "position": 40,
                }
            )
        return {
            "provider": self.provider_kind.value,
            "group_slug": slug,
            "mapping": (
                {
                    "id": uuid4(),
                    "category_id": CATEGORY,
                    "expected_category_name": f"{slug}__RULES",
                    "sync_state": "SYNCED",
                    "revision": 1,
                }
                if self.category_mapping_exists and group_id == FINANCE
                else None
            ),
            "categories": (
                categories if self.category_mapping_exists or self.category_name_collision else []
            ),
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

    def commit_provider_transaction_intent(self) -> None:
        pass

    def queue_execution(
        self, actor: Principal, group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        row = self.change_sets[change_set_id]
        assert row["creator_id"] == actor.user_id
        assert row["active_group_id"] == group_id
        row["state"] = "QUEUED"
        row["revision"] = int(row["revision"]) + 1
        row["validated_revision"] = row["revision"]
        return deepcopy(row)

    def commit_change_set_queue(self) -> None:
        pass

    def claim_queued_execution(self, actor: Principal, group_id: UUID, change_set_id: UUID) -> bool:
        row = self.change_sets[change_set_id]
        if (
            row["creator_id"] != actor.user_id
            or row["active_group_id"] != group_id
            or row["state"] != "QUEUED"
        ):
            return False
        row["state"] = "EXECUTING"
        return True

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
            if payload.get("object_id"):
                state = self.object_states[UUID(str(payload["object_id"]))]
                payload["object_native_id"] = f"{prefix}-{state['native_id']}"
                payload["expected_object_version"] = state["provider_version"]
                payload["expected_provider_name"] = state["name"]
            payload["source_zone_native_ids"] = [f"{prefix}-zone-inside"]
            payload["source_object_native_ids"] = [f"{prefix}-object-app"]
            if operation["kind"] == "CREATE_OBJECT":
                resolution = cast("dict[str, object]", deepcopy(operation["resolution"]))
                payload["provider_name"] = resolution.get("provider_name")
                payload["normalized_value"] = resolution.get("normalized_value")
                payload["resolution"] = resolution
            elif operation["kind"] == "MODIFY_OBJECT":
                payload["normalized_value"] = operation["resolution"]["normalized_value"]
            elif operation["kind"] == "ENSURE_RULE_CATEGORY":
                resolution = cast("dict[str, object]", deepcopy(operation["resolution"]))
                payload["provider_name"] = resolution["provider_name"]
                if resolution.get("category_id"):
                    payload["category_native_id"] = f"{prefix}-category-finance"
                    payload["expected_category_version"] = "2"
            prepared.append(
                {
                    "id": str(operation["id"]),
                    "kind": str(operation["kind"]),
                    "provider_payload": payload,
                }
            )
        return prepared

    def reconcile_successful_operations(
        self,
        change_set: dict[str, object],
        actor: Principal,
        group_id: UUID,
        operations: list[dict[str, object]],
        operation_results: list[dict[str, object]],
    ) -> None:
        del change_set
        succeeded = {
            str(item["operation_id"]): item
            for item in operation_results
            if item["status"] == "SUCCEEDED"
        }
        for operation in operations:
            result = succeeded.get(str(operation["id"]))
            if result is None:
                continue
            if operation["kind"] == "CREATE_OBJECT" and result["mutated"] is True:
                self.reconciled_objects.append(
                    {
                        "owner_group_id": group_id,
                        "created_by_user_id": actor.user_id,
                        "expected_provider_name": operation["resolution"]["provider_name"],
                    }
                )

    def record_successful_write_evidence(self, *args: object) -> set[str]:
        return set()

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
    assert repository.change_sets[UUID(str(change_set["id"]))]["state"] == "FAILED"


@pytest.mark.asyncio
async def test_queue_execution_persists_fixed_security_context_before_dispatch() -> None:
    repository, service, change_set = service_and_change(ProviderKind.FMC)
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(),
    )
    dispatched: list[tuple[UUID, UUID, UUID, UUID]] = []

    def dispatch(
        change_set_id: UUID, principal_id: UUID, group_id: UUID, organization_id: UUID
    ) -> None:
        dispatched.append((change_set_id, principal_id, group_id, organization_id))

    queued = service.queue_execution(
        principal(),
        FINANCE,
        UUID(str(ready["id"])),
        dispatch,
    )
    assert queued["state"] == "QUEUED"
    assert dispatched == [(UUID(str(ready["id"])), USER, FINANCE, ORG)]
    assert repository.change_sets[UUID(str(ready["id"]))]["active_group_id"] == FINANCE
    executed = await service.execute(principal(), FINANCE, UUID(str(ready["id"])), queued=True)
    assert executed["state"] == "SUCCEEDED"


def test_failed_change_set_without_provider_attempt_can_be_revalidated_and_requeued() -> None:
    repository, service, change_set = service_and_change(ProviderKind.FMC)
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(),
    )
    change_set_id = UUID(str(ready["id"]))
    repository.set_execution_state(
        principal(), FINANCE, change_set_id, "FAILED", {}, {"code": "QUEUE_PUBLISH_FAILED"}
    )
    dispatched: list[tuple[UUID, UUID, UUID, UUID]] = []

    def dispatch(change_id: UUID, user_id: UUID, group_id: UUID, organization_id: UUID) -> None:
        dispatched.append((change_id, user_id, group_id, organization_id))

    retried = service.retry_execution(
        principal(),
        FINANCE,
        change_set_id,
        dispatch,
    )

    assert retried["state"] == "QUEUED"
    assert dispatched == [(change_set_id, USER, FINANCE, ORG)]


def test_failed_change_set_with_provider_attempt_cannot_be_retried() -> None:
    repository, service, change_set = service_and_change(ProviderKind.FMC)
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.CREATE_RULE,
        valid_rule(),
    )
    change_set_id = UUID(str(ready["id"]))
    repository.set_execution_state(
        principal(), FINANCE, change_set_id, "FAILED", {}, {"code": "FAILED"}
    )
    repository.change_sets[change_set_id]["transactions"] = [{"state": "FAILED"}]

    def dispatch(_change_id: UUID, _user_id: UUID, _group_id: UUID, _organization_id: UUID) -> None:
        return None

    with pytest.raises(InvalidChangeSetStateError):
        service.retry_execution(principal(), FINANCE, change_set_id, dispatch)


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
        ("PORT_SERVICE", "tcp/8000-8080"),
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
    created = next(
        item for item in objects.items if item.name == f"FINANCE__created-{object_type.lower()}"
    )
    assert created.normalized_value == ProviderObjectNamingService().normalize_value(
        object_type, value
    )
    assert repository.reconciled_objects == [
        {
            "owner_group_id": FINANCE,
            "created_by_user_id": USER,
            "expected_provider_name": f"FINANCE__created-{object_type.lower()}",
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_kind", list(ProviderKind))
@pytest.mark.parametrize(
    ("object_id", "object_type", "value", "native_suffix"),
    [
        (FINANCE_OBJECT, "NETWORK", "10.20.30.0/24", "object-finance-servers"),
        (PORT_OBJECT, "PORT_SERVICE", "tcp/9444", "object-finance-service"),
        (URL_OBJECT, "URL", "updated.finance.example.test", "object-finance-url"),
    ],
)
async def test_owned_object_modify_follows_changeset_to_stateful_provider(
    provider_kind: ProviderKind,
    object_id: UUID,
    object_type: str,
    value: str,
    native_suffix: str,
) -> None:
    repository, service, change_set = service_and_change(provider_kind)
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MODIFY_OBJECT,
        {"object_id": str(object_id), "object_type": object_type, "value": value},
    )
    assert ready["state"] == "READY"
    result = await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))
    assert result["state"] == "SUCCEEDED"
    objects = await repository.provider.objects(f"{provider_kind.value}-domain-main", PageRequest())
    changed = next(
        item for item in objects.items if item.native_id == f"{provider_kind.value}-{native_suffix}"
    )
    assert changed.normalized_value == value


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_kind", list(ProviderKind))
async def test_unreferenced_owned_object_delete_follows_provider_path(
    provider_kind: ProviderKind,
) -> None:
    repository, service, change_set = service_and_change(provider_kind)
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.DELETE_OBJECT,
        {"object_id": str(FINANCE_OBJECT), "object_type": "NETWORK"},
    )
    assert ready["state"] == "READY"
    result = await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))
    assert result["state"] == "SUCCEEDED"
    objects = await repository.provider.objects(f"{provider_kind.value}-domain-main", PageRequest())
    assert all(
        item.native_id != f"{provider_kind.value}-object-finance-servers" for item in objects.items
    )


@pytest.mark.asyncio
async def test_another_authorized_finance_member_can_modify_group_owned_object() -> None:
    repository = MemoryChangeSetRepository()
    service = ChangeSetService(
        repository,
        repository,
        DeterministicMockTransactionExecutor(repository.provider),
    )
    actor = other_finance_principal()
    change_set = service.create(actor, FINANCE, POLICY, "Finance maintenance", "")
    ready = service.add_operation(
        actor,
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MODIFY_OBJECT,
        {
            "object_id": str(FINANCE_OBJECT),
            "object_type": "NETWORK",
            "value": "10.20.40.0/24",
        },
    )
    assert ready["state"] == "READY"
    result = await service.execute(actor, FINANCE, UUID(str(change_set["id"])))
    assert result["state"] == "SUCCEEDED"


@pytest.mark.parametrize(
    ("dependency_state", "kind", "expected_reason"),
    [
        ("CROSS_SCOPE", ChangeOperationKind.MODIFY_OBJECT, "OBJECT_DEPENDENCY_CONFLICT"),
        ("INCOMPLETE", ChangeOperationKind.MODIFY_OBJECT, "DEPENDENCY_STATE_INCOMPLETE"),
        ("WITHIN_SCOPE", ChangeOperationKind.DELETE_OBJECT, "OBJECT_DEPENDENCY_CONFLICT"),
    ],
)
def test_object_dependency_and_delete_safety_fail_closed(
    dependency_state: str, kind: ChangeOperationKind, expected_reason: str
) -> None:
    repository, service, change_set = service_and_change()
    repository.object_states[FINANCE_OBJECT]["dependency_state"] = dependency_state
    payload: dict[str, object] = {
        "object_id": str(FINANCE_OBJECT),
        "object_type": "NETWORK",
    }
    if kind is ChangeOperationKind.MODIFY_OBJECT:
        payload["value"] = "10.20.30.0/24"
    result = service.add_operation(principal(), FINANCE, UUID(str(change_set["id"])), kind, payload)
    assert result["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == expected_reason for item in result["operations"][0]["validation_results"]
    )


def test_object_mutation_uses_only_active_group_and_authoritative_owner() -> None:
    repository, service, _change_set = service_and_change()
    repository.memberships.add(ENGINEERING)
    engineering_change = service.create(principal(), ENGINEERING, POLICY, "Engineering", "")
    denied = service.add_operation(
        principal(),
        ENGINEERING,
        UUID(str(engineering_change["id"])),
        ChangeOperationKind.MODIFY_OBJECT,
        {
            "object_id": str(FINANCE_OBJECT),
            "object_type": "NETWORK",
            "value": "10.20.30.0/24",
        },
    )
    assert denied["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == "NOT_OWNER" for item in denied["operations"][0]["validation_results"]
    )


@pytest.mark.parametrize("value", ["10.21.0.0/16", "10.20.0.0/15"])
def test_network_object_modify_requires_complete_range_containment(value: str) -> None:
    _repository, service, change_set = service_and_change()
    result = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MODIFY_OBJECT,
        {"object_id": str(FINANCE_OBJECT), "object_type": "NETWORK", "value": value},
    )
    assert result["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == "IP_RANGE_NOT_GRANTED"
        for item in result["operations"][0]["validation_results"]
    )


def test_object_modify_cannot_create_an_equivalent_duplicate() -> None:
    repository, service, change_set = service_and_change()
    repository.equivalent_mutation_id = ENGINEERING_OBJECT
    result = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MODIFY_OBJECT,
        {
            "object_id": str(FINANCE_OBJECT),
            "object_type": "NETWORK",
            "value": "10.20.30.0/24",
        },
    )
    assert result["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == "EQUIVALENT_OBJECT_EXISTS"
        for item in result["operations"][0]["validation_results"]
    )


def test_provider_prefix_does_not_establish_ownership_and_drift_denies_mutation() -> None:
    lookalike = uuid4()
    repository, service, change_set = service_and_change()
    repository.object_states[lookalike] = {
        "owner_group_id": None,
        "owner_policy_id": None,
        "object_type": "NETWORK",
        "name": "FINANCE__SPOOFED",
        "native_id": "object-finance-name-conflict",
        "normalized_value": "10.20.99.0/24",
        "dependency_state": "UNREFERENCED",
        "management_state": "OBSERVED",
        "provider_version": "1",
        "provider_name_matches": False,
    }
    denied = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MODIFY_OBJECT,
        {"object_id": str(lookalike), "object_type": "NETWORK", "value": "10.20.30.0/24"},
    )
    assert denied["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == "NOT_OWNER" for item in denied["operations"][0]["validation_results"]
    )

    repository, service, change_set = service_and_change()
    repository.object_states[FINANCE_OBJECT]["provider_name_matches"] = False
    drifted = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MODIFY_OBJECT,
        {
            "object_id": str(FINANCE_OBJECT),
            "object_type": "NETWORK",
            "value": "10.20.30.0/24",
        },
    )
    assert drifted["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == "OWNERSHIP_DRIFT"
        for item in drifted["operations"][0]["validation_results"]
    )


def test_object_ownership_does_not_bypass_policy_context() -> None:
    repository, service, change_set = service_and_change()
    repository.object_states[FINANCE_OBJECT]["owner_policy_id"] = OTHER_POLICY
    result = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.MODIFY_OBJECT,
        {
            "object_id": str(FINANCE_OBJECT),
            "object_type": "NETWORK",
            "value": "10.20.30.0/24",
        },
    )
    assert result["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == "RESOURCE_OUT_OF_SCOPE"
        for item in result["operations"][0]["validation_results"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_kind", list(ProviderKind))
async def test_rule_category_ensure_uses_authoritative_mapping(
    provider_kind: ProviderKind,
) -> None:
    _repository, service, change_set = service_and_change(provider_kind)
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.ENSURE_RULE_CATEGORY,
        {},
    )
    assert ready["state"] == "READY"
    result = await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))
    assert result["state"] == "SUCCEEDED"
    assert result["transactions"][0]["operation_results"][0]["mutated"] is False


def test_rule_category_ensure_requires_create_permission_even_when_mapping_exists() -> None:
    repository, service, change_set = service_and_change()
    repository.capabilities = {"view"}
    denied = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.ENSURE_RULE_CATEGORY,
        {},
    )
    assert denied["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == "ACTION_NOT_GRANTED"
        for item in denied["operations"][0]["validation_results"]
    )


def test_rule_category_context_is_group_specific_and_cannot_cross_active_group() -> None:
    repository, service, finance_change = service_and_change()
    repository.memberships.add(ENGINEERING)
    with pytest.raises(ResourceOutOfScopeError):
        service.add_operation(
            principal(),
            ENGINEERING,
            UUID(str(finance_change["id"])),
            ChangeOperationKind.ENSURE_RULE_CATEGORY,
            {},
        )

    repository.category_mapping_exists = False
    engineering_change = service.create(principal(), ENGINEERING, POLICY, "Engineering", "")
    ready = service.add_operation(
        principal(),
        ENGINEERING,
        UUID(str(engineering_change["id"])),
        ChangeOperationKind.ENSURE_RULE_CATEGORY,
        {},
    )
    assert ready["state"] == "READY"
    assert ready["operations"][0]["resolution"]["provider_name"] == "ENGINEERING__RULES"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_kind", list(ProviderKind))
async def test_rule_category_create_if_absent_is_stateful(provider_kind: ProviderKind) -> None:
    repository, service, change_set = service_and_change(provider_kind)
    repository.category_mapping_exists = False
    repository.category_slug = "TREASURY"
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.ENSURE_RULE_CATEGORY,
        {},
    )
    assert ready["state"] == "READY"
    result = await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))
    assert result["state"] == "SUCCEEDED"
    categories = await repository.provider.categories(
        f"{provider_kind.value}-policy-edge", PageRequest()
    )
    assert any(item.name == "TREASURY__RULES" for item in categories.items)


def test_rule_category_name_collision_fails_safely() -> None:
    repository, service, change_set = service_and_change()
    repository.category_mapping_exists = False
    repository.category_name_collision = True
    collision = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.ENSURE_RULE_CATEGORY,
        {},
    )
    assert collision["state"] == "VALIDATION_FAILED"
    assert any(
        item["reason"] == "CATEGORY_NAME_CONFLICT"
        for item in collision["operations"][0]["validation_results"]
    )


@pytest.mark.asyncio
async def test_stale_rule_category_inventory_is_rejected_before_provider_mutation() -> None:
    repository, service, change_set = service_and_change()
    ready = service.add_operation(
        principal(),
        FINANCE,
        UUID(str(change_set["id"])),
        ChangeOperationKind.ENSURE_RULE_CATEGORY,
        {},
    )
    assert ready["state"] == "READY"
    repository.category_revision_marker = "categories-v2"
    with pytest.raises(ChangeSetConflictError):
        await service.execute(principal(), FINANCE, UUID(str(change_set["id"])))


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
    same_value_with_group_name = naming.resolve(
        provider=ProviderKind.FMC,
        group_slug="FINANCE",
        requested_name="alternate",
        object_type="NETWORK",
        value="10.20.30.0/24",
        candidates=[candidate],
    )
    assert exact.kind is NamingResolutionKind.EXACT_REUSE
    assert conflict.kind is NamingResolutionKind.NAMING_CONFLICT
    assert same_value_with_group_name.kind is NamingResolutionKind.NEW_OBJECT_REQUIRED


def test_port_service_normalization_accepts_one_port_or_range() -> None:
    naming = ProviderObjectNamingService()

    assert naming.normalize_value("PORT_SERVICE", "tcp/443") == "tcp/443"
    assert naming.normalize_value("PORT_SERVICE", "UDP/8000-8080") == "udp/8000-8080"
    with pytest.raises(ValueError, match="must use protocol"):
        naming.normalize_value("PORT_SERVICE", "tcp/80,tcp/443")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.10.10.1", "10.10.10.1"),
        ("10.10.10.12/24", "10.10.10.0/24"),
        ("10.10.10.1 - 10.10.20.30", "10.10.10.1-10.10.20.30"),
    ],
)
def test_network_normalization_accepts_hosts_subnets_and_ranges(value: str, expected: str) -> None:
    assert ProviderObjectNamingService().normalize_value("NETWORK", value) == expected


@pytest.mark.parametrize("value", ["10.10.20.30-10.10.10.1", "10.10.10.1-2001:db8::1"])
def test_network_normalization_rejects_invalid_ranges(value: str) -> None:
    with pytest.raises(ValueError, match="range endpoints"):
        ProviderObjectNamingService().normalize_value("NETWORK", value)


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
