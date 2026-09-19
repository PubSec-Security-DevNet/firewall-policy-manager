"""ChangeSet orchestration: authorization, drift checks, and mock-only execution."""

# ruff: noqa: PLR0913, PLR0917 -- orchestration retains explicit security context.

from collections import defaultdict
from typing import cast
from uuid import UUID

from firewall_manager.application.authorization import AuthorizationService
from firewall_manager.application.errors import (
    ChangeSetConflictError,
    InvalidChangeSetStateError,
    InvalidInputError,
    ProductionWriteDisabledError,
    ResourceOutOfScopeError,
)
from firewall_manager.application.naming import ObjectCandidate, ProviderObjectNamingService
from firewall_manager.application.ports import AuthorizationRepository, ChangeSetRepository
from firewall_manager.domain.models import (
    Action,
    AuthorizationDecision,
    AuthorizationResource,
    AuthorizationResourceType,
    ChangeOperationKind,
    ChangeSetState,
    DelegatedPolicyContext,
    NamingResolutionKind,
    OperationStatus,
    Principal,
    ProviderCapability,
    ProviderKind,
    ProviderTransactionState,
)
from firewall_manager.providers.transactions import ProviderTransactionExecutor

_RULE_ACTIONS = {"ALLOW", "BLOCK", "TRUST", "MONITOR"}
_TERMINAL_NAMING_CONFLICTS = {
    NamingResolutionKind.NAMING_CONFLICT,
    NamingResolutionKind.SEMANTIC_CONFLICT,
    NamingResolutionKind.UNSUPPORTED_PROVIDER_BEHAVIOR,
}
_OPERATION_CAPABILITY = {
    ChangeOperationKind.CREATE_RULE: ProviderCapability.ACCESS_RULE_CREATE,
    ChangeOperationKind.MODIFY_RULE: ProviderCapability.ACCESS_RULE_UPDATE,
    ChangeOperationKind.DELETE_RULE: ProviderCapability.ACCESS_RULE_DELETE,
    ChangeOperationKind.MOVE_RULE: ProviderCapability.RULE_ORDERING,
    ChangeOperationKind.ENSURE_RULE_CATEGORY: ProviderCapability.RULE_CATEGORY_MUTATION,
}
_OBJECT_CAPABILITY = {
    "NETWORK": ProviderCapability.NETWORK_OBJECT_CREATE,
    "PORT_SERVICE": ProviderCapability.PORT_SERVICE_OBJECT_CREATE,
    "URL": ProviderCapability.URL_OBJECT_CREATE,
    "APPLICATION": ProviderCapability.APPLICATION_OBJECT_CREATE,
    "APPLICATION_FILTER": ProviderCapability.APPLICATION_OBJECT_CREATE,
}
_OBJECT_MUTATION_CAPABILITY = {
    "NETWORK": ProviderCapability.NETWORK_OBJECT_MUTATION,
    "PORT_SERVICE": ProviderCapability.PORT_SERVICE_OBJECT_MUTATION,
    "URL": ProviderCapability.URL_OBJECT_MUTATION,
    "APPLICATION": ProviderCapability.APPLICATION_OBJECT_MUTATION,
    "APPLICATION_FILTER": ProviderCapability.APPLICATION_OBJECT_MUTATION,
}


def _as_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise InvalidInputError
    return cast("dict[str, object]", value)


def _as_dict_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise InvalidInputError
    return cast("list[dict[str, object]]", value)


class ChangeSetService:
    """One default-deny service reused by REST and future worker/MCP interfaces."""

    def __init__(
        self,
        authorization_repository: AuthorizationRepository,
        repository: ChangeSetRepository,
        executor: ProviderTransactionExecutor,
    ) -> None:
        self._authorization = AuthorizationService(authorization_repository)
        self._repository = repository
        self._naming = ProviderObjectNamingService()
        self._executor = executor

    def create(
        self,
        principal: Principal,
        active_group_id: UUID,
        policy_id: UUID,
        title: str,
        description: str,
        *,
        correlation_id: str | None = None,
    ) -> dict[str, object]:
        context = DelegatedPolicyContext(principal, active_group_id, policy_id)
        self._authorization.require(
            context,
            Action.READ,
            AuthorizationResource(AuthorizationResourceType.POLICY, policy_id),
            interface="rest",
            correlation_id=correlation_id,
        )
        row = self._repository.create_change_set(
            principal,
            active_group_id,
            policy_id,
            title,
            description,
            {"correlation_id": correlation_id} if correlation_id else {},
        )
        self._audit(principal, active_group_id, policy_id, row, "change_set_created", "ALLOW")
        return row

    def list_for_group(
        self, principal: Principal, active_group_id: UUID
    ) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for row in self._repository.list_change_sets(principal, active_group_id):
            policy_id = UUID(str(row["access_policy_id"]))
            decision = self._authorization.authorize(
                DelegatedPolicyContext(principal, active_group_id, policy_id),
                Action.READ,
                AuthorizationResource(AuthorizationResourceType.POLICY, policy_id),
            )
            if decision.allowed:
                result.append(row)
        return result

    def get(
        self, principal: Principal, active_group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        return self._load(principal, active_group_id, change_set_id)

    def update_metadata(
        self,
        principal: Principal,
        active_group_id: UUID,
        change_set_id: UUID,
        title: str,
        description: str,
        expected_revision: int,
    ) -> dict[str, object]:
        current = self._load(principal, active_group_id, change_set_id)
        result = self._repository.update_change_set_metadata(
            principal,
            active_group_id,
            change_set_id,
            title,
            description,
            expected_revision,
        )
        self._audit_for(current, principal, "change_set_updated", "ALLOW")
        return result

    def add_operation(
        self,
        principal: Principal,
        active_group_id: UUID,
        change_set_id: UUID,
        kind: ChangeOperationKind,
        payload: dict[str, object],
    ) -> dict[str, object]:
        current = self._load(principal, active_group_id, change_set_id)
        self._repository.add_operation(
            principal, active_group_id, change_set_id, kind.value, payload
        )
        self._audit_for(current, principal, "operation_added", "ALLOW", {"kind": kind.value})
        return self.preflight(principal, active_group_id, change_set_id)

    def update_operation(
        self,
        principal: Principal,
        active_group_id: UUID,
        change_set_id: UUID,
        operation_id: UUID,
        payload: dict[str, object],
        expected_revision: int,
    ) -> dict[str, object]:
        current = self._load(principal, active_group_id, change_set_id)
        self._repository.update_operation(
            principal,
            active_group_id,
            change_set_id,
            operation_id,
            payload,
            expected_revision,
        )
        self._audit_for(
            current, principal, "operation_updated", "ALLOW", {"operation_id": str(operation_id)}
        )
        # Editing deliberately invalidates the prior preflight. The caller must explicitly run it.
        return self._load(principal, active_group_id, change_set_id)

    def remove_operation(
        self,
        principal: Principal,
        active_group_id: UUID,
        change_set_id: UUID,
        operation_id: UUID,
    ) -> dict[str, object]:
        current = self._load(principal, active_group_id, change_set_id)
        self._repository.remove_operation(principal, active_group_id, change_set_id, operation_id)
        self._audit_for(
            current, principal, "operation_removed", "ALLOW", {"operation_id": str(operation_id)}
        )
        return self._load(principal, active_group_id, change_set_id)

    def preflight(
        self,
        principal: Principal,
        active_group_id: UUID,
        change_set_id: UUID,
    ) -> dict[str, object]:
        change_set = self._load(principal, active_group_id, change_set_id)
        operations = _as_dict_list(change_set["operations"])
        results = [
            self._evaluate_operation(principal, active_group_id, item) for item in operations
        ]
        valid = bool(results) and all(
            item["status"] == OperationStatus.READY.value for item in results
        )
        state = ChangeSetState.READY.value if valid else ChangeSetState.VALIDATION_FAILED.value
        snapshot = {str(item["operation_id"]): item["expected_revisions"] for item in results}
        result = self._repository.save_preflight(
            principal, active_group_id, change_set_id, results, state, snapshot
        )
        self._audit_for(
            change_set,
            principal,
            "change_set_preflight",
            "ALLOW" if valid else "DENY",
            {"operation_count": len(results), "state": state},
        )
        return result

    def refresh(
        self, principal: Principal, active_group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        """Revalidate current state without silently replacing a stale provider snapshot."""
        change_set = self._load(principal, active_group_id, change_set_id)
        conflicts = self._revision_conflicts(change_set, principal.organization_id)
        if conflicts:
            result = self._repository.set_execution_state(
                principal,
                active_group_id,
                change_set_id,
                ChangeSetState.CONFLICT.value,
                {},
                {"code": "STALE_PROVIDER_REVISION", "conflicts": conflicts},
            )
            self._audit_for(
                change_set,
                principal,
                "stale_revision_detected",
                "DENY",
                {"conflicts": conflicts},
            )
            return result
        return self.preflight(principal, active_group_id, change_set_id)

    async def execute(
        self, principal: Principal, active_group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        change_set = self._load(principal, active_group_id, change_set_id)
        if (
            change_set["state"] != ChangeSetState.READY.value
            or change_set["validated_revision"] != change_set["revision"]
        ):
            raise InvalidChangeSetStateError(
                details={
                    "required_state": ChangeSetState.READY.value,
                    "revalidation_required": True,
                }
            )
        conflicts = self._revision_conflicts(change_set, principal.organization_id)
        if conflicts:
            self._repository.set_execution_state(
                principal,
                active_group_id,
                change_set_id,
                ChangeSetState.CONFLICT.value,
                {},
                {"code": "STALE_PROVIDER_REVISION", "conflicts": conflicts},
            )
            self._audit_for(
                change_set,
                principal,
                "stale_revision_detected",
                "DENY",
                {"conflicts": conflicts},
            )
            raise ChangeSetConflictError(details={"conflicts": conflicts})

        # Grants and every element are re-evaluated immediately before the first mock mutation.
        operations = _as_dict_list(change_set["operations"])
        authorization_results = [
            self._evaluate_operation(principal, active_group_id, item) for item in operations
        ]
        denied = [
            item for item in authorization_results if item["status"] != OperationStatus.READY.value
        ]
        if denied:
            self._repository.set_execution_state(
                principal,
                active_group_id,
                change_set_id,
                ChangeSetState.VALIDATION_FAILED.value,
                {},
                {"code": "EXECUTION_REAUTHORIZATION_FAILED", "operations": denied},
            )
            self._audit_for(
                change_set,
                principal,
                "execution_authorization_denied",
                "DENY",
                {"operations": denied},
            )
            raise ResourceOutOfScopeError(details={"operations": denied})

        grouped: dict[UUID, list[dict[str, object]]] = defaultdict(list)
        for operation in operations:
            grouped[UUID(str(operation["manager_id"]))].append(operation)
        targets: dict[UUID, dict[str, object]] = {}
        for manager_id in grouped:
            target = self._repository.manager_execution_target(
                manager_id, principal.organization_id
            )
            if target is None or target.get("is_mock") is not True:
                self._audit_for(
                    change_set,
                    principal,
                    "production_write_blocked",
                    "DENY",
                    {"manager_id": str(manager_id)},
                )
                raise ProductionWriteDisabledError
            targets[manager_id] = target

        self._repository.set_execution_state(
            principal,
            active_group_id,
            change_set_id,
            ChangeSetState.EXECUTING.value,
            {},
            {},
        )
        transactions: list[dict[str, object]] = []
        for manager_id, operations in grouped.items():
            provider_operations = self._repository.prepare_provider_operations(
                operations, principal.organization_id
            )
            outcome = await self._executor.execute(
                targets[manager_id], change_set_id, manager_id, provider_operations
            )
            self._repository.reconcile_successful_operations(
                change_set,
                principal,
                active_group_id,
                operations,
                outcome.operation_results,
            )
            transaction = self._repository.upsert_provider_transaction(
                change_set,
                manager_id,
                outcome.state.value,
                outcome.operation_results,
                outcome.failure_info,
                outcome.reconciliation_required,
                outcome.external_operation_id,
            )
            transactions.append(transaction)
            self._audit_for(
                change_set,
                principal,
                "provider_transaction_result",
                outcome.state.value,
                {
                    "manager_id": str(manager_id),
                    "transaction_id": str(transaction["id"]),
                    "owner_group_id": str(active_group_id),
                    "actor_user_id": str(principal.user_id),
                },
            )
        transaction_states = {str(item["state"]) for item in transactions}
        if ProviderTransactionState.RECONCILIATION_REQUIRED.value in transaction_states:
            overall = ChangeSetState.RECONCILIATION_REQUIRED
        elif ProviderTransactionState.CONFLICT.value in transaction_states:
            overall = ChangeSetState.CONFLICT
        elif transaction_states == {ProviderTransactionState.SUCCEEDED.value}:
            overall = ChangeSetState.SUCCEEDED
        elif transaction_states & {
            ProviderTransactionState.SUCCEEDED.value,
            ProviderTransactionState.PARTIALLY_SUCCEEDED.value,
        }:
            overall = ChangeSetState.PARTIALLY_SUCCEEDED
        else:
            overall = ChangeSetState.FAILED
        execution_results: dict[str, object] = {"transactions": transactions, "atomic": False}
        failure_info: dict[str, object] = (
            {
                "code": overall.value,
                "provider_failures": [item for item in transactions if item["failure_info"]],
            }
            if overall is not ChangeSetState.SUCCEEDED
            else {}
        )
        result = self._repository.set_execution_state(
            principal,
            active_group_id,
            change_set_id,
            overall.value,
            execution_results,
            failure_info,
        )
        self._audit_for(change_set, principal, "change_set_execution", overall.value)
        return result

    def cancel(
        self, principal: Principal, active_group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        current = self._load(principal, active_group_id, change_set_id)
        result = self._repository.cancel_change_set(principal, active_group_id, change_set_id)
        self._audit_for(current, principal, "change_set_cancelled", "ALLOW")
        return result

    def delete(self, principal: Principal, active_group_id: UUID, change_set_id: UUID) -> None:
        current = self._load(principal, active_group_id, change_set_id)
        self._repository.delete_change_set(principal, active_group_id, change_set_id)
        self._audit_for(current, principal, "change_set_deleted", "ALLOW")

    def _load(
        self, principal: Principal, active_group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        row = self._repository.get_change_set(principal, active_group_id, change_set_id)
        if row is None:
            raise ResourceOutOfScopeError
        policy_id = UUID(str(row["access_policy_id"]))
        self._authorization.require(
            DelegatedPolicyContext(principal, active_group_id, policy_id),
            Action.READ,
            AuthorizationResource(AuthorizationResourceType.POLICY, policy_id),
        )
        return row

    def _evaluate_operation(
        self, principal: Principal, active_group_id: UUID, operation: dict[str, object]
    ) -> dict[str, object]:
        payload = _as_dict(operation["payload"])
        kind = ChangeOperationKind(str(operation["kind"]))
        policy_id = UUID(str(operation["access_policy_id"]))
        context = DelegatedPolicyContext(principal, active_group_id, policy_id)
        checks: list[dict[str, object]] = []

        manager_id = UUID(str(operation["manager_id"]))
        if kind is ChangeOperationKind.CREATE_OBJECT:
            capability = _OBJECT_CAPABILITY.get(str(payload.get("object_type", "")))
        elif kind in {ChangeOperationKind.MODIFY_OBJECT, ChangeOperationKind.DELETE_OBJECT}:
            capability = _OBJECT_MUTATION_CAPABILITY.get(str(payload.get("object_type", "")))
        else:
            capability = _OPERATION_CAPABILITY[kind]
        capability_status = (
            self._repository.provider_capability_state(
                manager_id, capability.value, principal.organization_id
            )
            if capability is not None
            else None
        )
        checks.append(
            {
                "operation": kind.value,
                "element_type": "provider_capability",
                "element": capability.value if capability is not None else "UNKNOWN",
                "permission": "provider_capability",
                "allowed": capability_status == "SUPPORTED",
                "reason": (
                    "ALLOWED"
                    if capability_status == "SUPPORTED"
                    else "PROVIDER_CAPABILITY_UNAVAILABLE"
                ),
            }
        )
        if kind is ChangeOperationKind.CREATE_RULE and payload.get("position") is not None:
            ordering_status = self._repository.provider_capability_state(
                manager_id,
                ProviderCapability.RULE_ORDERING.value,
                principal.organization_id,
            )
            checks.append(
                {
                    "operation": kind.value,
                    "element_type": "provider_capability",
                    "element": ProviderCapability.RULE_ORDERING.value,
                    "permission": "provider_capability",
                    "allowed": ordering_status == "SUPPORTED",
                    "reason": (
                        "ALLOWED"
                        if ordering_status == "SUPPORTED"
                        else "PROVIDER_CAPABILITY_UNAVAILABLE"
                    ),
                }
            )

        action = {
            ChangeOperationKind.CREATE_RULE: Action.CREATE,
            ChangeOperationKind.MODIFY_RULE: Action.MODIFY,
            ChangeOperationKind.DELETE_RULE: Action.DELETE,
            ChangeOperationKind.MOVE_RULE: Action.REORDER,
            ChangeOperationKind.CREATE_OBJECT: Action.CREATE,
            ChangeOperationKind.MODIFY_OBJECT: Action.MODIFY,
            ChangeOperationKind.DELETE_OBJECT: Action.DELETE,
            ChangeOperationKind.ENSURE_RULE_CATEGORY: Action.CREATE,
        }[kind]
        if kind in {
            ChangeOperationKind.CREATE_OBJECT,
            ChangeOperationKind.MODIFY_OBJECT,
            ChangeOperationKind.DELETE_OBJECT,
        }:
            resolution = self._evaluate_object(context, kind, payload, checks)
        elif kind is ChangeOperationKind.ENSURE_RULE_CATEGORY:
            resolution = self._evaluate_category(context, kind, checks)
        else:
            resolution = {}
            self._append_decision(
                checks,
                kind,
                "access_policy",
                str(policy_id),
                self._authorization.authorize(
                    context,
                    action,
                    AuthorizationResource(AuthorizationResourceType.POLICY, policy_id),
                ),
            )
            self._evaluate_rule(context, kind, payload, checks)
        expected = self._repository.current_revision_snapshot(operation, principal.organization_id)
        valid = bool(checks) and all(bool(item["allowed"]) for item in checks)
        if resolution and resolution.get("kind") in {
            item.value for item in _TERMINAL_NAMING_CONFLICTS
        }:
            valid = False
        return {
            "operation_id": str(operation["id"]),
            "operation": kind.value,
            "status": OperationStatus.READY.value if valid else OperationStatus.INVALID.value,
            "checks": checks,
            "resolution": resolution,
            "expected_revisions": expected,
        }

    def _evaluate_rule(
        self,
        context: DelegatedPolicyContext,
        kind: ChangeOperationKind,
        payload: dict[str, object],
        checks: list[dict[str, object]],
    ) -> None:
        if kind in {
            ChangeOperationKind.MODIFY_RULE,
            ChangeOperationKind.DELETE_RULE,
            ChangeOperationKind.MOVE_RULE,
        }:
            rule_id = self._required_uuid(payload, "rule_id")
            rule_action = {
                ChangeOperationKind.MODIFY_RULE: Action.MODIFY,
                ChangeOperationKind.DELETE_RULE: Action.DELETE,
                ChangeOperationKind.MOVE_RULE: Action.REORDER,
            }[kind]
            self._append_decision(
                checks,
                kind,
                "rule",
                str(rule_id),
                self._authorization.authorize(
                    context,
                    rule_action,
                    AuthorizationResource(AuthorizationResourceType.RULE, rule_id),
                ),
            )
        if kind is ChangeOperationKind.DELETE_RULE:
            return
        category_id = self._required_uuid(payload, "category_id")
        self._append_decision(
            checks,
            kind,
            "rule_category",
            str(category_id),
            self._authorization.authorize(
                context,
                Action.USE,
                AuthorizationResource(AuthorizationResourceType.CATEGORY, category_id),
            ),
        )
        if payload.get("position") is not None and kind is ChangeOperationKind.CREATE_RULE:
            self._append_decision(
                checks,
                kind,
                "rule_position",
                str(payload["position"]),
                self._authorization.authorize(
                    context,
                    Action.REORDER,
                    AuthorizationResource(
                        AuthorizationResourceType.POLICY, context.access_policy_id
                    ),
                ),
            )
        if kind is ChangeOperationKind.MOVE_RULE or (
            kind is ChangeOperationKind.CREATE_RULE and payload.get("position") is not None
        ):
            position = payload.get("position")
            bounds = self._repository.rule_ordering_bounds(
                context.active_group_id,
                context.access_policy_id,
                category_id,
                context.principal.organization_id,
            )
            allowed = (
                isinstance(position, int)
                and not isinstance(position, bool)
                and bounds is not None
                and bounds[0] <= position <= bounds[1]
            )
            checks.append(
                {
                    "operation": kind.value,
                    "element_type": "rule_ordering_boundary",
                    "element": str(position) if allowed else "NOT_DISCLOSED",
                    "permission": "mapped_category_ordering",
                    "allowed": allowed,
                    "reason": "ALLOWED" if allowed else "RULE_ORDERING_BOUNDARY_VIOLATION",
                }
            )
        for key, direction in (
            ("source_zone_ids", "SOURCE"),
            ("destination_zone_ids", "DESTINATION"),
        ):
            for zone_id in self._uuid_list(payload, key):
                self._append_decision(
                    checks,
                    kind,
                    "zone",
                    str(zone_id),
                    self._authorization.authorize(
                        context,
                        Action.USE,
                        AuthorizationResource(
                            AuthorizationResourceType.ZONE, zone_id, element=direction
                        ),
                    ),
                )
        for key, element in (
            ("source_object_ids", "SOURCE_NETWORK"),
            ("destination_object_ids", "DESTINATION_NETWORK"),
            ("port_object_ids", "PORT_SERVICE"),
            ("application_object_ids", "APPLICATION"),
            ("url_object_ids", "URL"),
        ):
            for object_id in self._uuid_list(payload, key):
                self._append_decision(
                    checks,
                    kind,
                    element.lower(),
                    str(object_id),
                    self._authorization.authorize(
                        context,
                        Action.USE,
                        AuthorizationResource(
                            AuthorizationResourceType.OBJECT, object_id, element=element
                        ),
                    ),
                )
        for key, element in (
            ("manual_source_networks", "manual_source_network"),
            ("manual_destination_networks", "manual_destination_network"),
        ):
            for value in self._string_list(payload, key):
                self._append_decision(
                    checks,
                    kind,
                    element,
                    value,
                    self._authorization.authorize(
                        context,
                        Action.USE,
                        AuthorizationResource(AuthorizationResourceType.IP_NETWORK, value=value),
                    ),
                )
        policy_allowed = all(
            item["allowed"] for item in checks if item["element_type"] == "access_policy"
        )
        for value in self._string_list(payload, "manual_ports"):
            allowed = self._valid_manual_port(value) and policy_allowed
            checks.append(
                {
                    "operation": kind.value,
                    "element_type": "manual_port",
                    "element": value,
                    "permission": "policy_rule_capability",
                    "allowed": allowed,
                    "reason": "ALLOWED" if allowed else "INVALID_OR_UNAUTHORIZED_PORT",
                }
            )
        if "action" in payload:
            value = str(payload["action"]).upper()
            allowed = value in _RULE_ACTIONS
            checks.append(
                {
                    "operation": kind.value,
                    "element_type": "rule_action",
                    "element": value,
                    "permission": "normalized_rule_action",
                    "allowed": allowed,
                    "reason": "ALLOWED" if allowed else "UNSUPPORTED_RULE_ACTION",
                }
            )

    def _evaluate_object(
        self,
        context: DelegatedPolicyContext,
        kind: ChangeOperationKind,
        payload: dict[str, object],
        checks: list[dict[str, object]],
    ) -> dict[str, object]:
        if kind is not ChangeOperationKind.CREATE_OBJECT:
            return self._evaluate_object_mutation(context, kind, payload, checks)
        object_type = str(payload.get("object_type", ""))
        requested_name = str(payload.get("name", ""))
        value = str(payload.get("value", ""))
        naming = self._repository.naming_context(
            context.access_policy_id,
            context.active_group_id,
            context.principal.organization_id,
        )
        if naming is None:
            raise ResourceOutOfScopeError
        slug = str(naming["group_slug"])
        prefix = requested_name.split("__", 1)[0] if "__" in requested_name else None
        prefix_ok = prefix is None or prefix == slug
        checks.append(
            {
                "operation": ChangeOperationKind.CREATE_OBJECT.value,
                "element_type": "provider_name_prefix",
                "element": requested_name,
                "permission": "active_group_prefix",
                "allowed": prefix_ok,
                "reason": "ALLOWED" if prefix_ok else "GROUP_PREFIX_MISMATCH",
            }
        )
        unprefixed = requested_name.split("__", 1)[1] if prefix == slug else requested_name
        candidates = [
            ObjectCandidate(
                object_id=UUID(str(item["object_id"])),
                name=str(item["name"]),
                object_type=str(item["object_type"]),
                normalized_value=(
                    str(item["normalized_value"])
                    if item.get("normalized_value") is not None
                    else None
                ),
            )
            for item in _as_dict_list(naming["objects"])
        ]
        resolution = self._naming.resolve(
            provider=ProviderKind(str(naming["provider"])),
            group_slug=slug,
            requested_name=unprefixed,
            object_type=object_type,
            value=value,
            candidates=candidates,
        )
        resolution_dict = resolution.to_dict()
        resolution_dict["kind"] = resolution.kind.value
        if resolution.existing_object_id is not None:
            resolution_dict["existing_object_id"] = str(resolution.existing_object_id)
        if (
            resolution.kind
            in {
                NamingResolutionKind.EXACT_REUSE,
                NamingResolutionKind.EQUIVALENT_REUSE,
            }
            and resolution.existing_object_id
        ):
            self._append_decision(
                checks,
                ChangeOperationKind.CREATE_OBJECT,
                "equivalent_object",
                str(resolution.existing_object_id),
                self._authorization.authorize(
                    context,
                    Action.USE,
                    AuthorizationResource(
                        AuthorizationResourceType.OBJECT, resolution.existing_object_id
                    ),
                ),
            )
        elif resolution.kind is NamingResolutionKind.NEW_OBJECT_REQUIRED:
            self._append_decision(
                checks,
                ChangeOperationKind.CREATE_OBJECT,
                "object_type",
                object_type,
                self._authorization.authorize(
                    context,
                    Action.CREATE,
                    AuthorizationResource(AuthorizationResourceType.OBJECT_TYPE, value=object_type),
                ),
            )
        else:
            checks.append(
                {
                    "operation": ChangeOperationKind.CREATE_OBJECT.value,
                    "element_type": "name_resolution",
                    "element": requested_name,
                    "permission": "provider_naming_equivalence",
                    "allowed": False,
                    "reason": resolution.kind.value,
                }
            )
        if object_type == "NETWORK" and resolution.normalized_value:
            self._append_decision(
                checks,
                ChangeOperationKind.CREATE_OBJECT,
                "network_value",
                resolution.normalized_value,
                self._authorization.authorize(
                    context,
                    Action.USE,
                    AuthorizationResource(
                        AuthorizationResourceType.IP_NETWORK,
                        value=resolution.normalized_value,
                    ),
                ),
            )
        return resolution_dict

    def _evaluate_object_mutation(
        self,
        context: DelegatedPolicyContext,
        kind: ChangeOperationKind,
        payload: dict[str, object],
        checks: list[dict[str, object]],
    ) -> dict[str, object]:
        object_id = self._required_uuid(payload, "object_id")
        action = Action.MODIFY if kind is ChangeOperationKind.MODIFY_OBJECT else Action.DELETE
        self._append_decision(
            checks,
            kind,
            "object",
            str(object_id),
            self._authorization.authorize(
                context,
                action,
                AuthorizationResource(AuthorizationResourceType.OBJECT, object_id),
            ),
        )
        current = self._repository.object_mutation_context(
            object_id,
            context.access_policy_id,
            context.principal.organization_id,
        )
        if current is None:
            raise ResourceOutOfScopeError
        object_type = str(payload.get("object_type", ""))
        type_matches = object_type == current["object_type"] and object_type in {
            "NETWORK",
            "PORT_SERVICE",
            "URL",
            "APPLICATION",
            "APPLICATION_FILTER",
        }
        checks.append(
            {
                "operation": kind.value,
                "element_type": "object_type",
                "element": object_type if type_matches else "NOT_DISCLOSED",
                "permission": "delegated_mutable_type",
                "allowed": type_matches,
                "reason": "ALLOWED" if type_matches else "OBJECT_TYPE_MISMATCH",
            }
        )
        resolution: dict[str, object] = {
            "object_id": str(object_id),
            "provider_name": current["name"],
            "object_type": current["object_type"],
        }
        if kind is ChangeOperationKind.DELETE_OBJECT:
            return resolution
        try:
            normalized = self._naming.normalize_value(object_type, str(payload.get("value", "")))
        except (TypeError, ValueError):
            checks.append(
                {
                    "operation": kind.value,
                    "element_type": "object_value",
                    "element": "NOT_DISCLOSED",
                    "permission": "normalized_object_value",
                    "allowed": False,
                    "reason": "INVALID_NORMALIZED_VALUE",
                }
            )
            return resolution
        resolution["normalized_value"] = normalized
        equivalent_id = self._repository.object_equivalent_id(
            UUID(str(current["manager_id"])),
            object_type,
            normalized,
            object_id,
            context.principal.organization_id,
        )
        checks.append(
            {
                "operation": kind.value,
                "element_type": "object_equivalence",
                "element": "NONE" if equivalent_id is None else "NOT_DISCLOSED",
                "permission": "no_duplicate_bypass",
                "allowed": equivalent_id is None,
                "reason": "ALLOWED" if equivalent_id is None else "EQUIVALENT_OBJECT_EXISTS",
            }
        )
        if object_type == "NETWORK":
            self._append_decision(
                checks,
                kind,
                "network_value",
                normalized,
                self._authorization.authorize(
                    context,
                    Action.USE,
                    AuthorizationResource(AuthorizationResourceType.IP_NETWORK, value=normalized),
                ),
            )
        return resolution

    def _evaluate_category(
        self,
        context: DelegatedPolicyContext,
        kind: ChangeOperationKind,
        checks: list[dict[str, object]],
    ) -> dict[str, object]:
        data = self._repository.category_ensure_context(
            context.access_policy_id,
            context.active_group_id,
            context.principal.organization_id,
        )
        if data is None:
            raise ResourceOutOfScopeError
        provider_name = self._naming.category_name(
            ProviderKind(str(data["provider"])), str(data["group_slug"])
        )
        if provider_name is None:
            checks.append(
                {
                    "operation": kind.value,
                    "element_type": "rule_category",
                    "element": "NOT_DISCLOSED",
                    "permission": "provider_naming",
                    "allowed": False,
                    "reason": "PROVIDER_NAME_RESTRICTION",
                }
            )
            return {}
        self._append_decision(
            checks,
            kind,
            "access_policy",
            str(context.access_policy_id),
            self._authorization.authorize(
                context,
                Action.CREATE,
                AuthorizationResource(AuthorizationResourceType.POLICY, context.access_policy_id),
            ),
        )
        categories = _as_dict_list(data["categories"])
        mapping = data.get("mapping")
        if isinstance(mapping, dict):
            mapped = cast("dict[str, object]", mapping)
            category = next(
                (item for item in categories if item["id"] == mapped["category_id"]), None
            )
            allowed = bool(
                category
                and mapped.get("expected_category_name") == provider_name
                and category.get("name") == provider_name
                and mapped.get("sync_state") == "SYNCED"
                and category.get("management_state") not in {"MISSING", "CONFLICT", "DRIFTED"}
            )
            checks.append(
                {
                    "operation": kind.value,
                    "element_type": "rule_category",
                    "element": str(mapped["category_id"]) if allowed else "NOT_DISCLOSED",
                    "permission": "authoritative_category_mapping",
                    "allowed": allowed,
                    "reason": "ALLOWED" if allowed else "CATEGORY_MAPPING_CONFLICT",
                }
            )
            return {
                "kind": "EXISTING_CATEGORY",
                "provider_name": provider_name,
                "category_id": str(mapped["category_id"]),
            }
        collision = next((item for item in categories if item.get("name") == provider_name), None)
        checks.append(
            {
                "operation": kind.value,
                "element_type": "rule_category",
                "element": provider_name if collision is None else "NOT_DISCLOSED",
                "permission": "create_mapped_category",
                "allowed": collision is None,
                "reason": "ALLOWED" if collision is None else "CATEGORY_NAME_CONFLICT",
            }
        )
        return {"kind": "NEW_CATEGORY_REQUIRED", "provider_name": provider_name}

    def _revision_conflicts(
        self, change_set: dict[str, object], organization_id: UUID
    ) -> list[dict[str, object]]:
        conflicts: list[dict[str, object]] = []
        for operation in _as_dict_list(change_set["operations"]):
            expected = cast("dict[str, str]", _as_dict(operation["expected_revisions"]))
            current = self._repository.current_revision_snapshot(operation, organization_id)
            for resource, expected_revision in expected.items():
                current_revision = current.get(resource, "MISSING")
                if current_revision != expected_revision:
                    conflicts.append(
                        {
                            "operation_id": str(operation["id"]),
                            "resource": resource,
                            "expected_revision": expected_revision,
                            "current_revision": current_revision,
                            "reason": "PROVIDER_RESOURCE_CHANGED",
                        }
                    )
        return conflicts

    @staticmethod
    def _append_decision(
        checks: list[dict[str, object]],
        kind: ChangeOperationKind,
        element_type: str,
        identifier: str,
        decision: AuthorizationDecision,
    ) -> None:
        checks.append(
            {
                "operation": kind.value,
                "element_type": element_type,
                "element": identifier if decision.allowed else "NOT_DISCLOSED",
                "permission": decision.action.value,
                "allowed": decision.allowed,
                "reason": decision.reason.value,
            }
        )

    @staticmethod
    def _required_uuid(payload: dict[str, object], key: str) -> UUID:
        try:
            return UUID(str(payload[key]))
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidInputError(details={"field": key}) from exc

    @staticmethod
    def _uuid_list(payload: dict[str, object], key: str) -> list[UUID]:
        try:
            values = payload.get(key, [])
            if not isinstance(values, list):
                raise ValueError
            return [UUID(str(item)) for item in cast("list[object]", values)]
        except (TypeError, ValueError) as exc:
            raise InvalidInputError(details={"field": key}) from exc

    @staticmethod
    def _string_list(payload: dict[str, object], key: str) -> list[str]:
        values = payload.get(key, [])
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise InvalidInputError(details={"field": key})
        return cast("list[str]", values)

    @staticmethod
    def _valid_manual_port(value: str) -> bool:
        try:
            protocol, raw_range = value.casefold().split("/", 1)
            if protocol not in {"tcp", "udp"}:
                return False
            parts = [int(item) for item in raw_range.split("-", 1)]
            return len(parts) in {1, 2} and 1 <= parts[0] <= parts[-1] <= 65535
        except (ValueError, TypeError):
            return False

    def _audit_for(
        self,
        change_set: dict[str, object],
        principal: Principal,
        action: str,
        result: str,
        details: dict[str, object] | None = None,
    ) -> None:
        self._audit(
            principal,
            UUID(str(change_set["active_group_id"])),
            UUID(str(change_set["access_policy_id"])),
            change_set,
            action,
            result,
            details,
        )

    def _audit(
        self,
        principal: Principal,
        group_id: UUID,
        policy_id: UUID,
        change_set: dict[str, object],
        action: str,
        result: str,
        details: dict[str, object] | None = None,
    ) -> None:
        self._repository.record_change_event(
            principal,
            group_id,
            policy_id,
            UUID(str(change_set["id"])),
            action,
            result,
            details or {},
        )
