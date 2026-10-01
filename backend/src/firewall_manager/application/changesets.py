"""ChangeSet orchestration: authorization, drift checks, and guarded execution."""

# ruff: noqa: PLR0913, PLR0917 -- orchestration retains explicit security context.

from collections import defaultdict
from collections.abc import Callable
from typing import cast
from uuid import UUID

from firewall_manager.application.authorization import AuthorizationService, require_action
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
from firewall_manager.providers.transactions import (
    ProviderTransactionExecutor,
    real_transaction_operation_id,
)

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
    "NETWORK_GROUP": ProviderCapability.NETWORK_OBJECT_CREATE,
    "PORT_SERVICE": ProviderCapability.PORT_SERVICE_OBJECT_CREATE,
    "PORT_SERVICE_GROUP": ProviderCapability.PORT_SERVICE_OBJECT_CREATE,
    "URL": ProviderCapability.URL_OBJECT_CREATE,
    "URL_GROUP": ProviderCapability.URL_OBJECT_CREATE,
    "APPLICATION": ProviderCapability.APPLICATION_OBJECT_CREATE,
    "APPLICATION_FILTER": ProviderCapability.APPLICATION_OBJECT_CREATE,
}
_OBJECT_MUTATION_CAPABILITY = {
    "NETWORK": ProviderCapability.NETWORK_OBJECT_MUTATION,
    "NETWORK_GROUP": ProviderCapability.NETWORK_OBJECT_MUTATION,
    "PORT_SERVICE": ProviderCapability.PORT_SERVICE_OBJECT_MUTATION,
    "PORT_SERVICE_GROUP": ProviderCapability.PORT_SERVICE_OBJECT_MUTATION,
    "URL": ProviderCapability.URL_OBJECT_MUTATION,
    "URL_GROUP": ProviderCapability.URL_OBJECT_MUTATION,
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

    def list_for_admin(self, principal: Principal) -> list[dict[str, object]]:
        require_action(principal, Action.MANAGE_PROVIDERS)
        return self._repository.list_all_change_sets(principal)

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

    def create_rollback(  # noqa: PLR0912, PLR0915 -- inverse operation mapping is explicit
        self, principal: Principal, active_group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        """Create a compensating ChangeSet from the original operation snapshots."""
        original = self._load(principal, active_group_id, change_set_id)
        inverse: list[tuple[ChangeOperationKind, dict[str, object]]] = []

        def require_unchanged(
            resource_type: str, resource_id: object, snapshot: dict[str, object]
        ) -> None:
            expected = snapshot.get("revision")
            if expected is None:
                raise InvalidChangeSetStateError(
                    details={"code": "ROLLBACK_SNAPSHOT_MISSING", "resource_id": str(resource_id)}
                )
            current = (
                self._repository.rule_revision(UUID(str(resource_id)), principal.organization_id)
                if resource_type == "rule"
                else self._repository.object_revision(
                    UUID(str(resource_id)), principal.organization_id
                )
            )
            management_state = (
                self._repository.rule_management_state(
                    UUID(str(resource_id)), principal.organization_id
                )
                if resource_type == "rule"
                else self._repository.object_management_state(
                    UUID(str(resource_id)), principal.organization_id
                )
            )
            if current != int(expected) + 1 and management_state != "MANAGED":
                raise InvalidChangeSetStateError(
                    details={
                        "code": "ROLLBACK_CONFLICT",
                        "resource_type": resource_type,
                        "resource_id": str(resource_id),
                        "expected_revision": int(expected) + 1,
                        "current_revision": current,
                    }
                )

        for operation in reversed(_as_dict_list(original["operations"])):
            kind = ChangeOperationKind(str(operation["kind"]))
            payload = _as_dict(operation.get("payload", {}))
            snapshot = _as_dict(operation.get("rollback_snapshot", {}))
            state = _as_dict(snapshot.get("state", {}))
            if kind is ChangeOperationKind.ENSURE_RULE_CATEGORY:
                continue
            if kind is ChangeOperationKind.CREATE_RULE:
                native_id = _as_dict(operation.get("execution_result", {})).get(
                    "provider_resource_id"
                )
                rule_id = (
                    self._repository.rule_id_by_native(
                        UUID(str(operation["manager_id"])),
                        str(native_id),
                        principal.organization_id,
                    )
                    if native_id
                    else None
                )
                if rule_id is None:
                    raise InvalidChangeSetStateError(
                        details={
                            "code": "ROLLBACK_RESOURCE_NOT_FOUND",
                            "operation": str(operation["id"]),
                        }
                    )
                if self._repository.rule_revision(rule_id, principal.organization_id) != 1:
                    raise InvalidChangeSetStateError(
                        details={"code": "ROLLBACK_CONFLICT", "resource_id": str(rule_id)}
                    )
                inverse.append((ChangeOperationKind.DELETE_RULE, {"rule_id": str(rule_id)}))
            elif kind is ChangeOperationKind.MODIFY_RULE:
                rule_id = state.get("resource_id") or payload.get("rule_id")
                if not rule_id or not state:
                    raise InvalidChangeSetStateError(
                        details={
                            "code": "ROLLBACK_SNAPSHOT_MISSING",
                            "operation": str(operation["id"]),
                        }
                    )
                require_unchanged("rule", rule_id, snapshot)
                inverse_state = dict(state)
                # Category authorization is independent from restoring the rule's
                # other fields. Do not re-submit an unchanged drifted category.
                inverse_state.pop("category_id", None)
                inverse.append(
                    (
                        ChangeOperationKind.MODIFY_RULE,
                        {"rule_id": str(rule_id), **inverse_state},
                    )
                )
            elif kind is ChangeOperationKind.MOVE_RULE:
                rule_id = state.get("resource_id") or payload.get("rule_id")
                if not rule_id or "position" not in state:
                    raise InvalidChangeSetStateError(
                        details={
                            "code": "ROLLBACK_SNAPSHOT_MISSING",
                            "operation": str(operation["id"]),
                        }
                    )
                require_unchanged("rule", rule_id, snapshot)
                inverse.append(
                    (
                        ChangeOperationKind.MOVE_RULE,
                        {"rule_id": str(rule_id), "position": state["position"]},
                    )
                )
            elif kind is ChangeOperationKind.DELETE_RULE:
                if not state:
                    raise InvalidChangeSetStateError(
                        details={
                            "code": "ROLLBACK_SNAPSHOT_MISSING",
                            "operation": str(operation["id"]),
                        }
                    )
                require_unchanged("rule", state.get("resource_id"), snapshot)
                inverse.append((ChangeOperationKind.CREATE_RULE, state))
            elif kind is ChangeOperationKind.CREATE_OBJECT:
                native_id = _as_dict(operation.get("execution_result", {})).get(
                    "provider_resource_id"
                )
                object_id = (
                    self._repository.object_id_by_native(
                        UUID(str(operation["manager_id"])),
                        str(native_id),
                        principal.organization_id,
                    )
                    if native_id
                    else None
                )
                if object_id is None:
                    raise InvalidChangeSetStateError(
                        details={
                            "code": "ROLLBACK_RESOURCE_NOT_FOUND",
                            "operation": str(operation["id"]),
                        }
                    )
                if self._repository.object_revision(object_id, principal.organization_id) != 1:
                    raise InvalidChangeSetStateError(
                        details={"code": "ROLLBACK_CONFLICT", "resource_id": str(object_id)}
                    )
                inverse.append(
                    (
                        ChangeOperationKind.DELETE_OBJECT,
                        {"object_id": str(object_id), "object_type": payload.get("object_type")},
                    )
                )
            elif kind is ChangeOperationKind.MODIFY_OBJECT:
                object_id = state.get("resource_id") or payload.get("object_id")
                if not object_id or not state:
                    raise InvalidChangeSetStateError(
                        details={
                            "code": "ROLLBACK_SNAPSHOT_MISSING",
                            "operation": str(operation["id"]),
                        }
                    )
                require_unchanged("object", object_id, snapshot)
                inverse.append(
                    (ChangeOperationKind.MODIFY_OBJECT, {"object_id": str(object_id), **state})
                )
            elif kind is ChangeOperationKind.DELETE_OBJECT:
                if not state:
                    raise InvalidChangeSetStateError(
                        details={
                            "code": "ROLLBACK_SNAPSHOT_MISSING",
                            "operation": str(operation["id"]),
                        }
                    )
                require_unchanged("object", state.get("resource_id"), snapshot)
                inverse.append((ChangeOperationKind.CREATE_OBJECT, state))
        if not inverse:
            raise InvalidChangeSetStateError(details={"code": "ROLLBACK_NOT_SUPPORTED"})
        policy_id = UUID(str(original["access_policy_id"]))
        result = self.create(
            principal,
            active_group_id,
            policy_id,
            f"Rollback: {original['title']}",
            f"Compensating ChangeSet for {original['id']}; "
            "generated from application state snapshots.",
        )
        rollback_id = UUID(str(result["id"]))
        for kind, inverse_payload in inverse:
            self._repository.add_operation(
                principal, active_group_id, rollback_id, kind.value, inverse_payload
            )
        return self.preflight(principal, active_group_id, rollback_id)

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
        seen_rule_names: set[str] = set()
        for operation, result in zip(operations, results, strict=True):
            if str(operation["kind"]) != ChangeOperationKind.CREATE_RULE.value:
                continue
            resolution = cast("dict[str, object]", result.get("resolution", {}))
            provider_name = str(resolution.get("provider_name", "")).casefold()
            if provider_name and provider_name in seen_rule_names:
                result["status"] = OperationStatus.INVALID.value
                cast("list[dict[str, object]]", result["checks"]).append(
                    {
                        "operation": ChangeOperationKind.CREATE_RULE.value,
                        "element_type": "rule_name",
                        "element": "NOT_DISCLOSED",
                        "permission": "unique_provider_name",
                        "allowed": False,
                        "reason": "DUPLICATE_RULE_NAME_IN_CHANGE_SET",
                    }
                )
            seen_rule_names.add(provider_name)
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

    def approve(
        self, principal: Principal, active_group_id: UUID, change_set_id: UUID
    ) -> dict[str, object]:
        """Approve exactly the validated revision; edits invalidate this evidence."""
        require_action(principal, Action.APPROVE)
        current = self._load(principal, active_group_id, change_set_id)
        if current["state"] != ChangeSetState.READY.value:
            raise InvalidChangeSetStateError
        result = self._repository.approve_change_set(principal, active_group_id, change_set_id)
        self._audit_for(
            current,
            principal,
            "change_set_approved",
            "ALLOW",
            {
                "approved_revision": result.get("approved_revision"),
            },
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

    def queue_execution(
        self,
        principal: Principal,
        active_group_id: UUID,
        change_set_id: UUID,
        dispatch: Callable[[UUID, UUID, UUID, UUID], object],
    ) -> dict[str, object]:
        """Durably claim a validated ChangeSet and publish its security context."""
        change_set = self._load(principal, active_group_id, change_set_id)
        if (
            change_set["state"] != ChangeSetState.READY.value
            or change_set["validated_revision"] != change_set["revision"]
        ):
            raise InvalidChangeSetStateError(details={"required_state": ChangeSetState.READY.value})
        queued = self._repository.queue_execution(principal, active_group_id, change_set_id)
        self._audit_for(change_set, principal, "change_set_submitted", "QUEUED")
        self._repository.commit_change_set_queue()
        try:
            dispatch(change_set_id, principal.user_id, active_group_id, principal.organization_id)
        except Exception as exc:
            self._repository.set_execution_state(
                principal,
                active_group_id,
                change_set_id,
                ChangeSetState.FAILED.value,
                {},
                {"code": "QUEUE_PUBLISH_FAILED"},
            )
            self._audit_for(change_set, principal, "change_set_queue_failed", "FAILED")
            self._repository.commit_change_set_queue()
            raise InvalidChangeSetStateError(details={"code": "QUEUE_PUBLISH_FAILED"}) from exc
        return queued

    def retry_execution(
        self,
        principal: Principal,
        active_group_id: UUID,
        change_set_id: UUID,
        dispatch: Callable[[UUID, UUID, UUID, UUID], object],
    ) -> dict[str, object]:
        """Revalidate and requeue a failed submission only after a known non-mutating attempt."""
        change_set = self._load(principal, active_group_id, change_set_id)
        retryable_state = change_set["state"] in {
            ChangeSetState.FAILED.value,
            ChangeSetState.CONFLICT.value,
        }
        transactions = _as_dict_list(change_set.get("transactions", []))
        provider_attempted = bool(transactions)
        retry_safe = not provider_attempted or all(
            transaction.get("reconciliation_required") is False
            and bool(_as_dict_list(transaction.get("operation_results", [])))
            and all(
                result.get("mutated") is False
                and result.get("status") in {"SUCCEEDED", "FAILED", "CONFLICT", "NOT_ATTEMPTED"}
                for result in _as_dict_list(transaction.get("operation_results", []))
            )
            for transaction in transactions
        )
        operation_kinds = {
            str(operation["kind"]) for operation in _as_dict_list(change_set.get("operations", []))
        }
        interrupted_idempotent_create = (
            change_set["state"] == ChangeSetState.FAILED.value
            and _as_dict(change_set.get("failure_info", {})).get("code")
            == "CHANGE_SET_EXECUTION_ERROR"
            and bool(transactions)
            and operation_kinds
            <= {
                ChangeOperationKind.CREATE_OBJECT.value,
                ChangeOperationKind.ENSURE_RULE_CATEGORY.value,
                ChangeOperationKind.CREATE_RULE.value,
            }
            and all(
                transaction.get("state") == ProviderTransactionState.EXECUTING.value
                and not _as_dict_list(transaction.get("operation_results", []))
                for transaction in transactions
            )
        )
        if interrupted_idempotent_create:
            retry_safe = True
        # A category followed by a rejected rule is recoverable. Re-preflight resolves
        # the now-existing authoritative category, so the successful category operation
        # becomes a verified no-op and only the non-mutating rule create is attempted.
        if change_set["state"] == ChangeSetState.PARTIALLY_SUCCEEDED.value:
            operation_kinds = {
                str(operation["id"]): str(operation["kind"])
                for operation in _as_dict_list(change_set.get("operations", []))
            }
            results = [
                result
                for transaction in transactions
                for result in _as_dict_list(transaction.get("operation_results", []))
            ]
            retryable_state = bool(results) and all(
                (
                    result.get("status") == "SUCCEEDED"
                    and result.get("mutated") is True
                    and operation_kinds.get(str(result.get("operation_id")))
                    in {
                        ChangeOperationKind.ENSURE_RULE_CATEGORY.value,
                        ChangeOperationKind.CREATE_OBJECT.value,
                    }
                )
                or (
                    result.get("status") in {"FAILED", "CONFLICT", "NOT_ATTEMPTED"}
                    and result.get("mutated") is False
                )
                for result in results
            )
            retry_safe = retryable_state
        if not retryable_state or not retry_safe:
            self._audit_for(
                change_set,
                principal,
                "change_set_retry_denied",
                "DENY",
                {
                    "state": change_set["state"],
                    "provider_attempted": provider_attempted,
                    "retry_safe": retry_safe,
                },
            )
            raise InvalidChangeSetStateError(
                details={
                    "code": "CHANGE_SET_RETRY_UNSAFE",
                    "provider_attempted": provider_attempted,
                    "retry_safe": retry_safe,
                }
            )

        self._repository.set_execution_state(
            principal,
            active_group_id,
            change_set_id,
            ChangeSetState.DRAFT.value,
            {},
            {},
        )
        self._audit_for(change_set, principal, "change_set_retry_requested", "ALLOW")
        validated = self.preflight(principal, active_group_id, change_set_id)
        if validated["state"] != ChangeSetState.READY.value:
            failed = self._repository.set_execution_state(
                principal,
                active_group_id,
                change_set_id,
                ChangeSetState.FAILED.value,
                {},
                {
                    "code": "RETRY_PREFLIGHT_FAILED",
                    "validation_results": validated["validation_results"],
                },
            )
            self._audit_for(change_set, principal, "change_set_retry_failed", "DENY")
            return failed
        return self.queue_execution(
            principal,
            active_group_id,
            change_set_id,
            dispatch,
        )

    async def execute(  # noqa: PLR0912, PLR0915 -- explicit transaction outcome state machine
        self,
        principal: Principal,
        active_group_id: UUID,
        change_set_id: UUID,
        *,
        queued: bool = False,
        execution_owner: str | None = None,
    ) -> dict[str, object]:
        if queued and not (
            self._repository.claim_queued_execution(
                principal, active_group_id, change_set_id, execution_owner
            )
            if execution_owner is not None
            else self._repository.claim_queued_execution(principal, active_group_id, change_set_id)
        ):
            raise InvalidChangeSetStateError(details={"code": "CHANGE_SET_ALREADY_CLAIMED"})
        change_set = self._load(principal, active_group_id, change_set_id)
        if (
            change_set["state"]
            != (ChangeSetState.EXECUTING.value if queued else ChangeSetState.READY.value)
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

        # Grants and every element are re-evaluated immediately before the first mutation.
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
                ChangeSetState.FAILED.value,
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
            real_write_blocked = (
                target is not None
                and target.get("is_mock") is not True
                and (
                    target.get("write_enabled") is not True
                    or target.get("read_only") is not False
                    or target.get("lifecycle") != "ACTIVE"
                    or target.get("connection_status") != "CONNECTED"
                )
            )
            if target is None or real_write_blocked:
                self._audit_for(
                    change_set,
                    principal,
                    "production_write_blocked",
                    "DENY",
                    {"manager_id": str(manager_id)},
                )
                raise ProductionWriteDisabledError
            targets[manager_id] = target

        if not queued:
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
            if targets[manager_id].get("is_mock") is not True:
                pending = self._repository.upsert_provider_transaction(
                    change_set,
                    manager_id,
                    ProviderTransactionState.EXECUTING.value,
                    [],
                    {},
                    False,
                    real_transaction_operation_id(change_set_id, manager_id),
                )
                self._audit_for(
                    change_set,
                    principal,
                    "provider_transaction_created",
                    ProviderTransactionState.EXECUTING.value,
                    {
                        "manager_id": str(manager_id),
                        "transaction_id": str(pending["id"]),
                    },
                )
                self._repository.commit_provider_transaction_intent()
                current_target = self._repository.manager_execution_target(
                    manager_id, principal.organization_id
                )
                if current_target is None or (
                    current_target.get("write_enabled") is not True
                    or current_target.get("read_only") is not False
                    or current_target.get("lifecycle") != "ACTIVE"
                    or current_target.get("connection_status") != "CONNECTED"
                ):
                    raise ProductionWriteDisabledError
                targets[manager_id] = current_target
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
            if targets[manager_id].get("is_mock") is not True:
                self._repository.record_successful_write_evidence(
                    change_set,
                    principal,
                    manager_id,
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
            operation_kinds = {str(item["id"]): str(item["kind"]) for item in operations}
            for operation_result in outcome.operation_results:
                operation_id = str(operation_result.get("operation_id", ""))
                kind = operation_kinds.get(operation_id, "UNKNOWN")
                lifecycle_event = {
                    ChangeOperationKind.ENSURE_RULE_CATEGORY.value: "category_creation",
                    ChangeOperationKind.MOVE_RULE.value: "rule_reorder",
                    ChangeOperationKind.MODIFY_OBJECT.value: "owned_object_mutation",
                    ChangeOperationKind.DELETE_OBJECT.value: "owned_object_mutation",
                }.get(kind, "provider_operation_result")
                self._audit_for(
                    change_set,
                    principal,
                    lifecycle_event,
                    str(operation_result.get("status", "UNKNOWN")),
                    {
                        "manager_id": str(manager_id),
                        "transaction_id": str(transaction["id"]),
                        "operation_id": operation_id,
                        "operation_kind": kind,
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

    def delete_for_admin(self, principal: Principal, change_set_id: UUID) -> None:
        require_action(principal, Action.MANAGE_PROVIDERS)
        self._repository.delete_admin_change_set(principal, change_set_id)

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
            resolution = self._evaluate_rule(context, kind, payload, checks)
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

    def _evaluate_rule(  # noqa: PLR0912 -- explicit per-element authorization decisions
        self,
        context: DelegatedPolicyContext,
        kind: ChangeOperationKind,
        payload: dict[str, object],
        checks: list[dict[str, object]],
    ) -> dict[str, object]:
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
            return {}
        resolution: dict[str, object] = {}
        if kind is ChangeOperationKind.CREATE_RULE:
            data = self._repository.category_ensure_context(
                context.access_policy_id,
                context.active_group_id,
                context.principal.organization_id,
            )
            if data is None:
                raise ResourceOutOfScopeError
            provider = ProviderKind(str(data["provider"]))
            group_slug = str(data["group_slug"])
            requested_name = str(payload.get("name", "")).strip()
            prefix = f"{group_slug}__"
            if requested_name.startswith(prefix):
                requested_name = requested_name[len(prefix) :]
            provider_name = self._naming.provider_name(provider, group_slug, requested_name)
            category_provider_name = self._naming.category_name(provider, group_slug)
            allowed = provider_name is not None and category_provider_name is not None
            checks.append(
                {
                    "operation": kind.value,
                    "element_type": "rule_name",
                    "element": provider_name if allowed else "NOT_DISCLOSED",
                    "permission": "provider_naming",
                    "allowed": allowed,
                    "reason": "ALLOWED" if allowed else "PROVIDER_NAME_RESTRICTION",
                }
            )
            if allowed:
                resolution = {
                    "provider_name": provider_name,
                    "category_provider_name": category_provider_name,
                }
                mapping = data.get("mapping")
                if isinstance(mapping, dict) and mapping.get("category_id"):
                    typed_mapping = cast("dict[str, object]", mapping)
                    resolution["category_id"] = str(typed_mapping["category_id"])
        category_id = (
            self._required_uuid(payload, "category_id") if payload.get("category_id") else None
        )
        if category_id is not None:
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
        # Choosing the initial position of a new rule is part of CREATE.  REORDER
        # authorization is reserved for moving a rule that already exists.  The
        # ordering-boundary check below still confines creation to this group's
        # authoritative category and validates the requested anchor/position.
        if kind is ChangeOperationKind.MOVE_RULE or (
            kind is ChangeOperationKind.CREATE_RULE and payload.get("position") is not None
        ):
            position = payload.get("position")
            bounds = (
                self._repository.rule_ordering_bounds(
                    context.active_group_id,
                    context.access_policy_id,
                    category_id,
                    context.principal.organization_id,
                )
                if category_id is not None
                else None
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
            ("source_port_object_ids", "PORT_SERVICE"),
            ("destination_port_object_ids", "PORT_SERVICE"),
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
        return resolution

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
        group_base_type = {
            "NETWORK_GROUP": "NETWORK",
            "PORT_SERVICE_GROUP": "PORT_SERVICE",
            "URL_GROUP": "URL",
        }.get(object_type)
        if group_base_type is not None:
            return self._evaluate_group_object(
                context, payload, checks, naming, slug, object_type, group_base_type
            )
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

    def _evaluate_group_object(
        self,
        context: DelegatedPolicyContext,
        payload: dict[str, object],
        checks: list[dict[str, object]],
        naming: dict[str, object],
        slug: str,
        object_type: str,
        member_type: str,
    ) -> dict[str, object]:
        requested_name = str(payload.get("name", ""))
        prefix = requested_name.split("__", 1)[0] if "__" in requested_name else None
        prefix_ok = prefix is None or prefix == slug
        members = payload.get("member_object_ids")
        member_ids = [str(item) for item in members] if isinstance(members, list) else []
        candidates = _as_dict_list(naming["objects"])
        by_id = {str(item["object_id"]): item for item in candidates}
        selected = [by_id[item] for item in member_ids if item in by_id]
        members_ok = bool(member_ids) and len(selected) == len(member_ids)
        types_ok = members_ok and all(str(item["object_type"]) == member_type for item in selected)
        protocols = {
            str(item.get("normalized_value", "")).split("/", 1)[0].casefold()
            for item in selected
            if member_type == "PORT_SERVICE" and "/" in str(item.get("normalized_value", ""))
        }
        protocol_ok = len(protocols) <= 1
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
        for element, allowed, reason in (
            (
                "provider_name_prefix",
                prefix_ok,
                "ALLOWED" if prefix_ok else "GROUP_PREFIX_MISMATCH",
            ),
            (
                "group_members",
                members_ok,
                "ALLOWED" if members_ok else "GROUP_MEMBERS_REQUIRED",
            ),
            (
                "group_member_types",
                types_ok,
                "ALLOWED" if types_ok else "GROUP_MEMBER_TYPE_MISMATCH",
            ),
            (
                "group_protocols",
                protocol_ok,
                "ALLOWED" if protocol_ok else "PORT_GROUP_MIXED_PROTOCOLS",
            ),
        ):
            checks.append(
                {
                    "operation": ChangeOperationKind.CREATE_OBJECT.value,
                    "element_type": element,
                    "element": object_type,
                    "permission": "provider_group_constraints",
                    "allowed": allowed,
                    "reason": reason,
                }
            )
        for item in selected:
            self._append_decision(
                checks,
                ChangeOperationKind.CREATE_OBJECT,
                "group_member",
                str(item["object_id"]),
                self._authorization.authorize(
                    context,
                    Action.USE,
                    AuthorizationResource(
                        AuthorizationResourceType.OBJECT, UUID(str(item["object_id"]))
                    ),
                ),
            )
        component = requested_name.split("__", 1)[1] if prefix == slug else requested_name
        provider_name = self._naming.provider_name(
            ProviderKind(str(naming["provider"])), slug, component
        )
        return {
            "kind": NamingResolutionKind.NEW_OBJECT_REQUIRED.value,
            "requested_name": component,
            "provider_name": provider_name,
            "normalized_value": "",
            "member_object_ids": member_ids,
        }

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
            "NETWORK_GROUP",
            "PORT_SERVICE",
            "PORT_SERVICE_GROUP",
            "URL",
            "URL_GROUP",
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
