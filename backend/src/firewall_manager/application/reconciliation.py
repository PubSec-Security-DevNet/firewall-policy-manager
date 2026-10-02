"""Safe provider-drift reconciliation proposals."""

from typing import cast
from uuid import UUID

from firewall_manager.application.changesets import ChangeSetService
from firewall_manager.application.errors import InvalidInputError, ResourceOutOfScopeError
from firewall_manager.application.inventory import InventoryService
from firewall_manager.application.ports import (
    AuthorizationRepository,
    ChangeSetRepository,
    InventoryRepository,
)
from firewall_manager.domain.models import ChangeOperationKind, Principal
from firewall_manager.providers.transactions import HttpMockTransactionExecutor


class ReconciliationService:
    """Turn eligible application intent into a new ChangeSet, never a direct provider write."""

    def __init__(
        self,
        inventory: InventoryRepository,
        authorization: AuthorizationRepository,
        changesets: ChangeSetRepository,
    ) -> None:
        self._inventory = InventoryService(inventory)
        self._changesets = ChangeSetService(
            authorization, changesets, HttpMockTransactionExecutor()
        )

    def restore(
        self, principal: Principal, drift_id: UUID, active_group_id: UUID
    ) -> dict[str, object]:
        proposal = self._inventory.reconciliation_proposal(principal, drift_id)
        owner_group_id = UUID(str(proposal["owner_group_id"]))
        policy_id = UUID(str(proposal["policy_id"]))
        if owner_group_id != active_group_id:
            raise ResourceOutOfScopeError
        desired_value = proposal["desired"]
        if not isinstance(desired_value, dict):
            raise InvalidInputError
        desired = cast("dict[str, object]", desired_value)
        change_set_prefix = (
            "Recreate missing" if proposal.get("status") == "MISSING" else "Restore provider drift"
        )
        change_set = self._changesets.create(
            principal,
            active_group_id,
            policy_id,
            f"{change_set_prefix}: {proposal['resource_name']}",
            "Propose restoration of the application-managed state after provider reconciliation.",
        )
        change_set_id = UUID(str(change_set["id"]))
        is_missing = proposal.get("status") == "MISSING"
        if proposal["resource_type"] == "firewall_objects" and is_missing:
            payload = {
                "object_type": str(desired.get("object_type", "NETWORK")),
                "name": str(desired.get("name", proposal["resource_name"])),
                "value": str(desired.get("normalized_value", "")),
            }
            if isinstance(desired.get("member_object_ids"), list):
                payload["member_object_ids"] = desired["member_object_ids"]
            result = self._changesets.add_operation(
                principal,
                active_group_id,
                change_set_id,
                ChangeOperationKind.CREATE_OBJECT,
                payload,
            )
            action = "RECREATE_PROPOSED"
        elif proposal["resource_type"] == "firewall_objects":
            payload = {
                "object_id": str(proposal["resource_id"]),
                "object_type": str(desired.get("object_type", "NETWORK")),
                "name": str(desired.get("name", proposal["resource_name"])),
                "value": str(desired.get("normalized_value", "")),
            }
            result = self._changesets.add_operation(
                principal,
                active_group_id,
                change_set_id,
                ChangeOperationKind.MODIFY_OBJECT,
                payload,
            )
            action = "RESTORE_PROPOSED"
        elif is_missing:
            payload: dict[str, object] = {
                "name": str(desired.get("name", proposal["resource_name"])),
                "action": str(desired.get("action", "ALLOW")),
                "enabled": bool(desired.get("enabled", True)),
                "logging": str(desired.get("logging", "NONE")),
                "position": int(str(desired.get("position", 0))),
            }
            for key in (
                "category_id",
                "intrusion_policy_id",
                "variable_set_id",
                "file_policy_id",
                "source_zone_ids",
                "destination_zone_ids",
                "source_object_ids",
                "destination_object_ids",
                "source_port_object_ids",
                "destination_port_object_ids",
                "application_object_ids",
                "url_object_ids",
            ):
                if key in desired:
                    payload[key] = desired[key]
            result = self._changesets.add_operation(
                principal, active_group_id, change_set_id, ChangeOperationKind.CREATE_RULE, payload
            )
            action = "RECREATE_PROPOSED"
        else:
            payload: dict[str, object] = {
                "rule_id": str(proposal["resource_id"]),
            }
            for key in (
                "name",
                "action",
                "enabled",
                "logging",
                "position",
                "category_id",
                "intrusion_policy_id",
                "variable_set_id",
                "file_policy_id",
                "source_zone_ids",
                "destination_zone_ids",
                "source_object_ids",
                "destination_object_ids",
                "source_port_object_ids",
                "destination_port_object_ids",
                "application_object_ids",
                "url_object_ids",
            ):
                if key in desired:
                    payload[key] = desired[key]
            payload.setdefault("name", proposal["resource_name"])
            payload.setdefault("action", "ALLOW")
            payload.setdefault("position", 0)
            result = self._changesets.add_operation(
                principal, active_group_id, change_set_id, ChangeOperationKind.MODIFY_RULE, payload
            )
            action = "RESTORE_PROPOSED"
        return {
            "action": action,
            "drift_id": drift_id,
            "state": str(result.get("state", "DRAFT")),
            "change_set_id": result["id"],
        }
