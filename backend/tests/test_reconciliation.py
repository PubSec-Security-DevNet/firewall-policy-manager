# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""ChangeSet-only restore and recreate proposals."""

from uuid import UUID, uuid4

from firewall_manager.application.reconciliation import ReconciliationService
from firewall_manager.domain.models import ChangeOperationKind, Principal

ORG = UUID("10000000-0000-0000-0000-000000000001")
USER = UUID("30000000-0000-0000-0000-000000000001")
GROUP = UUID("20000000-0000-0000-0000-000000000002")
POLICY = UUID("50000000-0000-0000-0000-000000000001")


class InventoryRepositoryFake:
    def __init__(self, proposal: dict[str, object]) -> None:
        self.proposal = proposal

    def reconciliation_proposal(self, organization_id: UUID, drift_id: UUID) -> dict[str, object]:
        assert organization_id == ORG
        return self.proposal


class ChangeSetSpy:
    def __init__(self) -> None:
        self.operations: list[tuple[ChangeOperationKind, dict[str, object]]] = []

    def create(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        return {"id": str(uuid4())}

    def add_operation(
        self,
        _principal: Principal,
        _group_id: UUID,
        _change_set_id: UUID,
        kind: ChangeOperationKind,
        payload: dict[str, object],
    ) -> dict[str, object]:
        self.operations.append((kind, payload))
        return {"id": str(uuid4()), "state": "DRAFT"}


def _service(proposal: dict[str, object]) -> tuple[ReconciliationService, ChangeSetSpy]:
    service = ReconciliationService(  # type: ignore[arg-type]
        InventoryRepositoryFake(proposal),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
    )
    spy = ChangeSetSpy()
    service._changesets = spy  # type: ignore[reportPrivateUsage]
    return service, spy


def _proposal(resource_type: str, status: str) -> dict[str, object]:
    return {
        "resource_type": resource_type,
        "resource_id": uuid4(),
        "resource_name": "ENGINEERING__rule",
        "owner_group_id": GROUP,
        "policy_id": POLICY,
        "status": status,
        "desired": {
            "name": "ENGINEERING__rule",
            "action": "ALLOW",
            "enabled": False,
            "logging": "BEGIN",
            "position": 4,
            "category_id": str(uuid4()),
            "intrusion_policy_id": str(uuid4()),
            "variable_set_id": str(uuid4()),
            "file_policy_id": str(uuid4()),
            "source_zone_ids": [str(uuid4())],
            "destination_zone_ids": [str(uuid4())],
            "source_object_ids": [str(uuid4())],
            "destination_object_ids": [str(uuid4())],
            "source_port_object_ids": [str(uuid4())],
            "destination_port_object_ids": [str(uuid4())],
            "application_object_ids": [str(uuid4())],
            "url_object_ids": [str(uuid4())],
        },
    }


def test_drift_restore_creates_complete_rule_changeset_operation() -> None:
    service, spy = _service(_proposal("access_rules", "DRIFTED"))

    result = service.restore(Principal(USER, ORG, "admin@example.test", "admin"), uuid4(), GROUP)

    assert result["action"] == "RESTORE_PROPOSED"
    kind, payload = spy.operations[0]
    assert kind is ChangeOperationKind.MODIFY_RULE
    assert payload["enabled"] is False
    assert payload["logging"] == "BEGIN"
    assert payload["application_object_ids"]
    assert payload["file_policy_id"]


def test_missing_object_creates_recreate_changeset_operation() -> None:
    proposal = _proposal("firewall_objects", "MISSING")
    proposal["desired"] = {
        "name": "ENGINEERING__network-group",
        "object_type": "NETWORK_GROUP",
        "normalized_value": "",
        "member_object_ids": [str(uuid4())],
    }
    service, spy = _service(proposal)

    result = service.restore(Principal(USER, ORG, "admin@example.test", "admin"), uuid4(), GROUP)

    assert result["action"] == "RECREATE_PROPOSED"
    kind, payload = spy.operations[0]
    assert kind is ChangeOperationKind.CREATE_OBJECT
    assert payload["object_type"] == "NETWORK_GROUP"
    assert payload["member_object_ids"]
