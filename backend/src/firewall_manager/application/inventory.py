"""Organization-scoped read-only inventory application service."""

import base64
import binascii
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from firewall_manager.application.authorization import require_action
from firewall_manager.application.errors import InvalidPaginationError, ResourceOutOfScopeError
from firewall_manager.application.ports import InventoryRepository
from firewall_manager.domain.models import Action, Principal


@dataclass(frozen=True, slots=True)
class InventoryPage:
    """Bounded REST-facing page without exposing database offsets."""

    items: list[dict[str, object]]
    total: int
    next_cursor: str | None


def _decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    try:
        value = int(base64.urlsafe_b64decode(cursor.encode()).decode())
        if value < 0:
            raise ValueError
        return value
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise InvalidPaginationError from exc


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(str(offset).encode()).decode()


class InventoryService:
    """Authorize and serve normalized inventory from persistence only."""

    def __init__(self, repository: InventoryRepository) -> None:
        self._repository = repository

    def _page(
        self,
        principal: Principal,
        cursor: str | None,
        limit: int,
        loader: Callable[[int, int], tuple[list[dict[str, object]], int]],
    ) -> InventoryPage:
        require_action(principal, Action.READ)
        if not 1 <= limit <= 100:
            raise InvalidPaginationError
        offset = _decode_cursor(cursor)
        items, total = loader(offset, limit)
        next_offset = offset + len(items)
        next_cursor = _encode_cursor(next_offset) if next_offset < total else None
        return InventoryPage(items, total, next_cursor)

    def managers(self, principal: Principal, cursor: str | None, limit: int) -> InventoryPage:
        return self._page(
            principal,
            cursor,
            limit,
            lambda offset, size: self._repository.list_managers(
                principal.organization_id, offset, size
            ),
        )

    def policies(
        self, principal: Principal, manager_id: UUID | None, cursor: str | None, limit: int
    ) -> InventoryPage:
        return self._page(
            principal,
            cursor,
            limit,
            lambda offset, size: self._repository.list_policies(
                principal.organization_id, manager_id, offset, size
            ),
        )

    def rules(
        self, principal: Principal, policy_id: UUID | None, cursor: str | None, limit: int
    ) -> InventoryPage:
        return self._page(
            principal,
            cursor,
            limit,
            lambda offset, size: self._repository.list_rules(
                principal.organization_id, policy_id, offset, size
            ),
        )

    def objects(
        self, principal: Principal, manager_id: UUID | None, cursor: str | None, limit: int
    ) -> InventoryPage:
        return self._page(
            principal,
            cursor,
            limit,
            lambda offset, size: self._repository.list_objects(
                principal.organization_id, manager_id, offset, size
            ),
        )

    def provider_status(self, principal: Principal) -> list[dict[str, object]]:
        require_action(principal, Action.READ)
        return self._repository.provider_status(principal.organization_id)

    def synchronization_discrepancies(  # noqa: PLR0913, PLR0917 -- explicit filter scope
        self,
        principal: Principal,
        manager_id: UUID | None,
        policy_id: UUID | None,
        resource_type: str | None,
        state: str | None,
        connection_id: UUID | None,
    ) -> list[dict[str, object]]:
        require_action(principal, Action.READ)
        return self._repository.synchronization_discrepancies(
            principal.organization_id, manager_id, policy_id, resource_type, state, connection_id
        )

    def accept_provider_state(self, principal: Principal, drift_id: UUID) -> dict[str, object]:
        require_action(principal, Action.MANAGE_PROVIDERS)
        result = self._repository.accept_provider_state(
            principal.organization_id, drift_id, principal.user_id
        )
        if result is None:
            raise ResourceOutOfScopeError
        return result

    def reconciliation_proposal(self, principal: Principal, drift_id: UUID) -> dict[str, object]:
        require_action(principal, Action.RECONCILE)
        result = self._repository.reconciliation_proposal(principal.organization_id, drift_id)
        if result is None:
            raise ResourceOutOfScopeError
        return result
