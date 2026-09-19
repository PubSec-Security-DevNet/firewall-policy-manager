"""Negative and positive authorization behavior."""

from uuid import UUID

import pytest

from firewall_manager.application.authorization import require_action
from firewall_manager.application.errors import ResourceOutOfScopeError
from firewall_manager.domain.models import Action, DelegatedPolicyContext, Principal


def principal(role: str) -> Principal:
    return Principal(
        user_id=UUID("30000000-0000-0000-0000-000000000001"),
        organization_id=UUID("10000000-0000-0000-0000-000000000001"),
        email="user@example.test",
        role=role,
    )


def test_viewer_can_read_but_cannot_modify() -> None:
    require_action(principal("viewer"), Action.READ)
    with pytest.raises(ResourceOutOfScopeError):
        require_action(principal("viewer"), Action.MODIFY)


def test_unknown_role_is_denied_by_default() -> None:
    with pytest.raises(ResourceOutOfScopeError):
        require_action(principal("invented-role"), Action.READ)


def test_delegated_context_selects_exactly_one_group_and_policy() -> None:
    user = principal("editor")
    policy_id = UUID("50000000-0000-0000-0000-000000000001")
    finance = DelegatedPolicyContext(user, UUID("20000000-0000-0000-0000-000000000001"), policy_id)
    engineering = DelegatedPolicyContext(
        user, UUID("20000000-0000-0000-0000-000000000002"), policy_id
    )
    assert finance.principal == engineering.principal
    assert finance.access_policy_id == engineering.access_policy_id
    assert finance.active_group_id != engineering.active_group_id
