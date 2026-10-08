# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Adversarial OIDC and uncertain-deployment regression tests."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256

from firewall_manager.application.deployments import (
    DeploymentService,
    is_definitive_provider_rejection,
    resolve_device_names,
)
from firewall_manager.application.errors import (
    InvalidChangeSetStateError,
    NotAuthenticatedError,
    ResourceOutOfScopeError,
)
from firewall_manager.application.inventory import InventoryService
from firewall_manager.application.naming import provider_native_id_equal
from firewall_manager.config import OidcProviderConfig, get_settings
from firewall_manager.domain.models import Principal
from firewall_manager.persistence.models import Deployment
from firewall_manager.persistence.repositories import (
    SqlAuthorizationRepository,
    _deployment_rule_resource_id,
)
from firewall_manager.security.api_tokens import authenticate
from firewall_manager.security.oidc import OidcService, _b64


@pytest.mark.parametrize(
    "change",
    [
        {"issued_at": 0},
        {"issued_at": float("nan")},
        {"issued_at": "now"},
        {"provider": "other"},
        {"nonce": ""},
        {"issued_at": datetime.now(UTC).timestamp() + 3600},
    ],
)
def test_oidc_state_is_bound_to_provider_and_server_expiry(change) -> None:
    state = {"issued_at": datetime.now(UTC).timestamp(), "provider": "test", "nonce": "nonce"}
    OidcService._validate_state_payload(state, "test")
    with pytest.raises(NotAuthenticatedError):
        OidcService._validate_state_payload({**state, **change}, "test")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"aud": ["client", "other"]},
        {"azp": "other"},
        {"exp": float("nan")},
        {"exp": "tomorrow"},
        {"exp": 0},
        {"sub": ""},
        {"sub": 123},
        {"nbf": 999999999999},
        {"iat": 999999999999},
        {"iss": "https://other.example/"},
        {"nonce": "other"},
        {"aud": "other"},
    ],
)
async def test_signed_oidc_tokens_with_invalid_claims_are_rejected(monkeypatch, change) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kid": "test",
                "kty": "RSA",
                "n": _b64(numbers.n.to_bytes(256, "big")),
                "e": _b64(numbers.e.to_bytes(3, "big")),
            }
        ]
    }
    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original_client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=jwks)), **kwargs
        ),
    )
    provider = OidcProviderConfig(
        id="test",
        kind="generic",
        display_name="Test",
        issuer_url="https://id.example/",
        client_id="client",
        client_secret="test-only",  # noqa: S106 -- synthetic signing fixture
    )
    service = OidcService(MagicMock(), get_settings())
    now = datetime.now(UTC).timestamp()
    claims = {
        "iss": str(provider.issuer_url),
        "sub": "stable",
        "aud": "client",
        "exp": now + 300,
        "iat": now - 1,
        "nonce": "nonce",
    }

    def token(values):
        header = _b64(json.dumps({"alg": "RS256", "kid": "test"}).encode())
        body = _b64(json.dumps(values).encode())
        signature = key.sign(f"{header}.{body}".encode(), PKCS1v15(), SHA256())
        return f"{header}.{body}.{_b64(signature)}"

    assert (
        await service._validate_id_token(
            token(claims), {"jwks_uri": "https://id.example/keys"}, provider, "nonce"
        )
    )["sub"] == "stable"
    with pytest.raises(NotAuthenticatedError):
        await service._validate_id_token(
            token({**claims, **change}), {"jwks_uri": "https://id.example/keys"}, provider, "nonce"
        )


@pytest.mark.parametrize(
    ("state", "task", "intent"),
    [
        ("RECONCILIATION_REQUIRED", None, False),
        ("UNKNOWN", None, False),
        ("FAILED", "accepted-task", False),
        ("FAILED", None, True),
    ],
)
def test_uncertain_deployment_cannot_be_retried(state, task, intent) -> None:
    session = MagicMock()
    row = Deployment(
        state=state, external_operation_id=task, plan_snapshot={"start_intent": intent}
    )
    session.scalar.return_value = row
    principal = Principal(uuid4(), uuid4(), "admin@example.test", "admin")
    with pytest.raises(InvalidChangeSetStateError, match="ChangeSet"):
        DeploymentService(session).retry(principal, uuid4())
    assert row.state == state
    assert row.external_operation_id == task


def test_deployment_without_provider_task_is_not_rollback_eligible() -> None:
    service = DeploymentService(MagicMock())
    row = Deployment(state="DEPLOYED", external_operation_id=None)

    assert service._rollback_eligibility(row) == (
        False,
        "The provider deployment task is unavailable.",
    )


def test_provider_validation_rejection_is_definitive_and_retryable() -> None:
    assert is_definitive_provider_rejection(
        {"provider_code": "PROVIDER_VALIDATION_ERROR", "provider_status": 400}
    )
    assert not is_definitive_provider_rejection(
        {"provider_code": "PROVIDER_DEPLOYMENT_START_UNCERTAIN", "provider_status": 400}
    )


def test_deployment_rule_state_uses_resolved_provider_name_for_prefixed_rules() -> None:
    rule_id = uuid4()
    operation = SimpleNamespace(
        payload={"name": "test"},
        resolution={"provider_name": "INFOTECH__test"},
        execution_result={"provider_resource_id": "provider-rule"},
    )
    rule = SimpleNamespace(id=rule_id, name="INFOTECH__test", native_id="provider-rule")

    assert _deployment_rule_resource_id(operation, [rule]) == rule_id


def test_provider_native_policy_ids_are_case_insensitive() -> None:
    assert provider_native_id_equal(
        "0EC35D91-7A63-0ed3-0000-004294967346",
        "0ec35d91-7a63-0ed3-0000-004294967346",
    )
    assert not provider_native_id_equal("policy-a", "policy-b")


def test_deployment_device_name_resolves_provider_native_alias() -> None:
    device = SimpleNamespace(
        native_id="local-device-id",
        name="nciesins-home-1200",
        native_metadata={"provider_native_id": "e4f05f5c-08e7-11f0-84d0-deee5ffea7d3"},
    )

    assert resolve_device_names([device], {"e4f05F5C-08E7-11F0-84D0-DEEE5FFEA7D3"}) == {
        "e4f05F5C-08E7-11F0-84D0-DEEE5FFEA7D3": "nciesins-home-1200"
    }


def test_newer_pending_deployment_does_not_inherit_older_deployed_rule_state() -> None:
    manager_id = uuid4()
    policy_id = uuid4()
    rule_id = uuid4()
    newest_change_set = uuid4()
    older_change_set = uuid4()
    rule = SimpleNamespace(
        id=rule_id,
        name="INFOTECH__test2",
        native_id="provider-rule",
        management_state="MANAGED",
    )
    pending_operation = SimpleNamespace(
        kind="MOVE_RULE",
        payload={"rule_id": str(rule_id)},
        resolution={},
        execution_result={},
        change_set_id=newest_change_set,
    )
    deployed_operation = SimpleNamespace(
        kind="MODIFY_RULE",
        payload={"rule_id": str(rule_id)},
        resolution={},
        execution_result={},
        change_set_id=older_change_set,
    )
    session = MagicMock()
    session.scalars.side_effect = [
        [
            Deployment(
                state="SCHEDULED",
                included_change_set_ids=[str(newest_change_set)],
            ),
            Deployment(
                state="DEPLOYED",
                included_change_set_ids=[str(older_change_set)],
            ),
        ],
        [pending_operation, deployed_operation],
    ]

    states = SqlAuthorizationRepository(session)._firewall_resource_states(
        manager_id, policy_id, [rule], [], True
    )

    assert states[rule_id] == "UNDEPLOYED"


@pytest.mark.parametrize("raw", ["fm_非ascii", "Bearer invalid", "fm_" + "a" * 300])
def test_malformed_api_tokens_fail_authentication_without_database_lookup(raw: str) -> None:
    session = MagicMock()
    assert authenticate(session, raw) is None
    session.scalar.assert_not_called()


@pytest.mark.parametrize("role", ["user", "approver", "firewall_operator"])
def test_accept_provider_state_cannot_be_authorized_by_supplied_group_id(role: str) -> None:
    repository = MagicMock()
    principal = Principal(uuid4(), uuid4(), "user@example.test", role)
    with pytest.raises(ResourceOutOfScopeError):
        InventoryService(repository).accept_provider_state(principal, uuid4(), uuid4())
    repository.accept_provider_state.assert_not_called()
