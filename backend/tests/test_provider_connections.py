# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Provider-connection authorization, isolation, lifecycle, and persistence regressions."""

import asyncio
import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Table, create_engine, event, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session

from firewall_manager.application.errors import (
    InvalidChangeSetStateError,
    InvalidInputError,
    ResourceOutOfScopeError,
    StaleWriteError,
)
from firewall_manager.application.provider_connections import ProviderConnectionService
from firewall_manager.domain.models import CapabilityStatus, Principal, ProviderCapability
from firewall_manager.persistence.changesets import SqlChangeSetRepository
from firewall_manager.persistence.models import (
    AuditEvent,
    Base,
    FirewallManager,
    Organization,
    ProviderCapabilityEvidence,
    ProviderConnection,
    ProviderConnectionScope,
    ProviderDomain,
    SecretRecord,
    User,
)
from firewall_manager.persistence.provider_connections import SqlProviderConnectionRepository
from firewall_manager.persistence.repositories import SqlAuthorizationRepository
from firewall_manager.persistence.secrets import EncryptedDatabaseSecretStore


@compiles(JSONB, "sqlite")
def _compile_jsonb_for_sqlite(_element: JSONB, _compiler: Any, **_kwargs: object) -> str:
    return "JSON"


ORG = UUID("10000000-0000-0000-0000-000000000001")
OTHER_ORG = UUID("10000000-0000-0000-0000-000000000002")
ADMIN = UUID("30000000-0000-0000-0000-000000000001")
OTHER_ADMIN = UUID("30000000-0000-0000-0000-000000000002")
NORMAL_USER = UUID("30000000-0000-0000-0000-000000000003")
GROUP_ADMIN = UUID("30000000-0000-0000-0000-000000000004")


def _principal(user_id: UUID, organization_id: UUID, role: str) -> Principal:
    return Principal(user_id, organization_id, f"{user_id}@example.test", role)


def _session(path: Path) -> Session:
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    tables = [
        Organization.__table__,
        User.__table__,
        SecretRecord.__table__,
        ProviderConnection.__table__,
        FirewallManager.__table__,
        ProviderConnectionScope.__table__,
        ProviderCapabilityEvidence.__table__,
        ProviderDomain.__table__,
        AuditEvent.__table__,
    ]
    Base.metadata.create_all(engine, tables=[cast(Table, table) for table in tables])
    session = Session(engine)
    session.add_all(
        [
            Organization(id=ORG, name="Primary"),
            Organization(id=OTHER_ORG, name="Other"),
            User(
                id=ADMIN,
                organization_id=ORG,
                identity_issuer="test",
                identity_subject="admin",
                email="admin@example.test",
                display_name="Admin",
                role="admin",
            ),
            User(
                id=OTHER_ADMIN,
                organization_id=OTHER_ORG,
                identity_issuer="test",
                identity_subject="other-admin",
                email="other-admin@example.test",
                display_name="Other Admin",
                role="admin",
            ),
            User(
                id=NORMAL_USER,
                organization_id=ORG,
                identity_issuer="test",
                identity_subject="normal",
                email="normal@example.test",
                display_name="Normal User",
                role="user",
            ),
            User(
                id=GROUP_ADMIN,
                organization_id=ORG,
                identity_issuer="test",
                identity_subject="group-admin",
                email="group-admin@example.test",
                display_name="Group Admin",
                role="user",
            ),
        ]
    )
    session.commit()
    return session


def _service(session: Session) -> ProviderConnectionService:
    key = base64.b64encode(os.urandom(32)).decode()
    return ProviderConnectionService(
        SqlAuthorizationRepository(session),
        SqlProviderConnectionRepository(session),
        EncryptedDatabaseSecretStore(session, key, 1),
    )


def _connections(
    service: ProviderConnectionService, principal: Principal, session: Session
) -> list[dict[str, object]]:
    values: list[dict[str, object]] = [
        {
            "provider_type": "fmc",
            "display_name": "FMC A",
            "base_endpoint": "https://fmc-a.example.test",
            "username": "api-a",
            "password": "password-a",
        },
        {
            "provider_type": "fmc",
            "display_name": "FMC B",
            "base_endpoint": "https://fmc-b.example.test",
            "username": "api-b",
            "password": "password-b",
        },
        {
            "provider_type": "scc",
            "display_name": "SCC A",
            "region": "us",
            "token": "token-a",
        },
        {
            "provider_type": "scc",
            "display_name": "SCC B",
            "region": "eu",
            "token": "token-b",
        },
    ]
    created: list[dict[str, object]] = []
    for value in values:
        created.append(service.create(principal, value))
        # Each creation represents its own request transaction in production.
        session.commit()
    return created


def test_connection_flushes_parent_before_manager_foreign_key(tmp_path: Path) -> None:
    session = _session(tmp_path / "flush-order.sqlite")
    service = _service(session)
    flush_stages: list[set[type[object]]] = []

    def capture_new_rows(flushing_session: Session, *_args: object) -> None:
        flush_stages.append({type(item) for item in flushing_session.new})

    event.listen(session, "before_flush", capture_new_rows)
    service.create(
        _principal(ADMIN, ORG, "admin"),
        {
            "provider_type": "scc",
            "display_name": "SCC flush ordering",
            "region": "us",
            "token": "write-only-test-token",
        },
    )

    connection_stage = next(
        index for index, stage in enumerate(flush_stages) if ProviderConnection in stage
    )
    manager_stage = next(
        index for index, stage in enumerate(flush_stages) if FirewallManager in stage
    )
    assert connection_stage < manager_stage
    assert FirewallManager not in flush_stages[connection_stage]


def test_real_write_gate_requires_acknowledgement_and_tested_version_evidence(
    tmp_path: Path,
) -> None:
    session = _session(tmp_path / "write-gate.sqlite")
    service = _service(session)
    principal = _principal(ADMIN, ORG, "admin")
    created = service.create(
        principal,
        {
            "provider_type": "fmc",
            "display_name": "Guarded FMC",
            "base_endpoint": "https://fmc-write.example.test",
            "username": "api-write",
            "password": "write-only-test-password",
        },
    )
    connection_id = UUID(str(created["id"]))
    connection = session.get(ProviderConnection, connection_id)
    assert connection is not None
    manager = session.scalar(
        select(FirewallManager).where(FirewallManager.provider_connection_id == connection_id)
    )
    assert manager is not None
    connection.lifecycle = "ACTIVE"
    connection.connection_status = "CONNECTED"
    connection.provider_version = "7.7.0-test"
    session.add_all(
        [
            ProviderCapabilityEvidence(
                organization_id=ORG,
                connection_id=connection_id,
                provider_version="7.7.0-test",
                capability=capability.value,
                status="SUPPORTED",
                evidence_level="TESTED",
                evidence_summary="Approved isolated non-production contract test.",
                tested_at=datetime.now(UTC),
            )
            for capability in (
                ProviderCapability.ACCESS_RULE_CREATE,
                ProviderCapability.PENDING_CHANGE_INSPECTION,
            )
        ]
    )
    session.commit()

    with pytest.raises(InvalidInputError):
        service.set_write_enabled(
            principal, connection_id, connection.revision, True, acknowledged=False
        )
    enabled = service.set_write_enabled(
        principal, connection_id, connection.revision, True, acknowledged=True
    )
    assert enabled["write_enabled"] is True
    assert manager.read_only is False
    session.commit()
    disabled = service.set_write_enabled(
        principal, connection_id, int(str(enabled["revision"])), False, acknowledged=False
    )
    assert disabled["write_enabled"] is False
    assert manager.read_only is True


def test_successful_live_mutation_promotes_version_specific_write_evidence(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    session = _session(tmp_path / "live-write-evidence.sqlite")
    service = _service(session)
    principal = _principal(ADMIN, ORG, "admin")
    created = service.create(
        principal,
        {
            "provider_type": "scc",
            "display_name": "Validated SCC",
            "region": "us",
            "token": "write-only-test-token",
        },
    )
    connection_id = UUID(str(created["id"]))
    connection = session.get(ProviderConnection, connection_id)
    manager = session.scalar(
        select(FirewallManager).where(FirewallManager.provider_connection_id == connection_id)
    )
    assert connection is not None
    assert manager is not None
    connection.lifecycle = "ACTIVE"
    connection.connection_status = "CONNECTED"
    connection.provider_version = "10.0-test"
    connection.write_enabled = True
    manager.provider_version = connection.provider_version
    manager.read_only = False
    session.add_all(
        ProviderCapabilityEvidence(
            organization_id=ORG,
            connection_id=connection_id,
            provider_version=connection.provider_version,
            capability=capability,
            status="PARTIAL",
            evidence_level="NOT_STARTED",
            evidence_summary="Awaiting live validation.",
        )
        for capability in ("access_rule_create", "pending_change_inspection")
    )
    session.flush()

    operation_id = uuid4()
    promoted = SqlChangeSetRepository(session).record_successful_write_evidence(
        {"id": uuid4()},
        principal,
        manager.id,
        [{"id": operation_id, "kind": "CREATE_RULE", "payload": {}}],
        [{"operation_id": str(operation_id), "status": "SUCCEEDED", "mutated": True}],
    )
    session.commit()

    assert promoted == {"access_rule_create", "pending_change_inspection"}
    visible = service.get(principal, connection_id)
    assert visible["write_validation_mode"] is False
    assert manager.capabilities["access_rule_create"] == "SUPPORTED"
    assert session.scalar(
        select(AuditEvent).where(AuditEvent.reason_code == "live_write_capabilities_tested")
    )

    sibling = service.create(
        principal,
        {
            "provider_type": "scc",
            "display_name": "Second SCC",
            "region": "eu",
            "token": "second-write-only-token",
        },
    )
    sibling_row = session.get(ProviderConnection, UUID(str(sibling["id"])))
    assert sibling_row is not None
    sibling_row.lifecycle = "ACTIVE"
    sibling_row.connection_status = "CONNECTED"
    sibling_row.provider_version = "10.0.200"
    session.commit()
    sibling_visible = service.get(principal, sibling_row.id)
    assert sibling_visible["version_family_tested"] is True
    assert sibling_visible["compatibility_warning"] is None

    SqlProviderConnectionRepository(session).record_connection_test(
        ORG,
        ADMIN,
        connection_id,
        {"status": "CONNECTED", "provider_version": "10.0.97 (build 2)"},
        {
            "access_rule_create": "PARTIAL",
            "pending_change_inspection": "PARTIAL",
        },
        [],
    )
    session.commit()
    retained = list(
        session.scalars(
            select(ProviderCapabilityEvidence).where(
                ProviderCapabilityEvidence.connection_id == connection_id,
                ProviderCapabilityEvidence.provider_version == "10.0.97 (build 2)",
            )
        )
    )
    assert {(item.capability, item.status, item.evidence_level) for item in retained} == {
        ("access_rule_create", "SUPPORTED", "TESTED"),
        ("pending_change_inspection", "SUPPORTED", "TESTED"),
    }
    assert connection.write_enabled is True
    assert manager.read_only is False
    assert service.get(principal, connection_id)["write_validation_mode"] is False

    SqlProviderConnectionRepository(session).record_connection_test(
        ORG,
        ADMIN,
        connection_id,
        {"status": "CONNECTED", "provider_version": "10.1.0"},
        {
            "access_rule_create": "PARTIAL",
            "pending_change_inspection": "PARTIAL",
        },
        [],
    )
    session.commit()
    assert connection.write_enabled is True
    assert manager.read_only is False
    unsupported_family = service.get(principal, connection_id)
    assert unsupported_family["version_family_tested"] is False
    assert "10.1.x has not been write-tested" in str(unsupported_family["compatibility_warning"])
    new_family = list(
        session.scalars(
            select(ProviderCapabilityEvidence).where(
                ProviderCapabilityEvidence.connection_id == connection_id,
                ProviderCapabilityEvidence.provider_version == "10.1.0",
            )
        )
    )
    assert {(item.status, item.evidence_level) for item in new_family} == {
        ("PARTIAL", "NOT_STARTED")
    }


def test_production_write_gate_allows_an_untested_provider_version_with_warning(
    tmp_path: Path,
) -> None:
    session = _session(tmp_path / "validation-write-gate.sqlite")
    service = _service(session)
    principal = _principal(ADMIN, ORG, "admin")
    created = service.create(
        principal,
        {
            "provider_type": "fmc",
            "display_name": "Non-production FMC",
            "base_endpoint": "https://fmc-validation.example.test",
            "username": "api-validation",
            "password": "validation-only-test-password",
        },
    )
    connection_id = UUID(str(created["id"]))
    connection = session.get(ProviderConnection, connection_id)
    assert connection is not None
    manager = session.scalar(
        select(FirewallManager).where(FirewallManager.provider_connection_id == connection_id)
    )
    assert manager is not None
    connection.lifecycle = "ACTIVE"
    connection.connection_status = "CONNECTED"
    connection.provider_version = "7.7.0-validation"
    manager.capabilities = {
        ProviderCapability.ACCESS_RULE_CREATE.value: "PARTIAL",
        ProviderCapability.PENDING_CHANGE_INSPECTION.value: "PARTIAL",
    }
    session.add_all(
        [
            ProviderCapabilityEvidence(
                organization_id=ORG,
                connection_id=connection_id,
                provider_version="7.7.0-validation",
                capability=capability.value,
                status="PARTIAL",
                evidence_level="NOT_STARTED",
                evidence_summary="Implemented but not validated against this provider version.",
            )
            for capability in (
                ProviderCapability.ACCESS_RULE_CREATE,
                ProviderCapability.PENDING_CHANGE_INSPECTION,
            )
        ]
    )
    session.commit()

    enabled = service.set_write_enabled(
        principal,
        connection_id,
        connection.revision,
        True,
        acknowledged=True,
    )

    assert enabled["write_enabled"] is True
    assert enabled["write_validation_mode"] is False
    assert enabled["version_family_tested"] is False
    assert "7.7.x has not been write-tested" in str(enabled["compatibility_warning"])
    assert manager.read_only is False
    assert manager.capabilities[ProviderCapability.ACCESS_RULE_CREATE.value] == "PARTIAL"
    assert session.scalar(
        select(AuditEvent.id).where(
            AuditEvent.resource_id == connection_id,
            AuditEvent.reason_code == "provider_writes_enabled",
        )
    )
    change_sets = SqlChangeSetRepository(session)
    assert (
        change_sets.provider_capability_state(
            manager.id,
            ProviderCapability.ACCESS_RULE_CREATE.value,
            ORG,
        )
        == "SUPPORTED"
    )
    session.commit()
    disabled = service.set_write_enabled(
        principal,
        connection_id,
        int(str(enabled["revision"])),
        False,
        acknowledged=False,
    )
    assert disabled["write_enabled"] is False
    assert (
        change_sets.provider_capability_state(
            manager.id,
            ProviderCapability.ACCESS_RULE_CREATE.value,
            ORG,
        )
        == "PARTIAL"
    )


@pytest.mark.asyncio
async def test_connection_probe_phase_runs_reads_concurrently() -> None:
    capabilities = {
        ProviderCapability.DEVICE_DISCOVERY.value: CapabilityStatus.NOT_STARTED.value,
        ProviderCapability.NETWORK_OBJECT_READ.value: CapabilityStatus.NOT_STARTED.value,
    }
    release = asyncio.Event()
    both_started = asyncio.Event()
    active = 0

    async def probe(value: str) -> str:
        nonlocal active
        active += 1
        if active == 2:
            both_started.set()
        await release.wait()
        return value

    task = asyncio.create_task(
        ProviderConnectionService._run_probe_phase(  # pyright: ignore[reportPrivateUsage]
            capabilities,
            {
                ProviderCapability.DEVICE_DISCOVERY: probe("devices"),
                ProviderCapability.NETWORK_OBJECT_READ: probe("objects"),
            },
        )
    )
    await asyncio.wait_for(both_started.wait(), timeout=1)
    release.set()
    results = await task

    assert results == {
        ProviderCapability.DEVICE_DISCOVERY: "devices",
        ProviderCapability.NETWORK_OBJECT_READ: "objects",
    }
    assert set(capabilities.values()) == {CapabilityStatus.READ_ONLY.value}


def test_failed_connection_status_is_recorded_as_bounded_audit_decision(tmp_path: Path) -> None:
    session = _session(tmp_path / "failed-test-audit.sqlite")
    service = _service(session)
    created = service.create(
        _principal(ADMIN, ORG, "admin"),
        {
            "provider_type": "fmc",
            "display_name": "FMC TLS failure",
            "base_endpoint": "https://fmc.example.test",
            "username": "api-user",
            "password": "write-only-test-password",
        },
    )
    connection_id = UUID(str(created["id"]))

    SqlProviderConnectionRepository(session).record_connection_test(
        ORG,
        ADMIN,
        connection_id,
        {
            "status": "TLS_VALIDATION_FAILED",
            "error_code": "TLS_VALIDATION_FAILED",
            "safe_message": "The provider TLS certificate could not be validated.",
            "correlation_id": "test-correlation-id",
        },
        {},
        [],
    )
    session.flush()

    event_row = session.scalar(
        select(AuditEvent).where(AuditEvent.reason_code == "connection_tested")
    )
    assert event_row is not None
    assert event_row.decision == "FAILED"
    assert event_row.details == {
        "provider": "fmc",
        "connection_status": "TLS_VALIDATION_FAILED",
        "error_code": "TLS_VALIDATION_FAILED",
    }


def test_two_fmc_and_two_scc_connections_are_fully_isolated(tmp_path: Path) -> None:
    session = _session(tmp_path / "connections.sqlite")
    service = _service(session)
    admin = _principal(ADMIN, ORG, "admin")
    connections = _connections(service, admin, session)

    assert len(connections) == 4
    assert {item["display_name"] for item in connections} == {"FMC A", "FMC B", "SCC A", "SCC B"}
    assert all("credential_reference" not in item for item in connections)
    public_json = json.dumps(connections, default=str)
    for secret in ("password-a", "password-b", "token-a", "token-b"):
        assert secret not in public_json

    stored_connections = list(session.scalars(select(ProviderConnection)))
    assert len({row.credential_reference for row in stored_connections}) == 4
    ciphertext = b"".join(session.scalars(select(SecretRecord.ciphertext)))
    assert all(
        secret.encode() not in ciphertext
        for secret in ("password-a", "password-b", "token-a", "token-b")
    )

    managers = list(session.scalars(select(FirewallManager).order_by(FirewallManager.display_name)))
    assert len({manager.id for manager in managers}) == 4
    assert len({manager.native_id for manager in managers}) == 4
    session.add_all(
        ProviderDomain(
            organization_id=ORG,
            manager_id=manager.id,
            native_id="same-provider-native-domain-id",
            name=f"Domain for {manager.display_name}",
            provider_fingerprint=f"fingerprint-{manager.id}",
        )
        for manager in managers
    )
    session.commit()
    assert session.scalar(select(ProviderDomain).where(ProviderDomain.manager_id == managers[0].id))
    assert session.scalar(select(ProviderDomain).where(ProviderDomain.manager_id == managers[1].id))

    repository = SqlProviderConnectionRepository(session)
    for index, connection in enumerate(connections):
        connection_id = UUID(str(connection["id"]))
        repository.record_connection_test(
            ORG,
            ADMIN,
            connection_id,
            {"status": "CONNECTED", "provider_version": f"version-{index}"},
            {"authentication_session": "READ_ONLY", "access_rule_create": "NOT_STARTED"},
            [{"native_id": "same-scope", "name": f"Scope {index}", "scope_type": "DOMAIN"}],
        )
    session.commit()
    evidence = list(session.scalars(select(ProviderCapabilityEvidence)))
    assert {(item.connection_id, item.provider_version) for item in evidence} == {
        (UUID(str(connection["id"])), f"version-{index}")
        for index, connection in enumerate(connections)
    }
    assert all(item.status != "SUPPORTED" for item in evidence)

    first_id = UUID(str(connections[0]["id"]))
    second_id = UUID(str(connections[1]["id"]))
    repository.record_connection_test(
        ORG,
        ADMIN,
        first_id,
        {
            "status": "AUTHENTICATION_FAILED",
            "error_code": "AUTHENTICATION_FAILED",
            "safe_message": "The provider rejected the configured credential.",
        },
        {},
        [],
    )
    session.commit()
    assert service.get(admin, first_id)["connection_status"] == "AUTHENTICATION_FAILED"
    assert service.get(admin, second_id)["connection_status"] == "CONNECTED"
    first_manager = session.scalar(
        select(FirewallManager).where(FirewallManager.provider_connection_id == first_id)
    )
    second_manager = session.scalar(
        select(FirewallManager).where(FirewallManager.provider_connection_id == second_id)
    )
    assert first_manager is not None
    assert second_manager is not None
    assert first_manager.provider_version is None
    assert set(first_manager.capabilities.values()) == {"NOT_STARTED"}
    assert second_manager.provider_version == "version-1"
    assert second_manager.capabilities["authentication_session"] == "READ_ONLY"


@pytest.mark.asyncio
async def test_provider_admin_boundary_bola_rotation_and_stale_updates(tmp_path: Path) -> None:
    session = _session(tmp_path / "authorization.sqlite")
    service = _service(session)
    admin = _principal(ADMIN, ORG, "admin")
    connection = _connections(service, admin, session)[0]
    connection_id = UUID(str(connection["id"]))

    normal = _principal(NORMAL_USER, ORG, "user")
    group_user = _principal(GROUP_ADMIN, ORG, "user")
    for denied in (normal, group_user):
        with pytest.raises(ResourceOutOfScopeError):
            service.list(denied)
        with pytest.raises(ResourceOutOfScopeError):
            service.create(
                denied,
                {
                    "provider_type": "scc",
                    "display_name": "Denied",
                    "region": "us",
                    "token": "must-not-store",
                },
            )
        with pytest.raises(ResourceOutOfScopeError):
            await service.test(denied, connection_id, "denied-test")
        with pytest.raises(ResourceOutOfScopeError):
            service.rotate_credentials(
                denied, connection_id, int(str(connection["revision"])), {"password": "denied"}
            )

    other_admin = _principal(OTHER_ADMIN, OTHER_ORG, "admin")
    with pytest.raises(ResourceOutOfScopeError):
        service.get(other_admin, connection_id)
    with pytest.raises(ResourceOutOfScopeError):
        service.get(admin, uuid4())
    with pytest.raises(ResourceOutOfScopeError):
        service.rotate_credentials(other_admin, connection_id, 1, {"password": "denied"})
    with pytest.raises(StaleWriteError):
        service.update(admin, connection_id, 999, {"display_name": "Stale"})


def test_lifecycle_queue_and_credential_rotation_are_connection_scoped(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    session = _session(tmp_path / "lifecycle.sqlite")
    key = base64.b64encode(os.urandom(32)).decode()
    repository = SqlProviderConnectionRepository(session)
    store = EncryptedDatabaseSecretStore(session, key, 1)
    service = ProviderConnectionService(SqlAuthorizationRepository(session), repository, store)
    admin = _principal(ADMIN, ORG, "admin")
    first, second, *_ = _connections(service, admin, session)
    first_id = UUID(str(first["id"]))
    second_id = UUID(str(second["id"]))

    first_context = repository.connection_context(ORG, first_id)
    second_context = repository.connection_context(ORG, second_id)
    assert first_context is not None
    assert second_context is not None
    with pytest.raises(ResourceOutOfScopeError):
        store.retrieve(
            ORG,
            UUID(str(second_context["credential_reference"])),
            f"provider-connection:{first_id}",
        )
    second_before = store.retrieve(
        ORG,
        UUID(str(second_context["credential_reference"])),
        f"provider-connection:{second_id}",
    )
    rotated = service.rotate_credentials(
        admin,
        first_id,
        int(str(first["revision"])),
        {"username": "api-a", "password": "replacement-a"},
    )
    session.commit()
    rotated_manager = session.scalar(
        select(FirewallManager).where(FirewallManager.provider_connection_id == first_id)
    )
    assert rotated_manager is not None
    assert rotated_manager.provider_version is None
    assert set(rotated_manager.capabilities.values()) == {"NOT_STARTED"}
    assert (
        store.retrieve(
            ORG,
            UUID(str(second_context["credential_reference"])),
            f"provider-connection:{second_id}",
        )
        == second_before
    )

    with pytest.raises(InvalidChangeSetStateError):
        service.request_sync(admin, first_id, lambda _value: None)
    tested = repository.record_connection_test(
        ORG,
        ADMIN,
        first_id,
        {"status": "CONNECTED", "provider_version": "7.7.0"},
        {"authentication_session": "READ_ONLY", "access_rule_create": "NOT_STARTED"},
        [],
    )
    session.commit()
    service.set_lifecycle(admin, first_id, int(str(tested["revision"])), "ACTIVE")
    session.commit()
    due = repository.due_connection_ids(datetime.now(UTC))
    assert first_id in due
    assert second_id not in due
    dispatched: list[UUID] = []
    service.request_sync(
        admin, first_id, lambda connection_id, _mode: dispatched.append(connection_id)
    )
    assert dispatched == [first_id]
    queued = service.get(admin, first_id)
    assert queued["sync_status"] == "QUEUED"
    disabled = service.set_lifecycle(admin, first_id, int(str(queued["revision"])), "DISABLED")
    session.commit()
    with pytest.raises(InvalidChangeSetStateError):
        service.request_sync(
            admin, first_id, lambda connection_id, _mode: dispatched.append(connection_id)
        )
    assert disabled["lifecycle"] == "DISABLED"

    retired = service.set_lifecycle(admin, first_id, int(str(disabled["revision"])), "RETIRED")
    session.commit()
    with pytest.raises(InvalidChangeSetStateError):
        service.rotate_credentials(
            admin,
            first_id,
            int(str(retired["revision"])),
            {"username": "api-a", "password": "cannot-unretire"},
        )
    with pytest.raises(InvalidChangeSetStateError):
        service.update(
            admin, first_id, int(str(retired["revision"])), {"display_name": "Cannot unretire"}
        )
    with pytest.raises(InvalidChangeSetStateError):
        repository.record_connection_test(
            ORG,
            ADMIN,
            first_id,
            {"status": "AUTHENTICATION_FAILED"},
            {},
            [],
        )

    audit_payload = json.dumps(
        [event.details for event in session.scalars(select(AuditEvent))], default=str
    )
    assert "replacement-a" not in audit_payload
    assert "password-a" not in audit_payload
    assert '"provider": "fmc"' in audit_payload
    assert rotated["connection_status"] == "NEVER_TESTED"
