# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Restart recovery uses persisted PostgreSQL state and mock FMC/SCC transports."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from firewall_manager.application.deployments import DeploymentService
from firewall_manager.persistence.models import (
    ChangeSet,
    Deployment,
    Device,
    FirewallManager,
    ProviderConnection,
    ProviderTransaction,
    User,
)
from firewall_manager.worker import tasks
from test_execution_fencing import jobs  # noqa: F401 -- disposable PostgreSQL fixture
from test_worker_dispatch import whole_worker  # noqa: F401 -- real worker with mock provider


@pytest.fixture(params=["fmc", "scc"])
def scheduled_worker(whole_worker, monkeypatch, request):  # noqa: F811 -- shared fixture
    engine, ids, transport, _ = whole_worker
    queued = []
    provider_kind = request.param
    monkeypatch.setattr(tasks.execute_deployment_batch, "send", queued.append)
    monkeypatch.setattr(tasks, "build_real_provider", lambda *_: transport.provider(provider_kind))
    with Session(engine) as session:
        connection = session.get(ProviderConnection, ids["connection"])
        connection.provider_type = provider_kind
        connection.deployment_status = "RUNNING"
        connection.deployment_next_at = datetime.now(UTC) - timedelta(minutes=5)
        deployment = session.get(Deployment, ids["deployment"])
        deployment.state = "SCHEDULED"
        manager = session.get(FirewallManager, deployment.manager_id)
        manager.provider = provider_kind
        if provider_kind == "scc":
            device = session.get(Device, ids["device"])
            device.native_id = "scc-device"
            device.native_metadata = {"access_policy_id": "policy", "fmc_native_id": "device"}
            deployment.target_device_ids = ["scc-device"]
        session.commit()
    return engine, ids, transport, queued


@pytest.mark.parametrize("overdue", [False, True])
def test_orphaned_schedule_recovers_after_restart(scheduled_worker, overdue):
    engine, ids, transport, queued = scheduled_worker
    scheduled_for = datetime.now(UTC) + timedelta(minutes=-5 if overdue else 5)
    with Session(engine) as session:
        session.get(ProviderConnection, ids["connection"]).deployment_next_at = scheduled_for
        session.commit()

    # A fresh session reconstructs work solely from persisted state.
    tasks.enqueue_scheduled_deployments.fn()
    with Session(engine) as session:
        connection = session.get(ProviderConnection, ids["connection"])
        deployment = session.get(Deployment, ids["deployment"])
        assert connection.deployment_status == "QUEUED"
        assert deployment.state == ("READY" if overdue else "SCHEDULED")
        assert len(list(session.scalars(select(Deployment)))) == 1
        assert deployment.included_change_set_ids == [str(ids["change"])]
        assert not deployment.mutation_intent
        if not overdue:
            assert connection.deployment_next_at == scheduled_for
    assert queued == ([str(ids["deployment"])] if overdue else [])
    assert transport.posts == []

    # Repeated scheduler messages and worker delivery must not create another batch/start.
    tasks.enqueue_scheduled_deployments.fn()
    for deployment_id in queued:
        tasks.execute_deployment_batch.fn(deployment_id)
    assert len(transport.posts) == (1 if overdue else 0)
    with Session(engine) as session:
        assert len(list(session.scalars(select(Deployment)))) == 1
        assert session.get(Deployment, ids["deployment"]).state == (
            "DEPLOYED" if overdue else "SCHEDULED"
        )

    if not overdue:
        with Session(engine) as session:
            session.get(ProviderConnection, ids["connection"]).deployment_next_at = datetime.now(
                UTC
            ) - timedelta(seconds=1)
            session.commit()
        tasks.enqueue_scheduled_deployments.fn()
        assert queued == [str(ids["deployment"])]
        tasks.execute_deployment_batch.fn(queued[0])
        tasks.execute_deployment_batch.fn(queued[0])
        assert len(transport.posts) == 1


@pytest.mark.parametrize(
    ("state", "rollback_state"),
    [
        ("READY", None),
        ("DEPLOYING", None),
        ("UNKNOWN", None),
        ("RECONCILIATION_REQUIRED", None),
        ("DEPLOYED", "READY"),
        ("DEPLOYED", "ROLLING_BACK"),
        ("DEPLOYED", "UNKNOWN"),
        ("DEPLOYED", "RECONCILIATION_REQUIRED"),
    ],
)
def test_recovery_preserves_active_or_uncertain_work(scheduled_worker, state, rollback_state):
    engine, ids, transport, queued = scheduled_worker
    with Session(engine) as session:
        scheduled = session.get(Deployment, ids["deployment"])
        change = ChangeSet(
            organization_id=scheduled.organization_id,
            principal_id=ids["principal"].user_id,
            acting_group_id=ids["group"],
            title="Existing deployment",
            summary="Independent batch",
            state="SUCCEEDED",
        )
        session.add(change)
        session.flush()
        transaction = ProviderTransaction(
            organization_id=scheduled.organization_id,
            manager_id=scheduled.manager_id,
            change_set_id=change.id,
            state="SUCCEEDED",
        )
        session.add(transaction)
        session.flush()
        active = Deployment(
            organization_id=scheduled.organization_id,
            manager_id=scheduled.manager_id,
            provider_connection_id=ids["connection"],
            provider_transaction_id=transaction.id,
            state=state,
            rollback_state=rollback_state,
        )
        session.add(active)
        session.commit()
    tasks.enqueue_scheduled_deployments.fn()
    with Session(engine) as session:
        assert session.get(ProviderConnection, ids["connection"]).deployment_status == "RUNNING"
        assert session.get(Deployment, ids["deployment"]).state == "SCHEDULED"
    assert str(ids["deployment"]) not in queued
    assert transport.posts == []


@pytest.mark.parametrize(
    "evidence",
    ["lease_owner", "lease_until", "external_operation_id", "mutation_intent", "start_intent"],
)
def test_recovery_does_not_erase_scheduled_execution_evidence(scheduled_worker, evidence):
    engine, ids, transport, queued = scheduled_worker
    values = {
        "lease_owner": "existing-worker",
        "lease_until": datetime.now(UTC) - timedelta(minutes=1),
        "external_operation_id": "domain:job",
        "mutation_intent": {"entries": [{"method": "POST"}]},
        "start_intent": {"start_intent": True},
    }
    field = "plan_snapshot" if evidence == "start_intent" else evidence
    with Session(engine) as session:
        setattr(session.get(Deployment, ids["deployment"]), field, values[evidence])
        session.commit()
    tasks.enqueue_scheduled_deployments.fn()
    with Session(engine) as session:
        assert session.get(ProviderConnection, ids["connection"]).deployment_status == "RUNNING"
        deployment = session.get(Deployment, ids["deployment"])
        assert deployment.state == "SCHEDULED"
        assert getattr(deployment, field) == values[evidence]
    assert queued == []
    assert transport.posts == []


@pytest.mark.parametrize("gate", ["pause", "schedule", "write", "lifecycle", "admin"])
def test_recovered_schedule_respects_operational_gates(scheduled_worker, gate):
    engine, ids, transport, queued = scheduled_worker
    with Session(engine) as session:
        connection = session.get(ProviderConnection, ids["connection"])
        if gate == "pause":
            connection.deployment_paused = True
        elif gate == "schedule":
            connection.deployment_schedule_enabled = False
        elif gate == "write":
            connection.write_enabled = False
        elif gate == "lifecycle":
            connection.lifecycle = "DISABLED"
        else:
            for user in session.scalars(select(User)):
                user.is_active = False
        session.commit()
    tasks.enqueue_scheduled_deployments.fn()
    with Session(engine) as session:
        assert session.get(Deployment, ids["deployment"]).state == "SCHEDULED"
        assert session.get(ProviderConnection, ids["connection"]).deployment_status == (
            "PAUSED" if gate == "pause" else "QUEUED"
        )
    assert queued == []
    assert transport.posts == []


def test_concurrent_scheduler_recovery_keeps_one_batch(scheduled_worker, monkeypatch):
    engine, ids, transport, queued = scheduled_worker
    barrier = Barrier(2)
    recover = DeploymentService.recover_scheduled_connections

    def simultaneous(self):
        recover(self)
        # One scheduler holds the connection lock; the other must skip it.
        barrier.wait(timeout=15)

    monkeypatch.setattr(DeploymentService, "recover_scheduled_connections", simultaneous)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(tasks.enqueue_scheduled_deployments.fn) for _ in range(2)]
        for future in futures:
            future.result(timeout=25)
    assert queued
    assert set(queued) == {str(ids["deployment"])}
    for deployment_id in queued:
        tasks.execute_deployment_batch.fn(deployment_id)
    assert len(transport.posts) == 1
    with Session(engine) as session:
        assert len(list(session.scalars(select(Deployment)))) == 1


def test_recovered_schedule_rechecks_authority_at_dispatch(scheduled_worker):
    engine, ids, transport, queued = scheduled_worker
    tasks.enqueue_scheduled_deployments.fn()
    assert queued == [str(ids["deployment"])]
    with Session(engine) as session:
        session.get(User, ids["principal"].user_id).is_active = False
        session.commit()
    tasks.execute_deployment_batch.fn(queued[0])
    assert transport.posts == []
    with Session(engine) as session:
        assert session.get(Deployment, ids["deployment"]).state != "DEPLOYED"


def test_recovery_resumes_expired_maintenance_pause(scheduled_worker):
    engine, ids, transport, queued = scheduled_worker
    with Session(engine) as session:
        connection = session.get(ProviderConnection, ids["connection"])
        connection.deployment_paused = True
        connection.deployment_pause_until = datetime.now(UTC) - timedelta(minutes=1)
        session.commit()
    tasks.enqueue_scheduled_deployments.fn()
    assert queued == [str(ids["deployment"])]
    with Session(engine) as session:
        connection = session.get(ProviderConnection, ids["connection"])
        assert not connection.deployment_paused
        assert connection.deployment_status == "QUEUED"
    tasks.execute_deployment_batch.fn(queued[0])
    assert len(transport.posts) == 1


def test_recovered_batch_survives_broker_failure(scheduled_worker, monkeypatch):
    engine, ids, transport, queued = scheduled_worker

    def unavailable(_):
        raise RuntimeError("Test broker unavailable")

    monkeypatch.setattr(tasks.execute_deployment_batch, "send", unavailable)
    with pytest.raises(RuntimeError, match="Test broker unavailable"):
        tasks.enqueue_scheduled_deployments.fn()
    with Session(engine) as session:
        assert session.get(Deployment, ids["deployment"]).state == "READY"
    monkeypatch.setattr(tasks.execute_deployment_batch, "send", queued.append)
    tasks.enqueue_scheduled_deployments.fn()
    assert queued == [str(ids["deployment"])]
    tasks.execute_deployment_batch.fn(queued[0])
    tasks.execute_deployment_batch.fn(queued[0])
    assert len(transport.posts) == 1
