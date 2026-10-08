# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic simultaneous PostgreSQL workers; barriers model a blocked provider call."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.orm import Session

from firewall_manager.application.errors import ApplicationError
from firewall_manager.domain.models import Principal
from firewall_manager.persistence.changesets import SqlChangeSetRepository
from firewall_manager.persistence.execution_fencing import ExecutionFence, ExecutionFenceLostError
from firewall_manager.persistence.models import (
    Base,
    ChangeSet,
    Deployment,
    FirewallManager,
    Group,
    Organization,
    ProviderTransaction,
    User,
)
from firewall_manager.worker import tasks


@pytest.fixture
def jobs():
    url = os.getenv("FPM_TEST_DATABASE_URL")
    if not url:
        pytest.skip("FPM_TEST_DATABASE_URL requires a disposable PostgreSQL database")
    engine = create_engine(url)
    schema = "fence_" + uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    scoped = engine.execution_options(schema_translate_map={None: schema})
    Base.metadata.create_all(scoped)
    with Session(scoped) as session:
        org = Organization(name=schema)
        session.add(org)
        session.flush()
        group = Group(
            organization_id=org.id, name="Test", provider_slug="TEST", approval_required=False
        )
        user = User(
            organization_id=org.id,
            identity_issuer="test",
            identity_subject=schema,
            email="fence@example.test",
            display_name="Fence",
            role="admin",
        )
        manager = FirewallManager(
            organization_id=org.id,
            provider="fmc",
            native_id="test",
            display_name="Test",
            base_url="https://fmc.example.test",
        )
        session.add_all([group, user, manager])
        session.flush()
        change = ChangeSet(
            organization_id=org.id,
            principal_id=user.id,
            acting_group_id=group.id,
            title="Test",
            summary="Test",
            state="QUEUED",
            revision=1,
            validated_revision=1,
        )
        session.add(change)
        session.flush()
        transaction = ProviderTransaction(
            organization_id=org.id,
            change_set_id=change.id,
            manager_id=manager.id,
            state="SUCCEEDED",
        )
        session.add(transaction)
        session.flush()
        deployment = Deployment(
            organization_id=org.id,
            manager_id=manager.id,
            provider_transaction_id=transaction.id,
            state="READY",
        )
        session.add(deployment)
        session.flush()
        ids = {
            "change": change.id,
            "deployment": deployment.id,
            "group": group.id,
            "principal": Principal(user.id, org.id, user.email, user.role),
        }
        session.commit()
    try:
        yield scoped, ids
    finally:
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
        engine.dispose()


def claim(session, model, job_id, owner):
    row = session.scalar(select(model).where(model.id == job_id).with_for_update())
    row.execution_epoch += 1
    row.state = "EXECUTING" if model is ChangeSet else "DEPLOYING"
    if model is ChangeSet:
        row.execution_owner = owner
        row.execution_lease_until = datetime.now(UTC) + timedelta(minutes=2)
    else:
        row.lease_owner = owner
        row.lease_until = datetime.now(UTC) + timedelta(minutes=2)
    epoch = row.execution_epoch
    session.commit()
    return ExecutionFence(session, model, job_id, epoch, owner)


def takeover(session, model, job_id):
    lease = model.execution_lease_until if model is ChangeSet else model.lease_until
    session.execute(
        update(model)
        .where(model.id == job_id)
        .values({lease: datetime.now(UTC) - timedelta(seconds=1)})
    )
    session.commit()
    if model is ChangeSet:
        recovered = SqlChangeSetRepository(session).recover_expired_execution_leases()
        assert recovered == []  # durable intent forbids returning this job to the mutation queue
    else:
        row = session.scalar(select(model).where(model.id == job_id).with_for_update())
        assert row.mutation_intent
        row.execution_epoch += 1
        row.lease_owner = "reconciler-B"
        row.lease_until = datetime.now(UTC) + timedelta(minutes=2)
        row.state = "RECONCILIATION_REQUIRED"
    session.commit()


@pytest.mark.parametrize(("model", "key"), [(ChangeSet, "change"), (Deployment, "deployment")])
@pytest.mark.parametrize("crash_point", ["during_call", "after_provider_success"])
def test_expired_inflight_worker_cannot_commit_or_repeat(jobs, model, key, crash_point):
    engine, ids = jobs
    job_id = ids[key]
    entered = Barrier(2)
    replaced = Barrier(2)
    external = []

    def worker_a():
        with Session(engine) as session:
            fence = claim(session, model, job_id, "worker-A")
            fence.before_mutation("POST", "/controlled-provider-mutation")
            if crash_point == "after_provider_success":
                external.append("provider succeeded")
            entered.wait(timeout=10)
            replaced.wait(timeout=10)
            if crash_point == "during_call":
                external.append("provider succeeded")
            with pytest.raises(ExecutionFenceLostError):
                fence.after_mutation()
            session.rollback()
            row = session.get(model, job_id)
            row.state = "SUCCEEDED" if model is ChangeSet else "DEPLOYED"
            with pytest.raises(ExecutionFenceLostError):
                session.commit()
            session.rollback()
            with pytest.raises(ExecutionFenceLostError):
                fence.before_mutation("DELETE", "/another-mutation")
            session.rollback()
            fence.close()

    def worker_b():
        entered.wait(timeout=10)
        with Session(engine) as session:
            takeover(session, model, job_id)
            if model is ChangeSet:
                assert not SqlChangeSetRepository(session).claim_queued_execution(
                    ids["principal"], ids["group"], job_id, "worker-B"
                )
        replaced.wait(timeout=10)

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(worker_a)
        b = pool.submit(worker_b)
        a.result(timeout=20)
        b.result(timeout=20)
    with Session(engine) as session:
        row = session.get(model, job_id)
        assert row.state == "RECONCILIATION_REQUIRED"
        assert row.execution_epoch == 2
        assert row.mutation_intent["epoch"] == 1
    assert len(external) == 1


@pytest.mark.parametrize(("model", "key"), [(ChangeSet, "change"), (Deployment, "deployment")])
def test_lease_lost_before_call_prevents_external_intent(jobs, model, key):
    engine, ids = jobs
    with Session(engine) as a:
        fence = claim(a, model, ids[key], "A")
        with Session(engine) as b:
            lease = model.execution_lease_until if model is ChangeSet else model.lease_until
            b.execute(
                update(model)
                .where(model.id == ids[key])
                .values({lease: datetime.now(UTC) - timedelta(seconds=1), model.execution_epoch: 2})
            )
            b.commit()
        with pytest.raises(ExecutionFenceLostError):
            fence.before_mutation("POST", "/never-sent")
        a.rollback()
        fence.close()
    with Session(engine) as session:
        assert session.get(model, ids[key]).mutation_intent == {}


def test_simultaneous_duplicate_deliveries_claim_exactly_once(jobs):
    engine, ids = jobs
    barrier = Barrier(2)

    def worker(owner):
        with Session(engine) as session:
            barrier.wait(timeout=10)
            result = SqlChangeSetRepository(session).claim_queued_execution(
                ids["principal"], ids["group"], ids["change"], owner
            )
            fence = session.info.get("execution_fence")
            if fence:
                fence.close()
            return result

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(worker, "A")
        b = pool.submit(worker, "B")
        assert sorted([a.result(timeout=20), b.result(timeout=20)]) == [False, True]


@pytest.mark.parametrize(("model", "key"), [(ChangeSet, "change"), (Deployment, "deployment")])
def test_crash_after_intent_preserves_uncertainty(jobs, model, key):
    engine, ids = jobs
    with Session(engine) as session:
        fence = claim(session, model, ids[key], "crashed-A")
        fence.before_mutation("POST", "/may-or-may-not-have-reached-provider")
        fence.close()
    with Session(engine) as replacement:
        takeover(replacement, model, ids[key])
        assert replacement.get(model, ids[key]).state == "RECONCILIATION_REQUIRED"


@pytest.mark.parametrize("revocation", ["user", "approval"])
def test_current_authorization_rechecked_at_mutation_boundary(jobs, revocation):
    engine, ids = jobs
    with Session(engine) as a:
        repo = SqlChangeSetRepository(a)
        assert repo.claim_queued_execution(ids["principal"], ids["group"], ids["change"], "A")
        repo.set_execution_authorizer(ids["principal"], ids["group"], ids["change"], lambda: None)
        fence = a.info["execution_fence"]
        # End the read transaction before the independently committed revocation.
        a.commit()
        with Session(engine) as b:
            if revocation == "user":
                b.get(User, ids["principal"].user_id).is_active = False
            else:
                b.get(Group, ids["group"]).approval_required = True
                b.get(ChangeSet, ids["change"]).approval_invalidated_at = datetime.now(UTC)
            b.commit()

        with pytest.raises(ApplicationError):
            fence.before_mutation("POST", "/never-authorized")
        a.rollback()
        fence.close()
    with Session(engine) as session:
        assert session.get(ChangeSet, ids["change"]).mutation_intent == {}


def test_actual_deployment_recovery_fences_inflight_worker(jobs, monkeypatch):

    engine, ids = jobs
    entered = Barrier(2)
    recovered = Barrier(2)
    monkeypatch.setattr(tasks, "new_session", lambda: Session(engine))

    def a():
        with Session(engine) as session:
            fence = claim(session, Deployment, ids["deployment"], "A")
            fence.before_mutation("POST", "/deploymentrequests")
            entered.wait(timeout=10)
            recovered.wait(timeout=10)
            with pytest.raises(ExecutionFenceLostError):
                fence.after_mutation()
            session.rollback()
            fence.close()

    def b():
        entered.wait(timeout=10)
        with Session(engine) as session:
            row = session.get(Deployment, ids["deployment"])
            row.lease_until = datetime.now(UTC) - timedelta(seconds=1)
            session.commit()
        tasks.recover_expired_deployments.fn()
        recovered.wait(timeout=10)

    with ThreadPoolExecutor(max_workers=2) as pool:
        aa = pool.submit(a)
        bb = pool.submit(b)
        aa.result(timeout=20)
        bb.result(timeout=20)
    with Session(engine) as session:
        row = session.get(Deployment, ids["deployment"])
        assert row.state == "RECONCILIATION_REQUIRED"
        assert row.execution_epoch == 2
        assert row.lease_owner is None
