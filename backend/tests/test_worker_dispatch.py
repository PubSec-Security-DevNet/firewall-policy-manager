# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Actual workers, real PostgreSQL claims and deterministic dispatch-boundary races."""

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from firewall_manager.application.changesets import ChangeSetService
from firewall_manager.application.errors import ProviderAuthenticationError, ProviderContractError
from firewall_manager.domain.models import (
    CapabilityStatus,
    ChangeOperationKind,
    DiscoveredObject,
    ProviderKind,
)
from firewall_manager.persistence.changesets import SqlChangeSetRepository
from firewall_manager.persistence.execution_fencing import ExecutionFence
from firewall_manager.persistence.models import (
    AccessPolicy,
    ChangeSet,
    Deployment,
    Device,
    FirewallManager,
    FirewallObject,
    Group,
    GroupMembership,
    PolicyDelegation,
    ProviderConnection,
    ProviderDomain,
    SecretRecord,
    SyncRun,
    User,
)
from firewall_manager.persistence.repositories import SqlAuthorizationRepository, SqlSyncRepository
from firewall_manager.providers.mock import DeterministicMockProvider
from firewall_manager.providers.transactions import DeterministicMockTransactionExecutor
from firewall_manager.worker import tasks
from test_deployment_dispatch import CiscoDeploymentTransport
from test_execution_fencing import jobs  # noqa: F401 -- shared disposable PostgreSQL fixture


class WorkerTransport(CiscoDeploymentTransport):
    def provider(self, kind):
        provider = super().provider(kind)
        provider._capabilities["rule_category_mutation"] = CapabilityStatus.SUPPORTED
        return provider

    def handler(self, request):
        path = request.url.path
        if path.endswith("/pendingchanges") and "expanded" not in request.url.params:
            return httpx.Response(200, json={"items": []})
        if path.endswith("/policy/accesspolicies/policy"):
            return httpx.Response(200, json={"id": "policy", "version": "1"})
        if path.endswith(("/categories", "/accessrules")):
            if request.method == "GET":
                return httpx.Response(200, json={"items": [], "paging": {"count": 0}})
            self.posts.append(request.url.path)
            self.category = {**json.loads(request.content), "id": "category", "version": "1"}
            return httpx.Response(201, json=self.category)
        if path.endswith("/categories/category"):
            return httpx.Response(200, json=self.category)
        return super().handler(request)


@pytest.fixture
def whole_worker(jobs, monkeypatch):  # noqa: F811 -- imported pytest fixture
    engine, ids = jobs
    transport = WorkerTransport()
    sends = []
    monkeypatch.setattr(tasks, "new_session", lambda: Session(engine, expire_on_commit=False))
    monkeypatch.setattr(
        tasks, "master_key", lambda _: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    monkeypatch.setattr(
        tasks.EncryptedDatabaseSecretStore,
        "retrieve",
        lambda *_: {"username": "test", "password": "test"},
    )
    monkeypatch.setattr(tasks, "build_real_provider", lambda *_: transport.provider("fmc"))
    monkeypatch.setattr(
        tasks.synchronize_provider_connection, "send", lambda *args: sends.append(args)
    )
    monkeypatch.setattr(tasks.execute_change_set, "send", lambda *args: None)
    monkeypatch.setattr(tasks.execute_deployment_batch, "send", lambda *args: None)
    with Session(engine, expire_on_commit=False) as session:
        org = ids["principal"].organization_id
        manager = session.scalar(select(FirewallManager))
        secret = SecretRecord(
            organization_id=org,
            purpose="test",
            ciphertext=b"fixture",
            nonce=b"fixture",
            key_version=1,
        )
        session.add(secret)
        session.flush()
        connection = ProviderConnection(
            organization_id=org,
            provider_type="fmc",
            display_name="Controlled",
            lifecycle="ACTIVE",
            connection_mode="DIRECT",
            credential_reference=secret.id,
            credential_type="BASIC",
            credential_updated_at=datetime.now(UTC),
            base_endpoint="https://fmc.example.test",
            connection_status="CONNECTED",
            provider_version="7.7.0",
            write_enabled=True,
        )
        session.add(connection)
        session.flush()
        manager.provider_connection_id = connection.id
        manager.is_mock = False
        manager.capabilities = {
            "pending_change_inspection": "SUPPORTED",
            "rule_category_mutation": "SUPPORTED",
        }
        manager.read_only = False
        domain = ProviderDomain(
            organization_id=org,
            manager_id=manager.id,
            native_id="domain",
            name="Domain",
            provider_version="1",
            provider_fingerprint="1",
        )
        session.add(domain)
        session.flush()
        policy = AccessPolicy(
            organization_id=org,
            manager_id=manager.id,
            domain_id=domain.id,
            native_id="policy",
            name="Policy",
            provider_version="1",
            provider_fingerprint="1",
        )
        session.add(policy)
        session.flush()
        device = Device(
            organization_id=org,
            manager_id=manager.id,
            domain_id=domain.id,
            native_id="device",
            name="Device",
            provider_fingerprint="1",
            native_metadata={"access_policy_id": "policy"},
        )
        grant = PolicyDelegation(
            organization_id=org,
            group_id=ids["group"],
            policy_id=policy.id,
            capabilities=["view", "create_rule", "approve"],
        )
        member = GroupMembership(
            organization_id=org,
            user_id=ids["principal"].user_id,
            group_id=ids["group"],
            status="ACTIVE",
        )
        approver = User(
            organization_id=org,
            identity_issuer="test",
            identity_subject=uuid4().hex,
            email="approver@example.test",
            display_name="Approver",
            role="admin",
        )
        session.add_all([device, grant, member, approver])
        change = session.get(ChangeSet, ids["change"])
        change.access_policy_id = policy.id
        change.state = "SUCCEEDED"
        change.revision = 4
        change.approved_revision = 1
        deployment = session.get(Deployment, ids["deployment"])
        deployment.provider_connection_id = connection.id
        deployment.included_change_set_ids = [str(change.id)]
        deployment.target_device_ids = ["device"]
        deployment.requested_by_user_id = ids["principal"].user_id
        session.flush()
        change.approved_by_user_id = approver.id
        ids.update(
            connection=connection.id,
            policy=policy.id,
            device=device.id,
            grant=grant.id,
            approver=approver.id,
        )
        session.commit()
    return engine, ids, transport, sends


def prepare_change(engine, ids, *, two_operations=False):
    with Session(engine, expire_on_commit=False) as session:
        repository = SqlChangeSetRepository(session)
        service = ChangeSetService(
            SqlAuthorizationRepository(session),
            repository,
            DeterministicMockTransactionExecutor(DeterministicMockProvider(ProviderKind.FMC)),
        )
        result = service.create(
            ids["principal"], ids["group"], ids["policy"], "Race", "Controlled worker"
        )
        change_id = UUID(str(result["id"]))
        result = service.add_operation(
            ids["principal"], ids["group"], change_id, ChangeOperationKind.ENSURE_RULE_CATEGORY, {}
        )
        assert result["state"] == "READY", result
        if two_operations:
            service.add_operation(
                ids["principal"],
                ids["group"],
                change_id,
                ChangeOperationKind.ENSURE_RULE_CATEGORY,
                {},
            )
        service.queue_execution(ids["principal"], ids["group"], change_id, lambda *_: None)
        ids["change"] = change_id
        session.commit()


def execute(kind, ids):
    if kind == "deployment":
        asyncio.run(tasks._execute_deployment_batch(ids["deployment"]))
    else:
        asyncio.run(
            tasks._execute_change_set(
                ids["change"],
                ids["principal"].user_id,
                ids["group"],
                ids["principal"].organization_id,
            )
        )


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            ProviderContractError(details={"code": "DEPLOYMENT_TARGET_UNAVAILABLE"}),
            "DEPLOYMENT_TARGET_UNAVAILABLE",
        ),
        (ProviderAuthenticationError(), "AUTHENTICATION_FAILED"),
    ],
)
def test_deployment_preflight_failure_is_not_reported_as_uncertain(error, expected):
    assert tasks._deployment_start_failure_info(error)["code"] == expected


def revoke(engine, ids, what):
    with Session(engine) as session:
        if what == "actor":
            session.get(User, ids["principal"].user_id).is_active = False
        elif what == "grant":
            session.get(PolicyDelegation, ids["grant"]).is_active = False
        elif what == "provider":
            session.get(ProviderConnection, ids["connection"]).write_enabled = False
        elif what == "target":
            session.get(Device, ids["device"]).native_metadata = {"access_policy_id": "other"}
        elif what == "approval":
            session.get(Group, ids["group"]).approval_required = True
            session.get(ChangeSet, ids["change"]).approval_invalidated_at = datetime.now(UTC)
        session.commit()


@pytest.mark.parametrize("kind", ["change", "deployment"])
def test_whole_worker_success_and_duplicate_delivery(whole_worker, kind):
    engine, ids, transport, sends = whole_worker
    if kind == "change":
        prepare_change(engine, ids)
    execute(kind, ids)
    execute(kind, ids)
    with Session(engine) as session:
        row = session.get(ChangeSet if kind == "change" else Deployment, ids[kind])
        assert row.state == ("SUCCEEDED" if kind == "change" else "DEPLOYED"), json.dumps(
            row.failure_info
        )
        assert len(row.mutation_intent["entries"]) == 1
        assert row.mutation_intent["state"] == "COMPLETED"
    assert len(transport.posts) == 1
    assert len(sends) == 1


@pytest.mark.parametrize("kind", ["change", "deployment"])
@pytest.mark.parametrize("what", ["actor", "grant", "provider", "approval"])
@pytest.mark.parametrize("boundary", ["before", "after"])
def test_whole_worker_revocation_boundary(whole_worker, monkeypatch, kind, what, boundary):
    engine, ids, transport, _ = whole_worker
    if kind == "change":
        prepare_change(engine, ids)
    if what == "approval":
        with Session(engine) as session:
            session.get(Group, ids["group"]).approval_required = True
            change = session.get(ChangeSet, ids["change"])
            change.approved_by_user_id = ids["approver"]
            change.approved_revision = change.revision - (2 if kind == "change" else 3)
            session.commit()
    original = ExecutionFence.before_mutation

    def guarded(self, *args):
        if boundary == "before":
            revoke(engine, ids, what)
        original(self, *args)
        if boundary == "after":
            revoke(engine, ids, what)

    monkeypatch.setattr(ExecutionFence, "before_mutation", guarded)
    execute(kind, ids)
    assert len(transport.posts) == (0 if boundary == "before" else 1)
    with Session(engine) as session:
        row = session.get(ChangeSet if kind == "change" else Deployment, ids[kind])
        assert bool(row.mutation_intent) == (boundary == "after")


@pytest.mark.parametrize("kind", ["change", "deployment"])
@pytest.mark.parametrize(
    "boundary", ["before_intent", "after_intent", "after_http", "after_receipt"]
)
def test_whole_worker_takeover_and_stale_return(whole_worker, monkeypatch, kind, boundary):
    engine, ids, transport, sends = whole_worker
    if kind == "change":
        prepare_change(engine, ids)
    entered, replaced = Barrier(2), Barrier(2)
    before, after = ExecutionFence.before_mutation, ExecutionFence.after_mutation

    def pause():
        entered.wait(timeout=15)
        replaced.wait(timeout=15)

    def guarded_before(self, *args):
        if boundary == "before_intent":
            pause()
        before(self, *args)
        if boundary == "after_intent":
            pause()

    def guarded_after(self, *args):
        if boundary == "after_http":
            pause()
        after(self, *args)
        if boundary == "after_receipt":
            pause()

    monkeypatch.setattr(ExecutionFence, "before_mutation", guarded_before)
    monkeypatch.setattr(ExecutionFence, "after_mutation", guarded_after)

    def replacement():
        entered.wait(timeout=15)
        with Session(engine) as session:
            row = session.get(ChangeSet if kind == "change" else Deployment, ids[kind])
            if kind == "change":
                row.execution_lease_until = datetime.now(UTC) - timedelta(seconds=1)
            else:
                row.lease_until = datetime.now(UTC) - timedelta(seconds=1)
            session.commit()
        if kind == "change":
            tasks.recover_expired_change_set_executions.fn()
        else:
            tasks.recover_expired_deployments.fn()
        execute(kind, ids)
        replaced.wait(timeout=15)

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(execute, kind, ids), pool.submit(replacement)
        a.result(timeout=35)
        b.result(timeout=35)
    assert len(transport.posts) == (0 if boundary == "before_intent" else 1)
    with Session(engine) as session:
        row = session.get(ChangeSet if kind == "change" else Deployment, ids[kind])
        assert row.state == (
            "DEPLOYED"
            if kind == "deployment" and boundary == "after_receipt"
            else "RECONCILIATION_REQUIRED"
        )
        if kind == "change" and boundary == "after_receipt":
            entries = row.mutation_intent["entries"]
            assert isinstance(entries, list)
            assert entries[0]["reconciliation"]["state"] == "DESIRED_STATE_PRESENT"
    assert len(sends) == (1 if kind == "deployment" and boundary == "after_receipt" else 0)


def test_target_changed_after_preflight_refuses_dispatch(whole_worker, monkeypatch):
    engine, ids, transport, _ = whole_worker
    original = ExecutionFence.before_mutation

    def guarded(self, *args):
        revoke(engine, ids, "target")
        original(self, *args)

    monkeypatch.setattr(ExecutionFence, "before_mutation", guarded)
    execute("deployment", ids)
    assert transport.posts == []


def test_revocation_after_first_intent_blocks_next_operation(whole_worker, monkeypatch):
    engine, ids, transport, _ = whole_worker
    prepare_change(engine, ids, two_operations=True)
    original = ExecutionFence.before_mutation

    def guarded(self, *args):
        original(self, *args)
        revoke(engine, ids, "grant")

    monkeypatch.setattr(ExecutionFence, "before_mutation", guarded)
    execute("change", ids)
    assert len(transport.posts) == 1
    with Session(engine) as session:
        row = session.get(ChangeSet, ids["change"])
        assert len(row.mutation_intent["entries"]) == 1
        assert row.state == "RECONCILIATION_REQUIRED"


@pytest.mark.parametrize("kind", ["change", "deployment"])
def test_actual_concurrent_duplicate_queue_delivery(whole_worker, kind):
    engine, ids, transport, _ = whole_worker
    if kind == "change":
        prepare_change(engine, ids)
    barrier = Barrier(2)

    def deliver():
        barrier.wait(timeout=10)
        execute(kind, ids)

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(deliver), pool.submit(deliver)
        a.result(timeout=20)
        b.result(timeout=20)
    assert len(transport.posts) == 1


@pytest.mark.parametrize("provider_kind", ["fmc", "scc"])
def test_post_preflight_external_edit_surfaces_as_database_drift(whole_worker, provider_kind):

    engine, ids, _, _ = whole_worker
    transport = CiscoDeploymentTransport("external_edit")

    async def deploy_and_read():
        provider = transport.provider(provider_kind)
        try:
            await provider.start_deployment(
                "domain",
                ["policy"],
                ["device" if provider_kind == "fmc" else "scc-device"],
                transport.intents(provider),
            )
            return await provider._get(provider._config_path("domain", "object/networks/object"))
        finally:
            await provider.aclose()

    observed = asyncio.run(deploy_and_read())
    with Session(engine) as session:
        policy = session.get(AccessPolicy, ids["policy"])
        org, manager, domain = policy.organization_id, policy.manager_id, policy.domain_id
        run = SyncRun(organization_id=org, manager_id=manager, status="RUNNING")
        session.add(run)
        session.flush()
        repo = SqlSyncRepository(session)
        object_id = repo.upsert_object(
            org,
            manager,
            domain,
            run.id,
            DiscoveredObject(
                native_id="object",
                name="FPM",
                native_version="2",
                fingerprint="before",
                normalized_value="10.1.0.0/16",
            ),
        )
        row = session.get(FirewallObject, object_id)
        row.owner_group_id = ids["group"]
        row.owner_policy_id = ids["policy"]
        row.expected_provider_name = "FPM"
        row.management_state = "MANAGED"
        row.application_snapshot = {
            "name": "FPM",
            "object_type": "NETWORK",
            "normalized_value": "10.1.0.0/16",
        }
        session.commit()
        repo.upsert_object(
            org,
            manager,
            domain,
            run.id,
            DiscoveredObject(
                native_id="object",
                name="FPM",
                native_version="3",
                fingerprint="after",
                normalized_value=observed["value"],
            ),
        )
        session.commit()
        assert row.management_state == "DRIFTED"
        assert row.application_snapshot["normalized_value"] == "10.1.0.0/16"
