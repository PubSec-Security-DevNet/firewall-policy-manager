# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Idempotent worker tasks for health and queue-backed provider synchronization."""

import asyncio
import calendar
import os
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import dramatiq
from redis import Redis
from sqlalchemy import delete, select

from firewall_manager.application.changesets import ChangeSetService
from firewall_manager.application.deployments import (
    DeploymentService,
    is_definitive_provider_rejection,
)
from firewall_manager.application.errors import ApplicationError
from firewall_manager.application.mutation_guard import mutation_context
from firewall_manager.application.synchronization import SynchronizationService
from firewall_manager.config import get_settings
from firewall_manager.domain.models import ChangeSetState, Principal
from firewall_manager.notifications import deliver_queued_email_notifications
from firewall_manager.observability import job as record_job
from firewall_manager.persistence.changesets import (
    CHANGE_SET_EXECUTION_LEASE_SECONDS,
    SqlChangeSetRepository,
)
from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.execution_fencing import (
    ExecutionFence,
    ExecutionFenceLostError,
    mutation_scope,
)
from firewall_manager.persistence.models import (
    AuditEvent,
    AuthenticationEvent,
    AuthSession,
    ChangeSet,
    Deployment,
    FirewallManager,
    ProviderConnection,
    ProviderTransaction,
    User,
)
from firewall_manager.persistence.provider_connections import SqlProviderConnectionRepository
from firewall_manager.persistence.repositories import SqlAuthorizationRepository, SqlSyncRepository
from firewall_manager.persistence.secrets import EncryptedDatabaseSecretStore
from firewall_manager.providers.factory import build_real_provider
from firewall_manager.providers.transactions import GuardedProviderTransactionExecutor
from firewall_manager.security.api_tokens import cleanup_expired as cleanup_expired_api_tokens
from firewall_manager.security.secret_provider import master_key
from firewall_manager.worker.broker import broker
from firewall_manager.worker.health_keys import WORKER_HEARTBEAT_KEY

BROKER = broker

AUDIT_PURGE_LOCK_KEY = "firewall-manager:audit-retention:last-run"


@dramatiq.actor(max_retries=3, min_backoff=1000)
def record_worker_heartbeat() -> None:
    """Record worker queue connectivity; repeated delivery is harmless."""
    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        redis.set(WORKER_HEARTBEAT_KEY, datetime.now(UTC).isoformat(), ex=120)
        record_job("worker_heartbeat", "success")
    finally:
        redis.close()


@dramatiq.actor(max_retries=2, min_backoff=5000)
def cleanup_expired_authentication() -> None:
    """Remove expired browser sessions and revoke expired API tokens."""
    cutoff = datetime.now(UTC)
    with new_session() as session:
        session.execute(
            delete(AuthSession).where(
                AuthSession.expires_at <= cutoff,
            )
        )
        cleanup_expired_api_tokens(session)
        session.commit()


@dramatiq.actor(max_retries=1, min_backoff=5000)
def purge_expired_audit_events() -> None:
    """Purge audit and authentication evidence beyond the configured retention window."""
    settings = get_settings()
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        # The scheduler ticks frequently; use a Redis lease so this maintenance task runs once
        # per day even when several scheduler ticks or worker processes are active.
        if not redis.set(AUDIT_PURGE_LOCK_KEY, "1", nx=True, ex=86400):
            return
    finally:
        redis.close()

    try:
        cutoff = subtract_calendar_months(datetime.now(UTC), settings.audit_retention_months)
        with new_session() as session:
            session.execute(delete(AuditEvent).where(AuditEvent.occurred_at < cutoff))
            session.execute(
                delete(AuthenticationEvent).where(AuthenticationEvent.occurred_at < cutoff)
            )
            session.commit()
    except Exception:
        # Let a transient database failure retry instead of suppressing maintenance for a day.
        retry_redis = Redis.from_url(settings.redis_url, decode_responses=True)
        try:
            retry_redis.delete(AUDIT_PURGE_LOCK_KEY)
        finally:
            retry_redis.close()
        raise


def subtract_calendar_months(value: datetime, months: int) -> datetime:
    """Subtract calendar months while preserving a valid day at month end."""
    month_index = value.year * 12 + value.month - 1 - months
    year, month_zero_based = divmod(month_index, 12)
    month = month_zero_based + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


@dramatiq.actor(max_retries=0)
def synchronize_provider_connection(connection_id: str, mode: str = "FULL") -> None:
    """Run one connection-isolated sync; retries are explicit to avoid duplicate full imports."""
    asyncio.run(_synchronize_provider_connection(UUID(connection_id), mode))


@dramatiq.actor(max_retries=0)
def execute_change_set(
    change_set_id: str, principal_id: str, group_id: str, organization_id: str
) -> None:
    """Execute one durably queued ChangeSet; mutation delivery is never blindly retried."""
    asyncio.run(
        _execute_change_set(
            UUID(change_set_id),
            UUID(principal_id),
            UUID(group_id),
            UUID(organization_id),
        )
    )


async def _execute_change_set(  # noqa: PLR0912, PLR0915 -- explicit execution and recovery routing
    change_set_id: UUID,
    principal_id: UUID,
    group_id: UUID,
    organization_id: UUID,
) -> None:
    settings = get_settings()
    with new_session() as check_session:
        current = check_session.get(ChangeSet, change_set_id)
        uncertain = current is not None and current.state == "RECONCILIATION_REQUIRED"
    if uncertain:
        await _reconcile_change_set(change_set_id)
        return
    with new_session() as session, mutation_scope(session):
        user = session.get(User, principal_id)
        row = session.get(ChangeSet, change_set_id)
        if (
            user is None
            or user.organization_id != organization_id
            or row is None
            or row.organization_id != organization_id
            or row.principal_id != principal_id
            or row.acting_group_id != group_id
            or row.state != ChangeSetState.QUEUED.value
        ):
            return
        principal = Principal(
            user_id=user.id,
            organization_id=user.organization_id,
            email=user.email,
            role=user.role,
            issuer=user.identity_issuer,
            subject=user.identity_subject,
        )
        repository = SqlChangeSetRepository(session)
        encoded_key = master_key(settings)
        secrets = EncryptedDatabaseSecretStore(
            session, encoded_key, settings.secret_store_key_version
        )
        service = ChangeSetService(
            SqlAuthorizationRepository(session),
            repository,
            GuardedProviderTransactionExecutor(secrets, build_real_provider),
        )
        worker_owner = f"{os.uname().nodename}:{os.getpid()}:{uuid4()}"
        lease_heartbeat = asyncio.create_task(
            _heartbeat_change_set_execution(change_set_id, worker_owner)
        )
        try:
            execution = await service.execute(
                principal, group_id, change_set_id, queued=True, execution_owner=worker_owner
            )
            session.commit()
            # A successful or ambiguous write is followed by a fresh provider read. The write
            # executor's response is not treated as the application's final inventory state.
            manager_ids = {
                UUID(str(item["manager_id"]))
                for item in cast("list[dict[str, object]]", execution.get("transactions", []))
                if item.get("manager_id")
            }
            if not manager_ids:
                manager_ids = set(
                    session.scalars(
                        select(ProviderTransaction.manager_id).where(
                            ProviderTransaction.change_set_id == change_set_id
                        )
                    )
                )
            connection_ids = list(
                session.scalars(
                    select(FirewallManager.provider_connection_id).where(
                        FirewallManager.id.in_(manager_ids),
                        FirewallManager.provider_connection_id.is_not(None),
                    )
                )
            )
            for connection_id in connection_ids:
                DeploymentService(session).schedule_connector(principal, connection_id)
                session.commit()
                fence = session.info.get("execution_fence")
                if isinstance(fence, ExecutionFence):
                    fence.check()
                synchronize_provider_connection.send(str(connection_id))
        except ExecutionFenceLostError:
            session.rollback()
            return
        except ApplicationError as exc:
            if exc.details.get("code") == "CHANGE_SET_ALREADY_CLAIMED":
                # Redis may redeliver while the original worker still owns the durable
                # execution claim. The duplicate must exit without changing its state.
                session.rollback()
                return
            current = repository.get_change_set(principal, group_id, change_set_id)
            if current is not None and current["state"] not in {
                ChangeSetState.QUEUED.value,
                ChangeSetState.EXECUTING.value,
            }:
                # The service persisted a deliberate terminal outcome (for example a current
                # authorization denial). Preserve that detailed result instead of rolling it back
                # and replacing it with a generic worker failure.
                session.commit()
                return
            session.rollback()
            current = repository.get_change_set(principal, group_id, change_set_id)
            if current is not None and current["state"] in {
                ChangeSetState.QUEUED.value,
                ChangeSetState.EXECUTING.value,
            }:
                repository.set_execution_state(
                    principal,
                    group_id,
                    change_set_id,
                    (
                        ChangeSetState.RECONCILIATION_REQUIRED.value
                        if getattr(session.get(ChangeSet, change_set_id), "mutation_intent", {})
                        else ChangeSetState.FAILED.value
                    ),
                    {},
                    {"code": exc.code},
                )
                repository.record_change_event(
                    principal,
                    group_id,
                    UUID(str(current["access_policy_id"])),
                    change_set_id,
                    "change_set_execution",
                    "FAILED",
                    {"error_code": exc.code},
                )
                session.commit()
        except Exception:
            session.rollback()
            current = repository.get_change_set(principal, group_id, change_set_id)
            if current is not None and current["state"] in {
                ChangeSetState.QUEUED.value,
                ChangeSetState.EXECUTING.value,
            }:
                repository.set_execution_state(
                    principal,
                    group_id,
                    change_set_id,
                    (
                        ChangeSetState.RECONCILIATION_REQUIRED.value
                        if getattr(session.get(ChangeSet, change_set_id), "mutation_intent", {})
                        else ChangeSetState.FAILED.value
                    ),
                    {},
                    {"code": "CHANGE_SET_EXECUTION_ERROR"},
                )
                repository.record_change_event(
                    principal,
                    group_id,
                    UUID(str(current["access_policy_id"])),
                    change_set_id,
                    "change_set_execution",
                    "FAILED",
                    {"error_code": "CHANGE_SET_EXECUTION_ERROR"},
                )
                session.commit()
            raise
        finally:
            lease_heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await lease_heartbeat


async def _heartbeat_change_set_execution(change_set_id: UUID, owner: str) -> None:
    """Keep a live provider call from expiring its durable worker claim."""
    while True:
        await asyncio.sleep(30)
        with new_session() as session:
            repository = SqlChangeSetRepository(session)
            if not repository.heartbeat_execution_lease(
                change_set_id,
                owner,
                lease_seconds=CHANGE_SET_EXECUTION_LEASE_SECONDS,
            ):
                return
            session.commit()


async def _reconcile_change_set(change_set_id: UUID) -> None:  # noqa: PLR0915 -- fenced read-only recovery
    """Recover result evidence only. An uncertain job can never enter mutation execution."""
    with new_session() as session, mutation_scope(session):
        row = session.scalar(
            select(ChangeSet).where(ChangeSet.id == change_set_id).with_for_update()
        )
        now = datetime.now(UTC)
        if row is None or row.state != "RECONCILIATION_REQUIRED" or not row.mutation_intent:
            return
        if row.execution_lease_until is not None and row.execution_lease_until > now:
            return
        row.execution_epoch += 1
        row.execution_owner = f"reconcile:{uuid4()}"
        row.execution_lease_until = now + timedelta(minutes=10)
        session.commit()
        fence = ExecutionFence(session, ChangeSet, row.id, row.execution_epoch, row.execution_owner)
        entries = list(row.mutation_intent.get("entries", []))
        settings = get_settings()
        secrets = EncryptedDatabaseSecretStore(
            session, master_key(settings), settings.secret_store_key_version
        )
        try:
            for index, intent in enumerate(entries):
                manager_id = intent.get("context", {}).get("manager_id")
                manager = (
                    session.get(FirewallManager, UUID(str(manager_id))) if manager_id else None
                )
                if manager is None or manager.provider_connection_id is None:
                    continue
                pinned_id = intent.get("context", {}).get("provider_connection_id")
                if not pinned_id:
                    continue
                context = SqlProviderConnectionRepository(session).connection_context(
                    row.organization_id, UUID(str(pinned_id))
                )
                if context is None:
                    continue
                recorded = intent.get("context", {})
                if recorded.get("provider_endpoint") != context.get(
                    "base_endpoint"
                ) or recorded.get("provider_region") != context.get("region"):
                    entries[index] = {
                        **intent,
                        "reconciliation": {
                            "state": "UNKNOWN",
                            "reason": "PROVIDER_CONTEXT_CHANGED",
                        },
                    }
                    row.mutation_intent = {**row.mutation_intent, "entries": entries}
                    session.commit()
                    continue
                credential = secrets.retrieve(
                    row.organization_id,
                    UUID(str(context["credential_reference"])),
                    f"provider-connection:{pinned_id}",
                )
                provider = build_real_provider(context, credential, context.get("capabilities", {}))
                try:
                    evidence = await provider.reconcile_mutation(intent)
                finally:
                    await provider.aclose()
                entries[index] = {**intent, "reconciliation": evidence}
                row.mutation_intent = {**row.mutation_intent, "entries": entries}
                row.failure_info = {
                    **row.failure_info,
                    "recovery": "READ_ONLY_RECONCILIATION",
                    "outcomes": [
                        item.get("reconciliation", {}).get("state", "UNKNOWN") for item in entries
                    ],
                }
                # Keep the aggregate job under review: remaining operations and ownership
                # adoption must not be inferred from desired state or a same-name object.
                session.commit()
        except ExecutionFenceLostError:
            session.rollback()
        finally:
            try:
                fence.check()
                row.execution_owner = None
                row.execution_lease_until = None
                session.commit()
            except ExecutionFenceLostError:
                session.rollback()


@dramatiq.actor(max_retries=0)
def recover_expired_change_set_executions() -> None:
    """Requeue expired workers; persisted operation evidence is retained for safe resume."""
    with new_session() as session:
        repository = SqlChangeSetRepository(session)
        recovered = repository.recover_expired_execution_leases()
        uncertain = list(
            session.scalars(
                select(ChangeSet).where(
                    ChangeSet.state == "RECONCILIATION_REQUIRED",
                    ChangeSet.execution_lease_until.is_(None),
                )
            )
        )
        rows = [session.get(ChangeSet, item) for item in recovered] + uncertain
        session.commit()
    for row in rows:
        if row is not None:
            execute_change_set.send(
                str(row.id),
                str(row.principal_id),
                str(row.acting_group_id),
                str(row.organization_id),
            )


@dramatiq.actor(max_retries=0)
def recover_expired_deployments() -> None:
    """Fence workers that stopped heartbeating and require explicit reconciliation."""
    now = datetime.now(UTC)
    with new_session() as session:
        rows = list(
            session.scalars(
                select(Deployment)
                .where(
                    Deployment.lease_until.is_not(None),
                    Deployment.lease_until <= now,
                    Deployment.state.in_(
                        ("READY", "DEPLOYING", "UNKNOWN", "RECONCILIATION_REQUIRED")
                    ),
                )
                .with_for_update()
            )
        )
        for row in rows:
            row.state = "RECONCILIATION_REQUIRED"
            row.failure_info = {
                **row.failure_info,
                "code": "DEPLOYMENT_WORKER_LEASE_EXPIRED",
                "message": "Provider state must be reconciled before retrying.",
            }
            row.execution_epoch += 1
            if row.rollback_state in {"READY", "ROLLING_BACK"}:
                row.rollback_state = "RECONCILIATION_REQUIRED"
            row.lease_owner = None
            row.lease_until = None
            row.heartbeat_at = now
            if row.provider_connection_id:
                connection = session.get(ProviderConnection, row.provider_connection_id)
                if connection is not None:
                    connection.deployment_status = "RECONCILIATION_REQUIRED"
        session.commit()
        recovered_ids = [str(row.id) for row in rows if row.provider_connection_id]
    for deployment_id in recovered_ids:
        execute_deployment_batch.send(deployment_id)


@dramatiq.actor(max_retries=0)
def deliver_email_notifications() -> None:
    """Deliver a bounded durable SMTP outbox batch."""
    with new_session() as session:
        deliver_queued_email_notifications(get_settings(), session)


@dramatiq.actor(max_retries=0)
def enqueue_scheduled_deployments() -> None:
    """Batch due staged changes per connector; the deployment worker handles provider jobs."""
    now = datetime.now(UTC)
    with new_session() as session:
        active_batch_ids = list(
            session.scalars(
                select(Deployment.id)
                .where(
                    Deployment.state.in_(("READY", "DEPLOYING")),
                    Deployment.provider_connection_id.is_not(None),
                )
                .join(
                    ProviderConnection, ProviderConnection.id == Deployment.provider_connection_id
                )
                .where(ProviderConnection.deployment_paused.is_(False))
            )
        )
        connections = list(
            session.scalars(
                select(ProviderConnection).where(
                    ProviderConnection.lifecycle == "ACTIVE",
                    ProviderConnection.write_enabled.is_(True),
                    ProviderConnection.deployment_schedule_enabled.is_(True),
                    (ProviderConnection.deployment_status.is_(None))
                    # QUEUED means a batch exists and must still be dispatched. Only
                    # RUNNING suppresses creation of another batch for this connector.
                    | ProviderConnection.deployment_status.notin_(("RUNNING", "NOT_APPLICABLE")),
                )
            )
        )
        # READY batches can be left behind if the worker restarts after the batch is
        # committed but before the message is delivered. Re-dispatch them here; the
        # execution task is state-aware and will only start a READY batch once.
        queued_ids: list[UUID] = list(active_batch_ids)
        for connection in connections:
            if connection.deployment_paused:
                if connection.deployment_pause_until and connection.deployment_pause_until <= now:
                    connection.deployment_paused = False
                    connection.deployment_pause_reason = None
                    connection.deployment_paused_at = None
                    connection.deployment_pause_until = None
                    connection.deployment_paused_by_user_id = None
                    connection.deployment_status = None
                else:
                    continue
            deployment_due = (
                connection.deployment_next_at is None or connection.deployment_next_at <= now
            )
            admin = session.scalar(
                select(User).where(
                    User.organization_id == connection.organization_id,
                    User.role == "admin",
                    User.is_active.is_(True),
                )
            )
            if admin is None:
                continue
            principal = Principal(
                user_id=admin.id,
                organization_id=admin.organization_id,
                email=admin.email,
                role=admin.role,
                issuer=admin.identity_issuer,
                subject=admin.identity_subject,
            )
            service = DeploymentService(session)
            # Materialize a visible SCHEDULED batch as soon as staged work exists.
            # The provider start remains gated by deployment_next_at below.
            service.schedule_connector(principal, connection.id)
            if deployment_due:
                result = service.queue_connector(principal, connection.id)
            else:
                result = {"status": "SCHEDULED_ONLY"}
            if result.get("id"):
                connection.deployment_next_at = now + timedelta(
                    minutes=connection.deployment_interval_minutes
                )
                queued_ids.append(UUID(str(result["id"])))
            elif result.get("status") == "NO_PENDING_CHANGES":
                connection.deployment_next_at = now + timedelta(
                    minutes=connection.deployment_interval_minutes
                )
        session.commit()
    for deployment_id in queued_ids:
        execute_deployment_batch.send(str(deployment_id))


@dramatiq.actor(max_retries=0)
def execute_deployment_batch(deployment_id: str) -> None:
    """Start or poll one connector batch; provider acceptance is persisted before polling."""
    asyncio.run(_execute_deployment_batch(UUID(deployment_id)))


async def _execute_deployment_batch(deployment_id: UUID) -> None:  # noqa: PLR0911, PLR0912, PLR0915
    settings = get_settings()
    with new_session() as session, mutation_scope(session):
        owner = f"deployment:{os.uname().nodename}:{os.getpid()}:{uuid4()}"
        now = datetime.now(UTC)
        deployment = session.scalar(
            select(Deployment).where(Deployment.id == deployment_id).with_for_update()
        )
        if deployment is None or deployment.provider_connection_id is None:
            return
        if deployment.state not in {
            "READY",
            "DEPLOYING",
            "RECONCILIATION_REQUIRED",
        } and deployment.rollback_state not in {
            "READY",
            "ROLLING_BACK",
        }:
            return
        connection = session.get(ProviderConnection, deployment.provider_connection_id)
        if connection is None or connection.lifecycle != "ACTIVE":
            return
        if connection.deployment_paused and deployment.state == "READY":
            return
        if deployment.lease_until is not None and deployment.lease_until > now:
            return
        deployment.execution_epoch += 1
        deployment.lease_owner = owner
        deployment.lease_until = now + timedelta(minutes=10)
        deployment.heartbeat_at = now
        session.commit()
        fence = ExecutionFence(
            session, Deployment, deployment.id, deployment.execution_epoch, owner
        )
        fence.authorize = lambda: DeploymentService(session).authorize_dispatch(deployment.id)
        repository = SqlProviderConnectionRepository(session)
        context = repository.connection_context(connection.organization_id, connection.id)
        if context is None:
            return
        encoded_key = master_key(settings)
        secrets = EncryptedDatabaseSecretStore(
            session, encoded_key, settings.secret_store_key_version
        )
        credential = secrets.retrieve(
            connection.organization_id,
            UUID(str(context["credential_reference"])),
            f"provider-connection:{connection.id}",
        )
        capabilities = {
            str(key): str(value)
            for key, value in cast("dict[object, object]", context.get("capabilities", {})).items()
        }
        provider = build_real_provider(context, credential, capabilities)
        try:
            if deployment.state == "RECONCILIATION_REQUIRED":
                entries = deployment.mutation_intent.get("entries", [])
                jobs = provider.recover_deployment_jobs(entries)
                scopes = {
                    str(item.get("context", {}).get("scope", {}).get("domain_id"))
                    for item in entries
                }
                planned = set(deployment.plan_snapshot.get("dispatch_domains", []))
                if (
                    not jobs
                    or not planned
                    or {str(job["domain_id"]) for job in jobs} != planned
                    or len(jobs) != len(scopes)
                    or deployment.rollback_state == "RECONCILIATION_REQUIRED"
                ):
                    deployment.failure_info = {
                        **deployment.failure_info,
                        "recovery": "PROVIDER_OUTCOME_UNKNOWN",
                    }
                    session.commit()
                    return
                deployment.plan_snapshot = {
                    **deployment.plan_snapshot,
                    "provider_jobs": jobs,
                    "recovered_from_intent": True,
                }
                deployment.external_operation_id = str(jobs[0]["external_operation_id"])
                deployment.state = "DEPLOYING"
                session.commit()
            if deployment.rollback_state == "READY":
                jobs = deployment.plan_snapshot.get("provider_jobs", [])
                first_job = jobs[0] if isinstance(jobs, list) and jobs else {}
                domain_id = (
                    str(first_job.get("domain_id") or "") if isinstance(first_job, dict) else ""
                )
                original_operation_id = deployment.external_operation_id
                device_ids = [
                    str(item.get("uid") or item.get("deviceUUID") or item.get("device_id"))
                    for item in deployment.device_results
                    if isinstance(item, dict)
                    and (item.get("uid") or item.get("deviceUUID") or item.get("device_id"))
                ]
                if not device_ids:
                    device_ids = list(deployment.target_device_ids)
                if not domain_id or not original_operation_id or not device_ids:
                    raise ApplicationError(details={"code": "ROLLBACK_PROVIDER_CONTEXT_MISSING"})
                deployment.rollback_state = "RECONCILIATION_REQUIRED"
                session.commit()
                token = mutation_context.set(
                    {
                        "operation_id": f"rollback:{deployment.id}:{original_operation_id}",
                        "provider_connection_id": str(connection.id),
                        "connection_revision": context.get("revision"),
                        "provider_endpoint": context.get("base_endpoint"),
                        "provider_region": context.get("region"),
                        "rollback_devices": device_ids,
                    }
                )
                try:
                    result = await provider.rollback_deployment(
                        domain_id, original_operation_id, device_ids
                    )
                finally:
                    mutation_context.reset(token)
                deployment.rollback_external_operation_id = (
                    str(result.get("external_operation_id") or "") or None
                )
                deployment.rollback_state = "ROLLING_BACK"
                deployment.plan_snapshot = {
                    **deployment.plan_snapshot,
                    "rollback_provider": result.get("provider", {}),
                }
                connection.deployment_status = "ROLLING_BACK"
                session.commit()
            if deployment.rollback_state == "ROLLING_BACK":
                rollback_operation_id = deployment.rollback_external_operation_id
                if not rollback_operation_id:
                    raise ApplicationError(details={"code": "ROLLBACK_PROVIDER_TASK_MISSING"})
                status = await provider.rollback_status(rollback_operation_id)
                rollback_state = str(status.get("state") or "UNKNOWN")
                deployment.rollback_device_results = [
                    item for item in status.get("devices", []) if isinstance(item, dict)
                ]
                deployment.plan_snapshot = {
                    **deployment.plan_snapshot,
                    "rollback_provider_status": status,
                }
                if rollback_state == "ROLLED_BACK":
                    deployment.rollback_state = "ROLLED_BACK"
                    connection.deployment_status = "COMPLETED"
                    connection.deployment_last_completed_at = datetime.now(UTC)
                elif rollback_state == "FAILED":
                    deployment.rollback_state = "FAILED"
                    deployment.rollback_failure_info = {
                        "code": "PROVIDER_ROLLBACK_FAILED",
                        "provider_status": status.get("provider_status"),
                        "provider": status.get("provider", {}),
                    }
                    connection.deployment_status = "FAILED"
                session.commit()
                return
            if deployment.state == "READY":
                if deployment.plan_snapshot.get("start_intent"):
                    deployment.state = "RECONCILIATION_REQUIRED"
                    connection.deployment_status = "RECONCILIATION_REQUIRED"
                    session.commit()
                    return
                deployment.plan_snapshot = {**deployment.plan_snapshot, "start_intent": True}
                deployment.state = "RECONCILIATION_REQUIRED"
                session.commit()
                jobs: list[dict[str, object]] = []
                dispatch_scopes = DeploymentService(session).dispatch_scope(deployment.id)
                deployment.plan_snapshot = {
                    **deployment.plan_snapshot,
                    "dispatch_domains": [work["domain_id"] for work in dispatch_scopes],
                }
                session.commit()
                already_deployed = True
                for work in dispatch_scopes:
                    token = mutation_context.set(
                        {
                            "operation_id": f"deployment:{deployment.id}:{work['domain_id']}",
                            "provider_connection_id": str(connection.id),
                            "connection_revision": context.get("revision"),
                            "provider_endpoint": context.get("base_endpoint"),
                            "provider_region": context.get("region"),
                            "scope": work,
                        }
                    )
                    try:
                        result = await provider.start_deployment(
                            str(work["domain_id"]),
                            work["policy_ids"],
                            work["device_ids"],
                            work["expected_mutations"],
                        )
                    finally:
                        mutation_context.reset(token)
                    if str(result.get("state") or "").upper() != "DEPLOYED":
                        already_deployed = False
                    jobs.append(
                        {
                            "external_operation_id": result.get("external_operation_id"),
                            "domain_id": work["domain_id"],
                            "provider": result.get("provider", {}),
                            "state": result.get("state"),
                            "devices": result.get("devices", []),
                        }
                    )
                    deployment.pending_change_evidence = result.get("preflight", {})
                    deployment.plan_snapshot = {**deployment.plan_snapshot, "provider_jobs": jobs}
                    session.commit()
                if not jobs:
                    raise ApplicationError(details={"code": "DEPLOYMENT_SCOPE_EMPTY"})
                deployment.plan_snapshot = {**deployment.plan_snapshot, "provider_jobs": jobs}
                if already_deployed:
                    deployment.state = "DEPLOYED"
                    deployment.device_results = [
                        device
                        for job in jobs
                        for device in job.get("devices", [])
                        if isinstance(device, dict)
                    ]
                    connection.deployment_status = "COMPLETED"
                    connection.deployment_last_completed_at = datetime.now(UTC)
                    session.commit()
                    fence.check()
                    synchronize_provider_connection.send(str(connection.id))
                    return
                if jobs:
                    deployment.external_operation_id = (
                        str(jobs[0].get("external_operation_id") or "") or None
                    )
                deployment.state = "DEPLOYING"
                connection.deployment_status = "RUNNING"
                connection.deployment_last_started_at = datetime.now(UTC)
                session.commit()
            jobs = deployment.plan_snapshot.get("provider_jobs", [])
            if jobs and not deployment.external_operation_id:
                deployment.external_operation_id = (
                    str(jobs[0].get("external_operation_id") or "") or None
                )
            statuses = []
            for job in jobs:
                operation_id = str(job.get("external_operation_id") or "")
                if operation_id:
                    statuses.append(await provider.deployment_status(operation_id))
            if statuses:
                deployment.plan_snapshot = {
                    **deployment.plan_snapshot,
                    "provider_statuses": statuses,
                }
            if statuses and all(str(item.get("state")) == "DEPLOYED" for item in statuses):
                deployment.state = "DEPLOYED"
                deployment.device_results = [
                    item for status in statuses for item in status.get("devices", [])
                ]
                connection.deployment_status = "COMPLETED"
                connection.deployment_last_completed_at = datetime.now(UTC)
                session.commit()
                fence.check()
                synchronize_provider_connection.send(str(connection.id))
            elif any(str(item.get("state")) == "FAILED" for item in statuses):
                deployment.state = "FAILED"
                deployment.failure_info = deployment_failure_info(statuses)
                deployment.device_results = [
                    item for status in statuses for item in status.get("devices", [])
                ]
                connection.deployment_status = "FAILED"
            deployment.heartbeat_at = datetime.now(UTC)
            deployment.lease_until = datetime.now(UTC) + timedelta(minutes=10)
            session.commit()
        except ExecutionFenceLostError:
            session.rollback()
            return
        except Exception as exc:
            session.rollback()
            deployment = session.get(Deployment, deployment_id)
            details = getattr(exc, "details", None)
            if (
                deployment is not None
                and deployment.state == "READY"
                and isinstance(details, dict)
                and details.get("code") == "NO_DEPLOYABLE_DEVICES"
            ):
                deployment.state = "NOT_DEPLOYED"
                deployment.failure_info = {
                    "code": "DEPLOYMENT_NOT_APPLICABLE",
                    "reason": "POLICY_HAS_NO_ASSIGNED_DEVICES",
                    "provider_messages": details.get("provider_messages", []),
                }
                deployment.plan_snapshot = {
                    **deployment.plan_snapshot,
                    "deployment_skipped": True,
                    "skip_reason": "POLICY_HAS_NO_ASSIGNED_DEVICES",
                }
                connection.deployment_status = "NOT_APPLICABLE"
                deployment.heartbeat_at = datetime.now(UTC)
                deployment.lease_owner = None
                deployment.lease_until = None
                session.commit()
                return
            if deployment is not None and deployment.rollback_state in ("READY", "ROLLING_BACK"):
                deployment.rollback_state = "FAILED"
                deployment.rollback_failure_info = {
                    "code": "PROVIDER_ROLLBACK_START_FAILED",
                    "details": str(exc)[:1000],
                }
                connection.deployment_status = "FAILED"
                deployment.heartbeat_at = datetime.now(UTC)
                deployment.lease_until = datetime.now(UTC) + timedelta(minutes=10)
                session.commit()
            elif deployment is not None and deployment.state in {
                "READY",
                "RECONCILIATION_REQUIRED",
            }:
                deployment.state = "RECONCILIATION_REQUIRED"
                failure_info = _deployment_start_failure_info(exc)
                deployment.failure_info = failure_info
                if (
                    not deployment.mutation_intent
                    and not deployment.external_operation_id
                ) or is_definitive_provider_rejection(failure_info):
                    # Preflight/authorization refused, or the provider definitively rejected
                    # the deployment request before accepting a job.
                    deployment.state = "FAILED"
                    if failure_info["code"] == "PROVIDER_DEPLOYMENT_START_UNCERTAIN":
                        failure_info["code"] = str(
                            failure_info.pop("provider_code", "PROVIDER_DEPLOYMENT_START_FAILED")
                        )
                    deployment.failure_info = failure_info
                    deployment.plan_snapshot = {
                        key: value
                        for key, value in deployment.plan_snapshot.items()
                        if key != "start_intent"
                    }
                    connection.deployment_status = "FAILED"
                else:
                    connection.deployment_status = "RECONCILIATION_REQUIRED"
            deployment.heartbeat_at = datetime.now(UTC)
            deployment.lease_until = datetime.now(UTC) + timedelta(minutes=10)
            session.commit()
            # The failure is now durable and visible through the deployment API.  Re-raising
            # after committing turns an expected provider rejection (for example, no FMC
            # deployable devices) into an unhandled Dramatiq error and obscures the operator
            # state.  The deployment actor has no retry budget, so return after recording the
            # terminal failure and let the normal lease cleanup run.
            return
        finally:
            try:
                fence.check()
                current = session.get(Deployment, deployment_id)
                if current is not None:
                    current.lease_owner = None
                    current.lease_until = None
                    current.heartbeat_at = datetime.now(UTC)
                    session.commit()
            except ExecutionFenceLostError:
                session.rollback()
            await provider.aclose()


def _deployment_start_failure_info(exc: BaseException) -> dict[str, object]:
    """Preserve deterministic preflight errors; reserve uncertain for in-flight writes."""
    if isinstance(exc, ApplicationError):
        return {"code": exc.code, **exc.details}
    details = getattr(exc, "details", None)
    info: dict[str, object] = {"code": "PROVIDER_DEPLOYMENT_START_UNCERTAIN"}
    if isinstance(details, dict):
        info.update(details)
    provider_code = getattr(exc, "code", None)
    if (
        isinstance(provider_code, str)
        and provider_code
        and info["code"] == "PROVIDER_DEPLOYMENT_START_UNCERTAIN"
    ):
        info["provider_code"] = provider_code
    return info


def deployment_failure_info(statuses: list[dict[str, object]]) -> dict[str, object]:
    """Normalize provider deployment errors without shadowing the live adapter instance."""
    provider_messages: list[dict[str, str]] = []
    for status in statuses:
        provider_payload = status.get("provider")
        if not isinstance(provider_payload, dict):
            continue
        for field in ("errorMsg", "errorMessage", "failureReason"):
            message = provider_payload.get(field)
            if message:
                provider_messages.append({"field": field, "message": str(message)[:1000]})
    return {
        "code": "PROVIDER_DEPLOYMENT_FAILED",
        "provider_statuses": [str(item.get("provider_status") or "UNKNOWN") for item in statuses],
        "provider_messages": provider_messages,
    }


async def _synchronize_provider_connection(connection_id: UUID, mode: str = "FULL") -> None:
    settings = get_settings()
    with new_session() as session:
        connections = SqlProviderConnectionRepository(session)
        try:
            organization_id, manager_id = connections.mark_sync_running(connection_id, mode)
        except ApplicationError:
            # A disabled, retired, or removed connection is a terminal stale queue message.
            session.rollback()
            return
        try:
            context = connections.connection_context(organization_id, connection_id)
            if context is None:
                return
            encoded_key = master_key(settings)
            secrets = EncryptedDatabaseSecretStore(
                session, encoded_key, settings.secret_store_key_version
            )
            credential = secrets.retrieve(
                organization_id,
                UUID(str(context["credential_reference"])),
                f"provider-connection:{connection_id}",
            )
            raw_capabilities = context.get("capabilities", {})
            capabilities = {
                str(key): str(value)
                for key, value in cast("dict[object, object]", raw_capabilities).items()
            }
            provider = build_real_provider(context, credential, capabilities)
            try:
                result = await SynchronizationService(SqlSyncRepository(session)).synchronize(
                    manager_id,
                    provider,
                    applications_only=mode == "APPLICATIONS",
                    include_applications=mode == "FULL",
                )
            finally:
                await provider.aclose()
            error_code = None if result.status.value == "COMPLETED" else "PROVIDER_SYNC_FAILED"
            connections.mark_sync_finished(connection_id, result.status.value, error_code, mode)
        except ApplicationError as exc:
            session.rollback()
            connections.mark_sync_finished(connection_id, "FAILED", exc.code, mode)
        except Exception:
            # Preserve a terminal observable state even when an unexpected adapter/parser defect
            # is re-raised for Dramatiq's bounded retry and traceback logging.
            session.rollback()
            connections.mark_sync_finished(connection_id, "FAILED", "PROVIDER_SYNC_FAILED", mode)
            raise


@dramatiq.actor(max_retries=1, min_backoff=5000)
def enqueue_scheduled_provider_syncs() -> None:
    """Claim due connections in one bounded batch; never create per-connection timers."""
    with new_session() as session:
        repository = SqlProviderConnectionRepository(session)
        jobs = repository.queue_due_sync_jobs(datetime.now(UTC))
    for connection_id, mode in jobs:
        synchronize_provider_connection.send(str(connection_id), mode)
