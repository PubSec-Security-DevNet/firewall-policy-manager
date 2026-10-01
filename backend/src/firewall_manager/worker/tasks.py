"""Idempotent worker tasks for health and queue-backed provider synchronization."""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import dramatiq
from redis import Redis
from sqlalchemy import select

from firewall_manager.application.changesets import ChangeSetService
from firewall_manager.application.deployments import DeploymentService
from firewall_manager.application.errors import ApplicationError
from firewall_manager.application.synchronization import SynchronizationService
from firewall_manager.config import get_settings
from firewall_manager.domain.models import ChangeSetState, Principal
from firewall_manager.notifications import deliver_queued_email_notifications
from firewall_manager.persistence.changesets import SqlChangeSetRepository
from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.models import (
    AccessPolicy,
    ChangeSet,
    Deployment,
    Device,
    FirewallManager,
    ProviderConnection,
    ProviderDomain,
    ProviderTransaction,
    User,
)
from firewall_manager.persistence.provider_connections import SqlProviderConnectionRepository
from firewall_manager.persistence.repositories import SqlAuthorizationRepository, SqlSyncRepository
from firewall_manager.persistence.secrets import EncryptedDatabaseSecretStore
from firewall_manager.providers.factory import build_real_provider
from firewall_manager.providers.transactions import GuardedProviderTransactionExecutor
from firewall_manager.worker.broker import broker

BROKER = broker

WORKER_HEARTBEAT_KEY = "firewall-manager:worker:last-heartbeat"


@dramatiq.actor(max_retries=3, min_backoff=1000)
def record_worker_heartbeat() -> None:
    """Record worker queue connectivity; repeated delivery is harmless."""
    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        redis.set(WORKER_HEARTBEAT_KEY, datetime.now(UTC).isoformat(), ex=120)
    finally:
        redis.close()


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


async def _execute_change_set(
    change_set_id: UUID,
    principal_id: UUID,
    group_id: UUID,
    organization_id: UUID,
) -> None:
    settings = get_settings()
    with new_session() as session:
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
        encoded_key = (
            settings.secret_store_master_key.get_secret_value()
            if settings.secret_store_master_key is not None
            else None
        )
        secrets = EncryptedDatabaseSecretStore(
            session, encoded_key, settings.secret_store_key_version
        )
        service = ChangeSetService(
            SqlAuthorizationRepository(session),
            repository,
            GuardedProviderTransactionExecutor(secrets, build_real_provider),
        )
        worker_owner = f"{os.uname().nodename}:{os.getpid()}"
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
                synchronize_provider_connection.send(str(connection_id))
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
                    ChangeSetState.FAILED.value,
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
                    ChangeSetState.FAILED.value,
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


@dramatiq.actor(max_retries=0)
def recover_expired_change_set_executions() -> None:
    """Requeue expired workers; persisted operation evidence is retained for safe resume."""
    with new_session() as session:
        repository = SqlChangeSetRepository(session)
        recovered = repository.recover_expired_execution_leases()
        rows = [session.get(ChangeSet, item) for item in recovered]
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
                select(Deployment.id).where(
                    Deployment.state.in_(("READY", "DEPLOYING")),
                    Deployment.provider_connection_id.is_not(None),
                )
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
                    | ProviderConnection.deployment_status.notin_(("RUNNING",)),
                )
            )
        )
        # READY batches can be left behind if the worker restarts after the batch is
        # committed but before the message is delivered. Re-dispatch them here; the
        # execution task is state-aware and will only start a READY batch once.
        queued_ids: list[UUID] = list(active_batch_ids)
        for connection in connections:
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
                connection.deployment_next_at = now + timedelta(minutes=15)
                queued_ids.append(UUID(str(result["id"])))
            elif result.get("status") == "NO_PENDING_CHANGES":
                connection.deployment_next_at = now + timedelta(minutes=15)
        session.commit()
    for deployment_id in queued_ids:
        execute_deployment_batch.send(str(deployment_id))


@dramatiq.actor(max_retries=0)
def execute_deployment_batch(deployment_id: str) -> None:
    """Start or poll one connector batch; provider acceptance is persisted before polling."""
    asyncio.run(_execute_deployment_batch(UUID(deployment_id)))


async def _execute_deployment_batch(deployment_id: UUID) -> None:  # noqa: PLR0912, PLR0915
    settings = get_settings()
    with new_session() as session:
        deployment = session.get(Deployment, deployment_id)
        if deployment is None or deployment.provider_connection_id is None:
            return
        connection = session.get(ProviderConnection, deployment.provider_connection_id)
        if connection is None or connection.lifecycle != "ACTIVE":
            return
        repository = SqlProviderConnectionRepository(session)
        context = repository.connection_context(connection.organization_id, connection.id)
        if context is None:
            return
        encoded_key = (
            settings.secret_store_master_key.get_secret_value()
            if settings.secret_store_master_key is not None
            else None
        )
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
                result = await provider.rollback_deployment(
                    domain_id, original_operation_id, device_ids
                )
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
                jobs: list[dict[str, object]] = []
                for change_set_id in deployment.included_change_set_ids:
                    change_set = session.get(ChangeSet, UUID(str(change_set_id)))
                    if change_set is None or change_set.access_policy_id is None:
                        continue
                    policy = session.get(AccessPolicy, change_set.access_policy_id)
                    if policy is None:
                        continue
                    domain = session.get(ProviderDomain, policy.domain_id)
                    if domain is None:
                        continue
                    device_ids = deployment.target_device_ids or list(
                        session.scalars(
                            select(Device.native_id).where(Device.domain_id == domain.id)
                        )
                    )
                    result = await provider.start_deployment(
                        domain.native_id, [policy.native_id], device_ids
                    )
                    jobs.append(
                        {
                            "external_operation_id": result.get("external_operation_id"),
                            "domain_id": domain.native_id,
                            "provider": result.get("provider", {}),
                        }
                    )
                deployment.plan_snapshot = {**deployment.plan_snapshot, "provider_jobs": jobs}
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
            elif any(str(item.get("state")) == "FAILED" for item in statuses):
                deployment.state = "FAILED"
                provider_messages: list[dict[str, str]] = []
                for status in statuses:
                    provider = status.get("provider")
                    if not isinstance(provider, dict):
                        continue
                    for field in ("errorMsg", "errorMessage", "failureReason"):
                        message = provider.get(field)
                        if message:
                            provider_messages.append(
                                {"field": field, "message": str(message)[:1000]}
                            )
                deployment.failure_info = {
                    "code": "PROVIDER_DEPLOYMENT_FAILED",
                    "provider_statuses": [
                        str(item.get("provider_status") or "UNKNOWN") for item in statuses
                    ],
                    "provider_messages": provider_messages,
                }
                deployment.device_results = [
                    item for status in statuses for item in status.get("devices", [])
                ]
                connection.deployment_status = "FAILED"
            session.commit()
        except Exception as exc:
            session.rollback()
            deployment = session.get(Deployment, deployment_id)
            if deployment is not None and deployment.rollback_state in ("READY", "ROLLING_BACK"):
                deployment.rollback_state = "FAILED"
                deployment.rollback_failure_info = {
                    "code": "PROVIDER_ROLLBACK_START_FAILED",
                    "details": str(exc)[:1000],
                }
                connection.deployment_status = "FAILED"
                session.commit()
            elif deployment is not None and deployment.state == "READY":
                deployment.state = "FAILED"
                failure_info: dict[str, object] = {"code": "PROVIDER_DEPLOYMENT_START_FAILED"}
                if isinstance(exc, ApplicationError):
                    failure_info.update(exc.details)
                else:
                    details = getattr(exc, "details", None)
                    if isinstance(details, dict):
                        failure_info.update(details)
                deployment.failure_info = failure_info
                connection.deployment_status = "FAILED"
                session.commit()
            raise
        finally:
            await provider.aclose()


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
            encoded_key = (
                settings.secret_store_master_key.get_secret_value()
                if settings.secret_store_master_key is not None
                else None
            )
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
