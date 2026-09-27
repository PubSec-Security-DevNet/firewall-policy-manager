"""Idempotent worker tasks for health and queue-backed provider synchronization."""

import asyncio
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import dramatiq
from redis import Redis
from sqlalchemy import select

from firewall_manager.application.changesets import ChangeSetService
from firewall_manager.application.errors import ApplicationError
from firewall_manager.application.synchronization import SynchronizationService
from firewall_manager.config import get_settings
from firewall_manager.domain.models import ChangeSetState, Principal
from firewall_manager.persistence.changesets import SqlChangeSetRepository
from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.models import ChangeSet, FirewallManager, User
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
        try:
            execution = await service.execute(principal, group_id, change_set_id, queued=True)
            session.commit()
            # A successful or ambiguous write is followed by a fresh provider read. The write
            # executor's response is not treated as the application's final inventory state.
            manager_ids = {
                UUID(str(item["manager_id"]))
                for item in cast("list[dict[str, object]]", execution.get("transactions", []))
                if item.get("manager_id")
            }
            connection_ids = list(
                session.scalars(
                    select(FirewallManager.provider_connection_id).where(
                        FirewallManager.id.in_(manager_ids),
                        FirewallManager.provider_connection_id.is_not(None),
                    )
                )
            )
            for connection_id in connection_ids:
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
