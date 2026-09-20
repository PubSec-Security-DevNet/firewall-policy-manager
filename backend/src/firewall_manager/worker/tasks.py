"""Idempotent worker tasks for health and queue-backed provider synchronization."""

import asyncio
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import dramatiq
from redis import Redis

from firewall_manager.application.errors import ApplicationError
from firewall_manager.application.synchronization import SynchronizationService
from firewall_manager.config import get_settings
from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.provider_connections import SqlProviderConnectionRepository
from firewall_manager.persistence.repositories import SqlSyncRepository
from firewall_manager.persistence.secrets import EncryptedDatabaseSecretStore
from firewall_manager.providers.factory import build_real_provider
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


@dramatiq.actor(max_retries=1, min_backoff=5000)
def synchronize_provider_connection(connection_id: str) -> None:
    """Run one connection-isolated, read-only sync outside the web request process."""
    asyncio.run(_synchronize_provider_connection(UUID(connection_id)))


async def _synchronize_provider_connection(connection_id: UUID) -> None:
    settings = get_settings()
    with new_session() as session:
        connections = SqlProviderConnectionRepository(session)
        try:
            organization_id, manager_id = connections.mark_sync_running(connection_id)
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
                    manager_id, provider
                )
            finally:
                await provider.aclose()
            error_code = None if result.status.value == "COMPLETED" else "PROVIDER_SYNC_FAILED"
            connections.mark_sync_finished(connection_id, result.status.value, error_code)
        except ApplicationError as exc:
            session.rollback()
            connections.mark_sync_finished(connection_id, "FAILED", exc.code)
        except Exception:
            # Preserve a terminal observable state even when an unexpected adapter/parser defect
            # is re-raised for Dramatiq's bounded retry and traceback logging.
            session.rollback()
            connections.mark_sync_finished(connection_id, "FAILED", "PROVIDER_SYNC_FAILED")
            raise


@dramatiq.actor(max_retries=1, min_backoff=5000)
def enqueue_scheduled_provider_syncs() -> None:
    """Claim due connections in one bounded batch; never create per-connection timers."""
    with new_session() as session:
        repository = SqlProviderConnectionRepository(session)
        connection_ids = repository.queue_due_connections(datetime.now(UTC))
    for connection_id in connection_ids:
        synchronize_provider_connection.send(str(connection_id))
