# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Single-purpose scheduler process for recurring durable jobs."""

import logging
import signal
import time
from collections.abc import Callable

from redis import Redis
from sqlalchemy import text

from firewall_manager.config import get_settings
from firewall_manager.persistence.database import SessionFactory
from firewall_manager.worker.health_keys import SCHEDULER_HEARTBEAT_KEY
from firewall_manager.worker.tasks import (
    cleanup_expired_authentication,
    deliver_email_notifications,
    enqueue_scheduled_deployments,
    enqueue_scheduled_provider_syncs,
    purge_expired_audit_events,
    record_worker_heartbeat,
    recover_expired_change_set_executions,
    recover_expired_deployments,
)

_running = True
logger = logging.getLogger(__name__)
SCHEDULER_LOCK_ID = 748_230_041


def stop(_signum: int, _frame: object) -> None:
    global _running  # noqa: PLW0603 -- signal handler owns process shutdown state
    _running = False


def main() -> None:
    """Run one scheduler instance and publish its liveness in Redis."""
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    settings = get_settings()
    interval = settings.scheduler_interval_seconds
    logging.basicConfig(level=settings.app_log_level)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    with SessionFactory() as lock_session:
        acquired = lock_session.execute(
            text("SELECT pg_try_advisory_lock(:lock_id)"), {"lock_id": SCHEDULER_LOCK_ID}
        ).scalar_one()
        if not acquired:
            raise SystemExit("Another scheduler owns the production singleton lock.")
        try:
            while _running:
                redis.set(SCHEDULER_HEARTBEAT_KEY, "ok", ex=max(120, interval * 4))
                _enqueue_safely(record_worker_heartbeat.send)
                _enqueue_safely(enqueue_scheduled_provider_syncs.send)
                _enqueue_safely(deliver_email_notifications.send)
                _enqueue_safely(enqueue_scheduled_deployments.send)
                _enqueue_safely(cleanup_expired_authentication.send)
                _enqueue_safely(purge_expired_audit_events.send)
                _enqueue_safely(recover_expired_deployments.send)
                _enqueue_safely(recover_expired_change_set_executions.send)
                deadline = time.monotonic() + interval
                while _running and time.monotonic() < deadline:
                    time.sleep(max(0.0, min(1.0, deadline - time.monotonic())))
        finally:
            redis.delete(SCHEDULER_HEARTBEAT_KEY)
            redis.close()
            lock_session.execute(
                text("SELECT pg_advisory_unlock(:lock_id)"), {"lock_id": SCHEDULER_LOCK_ID}
            )


def _enqueue_safely(send: Callable[[], object]) -> None:
    """Keep a transient broker timeout from terminating the scheduler loop."""
    try:
        send()
    except Exception:
        logger.exception("Unable to enqueue scheduled task; will retry on the next interval")


if __name__ == "__main__":
    main()
