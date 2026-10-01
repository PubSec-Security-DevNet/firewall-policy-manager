"""Single-purpose scheduler process for recurring durable jobs."""

import logging
import signal
import time
from collections.abc import Callable

from firewall_manager.config import get_settings
from firewall_manager.worker.tasks import (
    deliver_email_notifications,
    enqueue_scheduled_deployments,
    enqueue_scheduled_provider_syncs,
    record_worker_heartbeat,
)

_running = True
logger = logging.getLogger(__name__)


def stop(_signum: int, _frame: object) -> None:
    global _running  # noqa: PLW0603 -- signal handler owns process shutdown state
    _running = False


def main() -> None:
    """Enqueue the heartbeat on an interval; the worker performs the actual task."""
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    interval = get_settings().scheduler_interval_seconds
    logging.basicConfig(level=get_settings().app_log_level)
    while _running:
        _enqueue_safely(record_worker_heartbeat.send)
        _enqueue_safely(enqueue_scheduled_provider_syncs.send)
        _enqueue_safely(deliver_email_notifications.send)
        _enqueue_safely(enqueue_scheduled_deployments.send)
        deadline = time.monotonic() + interval
        while _running and time.monotonic() < deadline:
            time.sleep(max(0.0, min(1.0, deadline - time.monotonic())))


def _enqueue_safely(send: Callable[[], object]) -> None:
    """Keep a transient broker timeout from terminating the scheduler loop."""
    try:
        send()
    except Exception:
        logger.exception("Unable to enqueue scheduled task; will retry on the next interval")


if __name__ == "__main__":
    main()
