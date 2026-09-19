"""Single-purpose scheduler process for recurring durable jobs."""

import logging
import signal
import time

from firewall_manager.config import get_settings
from firewall_manager.worker.tasks import enqueue_scheduled_provider_syncs, record_worker_heartbeat

_running = True


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
        record_worker_heartbeat.send()
        enqueue_scheduled_provider_syncs.send()
        deadline = time.monotonic() + interval
        while _running and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))


if __name__ == "__main__":
    main()
