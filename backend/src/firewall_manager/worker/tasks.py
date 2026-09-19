"""Idempotent worker tasks for the initial runtime."""

from datetime import UTC, datetime

import dramatiq
from redis import Redis

from firewall_manager.config import get_settings
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
