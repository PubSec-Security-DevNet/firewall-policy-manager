# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Scheduler health check based on the scheduler's expiring Redis heartbeat."""

from redis import Redis

from firewall_manager.config import get_settings
from firewall_manager.worker.health_keys import SCHEDULER_HEARTBEAT_KEY


def main() -> None:
    redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        healthy = redis.get(SCHEDULER_HEARTBEAT_KEY) is not None
    finally:
        redis.close()
    raise SystemExit(0 if healthy else 1)


if __name__ == "__main__":
    main()
