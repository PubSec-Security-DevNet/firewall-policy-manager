"""Dramatiq broker configuration."""

import dramatiq
from dramatiq.brokers.redis import RedisBroker

from firewall_manager.config import get_settings

# Delayed jobs (retries and scheduled dispatches) must be promoted deterministically in
# the low-throughput development deployment. RedisBroker performs maintenance when its
# random draw is zero, so 1 means every maintenance opportunity performs the promotion.
broker = RedisBroker(url=get_settings().redis_url, maintenance_chance=1)
dramatiq.set_broker(broker)
