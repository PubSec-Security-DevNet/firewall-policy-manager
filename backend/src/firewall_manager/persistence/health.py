# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Database and Redis readiness adapter."""

from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from firewall_manager.application.errors import ProviderUnavailableError


class SqlRedisHealthProbe:
    """Check required local infrastructure without exposing clients to the API layer."""

    def __init__(self, session: Session, redis_url: str) -> None:
        self._session = session
        self._redis_url = redis_url

    async def check(self) -> None:
        try:
            self._session.execute(text("SELECT 1"))
            redis = Redis.from_url(self._redis_url)
            try:
                await redis.ping()
            finally:
                await redis.aclose()
        except (SQLAlchemyError, RedisError, ConnectionError, TimeoutError) as exc:
            raise ProviderUnavailableError from exc
