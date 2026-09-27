"""Queue task redelivery safety."""

from types import TracebackType
from typing import Self
from uuid import uuid4

import pytest

from firewall_manager.application.errors import InvalidChangeSetStateError
from firewall_manager.worker import tasks


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def set(self, key: str, value: str, ex: int) -> None:
        assert ex == 120
        self.values[key] = value

    def close(self) -> None:
        pass


def test_heartbeat_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()

    def fake_from_url(*_args: object, **_kwargs: object) -> FakeRedis:
        return fake

    monkeypatch.setattr(tasks.Redis, "from_url", fake_from_url)
    tasks.record_worker_heartbeat.fn()
    first = fake.values[tasks.WORKER_HEARTBEAT_KEY]
    tasks.record_worker_heartbeat.fn()
    assert fake.values[tasks.WORKER_HEARTBEAT_KEY] >= first


def test_stale_queue_message_cannot_restart_a_disabled_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeSession:
        rolled_back = False

        def __enter__(self) -> Self:
            return self

        def __exit__(
            self,
            _exception_type: type[BaseException] | None,
            _exception: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            return None

        def rollback(self) -> None:
            self.rolled_back = True

    class DisabledConnectionRepository:
        finished = False

        def mark_sync_running(self, _connection_id: object, _mode: str = "FULL") -> None:
            raise InvalidChangeSetStateError

        def mark_sync_finished(self, *_args: object) -> None:
            self.finished = True

    session = FakeSession()
    repository = DisabledConnectionRepository()

    def connection_repository(_session: object) -> DisabledConnectionRepository:
        return repository

    monkeypatch.setattr(tasks, "new_session", lambda: session)
    monkeypatch.setattr(tasks, "SqlProviderConnectionRepository", connection_repository)

    tasks.synchronize_provider_connection.fn(str(uuid4()))

    assert session.rolled_back is True
    assert repository.finished is False
