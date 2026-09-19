"""Queue task redelivery safety."""

import pytest

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
