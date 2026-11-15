"""Tests the retry / dead-letter flow with an in-memory stand-in for Redis."""
import json

import pytest

import app.worker as worker_module
from app.config import Settings
from app.worker import Worker


class FakeRedis:
    def __init__(self):
        self.streams: dict[str, list[dict]] = {}
        self.acked: list[str] = []

    def xadd(self, stream, fields, maxlen=None, approximate=True):
        self.streams.setdefault(stream, []).append(dict(fields))
        return f"{len(self.streams[stream])}-0"

    def xack(self, stream, group, message_id):
        self.acked.append(message_id)

    def events(self):
        return self.streams.get("scan:events", [])


@pytest.fixture
def worker(monkeypatch):
    monkeypatch.setattr(worker_module.time, "sleep", lambda *_: None)  # skip retry backoff
    settings = Settings(max_attempts=3, enable_network_checks=False, llm_provider="none")
    return Worker(settings, client=FakeRedis())


def job(attempt=1, payload=None, scan_type="url"):
    return {
        "scanId": "scan-1",
        "userId": "user-1",
        "type": scan_type,
        "payload": json.dumps(payload or {"url": "http://paypa1-secure-login.xyz/verify"}),
        "attempt": str(attempt),
    }


def test_successful_scan_publishes_scanning_then_done(worker):
    worker.handle("1-0", job())
    statuses = [e["status"] for e in worker.redis.events()]
    assert statuses == ["scanning", "done"]
    result = json.loads(worker.redis.events()[-1]["result"])
    assert result["verdict"] == "malicious"
    assert result["explanationSource"] == "rules"
    assert worker.redis.acked == ["1-0"]


def test_transient_error_is_retried(worker, monkeypatch):
    def flaky(*_args):
        raise ConnectionError("network blip")

    monkeypatch.setattr(worker_module, "run_scan", flaky)
    worker.handle("1-0", job(attempt=1))

    requeued = worker.redis.streams["scan:jobs"][0]
    assert requeued["attempt"] == "2"
    assert [e["status"] for e in worker.redis.events()] == ["scanning", "queued"]
    assert "scan:dlq" not in worker.redis.streams
    assert worker.redis.acked == ["1-0"]


def test_last_attempt_goes_to_dead_letter_queue(worker, monkeypatch):
    def broken(*_args):
        raise ConnectionError("still down")

    monkeypatch.setattr(worker_module, "run_scan", broken)
    worker.handle("1-0", job(attempt=3))

    assert worker.redis.streams["scan:dlq"][0]["error"] == "still down"
    assert worker.redis.events()[-1]["status"] == "failed"
    assert "scan:jobs" not in worker.redis.streams


def test_permanent_error_is_not_retried(worker):
    worker.handle("1-0", job(scan_type="pdf", payload={"x": 1}))
    assert "scan:jobs" not in worker.redis.streams
    assert worker.redis.streams["scan:dlq"][0]["error"].startswith("Unknown scan type")
    assert worker.redis.events()[-1]["status"] == "failed"


def test_malformed_job_goes_to_dlq(worker):
    worker.handle("1-0", {"type": "url", "payload": "{}"})
    assert "scan:dlq" in worker.redis.streams
    assert worker.redis.acked == ["1-0"]
