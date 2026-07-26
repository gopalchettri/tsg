"""SSE bus circuit-breaker: single-flight probing under concurrent publishes.

The autouse `_no_sse_publish` fixture (conftest.py) monkeypatches `bus.publish` to a
no-op for every other test — so this module captures the REAL function at import time
(collection happens before fixtures run) and calls it directly.
"""
from __future__ import annotations

import threading
import time

from app.sse import bus

_real_publish = bus.publish  # captured before conftest's autouse no-op patch rebinds the name


class _FakeRedis:
    """Stub client: counts publish calls; optionally sleeps (a slow/timing-out Redis) and raises."""

    def __init__(self, delay: float = 0.0, fail: bool = False):
        self.calls = 0
        self.delay = delay
        self.fail = fail
        self._lock = threading.Lock()

    def publish(self, ch, payload):
        with self._lock:
            self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise ConnectionError("redis down")


def _run_concurrent(n: int) -> None:
    barrier = threading.Barrier(n)

    def call(i: int) -> None:
        barrier.wait()  # maximize the "all mid-attempt before any failure" overlap
        _real_publish(f"session-{i}", {"type": "stage_started"})

    threads = [threading.Thread(target=call, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def test_concurrent_publishes_against_dead_redis_pay_exactly_one_timeout(monkeypatch):
    """5 greenlets race their first publish against a just-died Redis: only the lock winner
    (the prober) actually calls Redis; the rest wait for its outcome and no-op once the
    breaker opens — the docstring's 'at most one timeout per cooldown window' promise,
    extended to the pre-first-failure window."""
    fake = _FakeRedis(delay=0.3, fail=True)
    monkeypatch.setattr(bus, "_redis", lambda: fake)
    monkeypatch.setattr(bus, "_breaker_until", 0.0)

    _run_concurrent(5)

    assert fake.calls == 1  # exactly one attempt paid the timeout, not five
    assert time.monotonic() < bus._breaker_until  # and it opened the breaker

    _real_publish("another-session", {"type": "stage_completed"})
    assert fake.calls == 1  # breaker open → instant no-op, no new attempt


def test_concurrent_publishes_against_healthy_redis_all_deliver(monkeypatch):
    """The single-flight gate must never drop a legitimate event while Redis is up: every
    concurrent caller still makes its own publish call (followers just wait for the prober's
    round trip first)."""
    fake = _FakeRedis(delay=0.05, fail=False)
    monkeypatch.setattr(bus, "_redis", lambda: fake)
    monkeypatch.setattr(bus, "_breaker_until", 0.0)

    _run_concurrent(5)

    assert fake.calls == 5  # nothing dropped, nothing skipped
    assert bus._breaker_until == 0.0  # breaker never opened
