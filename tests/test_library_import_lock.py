"""Serialization of library imports, and the shared lock behind it.

Two concurrent imports of one source cost two MITRE downloads and ~1,000 redundant DB round
trips, and report contradictory counts for one button ("added 100" / "added 0"). The data stays
correct either way -- the upserts are first-writer -- so this guards cost and trust.

The guard lives in the CELERY TASK, not the route: the route returns 202 and the work happens
later, so a lock held only for the request's duration would protect nothing. The route's probe is
advisory, for a fast 409.
"""
from __future__ import annotations

import pytest

from app.core import joblock
from app.intel.library_import import ImportAlreadyRunning, ThreatLibraryImportError, lock_key


class _FakeRedis:
    """The surface redis.lock.Lock actually touches for acquire: SET NX, plus a register_script
    that returns a no-op (release/extend are exercised for real in
    tests/test_embeddings_group_lock.py against a Lua-faithful fake -- not re-tested here)."""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def set(self, name, value, nx=False, px=None, **_kw):
        if nx and name in self.store:
            return None
        self.store[name] = value
        return True

    def get(self, name):
        return self.store.get(name)

    def exists(self, name):
        return 1 if name in self.store else 0

    def register_script(self, _script):
        return lambda *a, **k: 1


def test_second_holder_of_the_same_key_gets_the_busy_exception():
    r = _FakeRedis()
    busy = ImportAlreadyRunning("an import of 'pytm' is already running")
    with joblock.job_lock(lock_key("pytm"), ttl=5, busy=busy, redis_factory=lambda: r):
        with pytest.raises(ImportAlreadyRunning, match="already running"):
            with joblock.job_lock(lock_key("pytm"), ttl=5, busy=busy, redis_factory=lambda: r):
                pytest.fail("the second acquire must not succeed")


def test_a_different_source_is_not_blocked():
    """Serialization is PER SOURCE -- importing emb3d while pytm runs is legitimate."""
    r = _FakeRedis()
    entered = []
    with joblock.job_lock(lock_key("pytm"), ttl=5, busy=ImportAlreadyRunning("x"),
                        redis_factory=lambda: r):
        with joblock.job_lock(lock_key("emb3d"), ttl=5, busy=ImportAlreadyRunning("y"),
                            redis_factory=lambda: r):
            entered.append("emb3d")
    assert entered == ["emb3d"]


def test_unreachable_redis_fails_open(monkeypatch):
    """These locks guard redundant COST, never correctness: every protected operation is safe to
    run twice. A Redis outage must not stop imports working."""
    warned = []
    monkeypatch.setattr(joblock.log, "warning", lambda event, **kw: warned.append(event))

    def boom():
        raise ConnectionError("redis down")

    ran = []
    with joblock.job_lock(lock_key("pytm"), ttl=5, busy=ImportAlreadyRunning("never"),
                        redis_factory=boom):
        ran.append(1)
    assert ran == [1], "must proceed, not raise"
    assert warned == ["joblock.redis_unavailable_fail_open"]


def test_probe_reports_held_and_free():
    r = _FakeRedis()
    key = lock_key("atlas")
    assert joblock.is_held(key, redis_factory=lambda: r) is False
    with joblock.job_lock(key, ttl=5, busy=ImportAlreadyRunning("x"), redis_factory=lambda: r):
        assert joblock.is_held(key, redis_factory=lambda: r) is True


def test_probe_reports_free_when_redis_is_down(monkeypatch):
    """Fail-open again, and it matters MORE here: a probe must never be the reason a job is
    refused. Reporting 'held' on an outage would 409 every import until Redis came back."""
    monkeypatch.setattr(joblock.log, "warning", lambda event, **kw: None)

    def boom():
        raise ConnectionError("redis down")

    assert joblock.is_held(lock_key("pytm"), redis_factory=boom) is False


def test_busy_is_terminal_not_retryable():
    """ImportAlreadyRunning subclasses ThreatLibraryImportError so import_threat_library_task's
    existing `except ThreatLibraryImportError` returns a terminal result. If it were a bare
    Exception, autoretry_for=(Exception,) would burn the whole retry budget waiting for a lock."""
    assert issubclass(ImportAlreadyRunning, ThreatLibraryImportError)


def test_lock_key_is_defined_once_and_is_source_scoped():
    """The worker's acquire and the route's probe must agree on the key, so both call lock_key."""
    assert lock_key("pytm") != lock_key("emb3d")
    assert lock_key("pytm").startswith("tsg:library-import:")
