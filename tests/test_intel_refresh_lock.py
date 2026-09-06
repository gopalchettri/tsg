"""Two guards from the 2026-09-06 incident where three OTX refreshes ran at once: a duplicate
refresh of ONE feed must not walk the feed again, and a failed OTX page must wait before its
second attempt (an instant retry got the same 502/504 40-150ms later, every time)."""
from __future__ import annotations

import urllib.error
from types import SimpleNamespace

import pytest

from app.core import joblock
from app.intel import otx
from app.intel.fetchers import RefreshAlreadyRunning
from app.pipeline import celery_app as ca


class _FakeRedis:  # same surface as tests/test_library_import_lock.py
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


def test_duplicate_refresh_of_one_feed_returns_0_without_fetching(monkeypatch):
    r = _FakeRedis()
    ran: list[str] = []
    monkeypatch.setattr("app.pipeline.llm._slot_redis", lambda: r)
    monkeypatch.setattr("app.intel.fetchers.refresh_one", lambda feed: ran.append(feed) or 7)
    with joblock.job_lock("tsg:intel-refresh:otx", ttl=5, busy=RefreshAlreadyRunning("x"),
                        redis_factory=lambda: r):
        assert ca.intel_refresh_feed_task("otx") == 0          # held: skipped, not retried
        assert ca.intel_refresh_feed_task("cisa_kev") == 7     # a different feed still runs
    assert ran == ["cisa_kev"]


def test_failed_page_waits_before_second_attempt(monkeypatch):
    slept: list[float] = []
    calls: list[int] = []
    monkeypatch.setattr(otx.time, "sleep", slept.append)

    def boom(url, headers=None):
        calls.append(1)
        raise urllib.error.HTTPError(url, 502, "Bad Gateway", {}, None)

    monkeypatch.setattr(otx, "_get", boom)
    s = SimpleNamespace(intel_otx_url="https://otx.example/p", intel_otx_page_size=50,
                        intel_otx_api_key="k")
    with pytest.raises(urllib.error.HTTPError):
        otx.fetch_page(s, 43)
    assert calls == [1, 1]                          # still exactly two attempts
    assert slept == [otx._RETRY_DELAY_SECONDS]      # and one pause between them
