"""Shared pytest fixtures.

Autouse, per-test: every process-lifetime `@lru_cache` this app builds keys off `get_settings()`
(directly or transitively) -- Settings itself, the DB engine/sessionmaker, and the SSE bus's
Redis client/pool/semaphore. A test that sets env vars or monkeypatches `get_settings` must not
leak a stale cached instance into the next test, and a leftover-locked SSE semaphore from one
test must not bleed into the next -- so every cache is cleared both before and after each test.
"""
from __future__ import annotations

import pytest


def _clear_process_caches() -> None:
    from app.api import sessions
    from app.core.config import get_settings
    from app.db.engine import _sessionmaker, get_engine
    from app.sse import bus

    get_settings.cache_clear()
    get_engine.cache_clear()
    _sessionmaker.cache_clear()
    bus._redis.cache_clear()
    bus._subscriber_pool.cache_clear()
    sessions._sse_semaphore.cache_clear()


@pytest.fixture(autouse=True)
def _isolated_process_caches():
    _clear_process_caches()
    yield
    _clear_process_caches()
