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
    from app.db import dal
    from app.db.engine import _sessionmaker, get_engine
    from app.pipeline import embeddings
    from app.sse import bus

    get_settings.cache_clear()
    get_engine.cache_clear()
    _sessionmaker.cache_clear()
    bus._redis.cache_clear()
    bus._subscriber_pool.cache_clear()
    sessions._sse_semaphore.cache_clear()
    embeddings._vector_store.cache_clear()
    embeddings._breaker_open_until = 0.0
    dal._clear_scope_type_entity_cache()


@pytest.fixture(autouse=True)
def _isolated_process_caches():
    _clear_process_caches()
    yield
    _clear_process_caches()


@pytest.fixture(autouse=True)
def _no_external_embedding_store(monkeypatch):
    """Tests must NEVER reach a real Mongo vector store. The dev machine's live store shares
    cache keys with the tests' fake LLMs, so one leaked read serves a foreign-dimension vector
    (real 1024-dim e5, or another test's fake) and grounding skips every candidate with
    `dimension_mismatch_skipped` -- an order-dependent failure whenever the per-test env pin
    loses a race with a get_settings() cache rebuild. _store_if_healthy is the single seam both
    the L2 read and write tiers go through, and None is its first-class "store unavailable"
    answer, so this disables L2 without touching any other embedding behaviour."""
    from app.pipeline import embeddings

    monkeypatch.setattr(embeddings, "_store_if_healthy", lambda: None)
