"""Shared pytest fixtures.

Autouse, per-test: every process-lifetime `@lru_cache` this app builds keys off `get_settings()`
(directly or transitively) -- Settings itself, the DB engine/sessionmaker, and the SSE bus's
Redis client/pool/semaphore. A test that sets env vars or monkeypatches `get_settings` must not
leak a stale cached instance into the next test, and a leftover-locked SSE semaphore from one
test must not bleed into the next -- so every cache is cleared both before and after each test.
"""
from __future__ import annotations

import json

import pytest


def register_sqlite_json_value(engine) -> None:
    """Give a SQLite test engine SQL Server's JSON_VALUE(blob, '$.path').

    dal.session_plan_board and dal.entity_plan_rows extract the scenario title server-side with
    JSON_VALUE; without this UDF the plan board and the register cannot execute against the
    in-memory test engine at all — which is how the board went untested at route level. ONE shim,
    here, rather than a copy per test file: a third copy is how two of them drift. ANY failure
    returns NULL, which is what MSSQL's JSON_VALUE does for a bad path or blob."""
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _register(dbapi_conn, _record):
        def json_value(blob, path):
            try:
                doc = json.loads(blob)
                for key in path.lstrip("$.").split("."):
                    doc = doc[key]
                return doc
            except Exception:  # noqa: BLE001 — UDF shim: any failure must be NULL, never raise
                return None
        dbapi_conn.create_function("json_value", 2, json_value)


def _clear_process_caches() -> None:
    from app.api import sessions
    from app.core.config import get_settings
    from app.db import dal
    from app.db.engine import _sessionmaker, get_engine
    from app.intel import technique_reference
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
    # technique_reference caches the WHOLE corpus in module globals for the life of the process.
    # Left uncleared, one test that loads it decides what every later test sees: the corpus
    # tests passed alone and failed in a full run the moment the live Mongo corpus stopped being
    # empty. Same reason as every clear above -- process-lifetime state is not test state.
    technique_reference._invalidate_cache()


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
    from app.intel import technique_reference
    from app.pipeline import embeddings

    monkeypatch.setattr(embeddings, "_store_if_healthy", lambda: None)
    # technique_reference has its OWN _store_if_healthy over a different Mongo collection, and
    # it was never covered by the stub above. That went unnoticed only while the live corpus
    # happened to be empty: the moment a real rebuild published 900 documents, ten
    # control-mapping tests started reading them, embedding them for real (the suite went from
    # ~85s to ~500s) and failing. The rule is the one already stated above -- tests must NEVER
    # reach a real Mongo store -- so it has to cover every seam that opens one, not just the
    # first one that caused trouble.
    monkeypatch.setattr(technique_reference, "_store_if_healthy", lambda name=None: None)
