"""Shared pytest fixtures.

Autouse, per-test: every process-lifetime `@lru_cache` this app builds keys off `get_settings()`
(directly or transitively) -- Settings itself, the DB engine/sessionmaker, and the SSE bus's
Redis client/pool/semaphore. A test that sets env vars or monkeypatches `get_settings` must not
leak a stale cached instance into the next test, and a leftover-locked SSE semaphore from one
test must not bleed into the next -- so every cache is cleared both before and after each test.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# ---------------------------------------------------------------------------------------------
# Pin the env file BEFORE anything imports app.core.config.
#
# Settings resolves `env_file` ONCE, at class-definition time (config.py's model_config calls
# _env_file()), so this cannot be a fixture -- by the time a fixture runs, model_config already
# says ".env". It has to be module level in conftest, which pytest imports before any test module,
# and it is why nothing above this line imports from `app`.
#
# WHAT IT FIXES. .env is machine-local and not in git, so every test that reached production code
# silently took that machine's configuration. The visible half was a suite green in CI and red
# locally (TSG_CONTROL_MAP_BACKFILL_MIN_SCORE=25.0, a DEPRECATED override this machine still had
# enabled, pinned a backfill floor the test expected to be derived). The dangerous half is the
# other direction: a test PASSING locally for a reason no test declares, which nothing reports.
#
# A test that needs a setting now says so -- monkeypatch.setenv, or Settings(field=...). Ambient
# configuration is no longer an input to any result.
os.environ["TSG_ENV_FILE"] = str(Path(__file__).with_name("testing.env"))

# ONE EXCEPTION, carried across explicitly: the database DSN.
#
# Five tests (test_api_contract, test_subsystem_busy_retry, test_library_first_identification,
# test_treatment_plan_versions, test_e2e_full_flow) never declare a database and fall through to
# whatever TSG_DB_DSN names -- on this machine, a REAL LOCAL SQL SERVER. They pass only because it
# holds the TSG schema, so they cannot pass on a machine without it, and they read and write a
# real database during `pytest` while nothing in them says so.
#
# That is a genuine defect, but it is a defect IN THOSE FIVE TESTS, not one this file can fix: a
# throwaway sqlite was tried, and with the schema created they still fail on seed data and dialect
# differences. So the dependency is carried across deliberately and named HERE, where it is one
# visible line, instead of being an invisible property of whoever's machine is running the suite.
# Making them hermetic is tracked separately.
#
# Read straight out of .env rather than left to leak: the pin above means Settings no longer sees
# that file at all, so without this the five would fail on the placeholder default instead. Every
# OTHER setting stays isolated, which is the whole point.
_dotenv = Path(__file__).resolve().parents[1] / ".env"
if "TSG_DB_DSN" not in os.environ and _dotenv.is_file():
    for _line in _dotenv.read_text(encoding="utf-8", errors="replace").splitlines():
        if _line.startswith("TSG_DB_DSN="):
            os.environ["TSG_DB_DSN"] = _line.partition("=")[2].strip().strip('"').strip("'")
            break

# Diagnostics capture OFF by default for the suite. The `logs` category writes EVERY log line to
# whatever TSG_DB_DSN names, and the writer runs on a background thread that outlives any one test
# -- so with it on, an ordinary unit test quietly writes to a real database. A test that wants
# capture turns it on explicitly (tests/test_diagnostics.py, tests/test_diagnostic_writer.py),
# which is the same rule as every other setting here: declared, never inherited.
os.environ.setdefault("TSG_DIAGNOSTIC_DB_CATEGORIES", "none")

import pytest  # noqa: E402 -- must follow the env pins above


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
    embeddings.clear_cache()   # L1 vectors + matrices: one test's embeds are another's cache hits
    embeddings._breaker_open_until = 0.0
    dal._clear_scope_type_entity_cache()
    # technique_reference caches the WHOLE corpus in module globals for the life of the process.
    # Left uncleared, one test that loads it decides what every later test sees: the corpus
    # tests passed alone and failed in a full run the moment the live Mongo corpus stopped being
    # empty. Same reason as every clear above -- process-lifetime state is not test state.
    technique_reference._invalidate_cache()
    # The diagnostics runtime override lives in REDIS, and this machine runs one. Left alone, any
    # test that logs would read a real override key -- the same defect as the suite reading a real
    # .env, one layer along: a result that depends on the machine and that no test declares.
    # Pinning the cache to never expire means active_categories() returns the ENV value and never
    # opens a socket. A test that wants the override resets this itself (test_diagnostics.py),
    # which is the rule everywhere else in this file: declared, never inherited.
    from app.core import diagnostics
    diagnostics._override_cache = (float("inf"), None)


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
