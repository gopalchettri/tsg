"""Liveness/readiness probes (app/api/health.py)."""
from __future__ import annotations

from tests.conftest import make_client


def test_healthz_always_ok():
    client = make_client(set())
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz_all_ok(engine, monkeypatch):
    # conftest's `engine` fixture points TSG_DB_DSN at a real (SQLite) database and sets
    # EMBEDDING_STORE=memory, so _check_database and _check_mongo run for real here —
    # only Redis (no broker running in the test sandbox) needs a stand-in.
    monkeypatch.setattr("app.api.health._check_redis", lambda: True)
    client = make_client(set())
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "checks": {"database": "ok", "redis": "ok", "mongo": "skipped"}}


def test_readyz_database_down_returns_503(engine, monkeypatch):
    monkeypatch.setattr("app.api.health._check_database", lambda: False)
    monkeypatch.setattr("app.api.health._check_redis", lambda: True)
    client = make_client(set())
    r = client.get("/readyz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["database"] == "error"


def test_readyz_redis_down_returns_503(engine, monkeypatch):
    monkeypatch.setattr("app.api.health._check_redis", lambda: False)
    client = make_client(set())
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json()["checks"]["redis"] == "error"


def test_readyz_mongo_down_returns_503_when_in_use(engine, monkeypatch):
    monkeypatch.setattr("app.api.health._check_redis", lambda: True)
    monkeypatch.setattr("app.api.health._check_mongo", lambda: False)
    client = make_client(set())
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json()["checks"]["mongo"] == "error"


def test_check_database_real_sqlite_connection(engine):
    from app.api.health import _check_database

    assert _check_database() is True


def test_check_mongo_skipped_when_store_not_mongo(engine):
    from app.api.health import _check_mongo

    assert _check_mongo() is None  # conftest's `engine` fixture sets EMBEDDING_STORE=memory


def test_check_mongo_reports_unreachable_when_store_is_mongo(engine, monkeypatch):
    from app.api.health import _check_mongo
    from app.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "embedding_store", "mongo")
    monkeypatch.setattr(s, "mongo_url", "mongodb://127.0.0.1:1")  # guaranteed-closed port: deterministic, no real Mongo needed
    monkeypatch.setattr(s, "mongo_connect_timeout_ms", 200)
    assert _check_mongo() is False


def test_check_redis_reports_unreachable_for_closed_port(engine, monkeypatch):
    from app.api.health import _check_redis
    from app.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "redis_url", "redis://127.0.0.1:1")  # guaranteed-closed port: deterministic, no real Redis needed
    monkeypatch.setattr(s, "sse_subscribe_connect_timeout_seconds", 0.2)
    assert _check_redis() is False
