"""API polish — every error response shares the same `{error_code, message}`
envelope (not FastAPI's bare `{"detail": ...}`), and the SSE stream keeps a
configurable heartbeat alive.
"""
from __future__ import annotations

from tests.conftest import make_client


def _make_client_no_raise(entities: set[str]):
    """Like `make_client`, but with `raise_server_exceptions=False` — Starlette's
    `ServerErrorMiddleware` always re-raises after generating the 500 response (by
    design, so a real bug surfaces during testing); to observe that response body
    the way a real client would, the test client must opt out of that re-raise.
    """
    from fastapi.testclient import TestClient

    from app.api.deps import Principal, get_principal
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(claims={"sub": "u1"}, entities=entities)
    return TestClient(app, raise_server_exceptions=False)


def test_404_uses_error_envelope(engine, monkeypatch):
    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    r = make_client({"5"}).get("/v1/sessions/does-not-exist")
    assert r.status_code == 404
    body = r.json()
    assert body["error_code"] == "not_found"
    assert "message" in body


def test_403_uses_error_envelope(engine, monkeypatch):
    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    sid = make_client({"5"}).post("/v1/sessions", json={"asset_id": 100, "entity": "5"}).json()["session_id"]
    r = make_client({"6"}).get(f"/v1/sessions/{sid}")
    assert r.status_code == 403
    assert r.json()["error_code"] == "forbidden"


def test_422_uses_error_envelope(engine, monkeypatch):
    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    r = make_client({"5"}).post("/v1/sessions", json={"entity": "5"})  # missing required asset_id
    assert r.status_code == 422
    body = r.json()
    assert body["error_code"] == "validation_error"
    assert body["details"]["errors"]


def test_500_hides_internals_in_prod(engine, monkeypatch):
    monkeypatch.setenv("APP_ENV", "prod")
    from app.core.config import get_settings
    get_settings.cache_clear()
    try:
        monkeypatch.setattr("app.db.dal.load_session", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        r = _make_client_no_raise({"5"}).get("/v1/sessions/anything")
        assert r.status_code == 500
        body = r.json()
        assert body["error_code"] == "internal_error"
        assert "boom" not in body["message"]
    finally:
        get_settings.cache_clear()


def test_500_shows_internals_in_dev(engine, monkeypatch):
    monkeypatch.setenv("APP_ENV", "dev")
    from app.core.config import get_settings
    get_settings.cache_clear()
    try:
        monkeypatch.setattr("app.db.dal.load_session", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        r = _make_client_no_raise({"5"}).get("/v1/sessions/anything")
        assert r.status_code == 500
        assert "boom" in r.json()["message"]
    finally:
        get_settings.cache_clear()


def test_sse_ping_configured(engine, monkeypatch):
    """Deliberately does NOT open a live stream (EventSourceResponse is a
    forever-running generator) — call the endpoint directly and inspect the
    returned response object's ping_interval instead."""
    import asyncio

    from app.api.deps import Principal
    from app.api.sessions import session_events
    from app.core.config import get_settings

    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    sid = make_client({"5"}).post("/v1/sessions", json={"asset_id": 100, "entity": "5"}).json()["session_id"]

    principal = Principal(claims={"sub": "u1"}, entities={"5"})
    response = asyncio.run(session_events(sid, principal))
    assert response.ping_interval == get_settings().sse_ping_seconds


def test_sse_heartbeat_is_a_real_client_visible_event(engine, monkeypatch):
    """SDD §9.1 requires `heartbeat` as a real SSE event a client can key liveness
    logic off, not sse-starlette's default raw `: ping` comment (which EventSource
    silently ignores) — verify the wired ping_message_factory actually produces one."""
    import asyncio
    import json as _json

    from app.api.deps import Principal
    from app.api.sessions import session_events

    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    sid = make_client({"5"}).post("/v1/sessions", json={"asset_id": 100, "entity": "5"}).json()["session_id"]

    principal = Principal(claims={"sub": "u1"}, entities={"5"})
    response = asyncio.run(session_events(sid, principal))
    assert response.ping_message_factory is not None

    sse_event = response.ping_message_factory()
    assert sse_event.event == "heartbeat"
    payload = _json.loads(sse_event.data)
    assert payload["type"] == "heartbeat"
    assert payload["session_id"] == sid
