"""Plan item 12 / verification 5: the SSE concurrency cap must reject with a clean 503 +
Retry-After, not a raw Redis connection error. Exercised entirely at the `sse_max_concurrent_streams`
semaphore -- the cap check runs BEFORE any board load or `bus.subscribe`, so filling it needs no
live Redis/MSSQL at all.
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.api.sessions as sessions_mod
from app.api.deps import Principal, get_principal
from app.api.errors import register_error_handlers


def _make_app() -> FastAPI:
    app = FastAPI()
    register_error_handlers(app)
    app.include_router(sessions_mod.router)
    app.dependency_overrides[get_principal] = lambda: Principal(
        claims={"sub": "1138"}, entities={"86"}, client_id="shield", tenant_id="DESC")
    return app


def test_sse_stream_at_capacity_returns_503_with_retry_after(monkeypatch):
    settings = sessions_mod.get_settings()
    monkeypatch.setattr(settings, "sse_max_concurrent_streams", 1)  # trivially fillable cap

    app = _make_app()
    client = TestClient(app)

    # Fill the one slot directly -- proves the 503 fires purely off the semaphore state, with no
    # dependency on an actual open stream or a live Redis connection existing anywhere.
    sem = sessions_mod._sse_semaphore()
    asyncio.run(sem.acquire())

    resp = client.get("/v1/sessions/11111111-1111-1111-1111-111111111111/events")

    assert resp.status_code == 503
    assert "Retry-After" in resp.headers
    assert resp.headers["Retry-After"] == str(settings.capacity_retry_after_seconds)
    body = resp.json()
    assert body["error_code"] == "sse_capacity_exceeded"


def test_sse_stream_under_capacity_does_not_503(monkeypatch):
    """Sanity control: with the slot free, the capacity gate itself must not misfire. The board
    load is stubbed to fail past the gate (no live DB here) -- proving the 503 above is really
    about capacity, not some other failure reusing the same status code."""
    settings = sessions_mod.get_settings()
    monkeypatch.setattr(settings, "sse_max_concurrent_streams", 1)

    def _boom(sid, principal):
        raise RuntimeError("no live db in this test")

    monkeypatch.setattr(sessions_mod, "_load_events_board", _boom)

    app = _make_app()
    # raise_server_exceptions=False: this test wants the HTTP response the catch-all handler
    # actually sends (500, from the stubbed board-load failure), not TestClient re-raising it.
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/v1/sessions/11111111-1111-1111-1111-111111111111/events")

    assert resp.status_code != 503
    # the failed-past-the-gate path must also release the slot, not leak it
    assert not sessions_mod._sse_semaphore().locked()
