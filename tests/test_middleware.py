"""RequestIDMiddleware (app/core/middleware.py) — request correlation ID + access logs."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_request_id_generated_and_echoed_back():
    client = TestClient(create_app())
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.headers["X-Request-Id"]  # non-empty — a real ID was generated


def test_request_id_from_inbound_header_is_reused_not_replaced():
    client = TestClient(create_app())
    resp = client.get("/healthz", headers={"X-Request-Id": "caller-supplied-id"})
    assert resp.headers["X-Request-Id"] == "caller-supplied-id"


def test_request_id_binds_into_log_lines(monkeypatch, capsys):
    client = TestClient(create_app())
    resp = client.get("/healthz", headers={"X-Request-Id": "trace-me-123"})
    assert resp.status_code == 200
    out = capsys.readouterr().out
    assert '"request_id": "trace-me-123"' in out
    assert "http.request_started" in out and "http.request_finished" in out


def test_request_id_survives_an_unhandled_exception(capsys):
    # [REVIEW-FIX] Starlette's catch-all Exception handler runs on ServerErrorMiddleware,
    # OUTSIDE RequestIDMiddleware — this is the one path where contextvars alone don't carry
    # the request_id through, so it must reach both the response header and the crash log
    # via request.state instead (see middleware.py's module docstring).
    app = create_app()

    @app.get("/_boom")
    def boom():
        raise RuntimeError("boom")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/_boom", headers={"X-Request-Id": "crash-trace-1"})
    assert resp.status_code == 500
    assert resp.headers["X-Request-Id"] == "crash-trace-1"
    out = capsys.readouterr().out
    assert '"request_id": "crash-trace-1"' in out
    assert "unhandled_exception" in out
