"""API polish — every error response shares the same `{error_code, message}`
envelope (not FastAPI's bare `{"detail": ...}`), and the SSE stream keeps a
configurable heartbeat alive.
"""
from __future__ import annotations

from tests.conftest import make_client, session_body


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
    sid = make_client({"5"}).post("/v1/sessions", json=session_body(100)).json()["session_id"]
    r = make_client({"6"}).get(f"/v1/sessions/{sid}")
    assert r.status_code == 403
    assert r.json()["error_code"] == "forbidden"


def test_422_uses_error_envelope(engine, monkeypatch):
    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    r = make_client({"5"}).post("/v1/sessions", json={"entity_id": "5"})  # missing required asset_id
    assert r.status_code == 422
    body = r.json()
    assert body["error_code"] == "validation_error"
    assert body["details"]["errors"]


def test_accept_body_mode_is_required_and_exclusive_with_output_ids():
    """AcceptBody's `mode` is required and mutually exclusive with `output_ids`' presence —
    accept-all/none/subset are unambiguous choices at the JSON level, replacing the old
    `subset` null-vs-omitted-vs-empty-list overload ([R8])."""
    import pytest
    from pydantic import ValidationError

    from app.api.schemas import _MAX_BATCH, AcceptBody

    # a real GUID: output_ids are now canonicalized at the boundary, so a placeholder like "o"
    # is (correctly) a 422 rather than an accepted id — see test_output_ids_are_canonicalized.
    oid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

    assert AcceptBody(mode="all").output_ids is None
    assert AcceptBody(mode="none").output_ids is None
    assert AcceptBody(mode="subset", output_ids=[oid]).output_ids == [oid]
    assert len(AcceptBody(mode="subset", output_ids=[oid] * _MAX_BATCH).output_ids) == _MAX_BATCH

    with pytest.raises(ValidationError):  # mode omitted — no default, must be explicit
        AcceptBody()
    with pytest.raises(ValidationError, match="required"):  # subset with no ids at all
        AcceptBody(mode="subset")
    with pytest.raises(ValidationError, match="required"):  # subset with an explicitly empty list
        AcceptBody(mode="subset", output_ids=[])
    with pytest.raises(ValidationError, match="must not be provided"):  # output_ids given but mode isn't subset
        AcceptBody(mode="all", output_ids=[oid])
    # an EMPTY list under mode="all" is still "provided" — the error must say REMOVE the field,
    # not "add items" (which is why the length bounds live in the model validator, not the Field:
    # a field-level min_length would fire first and skip the context-aware message entirely)
    with pytest.raises(ValidationError, match="must not be provided"):
        AcceptBody(mode="all", output_ids=[])
    with pytest.raises(ValidationError, match="at most"):  # over the batch bound
        AcceptBody(mode="subset", output_ids=[oid] * (_MAX_BATCH + 1))


def test_output_ids_are_canonicalized_at_the_boundary():
    """[canonicalization] models.GUID normalizes on bind AND result, so SQL matches any spelling
    while a PYTHON-side comparison against a DB-derived id does not — that gap produced a false
    `regenerate_conflict` on a valid regenerate and a spurious 404 + full rollback on accept.
    Both bodies must therefore hand downstream code exactly one spelling, and reject malformed
    ids as a 422 here rather than letting them reach GUID.bind_processor as a 500."""
    import pytest
    from pydantic import ValidationError

    from app.api.schemas import AcceptBody, RegenerateScenariosBody

    canonical = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    spellings = [canonical.upper(), canonical.replace("-", ""), "{" + canonical + "}",
                f"  {canonical}  ", f"urn:uuid:{canonical}"]

    for raw in spellings:
        assert AcceptBody(mode="subset", output_ids=[raw]).output_ids == [canonical], raw
        assert RegenerateScenariosBody(output_ids=[raw]).output_ids == [canonical], raw

    # the same id in two spellings must collapse — counting them as 2 distinct ids is exactly
    # what inflated accept's `requested` past `matched` and 404'd a legitimate request
    both = AcceptBody(mode="subset", output_ids=[canonical.upper(), canonical.replace("-", "")])
    assert set(both.output_ids) == {canonical}

    for bad in ("o", "not-a-guid", ""):
        with pytest.raises(ValidationError, match="not a valid GUID"):
            RegenerateScenariosBody(output_ids=[bad])


def test_oversized_output_ids_are_rejected_without_canonicalizing_every_item():
    """[review-fix] AcceptBody's batch bound lives in the mode="after" model validator (to keep its
    context-aware message), which pydantic runs AFTER field validators — so an oversized body used
    to run the per-item uuid parse to completion before the 422, burning GIL-holding CPU on the
    event loop. The canonicalizer must short-circuit above the bound."""
    import pytest
    from pydantic import ValidationError

    from app.api import schemas
    from app.api.schemas import _MAX_BATCH, AcceptBody

    calls = []
    real = schemas.canonical_guid
    schemas.canonical_guid = lambda v: calls.append(v) or real(v)
    try:
        oversized = ["6ba7b810-9dad-11d1-80b4-00c04fd430c8"] * (_MAX_BATCH + 1)
        with pytest.raises(ValidationError):
            AcceptBody(mode="subset", output_ids=oversized)
        assert calls == []  # rejected on size alone — not one id was parsed
    finally:
        schemas.canonical_guid = real


def test_500_hides_internals_in_prod(engine, monkeypatch):
    monkeypatch.setenv("APP_ENV", "prod")
    from app.core.config import get_settings
    get_settings.cache_clear()
    try:
        monkeypatch.setattr("app.db.dal.load_session_board", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
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
        monkeypatch.setattr("app.db.dal.load_session_board", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
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
    sid = make_client({"5"}).post("/v1/sessions", json=session_body(100)).json()["session_id"]

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
    sid = make_client({"5"}).post("/v1/sessions", json=session_body(100)).json()["session_id"]

    principal = Principal(claims={"sub": "u1"}, entities={"5"})
    response = asyncio.run(session_events(sid, principal))
    assert response.ping_message_factory is not None

    sse_event = response.ping_message_factory()
    assert sse_event.event == "heartbeat"
    payload = _json.loads(sse_event.data)
    assert payload["type"] == "heartbeat"
    assert payload["session_id"] == sid
