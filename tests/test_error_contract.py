"""The error contract: ONE envelope on the wire, one envelope in the published schema, and no
raw exception text in a client-visible field.

Each test below pins a defect found by the 2026-08 error-handling audit. They are written so the
ORIGINAL bug fails them — a pin that cannot fail proves nothing:
  * framework 404/405 used to answer with Starlette's `{"detail": ...}` — a second, undocumented
    shape (no HTTPException handler was registered);
  * all 44 auto-added 422s were published as `HTTPValidationError` while the handler actually
    returns the envelope;
  * promote.py put `str(exc)` — a SQLAlchemy statement plus its bound parameters — into a
    tenant-facing response body in EVERY app_env;
  * tasks._classify_llm_failure returned `repr(exc)` as the client-safe parse message.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from app.pipeline import promote, tasks
from app.pipeline.validation import LLMResponseParseError

_ENVELOPE_KEYS = {"error_code", "message"}


def _client() -> TestClient:
    # raise_server_exceptions=False so the registered handlers answer, exactly as in production;
    # TestClient's default re-raises instead, which would test Starlette rather than this app.
    return TestClient(create_app(), raise_server_exceptions=False)


def test_unrouted_path_uses_the_standard_envelope():
    """A 404 from the ROUTER (not from app code) is an HTTPException too — it was the most common
    way a caller met the `{"detail": ...}` shape."""
    body = _client().get("/v1/no-such-route-anywhere").json()
    assert _ENVELOPE_KEYS <= body.keys(), f"framework 404 escaped the envelope: {body}"
    assert body["error_code"] == "not_found"


def test_wrong_method_keeps_its_allow_header_and_the_envelope():
    """405 must ALSO keep `Allow` — a handler that returns a bare JSONResponse would drop the
    header and break the 405 contract while fixing the body."""
    resp = _client().post("/health")
    assert resp.status_code == 405
    assert _ENVELOPE_KEYS <= resp.json().keys()
    assert resp.json()["error_code"] == "method_not_allowed"
    assert resp.headers.get("allow"), "Allow header lost — exc.headers was not preserved"


def test_every_published_422_matches_what_the_handler_returns():
    """Route-count-agnostic on purpose: a route (or a whole router) added later is covered with
    nothing to remember, which is the point of rewriting the finished schema in main.py."""
    schema = create_app().openapi()
    wrong = [
        (method.upper(), path)
        for path, ops in schema["paths"].items()
        for method, op in ops.items()
        for media in (op.get("responses", {}).get("422") or {}).get("content", {}).values()
        if media.get("schema", {}).get("$ref") != "#/components/schemas/ErrorResponse"
    ]
    assert not wrong, f"routes publishing a 422 shape the handler never returns: {wrong}"


def test_promote_actor_link_failure_reports_no_exception_text(monkeypatch):
    """The leak was tenant-facing and env-INDEPENDENT: errors.py's local/dev-only raw-text gate
    never applies to a value a handler puts in the body itself."""
    monkeypatch.setattr(promote.grounding, "stored_actor_ids", lambda _blob: [7])
    monkeypatch.setattr(promote.grounding, "stored_actors", lambda _blob: ["APT33"])
    monkeypatch.setattr(promote.dal, "active_actor_ids", lambda _sess, _ids: {7})

    def _boom(*_a, **_k):
        raise RuntimeError(
            "(pyodbc.IntegrityError) UNIQUE KEY 'UX_Map' — INSERT INTO ThreatType_ThreatActor_Map "
            "(ThreatTypeID, ThreatActorID) VALUES (3, 7)")

    monkeypatch.setattr(promote.dal, "link_type_actor", _boom)
    threat = type("T", (), {"ThreatID": "t1", "ThreatActorsJSON": "[]"})()

    entry = promote._actor_entries(None, threat, type_id=3, write=True)[0]

    assert entry["status"] == promote.FAILED
    for leaked in ("pyodbc", "INSERT INTO", "UX_Map", "ThreatType_ThreatActor_Map"):
        assert leaked not in entry["error"], f"internal detail on the wire: {entry['error']!r}"


def test_parse_failure_message_is_prose_not_a_repr():
    """`_classify_llm_failure`'s message is published as the stage ErrorMessage and in the SSE
    error event. The TOKEN is the contract, so the wording is free to change — but it must never
    be a Python repr."""
    token, message = tasks._classify_llm_failure(
        LLMResponseParseError("threat_identification", dict))
    assert token == "parse", "the machine-readable token is the contract and must not drift"
    assert "LLMResponseParseError" not in message, message
    assert "(" not in message, f"looks like a repr, not a sentence: {message!r}"
