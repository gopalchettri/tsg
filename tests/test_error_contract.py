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


def test_the_422_handler_can_echo_any_value_without_becoming_a_500():
    """The echoed `input` is whatever the client sent, and JSONResponse serializes with
    allow_nan=False. A non-finite float (stdlib json.loads accepts NaN/Infinity) or a Decimal (the
    ExactNumberRoute routes) used to raise INSIDE the handler — a 500 on the 422 it was reporting.
    Found live: final_risk_rating=NaN returned 500."""
    import asyncio
    import json
    from decimal import Decimal

    from fastapi.exceptions import RequestValidationError

    from app.api.errors import _handle_validation_error

    exc = RequestValidationError([
        {"type": "finite_number", "loc": ("body", "x"), "msg": "Input should be a finite number",
         "input": float("nan")},
        {"type": "finite_number", "loc": ("body", "y"), "msg": "m", "input": float("-inf")},
        {"type": "decimal_max_digits", "loc": ("body", "z"), "msg": "m",
         "input": Decimal("4.1234000000000000001")},
        {"type": "missing", "loc": ("body", "w"), "msg": "m", "input": {"nested": float("inf")}},
        # A non-JSON body is echoed as raw bytes; jsonable_encoder's own bytes.decode() raised on
        # invalid UTF-8 — still a 500 until the handler escaped it.
        {"type": "model_attributes_type", "loc": ("body",), "msg": "m", "input": b'\xff\xfe{"a":1}'},
    ])
    resp = asyncio.run(_handle_validation_error(None, exc))
    assert resp.status_code == 422
    echoed = [e["input"] for e in json.loads(resp.body)["details"]["errors"]]
    assert echoed == ["nan", "-inf", "4.1234000000000000001", {"nested": "inf"},
                      '\\xff\\xfe{"a":1}']


def test_no_api_model_accepts_nan_or_infinity():
    """ApiModel sets allow_inf_nan=False once; pydantic merges it into every subclass's own
    model_config. Pinned for EVERY model, so a subclass that re-declares model_config and turns it
    back on fails here, not in production."""
    import pytest
    from pydantic import ValidationError

    import app.api.schemas_treatment  # noqa: F401  (registers the treatment models as subclasses)
    from app.api.schemas import ApiModel

    def _all(cls):
        for sub in cls.__subclasses__():
            yield sub
            yield from _all(sub)

    lenient = sorted(c.__name__ for c in _all(ApiModel) if c.model_config.get("allow_inf_nan") is not False)
    assert not lenient, f"models that accept NaN/Infinity: {lenient}"

    class _Probe(ApiModel):
        x: float

    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError, match="finite"):
            _Probe(x=bad)
    assert _Probe(x=4.5).x == 4.5


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
