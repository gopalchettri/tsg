"""The support-facing diagnostics routes, and the properties that make them safe to leave open.

THE POINT OF THE ROUTES. Diagnosing session 6174F288 needed a container log pasted into a chat
window. The table fixed durability; these routes fix REACH — a support engineer answers "why did
this run fail" from a URL, with no admin key and no database credentials. Requiring a key is what
put diagnosis behind the engineering team, which is the problem being solved.

WHAT PAYS FOR THAT, each pinned below by the failure it prevents:

  1. READS ARE OPEN, THE WRITE IS NOT. PATCH /config turns on durable capture of prompt text and
     asset context. Public, it is a stranger's switch to start recording personal data and to fill
     the database doing it. That asymmetry is the security boundary of this feature.
  2. THE PAYLOAD FIELDS ARE WITHHELD BY DEFAULT. Traceback, captured log bodies and the context
     blob appear only with TSG_DIAGNOSTIC_PUBLIC_DETAIL on. What stays public is what support
     actually asks for, and none of it is personal data.
  3. A REDACTED ROW SAYS SO. `detail_redacted` exists because "there was no traceback" and
     "the traceback was withheld" look identical otherwise, and an engineer who reads the first
     as the second stops looking.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.db.dal import now


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A throwaway database holding the two diagnostics tables, and nothing else."""
    dsn = f"sqlite:///{(tmp_path / 'diag.db').as_posix()}"
    engine = create_engine(dsn, future=True)
    m.Diagnostic_Event.__table__.create(engine)
    m.Application_Log.__table__.create(engine)
    monkeypatch.setenv("TSG_DB_DSN", dsn)

    from app.core.config import get_settings
    get_settings.cache_clear()
    return sessionmaker(engine, future=True)


@pytest.fixture
def client(db):
    """The real app, so the routes run through their real dependencies — including the ABSENCE of
    an auth dependency, which is the thing under test."""
    from app.main import create_app

    return TestClient(create_app())


def _seed_failure(db, *, session_id=None, kind="stage_error"):
    """One recorded failure, shaped like the one this whole effort came from."""
    with db() as s:
        s.add(m.Diagnostic_Event(
            DiagnosticID=str(uuid.uuid4()), CreatedAt=now(), SessionID=session_id, Kind=kind,
            ExceptionClass="Timeout",
            ExceptionMessage="Connection timed out after 120.0 seconds",
            Traceback='Traceback (most recent call last):\n  File "/app/internal/path.py"...',
            ClientMessage="stage processing failed",
            ContextJSON='{"stage": "REGROUNDING", "asset": "synthetic tenancy record"}'))
        s.commit()


def _seed_log(db, *, session_id=None, level="INFO"):
    with db() as s:
        s.add(m.Application_Log(
            LogID=str(uuid.uuid4()), CreatedAt=now(), Level=level,
            Logger="app.pipeline.grounding", Event="pipeline.step", SessionID=session_id,
            FieldsJSON='{"prompt": "synthetic id 000-0000-0000000-0"}'))
        s.commit()


# --- 1. the routes answer without a credential -------------------------------------------------

def test_a_support_engineer_can_read_a_failure_with_no_credential(client, db):
    """THE WHOLE POINT. No admin key, no database access — the question support actually asks,
    answered by a URL. If this ever needs a header again, the feature has regressed into the thing
    it was built to replace."""
    sid = str(uuid.uuid4())
    _seed_failure(db, session_id=sid)

    r = client.get("/v1/tsg/diagnostics", params={"session_id": sid})

    assert r.status_code == 200, f"support cannot read diagnostics without a key: {r.text}"
    rows = r.json()["rows"]
    assert len(rows) == 1
    assert rows[0]["exception_class"] == "Timeout", (
        "the exception class is the one field that would have ended the 6174F288 investigation in "
        "seconds, and it must survive every redaction rule")
    assert rows[0]["client_message"] == "stage processing failed", (
        "the sanitised text the customer saw is the JOIN — without it, a report of 'it said stage "
        "processing failed' still matches every failure the system has ever produced")


def test_the_config_route_answers_without_a_credential(client):
    """Support's first question when a lookup comes back empty is "is anything being captured at
    all?". That has to be answerable by the same person, the same way."""
    r = client.get("/v1/tsg/diagnostics/config")
    assert r.status_code == 200, r.text
    assert "effective" in r.json()


# --- 2. the write is NOT open -------------------------------------------------------------------

def test_turning_capture_on_is_not_something_a_stranger_can_do(client):
    """THE SECURITY BOUNDARY OF THIS FEATURE, and the asymmetry that makes open reads defensible.

    PATCH /config enables the `logs` category, which durably records whatever the application was
    logging — asset context and prompt text. Open, it is an unauthenticated switch to begin
    recording personal data, and to fill the database while doing it."""
    r = client.patch("/v1/tsg/diagnostics/config", json={"categories": "logs"})
    assert r.status_code in (401, 403), (
        f"an unauthenticated caller changed what the system captures (got {r.status_code}) — that "
        "is a switch to start recording prompt text and asset context, not a support action")


# --- 3. the payload fields are withheld by default ----------------------------------------------

def test_a_traceback_is_not_published_to_the_internet_by_default(client, db, monkeypatch):
    """A traceback names internal paths and code structure, and the context blob carries whatever
    the failing code was holding. Neither is needed to answer a support question, and the route is
    public — so the default has to be to withhold them."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_PUBLIC_DETAIL", "false")
    from app.core.config import get_settings
    get_settings.cache_clear()
    _seed_failure(db)

    row = client.get("/v1/tsg/diagnostics").json()["rows"][0]

    assert row["traceback"] is None, "a traceback was published on an unauthenticated route"
    assert row["context"] is None, "the context blob was published on an unauthenticated route"
    assert row["detail_redacted"] is True, (
        "the row does not say its detail was withheld — an engineer reads a redacted row as "
        "'there was no traceback' and stops looking")
    assert row["exception_message"] == "Connection timed out after 120.0 seconds", (
        "redaction went too far: the message is the answer support needs, and it names nobody")


def test_captured_log_bodies_are_withheld_harder_than_tracebacks(client, db, monkeypatch):
    """The gate bites hardest here. A diagnostic row is a failure with a traceback attached; a
    captured log line is whatever the application happened to be logging, which in this system
    routinely includes tenancy contracts, landlord and tenant data and Emirates ID."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_PUBLIC_DETAIL", "false")
    from app.core.config import get_settings
    get_settings.cache_clear()
    _seed_log(db)

    row = client.get("/v1/tsg/diagnostics/logs").json()["rows"][0]

    assert row["fields"] is None, (
        "captured log fields were published unauthenticated — that blob holds prompt text")
    assert row["event"] == "pipeline.step", (
        "the event NAME and level must stay: a timeline is not a disclosure, and without them the "
        "route answers nothing at all")


def test_the_switch_actually_opens_the_detail(client, db, monkeypatch):
    """The converse. A switch that redacted either way would be worse than no switch — an operator
    would turn it on for a test environment and still have nothing to read."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_PUBLIC_DETAIL", "true")
    from app.core.config import get_settings
    get_settings.cache_clear()
    _seed_failure(db)

    row = client.get("/v1/tsg/diagnostics").json()["rows"][0]

    assert row["traceback"], "the detail switch is on and the traceback is still withheld"
    assert row["detail_redacted"] is False


# --- 4. the queries stay bounded -----------------------------------------------------------------

def test_a_caller_cannot_ask_for_an_unbounded_read(client):
    """These tables grow without limit — Application_Log by six figures a day. A public route that
    accepts limit=1000000 is a denial-of-service primitive, not an API. Bounded server-side, never
    by the caller's good manners."""
    assert client.get("/v1/tsg/diagnostics", params={"limit": 10_000}).status_code == 422
    assert client.get("/v1/tsg/diagnostics/logs",
                      params={"since_hours": 100_000}).status_code == 422


def test_a_short_answer_is_never_mistaken_for_a_complete_one(client, db):
    """`truncated` decides whether an operator narrows the window or concludes there is nothing
    more. Guessing at the boundary is what makes a cap misleading, so it is measured with one
    extra row rather than inferred from the returned count."""
    for _ in range(3):
        _seed_failure(db)

    body = client.get("/v1/tsg/diagnostics", params={"limit": 2}).json()

    assert len(body["rows"]) == 2
    assert body["truncated"] is True, "the cap was hit and the response did not say so"


# --- 5. a typo is rejected, not stored ------------------------------------------------------------

def test_an_unknown_category_is_refused_rather_than_stored():
    """A typo stored verbatim is the worst outcome available: it is accepted, it changes nothing
    visibly, and capture silently narrows to whatever the typo happened to match. The operator
    then trusts a switch that did nothing at all."""
    from fastapi import HTTPException

    from app.api.diagnostics import _validated

    assert _validated("exceptions,retries") == "exceptions,retries"
    assert _validated(None) is None
    assert _validated("none") == "none"
    with pytest.raises(HTTPException) as caught:
        _validated("exceptons")           # one letter out
    assert caught.value.status_code == 422
    assert "exceptons" in str(caught.value.detail), (
        "the error must name the typo — an operator needs to see what they actually mistyped")


def test_the_category_list_is_read_from_the_capture_module_not_copied():
    """The validator and the capture code must never hold two lists. A copy is how the API starts
    refusing a category the pipeline implements, or accepting one it does not."""
    from app.api.diagnostics import _validated
    from app.core import diagnostics

    for name in diagnostics.known_categories():
        assert _validated(name) == name, (
            f"the capture module implements {name!r} but the API refuses it — the two lists have "
            "drifted apart")
