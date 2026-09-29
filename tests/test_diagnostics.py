"""A failure is diagnosable from the database, and the tenant still sees nothing internal.

THE INCIDENT. Diagnosing session 6174F288 needed a pasted container log. Every durable surface
said "stage processing failed": ErrorMessage, the stage_error audit row and the SSE event all
carry the sanitised client message, and the only place holding the real exception was a log line
on stdout — which in UAT dies with the container and needs shell access to read.

The sanitising was never the bug; having one surface was. The tests below pin BOTH halves, and the
second matters more than the first: a traceback reaching a tenant-visible surface would be a worse
defect than the one being fixed.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core import diagnostics
from app.core.enums import DiagnosticKind
from app.db import models as m


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A throwaway database wired through the production seam, so `record` takes the real path."""
    path = tmp_path / "diag.db"
    engine = create_engine(f"sqlite:///{path}", future=True)
    m.Diagnostic_Event.__table__.create(engine)
    monkeypatch.setenv("TSG_DB_DSN", f"sqlite:///{path.as_posix()}")

    from app.core.config import get_settings
    from app.db.engine import _sessionmaker, get_engine

    get_settings.cache_clear()
    get_engine.cache_clear()
    _sessionmaker.cache_clear()
    return sessionmaker(bind=engine, future=True)


def _rows(Session):
    with Session() as s:
        return list(s.execute(select(m.Diagnostic_Event)).scalars())


def _boom(message="Connection timed out after 120.0 seconds") -> Exception:
    """An exception WITH a traceback — format_exception on a never-raised object yields nothing."""
    try:
        raise TimeoutError(message)
    except TimeoutError as exc:
        return exc


def test_the_exception_class_and_traceback_are_recorded(db):
    """The whole point. For 6174F288 the class name ALONE would have ended the investigation:
    "TimeoutError: Connection timed out after 120.0 seconds" instead of "stage processing
    failed"."""
    diagnostics.record(DiagnosticKind.stage_error, _boom(), session_id=str(uuid.uuid4()),
                       client_message="stage processing failed")
    (row,) = _rows(db)
    assert row.ExceptionClass == "TimeoutError"
    assert "120.0 seconds" in row.ExceptionMessage
    assert "TimeoutError" in row.Traceback and "_boom" in row.Traceback
    assert row.ClientMessage == "stage processing failed", (
        "the sanitised text must be stored too — it is what joins a user's report to the cause")


def test_a_recovered_retry_is_recorded_too(db):
    """Fix 1 made provider outages survivable, which also made them INVISIBLE: a session that
    retried and then worked leaves no other mark. This trail is how a degrading reranker is
    spotted before it cancels anything."""
    diagnostics.record(DiagnosticKind.transient_retry, _boom(), session_id=str(uuid.uuid4()),
                       context={"site": "run_pipeline.asset_stage"})
    (row,) = _rows(db)
    assert row.Kind == str(DiagnosticKind.transient_retry)
    assert "run_pipeline.asset_stage" in row.ContextJSON


@pytest.mark.parametrize("categories, kind, expected", [
    ("all", DiagnosticKind.stage_error, 1),
    ("all", DiagnosticKind.transient_retry, 1),
    ("none", DiagnosticKind.stage_error, 0),
    ("exceptions", DiagnosticKind.stage_error, 1),
    ("exceptions", DiagnosticKind.transient_retry, 0),
    ("retries", DiagnosticKind.stage_error, 0),
    ("retries", DiagnosticKind.transient_retry, 1),
])
def test_each_category_is_independently_switchable(db, monkeypatch, categories, kind, expected):
    """Switching one category on must not switch another on. `retries` is the one whose volume an
    operator might decline — exceptions are rare by definition, retries spike during an outage."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", categories)
    from app.core.config import get_settings
    get_settings.cache_clear()

    diagnostics.record(kind, _boom())
    assert len(_rows(db)) == expected


def test_a_broken_diagnostics_write_never_reaches_the_caller(monkeypatch):
    """NOT politeness — a correctness requirement.

    The failure being recorded may itself BE a database failure (OperationalError is half of
    TRANSIENT_INFRA_ERRORS). A diagnostics write that raised would replace a diagnosable error
    with an undiagnosable one: exactly the outcome this module exists to remove. And
    _record_failure runs mid-rollback with a lock release in its caller's `finally`, where a stray
    exception surfaces INSTEAD of the real one."""
    monkeypatch.setenv("TSG_DB_DSN", "sqlite:///nonexistent-dir/definitely-not-there.db")
    from app.core.config import get_settings
    from app.db.engine import _sessionmaker, get_engine
    get_settings.cache_clear()
    get_engine.cache_clear()
    _sessionmaker.cache_clear()

    diagnostics.record(DiagnosticKind.stage_error, _boom())   # must not raise


def test_a_traceback_never_reaches_a_tenant_visible_surface():
    """THE REGRESSION THAT MATTERS MOST HERE.

    _classify_llm_failure is what keeps internals away from tenants: its output goes to
    Subsystem_Stage_State.ErrorMessage, the stage_error audit row's DetailJSON (which
    sessions._audit_event reads straight into a client timeline) and the SSE error event. Adding a
    diagnostics table must not tempt anyone into widening it. A traceback on one of those three
    surfaces would be a worse defect than the one being fixed."""
    from app.pipeline.tasks import _failure_client_message

    message = _failure_client_message(_boom("psycopg2.OperationalError at line 412"))
    assert message == "stage processing failed", (
        "the tenant-facing message stopped being sanitised — internals are leaking")
    assert "Traceback" not in message and "line 412" not in message
