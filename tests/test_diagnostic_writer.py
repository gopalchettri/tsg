"""The background writer's guarantees, each pinned by the failure it prevents.

These are not properties worth having; they are properties whose absence takes a process down:

  1. OFF THE HOT PATH — no IO on the caller's thread, so logging cannot slow the pipeline.
  2. BOUNDED — a full queue DROPS and counts, so a slow database cannot become an out-of-memory
     kill. Losing diagnostics is a bad day; losing the worker is an outage.
  3. NEVER RAISES — the database being down is exactly when diagnostics matter and exactly when
     writing them fails.
  4. NO RECURSION — SQLAlchemy emits log records; capturing them turns one insert into more
     records into more inserts. Unguarded this is exponential, not a leak.

Plus the one that makes it worth doing at all: BATCHING, so N rows cost one round trip and not N.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine, event, func, select

from app.core.diagnostic_writer import WRITER
from app.db import models as m


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A throwaway database, plus a counter of the INSERT statements that actually reached it."""
    path = tmp_path / "writer.db"
    dsn = f"sqlite:///{path.as_posix()}"
    engine = create_engine(dsn, future=True)
    m.Application_Log.__table__.create(engine)
    m.Diagnostic_Event.__table__.create(engine)
    monkeypatch.setenv("TSG_DB_DSN", dsn)

    from app.core.config import get_settings
    get_settings.cache_clear()
    WRITER._dispose()          # force a fresh engine against this test's database
    return engine


def _row(i: int) -> dict:
    from app.db.dal import guid, now

    return {"LogID": guid(), "CreatedAt": now(), "Level": "INFO", "Logger": "app.test",
            "Event": f"probe.{i}", "SessionID": None, "RequestID": None, "TaskID": None,
            "FieldsJSON": None}


def _count(engine, table) -> int:
    with engine.connect() as c:
        return c.execute(select(func.count()).select_from(table.__table__)).scalar()


def test_rows_are_written_in_batches_not_one_statement_each(db):
    """THE IO OPTIMISATION, measured. 250 rows must not cost 250 round trips — that is the whole
    reason the raw log stream is viable at all. Counted at the driver, because a batch size that
    silently stopped applying would leave every other test passing."""
    inserts: list[str] = []

    @event.listens_for(db, "before_cursor_execute")
    def _seen(conn, cursor, statement, params, context, executemany):
        if "INSERT INTO" in statement.upper():
            inserts.append(statement)

    for i in range(250):
        WRITER.submit("Application_Log", _row(i), maxsize=10_000)
    WRITER.flush_now()

    assert _count(db, m.Application_Log) == 250, "rows were lost"
    assert len(inserts) <= 5, (
        f"250 rows took {len(inserts)} INSERT statements — batching is not applying, and the raw "
        "log stream would put a round trip on every log call")


def test_a_full_queue_drops_and_counts_instead_of_growing(db):
    """BOUNDED. The alternative is unbounded memory behind a slow database, which ends as an
    out-of-memory kill of the worker — a far worse outcome than missing diagnostics. The drop is
    counted so the loss is never silent."""
    before = WRITER.dropped
    for i in range(50):
        WRITER.submit("Application_Log", _row(i), maxsize=1)
    assert WRITER.dropped > before, "a full queue accepted rows without bound"
    WRITER.flush_now()


def test_a_dead_database_never_reaches_the_caller(monkeypatch):
    """NEVER RAISES. Submitting must be safe when the database is unreachable — which is precisely
    when an operator most wants the diagnostic, and precisely when writing it fails."""
    monkeypatch.setenv("TSG_DB_DSN", "sqlite:///nonexistent-dir/nope.db")
    from app.core.config import get_settings
    get_settings.cache_clear()
    WRITER._dispose()

    for i in range(10):
        WRITER.submit("Application_Log", _row(i), maxsize=10_000)   # must not raise
    WRITER.flush_now()                                              # nor must the flush


def test_sqlalchemy_log_records_are_never_captured(db, monkeypatch):
    """NO RECURSION, and this is the one that is catastrophic rather than merely wrong.

    The DB layer emits log records. Capture them and each insert produces more records, which
    produce more inserts. The guard is a prefix denylist; this drives REAL log calls through the
    real processor chain and asserts none of the database layer's own chatter came back."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "all")
    from app.core.config import get_settings
    get_settings.cache_clear()

    from app.core.logging import get_logger

    get_logger("sqlalchemy.engine.Engine").info("SELECT 1", rows=1)
    get_logger("app.pipeline.real").info("pipeline.step", session_id="s")
    WRITER.flush_now()

    with db.connect() as c:
        rows = c.execute(select(m.Application_Log.Logger)).scalars().all()
    assert not [r for r in rows if str(r).startswith("sqlalchemy")], (
        "a sqlalchemy log record was captured — each insert emits more records, so this is an "
        "exponential cascade, not a slow leak")
    assert any(str(r).startswith("app.pipeline") for r in rows), (
        "the denylist swallowed application events too — it must exclude the DB layer only")


def test_capture_is_off_unless_the_logs_category_is_enabled(db, monkeypatch):
    """`logs` is the one category with real volume and real personal-data weight, so it must never
    turn itself on as a side effect of any other setting."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "exceptions")
    from app.core.config import get_settings
    get_settings.cache_clear()

    from app.core.logging import get_logger

    get_logger("app.pipeline.real").info("pipeline.step")
    WRITER.flush_now()
    assert _count(db, m.Application_Log) == 0, "log capture ran with the logs category off"


def test_a_log_line_survives_its_own_capture_failing(db, monkeypatch):
    """The processor returns the event dict on EVERY path. One that raises, or drops the dict,
    silences the very line it was meant to record — turning an observability feature into an
    observability outage."""
    from app.core import diagnostics

    monkeypatch.setattr(diagnostics.WRITER, "submit",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("writer exploded")))
    event_dict = {"event": "still.logged", "level": "info"}
    out = diagnostics.capture_log_record(None, "info", dict(event_dict))
    assert out == event_dict, "the log line was altered or lost when capture failed"
