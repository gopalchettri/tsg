"""Operational self-check task (app/pipeline/selfcheck.py)."""
from __future__ import annotations

from app.core.config import get_settings
from app.pipeline.selfcheck import check_active_sessions, run_self_checks
from tests.test_slice import _seed_session


def test_check_active_sessions_below_ceiling_is_quiet(db):
    _seed_session(db, asset_id=100)
    assert check_active_sessions(db) is None  # default ceiling (100) — nowhere near the warn ratio


def test_check_active_sessions_fires_near_ceiling(db, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "max_active_sessions", 1)
    monkeypatch.setattr(s, "active_sessions_warn_ratio", 0.9)
    _seed_session(db, asset_id=100)
    assert check_active_sessions(db) == "active_sessions_high"


def test_run_self_checks_skips_mssql_only_checks_on_sqlite(db):
    # engine fixture runs on SQLite; the 3 tempdb/pool checks must not even attempt to
    # run there (they'd error against a database with no sys.dm_tran_* views).
    assert run_self_checks(db) == []


def test_run_self_checks_reports_active_sessions_high_on_sqlite(db, monkeypatch):
    monkeypatch.setattr(get_settings(), "max_active_sessions", 1)
    _seed_session(db, asset_id=100)
    assert run_self_checks(db) == ["active_sessions_high"]


def test_run_self_checks_isolates_one_check_failure_from_the_rest(db, monkeypatch):
    # A broken check must be logged and skipped, never take down the whole pass.
    monkeypatch.setattr(
        "app.pipeline.selfcheck.check_active_sessions",
        lambda sess: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert run_self_checks(db) == []  # the broken check contributes nothing; no exception propagates


def test_self_check_task_registered_in_beat_schedule():
    from app.pipeline.celery_app import celery_app

    schedule = celery_app.conf.beat_schedule
    assert "operational-self-check" in schedule
    assert schedule["operational-self-check"]["task"] == "tsg.self_check"


def test_self_check_task_roundtrips_through_db_session(engine):
    from app.pipeline.celery_app import self_check_task

    result = self_check_task()
    assert isinstance(result, list)
