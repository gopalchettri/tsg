""" runs periodic health checks that don't crash anything by
themselves, but are worth an operator's attention before they become a real
problem — most notably SQL Server's tempdb usage, which the RCSI concurrency
mode this app depends on can make grow if nothing is watching it.

Operational self-check — a periodic Celery beat task (see celery_app.py's
"operational-self-check" schedule entry), NOT a startup guard like
app/db/invariants.py. Each check here logs a WARNING and moves on; nothing
here ever raises or blocks the app from working. Threshold values all come
from Settings (self_check_interval_seconds and friends) so an operator can
tune them for their own deployment's real traffic without a code change.
"""
from __future__ import annotations

from typing import cast

from sqlalchemy import text
from sqlalchemy.orm import Session
from sqlalchemy.pool import QueuePool

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db import dal
from app.db.engine import get_engine

log = get_logger(__name__)


def check_active_sessions(sess: Session) -> str | None:
    """Warn once the active-session count gets close to max_active_sessions, so an
    operator has some runway before new sessions actually start getting rejected
    with a 503. Reuses dal.count_active_sessions — the same racy-by-design count
    assert_capacity_available already checks on every POST /v1/sessions."""
    s = get_settings()
    active = dal.count_active_sessions(sess)
    ceiling = s.max_active_sessions * s.active_sessions_warn_ratio
    if active >= ceiling:
        log.warning("selfcheck.active_sessions_high", active=active, ceiling=s.max_active_sessions,
                    ratio=s.active_sessions_warn_ratio)
        return "active_sessions_high"
    return None


def check_pool_utilization() -> str | None:
    """Warn once the database connection pool is close to fully checked-out, so an
    operator has some runway before requests start actually queuing for a free
    connection (see engine.py's db_pool_timeout)."""
    s = get_settings()
    # engine.pool is annotated as the base Pool type, but get_engine() always builds a
    # QueuePool (SQLAlchemy's default for pyodbc) — checkedout() is a QueuePool-only
    # method, not on the base interface, so narrow it once here (same idiom as
    # dal.py::execute_dml's CursorResult cast).
    pool = cast(QueuePool, get_engine().pool)
    checked_out = pool.checkedout()
    capacity = s.db_pool_size + s.db_max_overflow
    if capacity and checked_out >= capacity * s.pool_utilization_warn_ratio:
        log.warning("selfcheck.pool_saturated", checked_out=checked_out, capacity=capacity,
                    ratio=s.pool_utilization_warn_ratio)
        return "pool_saturated"
    return None


def check_tempdb_version_store() -> str | None:
    """Warn once tempdb's RCSI version store (see app/db/invariants.py's RCSI
    checklist entry) grows past a configured size — the specific risk
    scripts/production_setup.sql's RCSI section warns about: an unbounded version
    store can fill tempdb and take down the whole SQL Server instance, not just
    this app's database."""
    s = get_settings()
    with get_engine().connect() as c:
        pages = c.execute(text(
            "SELECT SUM(reserved_page_count) FROM sys.dm_tran_version_store_space_usage"
        )).scalar() or 0
    mb = (pages * 8) / 1024  # SQL Server pages are 8KB each
    if mb >= s.tempdb_version_store_warn_mb:
        log.warning("selfcheck.tempdb_version_store_high", version_store_mb=round(mb, 1),
                    threshold_mb=s.tempdb_version_store_warn_mb)
        return "tempdb_version_store_high"
    return None


def check_tempdb_long_running_txn() -> str | None:
    """Warn once a read transaction has been open longer than a configured
    threshold — exactly what scripts/production_setup.sql's RCSI section names as
    the OTHER thing (besides raw write volume) that lets the version store above
    keep growing instead of shrinking back down."""
    s = get_settings()
    with get_engine().connect() as c:
        longest = c.execute(text(
            "SELECT MAX(elapsed_time_seconds) FROM sys.dm_tran_active_snapshot_database_transactions"
        )).scalar()
    if longest is not None and longest >= s.tempdb_long_txn_warn_seconds:
        log.warning("selfcheck.tempdb_long_running_txn", longest_seconds=longest,
                    threshold_seconds=s.tempdb_long_txn_warn_seconds)
        return "tempdb_long_running_txn"
    return None


def run_self_checks(sess: Session) -> list[str]:
    """THE ENTRY POINT — runs every check above, in order, and returns the names of
    whichever ones fired a warning this pass (same list[str] contract reaper.py's
    clean_up_abandoned_sessions returns). One check's own failure (e.g. a DMV query
    erroring on a locked-down permission set) is caught and logged individually so
    it never stops the rest of the checks from running — same per-item isolation
    discipline reaper.py already uses for finalizing abandoned sessions.

    The three tempdb/pool checks need real SQL Server system views, so — like
    app/db/invariants.py's own MSSQL-only checklist entries — they're skipped
    entirely against SQLite (the automated test suite's database), where they'd
    either error out or measure nothing meaningful.
    """
    checks: list[tuple[str, object]] = [("active_sessions", lambda: check_active_sessions(sess))]
    if get_engine().dialect.name == "mssql":
        checks += [
            ("pool_utilization", lambda: check_pool_utilization()),
            ("tempdb_version_store", lambda: check_tempdb_version_store()),
            ("tempdb_long_running_txn", lambda: check_tempdb_long_running_txn()),
        ]
    fired: list[str] = []
    for name, check in checks:
        try:
            result = check()  # type: ignore[operator]
        except Exception:  # noqa: BLE001 — one broken check must never stop the rest
            log.warning("selfcheck.check_failed", check=name, exc_info=True)
            continue
        if result:
            fired.append(result)
    return fired
