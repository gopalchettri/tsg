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

from sqlalchemy import select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import QueuePool

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.engine import get_engine

log = get_logger(__name__)


def check_active_sessions(sess: Session) -> str | None:
    """Warn once the active-session count gets close to max_active_sessions, so an
    operator has some runway before new sessions actually start getting rejected
    with a 503. Reuses dal.count_active_sessions — the same racy-by-design count
    assert_capacity_available already checks on every POST /v1/sessions."""
    s = get_settings()
    if not s.max_active_sessions:
        return None
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
    scripts/TSG_Core.sql's RCSI section warns about: an unbounded version
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
    threshold — exactly what scripts/TSG_Core.sql's RCSI section names as
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


def check_llm_slots() -> str | None:
    """Warn once in-flight LLM calls (chat/embed/rerank, app.pipeline.llm._llm_slot) get close
    to max_concurrent_llm_calls, so an operator has runway before real requests start hitting
    LLMSlotUnavailable. Reads Redis, not the DB — zero-arg like the other non-DB checks below,
    unlike check_active_sessions (which genuinely needs `sess`). Only wired into
    run_self_checks when the limiter is actually enabled (max_concurrent_llm_calls > 0)."""
    from app.pipeline.llm import current_llm_slot_count

    s = get_settings()
    if not s.max_concurrent_llm_calls:  # disabled — nothing to warn about (also guards a 0/0 ceiling)
        return None
    count = current_llm_slot_count()
    ceiling = s.max_concurrent_llm_calls * s.llm_slots_warn_ratio
    if count >= ceiling:
        log.warning("selfcheck.llm_slots_high", count=count, limit=s.max_concurrent_llm_calls,
                    ratio=s.llm_slots_warn_ratio)
        return "llm_slots_high"
    return None


def check_litellm_proxy_health() -> str | None:
    """Warn if the LiteLLM proxy is unreachable/unhealthy. Chat/completion has no
    local/offline fallback (app.pipeline.llm's module docstring) — unlike embeddings/
    reranking, which can run fully in-process — so a degraded proxy would otherwise stay
    invisible here until a real pipeline run actually fails on it. Only registered (see
    run_self_checks) when llm_provider itself is 'litellm_proxy' — deliberately NOT gated on
    embedding_provider/reranker_provider too: those two have a real local fallback, so their
    routing through the proxy isn't the fallback-less, must-be-reachable case this exists
    for (and tests/conftest.py's `db` fixture sets both to 'litellm_proxy' purely to avoid
    loading real local models, which would otherwise make this check fire in every test)."""
    import httpx

    from app.pipeline.llm import _ensure_litellm_proxy_bypassed

    s = get_settings()
    # This check's own httpx.Client() call never goes through get_llm() — applying the
    # proxy-bypass fix here too (idempotent, in-memory only) rather than assuming some
    # other code path already ran it first in this process (see llm.py's docstring on why
    # verify_litellm_models needed this exact same explicit call at worker boot).
    _ensure_litellm_proxy_bypassed(s)
    try:
        # Same retries=llm_max_retries as verify_litellm_models (llm.py) — a brief blip
        # shouldn't itself be the thing that fires the warning; consistent with every other
        # call to this proxy in the codebase getting the same retry budget.
        with httpx.Client(transport=httpx.HTTPTransport(retries=s.llm_max_retries)) as client:
            resp = client.get(f"{s.litellm_base_url}/health/readiness",
                            headers={"Authorization": f"Bearer {s.litellm_api_key}"},
                            timeout=s.llm_timeout_seconds)
            resp.raise_for_status()
    except httpx.HTTPError:
        # Best-effort richer diagnostics on top of the plain pass/fail above — /health/readiness
        # only says "up or down"; /health/readiness/details (real response shape unconfirmed
        # from this dev environment, no live proxy access) may say WHY. Logged raw, no assumed
        # field paths, so an unexpected shape just means less detail in the log, never a second
        # failure mode — this whole block is strictly additive to the warning already below.
        details: object = None
        try:
            with httpx.Client(transport=httpx.HTTPTransport(retries=s.llm_max_retries)) as client:
                details_resp = client.get(f"{s.litellm_base_url}/health/readiness/details",
                                        headers={"Authorization": f"Bearer {s.litellm_api_key}"},
                                        timeout=s.llm_timeout_seconds)
                details = details_resp.json()
        except Exception:  # noqa: BLE001 — diagnostics only; the primary warning below still fires either way
            pass
        log.warning("selfcheck.litellm_proxy_unreachable", details=details, exc_info=True)
        return "litellm_proxy_unreachable"
    return None


def check_orphaned_scenario_outputs(sess: Session) -> str | None:
    """Warn on any active Threat_Scenario_Output whose Scoped_Threat parent is superseded or gone.

    This shape renders INCONSISTENTLY and silently: /results returns the row in `scenarios[]`
    (dal's scenario read select outer-joins with no Superseded predicate on the parent) while
    dropping its threat from `threats[]` (that query requires both rows active). A reviewer sees a
    scenario card belonging to a threat the same response says does not exist.

    It is the failure mode tasks._mark_next_set_targets_rescored_out used to have — it retired a
    threat's Scoped_Threat rows without retiring the outputs hanging off them, which became
    reachable the moment next_unserved_unique_threats stopped counting failure cards as served.
    dal.supersede_outputs_for_threats now closes it; this is the regression guard, and it catches
    any FUTURE one-sided supersede too, because it asserts the invariant rather than the fix.
    Cheap: one NOT EXISTS, no session scoping, nothing session-specific to iterate."""
    o, st = m.Threat_Scenario_Output, m.Scoped_Threat
    has_active_parent = select(st.ScopedThreatID).where(
        st.ScopedThreatID == o.ScopedThreatID, st.Superseded == 0)
    orphans = sess.execute(
        select(o.ScenarioID).where(o.Superseded == 0, ~has_active_parent.exists()).limit(20)
    ).scalars().all()
    if orphans:
        log.warning("selfcheck.orphaned_scenario_outputs",
                    scenario_ids=[str(x) for x in orphans], sample_capped_at=20)
        return "orphaned_scenario_outputs"
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
    s = get_settings()
    checks: list[tuple[str, object]] = [
        ("active_sessions", lambda: check_active_sessions(sess)),
        ("orphaned_scenario_outputs", lambda: check_orphaned_scenario_outputs(sess)),
    ]
    if s.max_concurrent_llm_calls:
        checks.append(("llm_slots", lambda: check_llm_slots()))
    if s.llm_provider == "litellm_proxy":
        checks.append(("litellm_proxy_health", lambda: check_litellm_proxy_health()))
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
        except Exception:
            log.warning("selfcheck.check_failed", check=name, exc_info=True)
            continue
        if result:
            fired.append(result)
    return fired
