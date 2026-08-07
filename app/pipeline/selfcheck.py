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
from app.db import dal, models as m
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


def check_dead_threat_rules(sess: Session) -> str | None:
    """Warn once an active Config_Threat_Rule.RuleKey falls outside scoping's fixed
    _RULE_KEY_FIELDS allowlist. _apply_rules doesn't error on an unknown key — it logs
    and no-ops the rule (scoping.py §5.4 step 1) — so a curator adding or renaming a
    RuleKey the code doesn't actually resolve would otherwise stay invisible until
    someone notices a rule that never fires. This already happened once (scoping.py's
    own comment: keys removed 2026-07-12 when their backing columns went away)."""
    from app.pipeline.scoping import _RULE_KEY_FIELDS

    ct = m.Config_Threat_Rule
    active_keys = sess.execute(
        select(ct.RuleKey).where(ct.IsActive == True, ct.IsDeleted == False).distinct()  # noqa: E712
    ).scalars().all()
    dead = sorted(set(active_keys) - _RULE_KEY_FIELDS.keys())
    if dead:
        log.warning("selfcheck.dead_threat_rules", rule_keys=dead)
        return "dead_threat_rules"
    return None


def check_ctm_scan_category_names(sess: Session) -> str | None:
    """Warn if the real platform ctm_scan_category.name values don't cover every asset_type
    value the seeded Config_Threat_Rule tech_gate rules expect. scoping._matches does a
    case-insensitive, WHITESPACE-STRIPPED TEXT compare between a subsystem's resolved asset_type
    (context.py's ctm_scan_category.name lookup) and each rule's RuleValue (e.g. "Operational
    Technology (OT)") — a spelling drift on the platform side makes that rule permanently no-op
    (it never excludes anything again) with no error anywhere, silently weakening threat
    filtering. This check mirrors that same strip+lower comparison exactly, or it would flag
    false-positive "mismatches" for rules that actually work fine at runtime (e.g. a stray
    trailing space in a platform-table name).

    check_dead_threat_rules (above) can't catch this: that checks RuleKey names, not RuleValue
    content. Nothing here is hardcoded — both sides are read live, so this never needs updating
    when new asset_type rules are added."""
    ct = m.Config_Threat_Rule
    # RuleValue is nullable at the type level (Mapped[str | None]) even though the WHERE clause
    # below already excludes NULL rows at the SQL level — mypy can't see through that runtime
    # filter, so narrow it here too, the same "belt and suspenders" a `None` in expected would
    # otherwise crash .strip() on. A blank/whitespace-only RuleValue is excluded on purpose: per
    # scoping.py's own _apply_rules comment, "" is a real curator sentinel meaning "match
    # subsystems with a blank asset_type" — not a category name to look up here at all.
    expected = [v.strip() for v in sess.execute(
        select(ct.RuleValue).where(
            ct.RuleKey == "asset_type", ct.IsActive == True, ct.IsDeleted == False,  # noqa: E712
            ct.RuleValue.is_not(None),
        ).distinct()
    ).scalars().all() if v is not None and v.strip()]
    if not expected:
        return None
    cat = m.ctm_scan_category
    real_names = {n.strip().lower() for n in sess.execute(select(cat.name)).scalars().all() if n and n.strip()}
    missing = sorted({v for v in expected if v.lower() not in real_names})
    if missing:
        log.warning("selfcheck.ctm_scan_category_asset_type_mismatch", missing_values=missing)
        return "ctm_scan_category_asset_type_mismatch"
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
        ("dead_threat_rules", lambda: check_dead_threat_rules(sess)),
        ("ctm_scan_category_names", lambda: check_ctm_scan_category_names(sess)),
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
        except Exception:  # noqa: BLE001 — one broken check must never stop the rest
            log.warning("selfcheck.check_failed", check=name, exc_info=True)
            continue
        if result:
            fired.append(result)
    return fired
