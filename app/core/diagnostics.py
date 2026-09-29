"""Operator-only failure detail, durable and queryable.

WHY THIS EXISTS. Diagnosing session 6174F288 took a pasted container log. Everything the database
held said `"stage processing failed"` — _record_failure writes to four places and three of them
carry the sanitised client message, because those three are tenant-visible. The fourth is a log
line on stdout, which in UAT lives only as long as the container and is reachable only with shell
access.

The sanitising is right. Having only ONE surface was the defect: the tenant must see nothing
internal, the operator must see everything, and only the tenant was served. This module is the
second surface. It does not weaken the first — Subsystem_Stage_State.ErrorMessage, the stage_error
audit row and the SSE event keep exactly the text they had.

EVERY WRITE HERE IS BEST-EFFORT, and that is not politeness. Two hazards make it a correctness
requirement:

  * The failure being recorded may itself BE a database failure — OperationalError is half of
    TRANSIENT_INFRA_ERRORS. A diagnostics write that raised would replace a diagnosable error with
    an undiagnosable one: precisely the outcome this module exists to remove.
  * _record_failure rolls back first and its caller's `finally` releases a lock. A diagnostic
    insert that left the session dirty would surface as PendingRollbackError INSTEAD of the real
    exception mid-flight — a hazard this codebase has already been bitten by and documented at
    tasks.py's transient handler.

So: its own session, its own transaction, everything swallowed, and stdout as the fallback.

KNOWN LIMIT, stated so nobody over-trusts the table: this records HANDLED failures. A worker killed
by OOM, a segfault, or a container terminated mid-stage writes nothing and leaves only stdout. It
covers the class of failure 6174F288 belonged to, not every possible death.
"""
from __future__ import annotations

import json
import time
import traceback as _traceback
from typing import Any

from app.core.config import get_settings
from app.core import diagnostic_backends as backends
from app.core.diagnostic_writer import WRITER
from app.core.enums import DiagnosticKind
from app.core.logging import get_logger

log = get_logger(__name__)

#: Category names an operator can switch on, mapped to the kinds each covers. `retries` is its own
#: category because it is the one whose VOLUME an operator might want to decline: exceptions are
#: rare by definition, retries spike during an outage.
#: Which CATEGORY each kind belongs to. One direction only — kind -> category — because a kind
#: belongs to exactly one category and the reverse mapping is derivable. Two hand-maintained
#: dictionaries pointing at each other is how a new kind ends up switchable by nothing.
_KIND_CATEGORY: dict[DiagnosticKind, str] = {
    DiagnosticKind.stage_error: "exceptions",
    DiagnosticKind.retries_exhausted: "exceptions",
    DiagnosticKind.transient_retry: "retries",
    DiagnosticKind.degraded_outcome: "degraded",
    DiagnosticKind.slow_step: "slow",
}

#: Log EVENT NAMES that mean "it finished, but worse than asked". Curated rather than inferred:
#: every one of these is already being logged by the pipeline, so `degraded` costs no new
#: instrumentation — it is a filter over a stream that already exists, which is what makes the
#: category cheap enough to leave on permanently.
_DEGRADED_EVENTS = frozenset({
    "threats.partial_delivery",          # fewer threats admitted than the subsystem asked for
    "llm.fallback_model_used",           # answered by the second model, not the configured one
    "rerank_many.item_failed",           # one item dropped out of a rerank batch
    "controls.rerank_item_failed",       # same, on the control-mapping side
    # The AGGREGATE alarm, raised by pipeline_common when the deployment-wide retry rate crosses
    # its threshold. Listed here so the P1 signal lands in a queryable table and not only in a log
    # stream somebody has to be watching -- the whole complaint that started this work.
    "infra.degraded",
})

#: Matched on the LAST dotted segment, not the whole name, because these events are built with an
#: f-string prefix (`f"{kind}.lock_lost"` in cascade.py). A literal list would silently miss every
#: prefix nobody thought to enumerate — which is the same open-list mistake that cancelled 6174F288.
_DEGRADED_SEGMENT_PREFIXES = ("claim_lost", "lock_lost")

#: Loggers whose records are NEVER captured, because capturing them is recursive: the DB layer
#: emits log records, each captured record becomes an insert, and each insert emits more records.
#: Left unguarded this is not a slow leak, it is an exponential one that takes the process out.
#: Prefix match, so `sqlalchemy.engine.Engine` is covered by `sqlalchemy`.
_NEVER_CAPTURE = ("sqlalchemy", "aioodbc", "pyodbc", "app.core.diagnostic_writer",
                  "app.core.diagnostics", "app.core.diagnostic_backends")


#: Redis key holding the runtime override. ONE key, shared by the API process and every Celery
#: worker — which is the entire reason this lives in Redis rather than in a module global. A
#: toggle held in one process's memory changes nothing in the workers, where the pipeline actually
#: runs: you would flip the switch, watch the API agree, and the capture would carry on unchanged.
_OVERRIDE_KEY = "tsg:diagnostics:categories"

#: Seconds a process may serve the override from memory before re-reading it. The trade this
#: number makes: a change takes up to this long to reach every process, and in exchange a Redis
#: round trip happens at most once per interval per process instead of ONCE PER LOG RECORD.
_OVERRIDE_TTL = 10.0

#: Seconds to back off after a FAILED read — deliberately far longer than the TTL. With Redis
#: down, retrying on the normal interval would put a connect timeout on a log call every 10
#: seconds forever, so the outage would degrade logging rather than just the toggle.
_OVERRIDE_BACKOFF = 60.0

#: Hard ceiling on how long one refresh may stall its caller. This read sits ON THE LOG PATH, so
#: a slow Redis must degrade to "use the env value", never to "the application logs slowly".
#: ponytail: a 250ms stall once per interval is the accepted cost; move the refresh onto the
#: writer thread if that ever shows up in a latency profile.
_OVERRIDE_TIMEOUT = 0.25

#: (expires_at_monotonic, value). A plain tuple, reassigned atomically — no lock, because the
#: worst outcome of two threads refreshing at once is two Redis reads and one discarded answer.
#: MONOTONIC, not wall clock: a clock step must not freeze the cache or expire it early.
_override_cache: tuple[float, str | None] = (0.0, None)
_redis_client = None


def _override_redis():
    """A small client of our own, on the Redis this deployment already runs for the SSE bus and
    the LLM slot limiter. Neither `bus._redis()` nor `llm._slot_redis()`: app.core must not import
    app.sse or app.pipeline, and this client wants a far shorter timeout than either — it is read
    from inside a log call, where their multi-second timeouts would be a stall, not a retry."""
    global _redis_client
    if _redis_client is None:
        import redis

        _redis_client = redis.Redis.from_url(
            get_settings().redis_url, decode_responses=True,
            socket_connect_timeout=_OVERRIDE_TIMEOUT, socket_timeout=_OVERRIDE_TIMEOUT)
    return _redis_client


def active_categories() -> str:
    """The category list in force RIGHT NOW, normalised. The one source both readers below use.

    Precedence, highest first: the runtime override in Redis, then the env var, then the built-in
    default. Redis unreachable falls back to the env value rather than failing — an observability
    switch must never be the thing that breaks the system it observes.
    """
    global _override_cache
    env = (get_settings().diagnostic_db_categories or "").strip().lower()
    expires, cached = _override_cache
    now = time.monotonic()
    if now >= expires:
        try:
            value = _override_redis().get(_OVERRIDE_KEY)
            cached = (str(value).strip().lower() or None) if value is not None else None
            _override_cache = (now + _OVERRIDE_TTL, cached)
        except Exception:  # noqa: BLE001 — the env value is the documented fallback
            cached = None
            _override_cache = (now + _OVERRIDE_BACKOFF, None)
    return cached or env


def set_override(categories: str | None, ttl_seconds: int | None = None) -> None:
    """Write (or, with None, clear) the runtime override. RAISES — unlike everything else here.

    Deliberately the one loud function in this module: it is called from an admin endpoint by a
    human who needs to know whether the switch actually moved. A silent failure would leave an
    operator believing capture was off while every worker carried on writing.

    `ttl_seconds` makes the override EXPIRE BY ITSELF, and it is the safety valve for the one
    category that matters: `logs` writes personal data durably, and the realistic failure is not a
    bad decision but a forgotten one — switched on to reproduce something, then left on for a
    month. An operator who says "on for 30 minutes" cannot forget. None means no expiry, which
    stays the right default for the four small categories."""
    global _override_cache
    r = _override_redis()
    if categories is None:
        r.delete(_OVERRIDE_KEY)
    else:
        r.set(_OVERRIDE_KEY, categories.strip().lower(), ex=ttl_seconds or None)
    _override_cache = (0.0, None)   # expire OUR copy now; other processes follow within the TTL


def override_status() -> dict[str, Any]:
    """What this ONE process currently believes, for the admin config endpoint.

    Per process on purpose. The endpoint answers "did my change land?", and the honest answer
    differs between the API and each worker until their caches lapse — reporting a single global
    number would hide exactly the case an operator is checking for."""
    try:
        raw = _override_redis().get(_OVERRIDE_KEY)
        reachable, override = True, (str(raw).strip().lower() if raw is not None else None)
    except Exception as exc:  # noqa: BLE001 — "Redis is down" is an ANSWER here, not a failure
        reachable, override = False, None
        return {"override": None, "redis_reachable": False,
                "redis_error": f"{type(exc).__name__}: {exc}"[:200],
                "env": (get_settings().diagnostic_db_categories or "").strip().lower(),
                "effective": (get_settings().diagnostic_db_categories or "").strip().lower(),
                "cache_ttl_seconds": _OVERRIDE_TTL, "dropped_rows": WRITER.dropped}
    env = (get_settings().diagnostic_db_categories or "").strip().lower()
    return {"override": override, "redis_reachable": reachable, "redis_error": None, "env": env,
            "effective": override or env, "cache_ttl_seconds": _OVERRIDE_TTL,
            "dropped_rows": WRITER.dropped}


def known_categories() -> tuple[str, ...]:
    """The accepted category names, so the admin endpoint validates against the implementation
    rather than a hand-copied list that would drift the moment a category is added.

    Delegates to the backends module, which is where the list actually lives now: the API, the
    operator guide and every backend must agree on it, and three copies is three chances to
    disagree."""
    from app.core.diagnostic_backends import CATEGORIES

    return CATEGORIES


def _category_of(kind: DiagnosticKind) -> str:
    """Which switch governs this kind. An unmapped kind falls under `exceptions` rather than
    silently under nothing: a new kind that nobody can see is worse than one filed slightly wrong,
    and `exceptions` is the category that is always on."""
    return _KIND_CATEGORY.get(kind, "exceptions")


def record(kind: DiagnosticKind, exc: BaseException, *, session_id: str | None = None,
           entity_id: str | None = None,
           subsystem_id: int | None = None, task_id: str | None = None,
           client_message: str | None = None, context: dict[str, Any] | None = None) -> None:
    """Save one operator-visible diagnostic. Never raises, never reports a failure to its caller.

    `client_message` is the sanitised text the tenant was shown. Storing it is what turns a report
    of "it said stage processing failed" into one query rather than a conversation.
    """
    category = _category_of(kind)
    try:
        # The CHEAP gate first, before any formatting. Building a traceback string for an event
        # nobody is recording is pure waste, and `retries` fires in bursts during exactly the
        # outage when there is least headroom to waste.
        if not backends.wants_any(category):
            return
        # Imported here, not at module import: app.db pulls in the engine, and this module is
        # imported by app.core, which must stay loadable without a database.
        from app.db.dal import now

        backends.emit(backends.DiagnosticEvent(
            ts=now(), category=category, kind=str(kind), level="ERROR",
            session_id=session_id, entity_id=entity_id,
            subsystem_id=subsystem_id, task_id=task_id, request_id=_request_id(),
            # ALWAYS the class, whatever the classifier made of it. For 6174F288 this alone would
            # have said "Timeout" where every durable surface said "stage processing failed".
            exception_class=type(exc).__name__,
            exception_message=str(exc)[:4000] or None,
            traceback="".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)),
            client_message=client_message,
            context=context or {}))
    except Exception as write_failure:  # noqa: BLE001 — see the module docstring
        # stdout is the fallback and is always available. The ORIGINAL exception is logged here
        # too, because losing it is the one outcome worse than losing the diagnostic row.
        log.warning("diagnostic.write_failed", kind=str(kind),
                    write_error=f"{type(write_failure).__name__}: {write_failure}"[:300],
                    original_error=f"{type(exc).__name__}: {exc}"[:300])


def transient_retry_rate_exceeded(error_kind: str) -> int | None:
    """Count one recovered hiccup. Returns the running count IF this call is the one that should
    raise the alarm, and None every other time. Never raises.

    THE PROBLEM THIS SOLVES IS ONE THIS CODEBASE CREATED. Making provider outages survivable also
    made them invisible: before the retry fix a reranker outage cancelled sessions and people
    complained — crude, but an alert. Now the same outage is absorbed silently until the attempt
    cap is reached, so a loud failure became a quiet one, and a quiet failure runs for a week.

    A single retry is not news. Thousands of individually unremarkable retries are, and nothing
    was counting them — so no amount of log-reading would ever surface the aggregate, because the
    aggregate did not exist anywhere.

    THREE DESIGN POINTS, each of them load-bearing:

      * COUNTED IN REDIS. Retries spread across every worker, so a per-process counter would sit
        comfortably below any useful threshold while the deployment as a whole was on fire.
      * ONE ALARM PER WINDOW, DEPLOYMENT-WIDE. The `nx` latch below is what makes that true: every
        worker crosses the threshold at nearly the same moment, and without it an outage would
        produce a second flood on top of the first.
      * IT RETURNS RATHER THAN LOGS. The caller logs, because this module's own logger is on the
        recursion denylist — an alarm emitted from here would be filtered out of the capture it is
        supposed to land in, and would have looked like it worked.
    """
    try:
        s = get_settings()
        threshold = s.infra_degraded_threshold
        if threshold <= 0:                       # explicitly switched off
            return None
        window = s.infra_degraded_window_seconds
        r = _override_redis()
        # A FIXED time bucket, not a sliding window. A sliding window needs a sorted set and a
        # prune on every retry; this needs one INCR. During an outage the retry path is the
        # hottest path there is, and it is the worst possible moment to make it more expensive.
        key = f"tsg:infra_retry:{error_kind}:{int(time.time() // window)}"
        count = int(r.incr(key))
        if count == 1:
            r.expire(key, window * 2)            # self-cleaning: no purge, no growth
        if count < threshold:
            return None
        # The latch. `nx` means exactly one caller in the deployment gets True per bucket.
        if not r.set(f"{key}:alarmed", "1", nx=True, ex=window * 2):
            return None
        return count
    except Exception:  # noqa: BLE001 — the retry path must never fail because counting failed
        return None


def record_slow_step(*, step: str, duration_ms: float, session_id: str | None = None,
                     context: dict[str, Any] | None = None) -> None:
    """Record one step that took longer than the configured threshold. Never raises.

    THE EARLY WARNING THE RETRY FIX OTHERWISE REMOVES. A provider that has gone from 2s to 80s is
    still succeeding, so nothing fails, nothing retries, and no other surface says a word — until
    it crosses the timeout and starts cancelling sessions. The step that is merely slow is the one
    observation that arrives before the incident does."""
    try:
        if not backends.wants_any("slow"):
            return
        from app.db.dal import now

        backends.emit(backends.DiagnosticEvent(
            ts=now(), category="slow", kind=str(DiagnosticKind.slow_step), level="WARNING",
            event=step, session_id=session_id, duration_ms=duration_ms,
            exception_message=f"{step} took {duration_ms:.0f} ms",
            context={**(context or {}), "duration_ms": duration_ms}))
    except Exception:  # noqa: BLE001 — observability must never break what it observes
        pass


def _request_id() -> str | None:
    """The HTTP request id from the logging contextvars, when there is one.

    Worker-side failures have none, which is fine — the task id is the pivot there. Wrapped
    because a contextvar lookup must never be the thing that breaks a diagnostic write."""
    try:
        import structlog

        return structlog.contextvars.get_contextvars().get("request_id")
    except Exception:  # noqa: BLE001 — best-effort, like everything else in this module
        return None


def log_enabled() -> bool:
    """Is the raw log stream being captured by ANY destination?

    Asks the backends rather than parsing the setting itself — with a second destination present,
    "is it enabled" stops being a question about one config string, and a local answer would be
    right only by accident."""
    return backends.wants_any("logs")


def is_degraded_event(event_name: str) -> bool:
    """Does this log event mean "it finished, but worse than asked"?

    Matched on the LAST dotted segment as well as the whole name, because some of these are built
    with an f-string prefix. An exact-name list would silently miss every prefix nobody thought to
    enumerate — the same open-list mistake that let a timeout cancel 6174F288."""
    if event_name in _DEGRADED_EVENTS:
        return True
    return event_name.rsplit(".", 1)[-1].startswith(_DEGRADED_SEGMENT_PREFIXES)


def capture_log_record(logger, method_name, event_dict):
    """structlog processor: record this event, then pass it through unchanged.

    A PROCESSOR, not a logging handler. structlog uses PrintLoggerFactory here and bypasses stdlib
    logging entirely, so a stdlib handler would see the FOREIGN records (uvicorn, sqlalchemy) and
    miss every application event — the opposite of what is wanted. Sitting in the processor chain
    catches app events, which is the half worth keeping.

    TWO CATEGORIES COME OUT OF ONE STREAM. Most lines are `logs`. A curated few also mean the run
    delivered less than it was asked for, and those are additionally recorded as `degraded` — which
    is why that category costs no new instrumentation anywhere in the pipeline. It is a filter over
    a stream that already exists.

    RECORDED UNDER BOTH when both are enabled, deliberately. Routing a degraded line to `degraded`
    INSTEAD of `logs` would punch silent holes in a stream whose whole contract is "every line at
    INFO and above" — and a stream with holes you cannot see is worse than a few duplicated rows.

    Returns event_dict unchanged on EVERY path, including failure: a processor that raises, or that
    drops the dict, silences the log line it was meant to record.
    """
    try:
        wants_logs = backends.wants_any("logs")
        name = getattr(logger, "name", "") or event_dict.get("logger") or ""
        event_name = str(event_dict.get("event", "") or "")
        degraded = backends.wants_any("degraded") and is_degraded_event(event_name)
        if not (wants_logs or degraded):
            return event_dict
        # The RECURSION GUARD, and it has to sit above every emit below. The DB layer emits log
        # records; capturing them turns one insert into more records into more inserts. Unguarded
        # this is exponential, not a leak.
        if any(str(name).startswith(p) for p in _NEVER_CAPTURE):
            return event_dict
        level = str(event_dict.get("level", method_name) or "").upper()
        if level not in _CAPTURED_LEVELS:
            return event_dict

        from app.db.dal import now

        known = {"event", "level", "logger", "timestamp", "session_id", "request_id", "task_id"}
        common = {
            "ts": now(), "level": level, "logger": str(name)[:200] or None,
            "event": event_name[:500] or None,
            "session_id": _text(event_dict.get("session_id")),
            "request_id": _text(event_dict.get("request_id")),
            "task_id": _text(event_dict.get("task_id")),
            "context": {k: v for k, v in event_dict.items() if k not in known},
        }
        if wants_logs:
            backends.emit(backends.DiagnosticEvent(category="logs", **common))
        if degraded:
            backends.emit(backends.DiagnosticEvent(
                category="degraded", kind=str(DiagnosticKind.degraded_outcome),
                exception_message=event_name[:4000] or None, **common))
    except Exception:  # noqa: BLE001 — a log line must survive its own capture failing
        pass
    return event_dict


#: INFO and above. DEBUG is deliberately excluded even when someone sets the app to DEBUG: debug
#: logging is a development tool and would multiply this table's volume for no operator benefit.
_CAPTURED_LEVELS = frozenset({"INFO", "WARNING", "WARN", "ERROR", "CRITICAL", "EXCEPTION"})


def _text(value) -> str | None:
    """Truncate to the column, and never let a non-string id break the capture."""
    if value in (None, ""):
        return None
    return str(value)[:100]
