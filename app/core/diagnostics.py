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
from app.core.diagnostic_writer import WRITER
from app.core.enums import DiagnosticKind
from app.core.logging import get_logger

log = get_logger(__name__)

#: Category names an operator can switch on, mapped to the kinds each covers. `retries` is its own
#: category because it is the one whose VOLUME an operator might want to decline: exceptions are
#: rare by definition, retries spike during an outage.
_CATEGORIES: dict[str, frozenset[DiagnosticKind]] = {
    "exceptions": frozenset({DiagnosticKind.stage_error, DiagnosticKind.retries_exhausted}),
    "retries": frozenset({DiagnosticKind.transient_retry}),
    # `logs` is not a DiagnosticKind: it is the raw stream, which lands in Application_Log rather
    # than Diagnostic_Event. It is a CATEGORY name so one setting governs everything, and it is
    # checked by name in log_enabled() below.
    "logs": frozenset(),
}

#: Loggers whose records are NEVER captured, because capturing them is recursive: the DB layer
#: emits log records, each captured record becomes an insert, and each insert emits more records.
#: Left unguarded this is not a slow leak, it is an exponential one that takes the process out.
#: Prefix match, so `sqlalchemy.engine.Engine` is covered by `sqlalchemy`.
_NEVER_CAPTURE = ("sqlalchemy", "aioodbc", "pyodbc", "app.core.diagnostic_writer",
                  "app.core.diagnostics")


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
    """The accepted category names, so the admin endpoint validates against this module rather
    than against a second hand-copied list that would drift the moment a category is added."""
    return tuple(_CATEGORIES)


def _enabled_kinds() -> frozenset[DiagnosticKind]:
    """Which kinds the current configuration saves.

    Resolved per call, deliberately: a cached settings lookup plus a cached override read. Reading
    it live is what lets the runtime toggle take effect without some code path holding the old
    answer for the life of the process."""
    raw = active_categories()
    if raw in {"", "none"}:
        return frozenset()
    if raw == "all":
        return frozenset().union(*_CATEGORIES.values())
    wanted = {part.strip() for part in raw.split(",") if part.strip()}
    if not wanted:
        return frozenset()
    return frozenset().union(*(_CATEGORIES.get(name, frozenset()) for name in wanted))


def record(kind: DiagnosticKind, exc: BaseException, *, session_id: str | None = None,
           tenant_id: str | None = None, entity_id: str | None = None,
           subsystem_id: int | None = None, task_id: str | None = None,
           client_message: str | None = None, context: dict[str, Any] | None = None) -> None:
    """Save one operator-visible diagnostic. Never raises, never reports a failure to its caller.

    `client_message` is the sanitised text the tenant was shown. Storing it is what turns a report
    of "it said stage processing failed" into one query rather than a conversation.
    """
    try:
        if kind not in _enabled_kinds():
            return
        # Imported here, not at module import: app.db pulls in the engine, and this module is
        # imported by app.core, which must stay loadable without a database.
        from app.db.dal import guid, now

        tb = "".join(_traceback.format_exception(type(exc), exc, exc.__traceback__))
        client = (client_message or "")[:1000] or None
        row = {
            "DiagnosticID": guid(), "CreatedAt": now(), "SessionID": session_id,
            "TenantID": tenant_id, "EntityID": entity_id, "SubsystemID": subsystem_id,
            "TaskID": task_id, "RequestID": _request_id(), "Kind": str(kind),
            # ALWAYS the class, whatever the classifier made of it. For 6174F288 this alone would
            # have said "Timeout" where every durable surface said "stage processing failed".
            "ExceptionClass": type(exc).__name__,
            "ExceptionMessage": str(exc)[:4000] or None,
            "Traceback": tb,
            "ClientMessage": client,
            "ContextJSON": json.dumps(context, default=str) if context else None,
        }
        # QUEUED, never inserted here. Off the caller's thread entirely: the caller may be
        # mid-rollback, holds a lock, and in the `logs` case is in the middle of a log call that
        # must not perform IO. diagnostic_writer batches and owns its own connection.
        WRITER.submit("Diagnostic_Event", row, get_settings().diagnostic_queue_max)
    except Exception as write_failure:  # noqa: BLE001 — see the module docstring
        # stdout is the fallback and is always available. The ORIGINAL exception is logged here
        # too, because losing it is the one outcome worse than losing the diagnostic row.
        log.warning("diagnostic.write_failed", kind=str(kind),
                    write_error=f"{type(write_failure).__name__}: {write_failure}"[:300],
                    original_error=f"{type(exc).__name__}: {exc}"[:300])


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
    """Is the raw log stream being captured? Read per record, so the runtime toggle takes effect
    without a restart and without this module holding a stale answer."""
    raw = active_categories()
    return raw == "all" or "logs" in {p.strip() for p in raw.split(",")}


def capture_log_record(logger, method_name, event_dict):
    """structlog processor: queue this event for Application_Log, then pass it through unchanged.

    A PROCESSOR, not a logging handler. structlog uses PrintLoggerFactory here and bypasses stdlib
    logging entirely, so a stdlib handler would see the FOREIGN records (uvicorn, sqlalchemy) and
    miss every application event — the opposite of what is wanted. Sitting in the processor chain
    catches app events, which is the half worth keeping.

    Returns event_dict unchanged on EVERY path, including failure: a processor that raises, or that
    drops the dict, silences the log line it was meant to record.
    """
    try:
        if not log_enabled():
            return event_dict
        name = getattr(logger, "name", "") or event_dict.get("logger") or ""
        if any(str(name).startswith(p) for p in _NEVER_CAPTURE):
            return event_dict
        level = str(event_dict.get("level", method_name) or "").upper()
        if level not in _CAPTURED_LEVELS:
            return event_dict

        from app.db.dal import guid, now

        known = {"event", "level", "logger", "timestamp", "session_id", "request_id", "task_id"}
        WRITER.submit("Application_Log", {
            "LogID": guid(), "CreatedAt": now(), "Level": level[:20],
            "Logger": (str(name) or None) and str(name)[:200],
            "Event": str(event_dict.get("event", ""))[:500] or None,
            "SessionID": _text(event_dict.get("session_id")),
            "RequestID": _text(event_dict.get("request_id")),
            "TaskID": _text(event_dict.get("task_id")),
            "FieldsJSON": json.dumps({k: v for k, v in event_dict.items() if k not in known},
                                     default=str) or None,
        }, get_settings().diagnostic_queue_max)
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
