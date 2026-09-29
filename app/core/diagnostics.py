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


def _enabled_kinds() -> frozenset[DiagnosticKind]:
    """Which kinds the current configuration saves.

    Parsed per call, deliberately: get_settings is cached so this is a dict lookup, and reading it
    live means a settings change takes effect without some code path holding the old answer."""
    raw = (get_settings().diagnostic_db_categories or "").strip().lower()
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
    raw = (get_settings().diagnostic_db_categories or "").strip().lower()
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
