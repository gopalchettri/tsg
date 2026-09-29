"""The seam: one normalised event, many destinations, and a registry between them.

WHY THIS EXISTS. Before it, `record()` and the log-capture processor each built a database row and
handed it straight to the writer. Adding Prometheus or OpenTelemetry would have meant editing both
call sites and every future one — so "we can add metrics later" was a hope, not a property. The
requirement was that adding a destination is easy; this file is what makes that true, and nothing
else in the pipeline has to know a second destination exists.

THE THING THAT MAKES A NEW BACKEND CHEAP is the normalised event, not the registry.
`DiagnosticEvent` is constructed ONCE at the capture site and handed to every enabled backend. A
new backend is a new module that reads those fields; it is never a re-instrumentation of the
pipeline.

TWO ORTHOGONAL AXES, kept apart deliberately — conflating them is what makes observability stacks
hard to change later:

    WHAT to capture   the five categories (exceptions, retries, degraded, slow, logs)
    WHERE to send it  the backends

Crossing them gives one uniform rule: every backend is configurable per category, through a
setting named `diagnostic_<backend>_categories`. The db backend resolves its own through the
runtime override so it can be flipped without a restart; a backend that does not care reads the
environment value.

BACKENDS ARE ON BY DEFAULT ONCE AVAILABLE — a denylist, not an allowlist, and the same inversion
as the transient-error rule for the same reason. "Available" means registered AND its
prerequisites satisfied (a package importable, an endpoint configured). Configuring the
prerequisite IS the opt-in; making someone say yes twice is how observability quietly ends up
switched off in the environment that needed it. `TSG_DIAGNOSTIC_BACKENDS_DISABLED` is the
operator's kill switch and nothing overrides it.

FAN-OUT IS PER-BACKEND BEST-EFFORT. One backend failing must never stop the others and must never
reach the caller. That is not politeness: these calls sit inside failure handlers and inside log
calls, where raising would replace a diagnosable error with an undiagnosable one.

STDOUT IS NOT A BACKEND HERE, and that is a deliberate departure worth stating. Every event this
module carries was ALREADY logged by the code that produced it — the failure recorder logs, the
retry helper logs, and a captured log line is by definition a log line. A stdout backend would
print each one a second time. Stdout is the substrate the others sit beside: always on, never
switchable, and already what Loki, Fluent Bit and Vector consume.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from app.core.config import get_settings
from app.core.diagnostic_writer import WRITER
from app.core.logging import get_logger

log = get_logger(__name__)

#: Every category an event can belong to. The single source the API validates against, the capture
#: sites tag with, and the operator guide documents — so none of the three can describe a set the
#: others do not implement.
CATEGORIES: tuple[str, ...] = ("exceptions", "retries", "degraded", "slow", "logs")


@dataclass(frozen=True, slots=True)
class DiagnosticEvent:
    """One thing worth recording, in a shape every destination can read.

    FROZEN because it fans out to several backends: a backend that mutated a shared event would
    change what the next one records, and that bug would only appear once a second backend existed.

    SLOTS because this is allocated per captured log line — hundreds per pipeline run — and the
    instance dict a plain dataclass carries is pure overhead at that rate.

    Most fields are optional because the events genuinely differ: a slow step has no exception, a
    captured log line has no client message, and a failure that happened before authentication has
    no entity. A diagnostic must never fail to record because one identifier was unavailable.
    """

    ts: datetime
    #: One of CATEGORIES. What an operator switches on and off.
    category: str
    #: enums.DiagnosticKind for the structured categories; None for the raw `logs` stream.
    kind: str | None = None
    level: str = "ERROR"
    logger: str | None = None
    #: structlog's event name ("pipeline.failed") — the stable handle for log queries.
    event: str | None = None
    session_id: str | None = None
    tenant_id: str | None = None
    entity_id: str | None = None
    subsystem_id: int | None = None
    task_id: str | None = None
    request_id: str | None = None
    exception_class: str | None = None
    exception_message: str | None = None
    traceback: str | None = None
    #: The sanitised text the tenant was shown, so the two halves of a failure can be joined.
    client_message: str | None = None
    duration_ms: float | None = None
    context: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class DiagnosticBackend(Protocol):
    """What a destination must provide. Four small methods, and one hard rule.

    THE RULE: `emit` MUST NOT BLOCK. It is called from inside failure handlers and from inside log
    calls, so any backend doing network or disk IO buffers it itself — exactly as the db backend
    queues rather than inserting. A backend that blocks does not slow down diagnostics, it slows
    down the pipeline.
    """

    #: Lowercase and stable. It is the name in TSG_DIAGNOSTIC_BACKENDS_DISABLED and the middle of
    #: the `diagnostic_<name>_categories` setting, so renaming one silently retires an operator's
    #: configuration.
    name: str

    def available(self) -> bool:
        """Are this backend's prerequisites met? False means absent, never an error at boot — an
        unconfigured destination is one nobody asked for, not a misconfiguration."""

    def wants(self, category: str) -> bool:
        """Does this backend record that category right now? Read live, so a runtime toggle is not
        defeated by a backend that cached the answer."""

    def emit(self, event: DiagnosticEvent) -> None:
        """Record it. Must not block, and may raise — the fan-out contains the failure."""

    def close(self) -> None:
        """Flush and release. Called at shutdown; must be safe to call twice."""


def env_categories(backend_name: str) -> str:
    """The configured category list for a backend, by naming convention.

    `diagnostic_<name>_categories` on Settings. Convention rather than per-backend registration so
    that adding Prometheus is one Settings field plus one module — the fan-out below never learns
    the new name. A backend with no such field defaults to `all`, which is the same
    on-by-default rule the module docstring states."""
    raw = getattr(get_settings(), f"diagnostic_{backend_name}_categories", "all")
    return (raw or "").strip().lower()


def categories_from(raw: str) -> frozenset[str]:
    """Parse one category list: `all`, `none`, or names.

    THE ONE PARSER every backend shares, so two of them can never disagree about what `all` means.
    Unknown names are dropped rather than honoured — the API rejects them at the door, and a name
    that reached here anyway must not silently widen capture."""
    raw = (raw or "").strip().lower()
    if raw in {"", "none"}:
        return frozenset()
    if raw == "all":
        return frozenset(CATEGORIES)
    return frozenset(p.strip() for p in raw.split(",") if p.strip()) & frozenset(CATEGORIES)


class _DbBackend:
    """The database. The only backend that ships, and the one the read endpoints serve.

    It does NOT resolve its categories through `env_categories` as a generic backend would: the db
    category list is the one carrying a Redis-backed runtime override, so it reads through
    `diagnostics.active_categories()` and a change reaches every worker within the cache TTL."""

    name = "db"

    def available(self) -> bool:
        """Always. A database is configured or the application does not run at all, so there is no
        half-configured state to detect here."""
        return True

    def wants(self, category: str) -> bool:
        from app.core import diagnostics      # late: diagnostics imports this module

        return category in categories_from(diagnostics.active_categories())

    def emit(self, event: DiagnosticEvent) -> None:
        """Queue one row. Never inserts here — see app/core/diagnostic_writer.py for why."""
        import json

        from app.db.dal import guid

        maxsize = get_settings().diagnostic_queue_max
        if event.category == "logs":
            WRITER.submit("Application_Log", {
                "LogID": guid(), "CreatedAt": event.ts, "Level": event.level[:20],
                "Logger": (event.logger or None) and str(event.logger)[:200],
                "Event": (event.event or None) and str(event.event)[:500],
                "SessionID": _short(event.session_id), "RequestID": _short(event.request_id),
                "TaskID": _short(event.task_id),
                "FieldsJSON": json.dumps(event.context, default=str) if event.context else None,
            }, maxsize)
            return
        WRITER.submit("Diagnostic_Event", {
            "DiagnosticID": guid(), "CreatedAt": event.ts, "SessionID": event.session_id,
            "TenantID": event.tenant_id, "EntityID": event.entity_id,
            "SubsystemID": event.subsystem_id, "TaskID": event.task_id,
            "RequestID": event.request_id, "Kind": event.kind or event.category,
            # NEVER NULL, and for a row with no exception it names what the row IS (SlowStep,
            # DegradedOutcome) rather than inventing an exception that never happened. `Kind`
            # already says which sort of row this is, so the column stays honest either way.
            "ExceptionClass": (event.exception_class or _sentinel(event.category))[:200],
            "ExceptionMessage": (event.exception_message or event.event or "")[:4000] or None,
            "Traceback": event.traceback,
            "ClientMessage": (event.client_message or "")[:1000] or None,
            "ContextJSON": json.dumps(event.context, default=str) if event.context else None,
        }, maxsize)

    def close(self) -> None:
        WRITER.close()


def _sentinel(category: str) -> str:
    """What to file a non-exception row under, so ExceptionClass is never NULL and never a lie."""
    return {"slow": "SlowStep", "degraded": "DegradedOutcome"}.get(category, "Unknown")


def _short(value) -> str | None:
    """Truncate to the column, and never let a non-string identifier break a capture."""
    if value in (None, ""):
        return None
    return str(value)[:100]


#: name -> instance. Module-level and populated at import; a backend is registered once per
#: process, never per event.
_REGISTRY: dict[str, DiagnosticBackend] = {}
_lock = threading.Lock()


def register(backend: DiagnosticBackend) -> None:
    """Add a destination. Idempotent, so importing a backend module twice is harmless."""
    with _lock:
        _REGISTRY[backend.name] = backend


def registered() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def _disabled() -> frozenset[str]:
    """The operator's kill switch, and the highest precedence there is. A name here cannot be
    re-enabled by any runtime override — which is what makes it usable during an incident."""
    raw = (get_settings().diagnostic_backends_disabled or "").strip().lower()
    return frozenset(p.strip() for p in raw.split(",") if p.strip())


def active_backends() -> tuple[DiagnosticBackend, ...]:
    """Every backend that is registered, available, and not switched off.

    Recomputed per call rather than cached: the denylist is configuration, and a cached answer is
    how a kill switch stops killing. The loop covers a handful of objects and each check is a
    cached settings read, so this costs nothing measurable."""
    off = _disabled()
    out = []
    for name, backend in _REGISTRY.items():
        if name in off:
            continue
        try:
            if backend.available():
                out.append(backend)
        except Exception:  # noqa: BLE001 — an unavailable backend is absent, never an error
            continue
    return tuple(out)


def wants_any(category: str) -> bool:
    """Is ANY destination recording this category?

    The cheap pre-check that keeps capture off the hot path. The log processor calls it per record
    and must be able to return without building an event — with capture off, the cost of this whole
    subsystem is one settings lookup per log line and nothing else."""
    try:
        return any(b.wants(category) for b in active_backends())
    except Exception:  # noqa: BLE001 — a broken backend must never silence logging
        return False


#: Failures are logged on a curve, never per event: a broken backend is broken for every event, and
#: logging each one turns one outage into a second flood. The FIRST failure is the one worth seeing.
_failures: dict[str, int] = {}


def emit(event: DiagnosticEvent) -> None:
    """Hand one event to every destination that wants it. Never raises.

    PER-BACKEND best-effort, not best-effort overall: one destination failing must not cost the
    others their copy of the event. That distinction is the entire reason the `try` is INSIDE the
    loop rather than around it."""
    for backend in active_backends():
        try:
            if backend.wants(event.category):
                backend.emit(event)
        except Exception as exc:  # noqa: BLE001 — see the docstring
            count = _failures[backend.name] = _failures.get(backend.name, 0) + 1
            if count in (1, 10, 100) or count % 1000 == 0:
                log.warning("diagnostic.backend_failed", backend=backend.name, failures=count,
                            error=f"{type(exc).__name__}: {exc}"[:300],
                            note="diagnostics for this destination are being lost; application "
                                 "behaviour is unaffected")


def backend_status() -> list[dict[str, Any]]:
    """What each registered destination is doing, for the admin config endpoint.

    Reports the DISABLED and UNAVAILABLE ones too. A destination that is silently absent is the
    hardest observability problem there is to debug — someone configures Prometheus, sees no data,
    and has nothing to look at. This is that something."""
    off = _disabled()
    out = []
    for name, backend in sorted(_REGISTRY.items()):
        try:
            available = bool(backend.available())
        except Exception:  # noqa: BLE001 — reported as unavailable, never raised
            available = False
        enabled = available and name not in off
        out.append({
            "name": name,
            "available": available,
            "disabled": name in off,
            "categories": sorted(_live_categories(backend)) if enabled else [],
            "failures": _failures.get(name, 0),
        })
    return out


def _live_categories(backend: DiagnosticBackend) -> list[str]:
    """The categories a backend is ACTUALLY applying, asked of the backend rather than derived from
    settings — the db backend's answer comes through the runtime override, and reporting the
    environment value instead would tell an operator their change had not landed when it had."""
    return [c for c in CATEGORIES if _safe_wants(backend, c)]


def _safe_wants(backend: DiagnosticBackend, category: str) -> bool:
    try:
        return bool(backend.wants(category))
    except Exception:  # noqa: BLE001 — a status read must never raise
        return False


def close_all() -> None:
    """Flush every destination at shutdown. Each failure is contained, so one stuck backend cannot
    stop the others from flushing or the process from exiting."""
    for backend in tuple(_REGISTRY.values()):
        try:
            backend.close()
        except Exception:  # noqa: BLE001 — shutdown is best-effort everywhere in this subsystem
            pass


register(_DbBackend())
