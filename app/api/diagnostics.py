"""Admin API — read the operator-only failure record, and flip capture without a restart.

WHY THIS FILE IS THE POINT OF THE WHOLE DIAGNOSTICS EFFORT. Diagnosing session 6174F288 needed a
container log pasted into a chat window. `Diagnostic_Event` fixed half of that — the cause is now
durable and queryable instead of dying with the container — but a table an engineer can only reach
with database credentials has MOVED the problem, not solved it. The original complaint was about
REACH. These four routes are the half that answers it.

THE READ ROUTES ARE UNAUTHENTICATED, BY EXPLICIT DECISION. A support engineer must be able to
answer "why did this run fail" with a URL — no admin key to obtain, no database credentials, no
shell. Requiring a key is what put diagnosis behind the engineering team in the first place, which
is the problem being solved, so the key is gone.

WHAT THAT COSTS, AND THE TWO THINGS THAT PAY FOR IT. Public means public: the same URL answers
anyone who finds it, including someone who was never given it.

  1. READS ARE OPEN; WRITING IS NOT. `PATCH /config` keeps `require_admin`. It is the switch that
     turns on `logs` capture, and a public switch for that would let a stranger start a durable
     recording of prompt text and asset context, and fill the database doing it. Support needs to
     READ failures; changing what the system captures is not a support action.
  2. THE HEAVY FIELDS ARE GATED. Traceback, captured log bodies and the context blob are returned
     only when TSG_DIAGNOSTIC_PUBLIC_DETAIL is on, and it is off by default. Those three carry
     payload rather than fact — a log line here can hold tenancy contracts, landlord and tenant
     data and Emirates ID. Everything support actually asks for stays public regardless: which
     session, when, what kind of failure, the exception class and message, and the sanitised text
     the customer was shown. "Timeout: Connection timed out after 120.0 seconds" is the answer to
     6174F288, and none of it is personal data.

KNOWN LIMIT, stated rather than papered over: there is no rate limiting in this application, so
these routes are as reachable as any other public endpoint. Each request is bounded — a time
window and a row cap, both enforced server-side — so one call cannot be expensive, but many calls
are not throttled. If that matters for your deployment it belongs at the gateway, not here.

TWO DIFFERENT CONTRACTS, deliberately:
  * The READ routes are best-effort reporting. They bound every query — a time window, a row
    cap — because an unbounded scan of a table that takes every log line is itself an incident.
  * `PATCH /config` is LOUD. It is a human flipping a switch who must know whether it moved; a
    Redis outage there answers 503 and says so, rather than appearing to succeed and leaving an
    operator believing capture is off while every worker carries on writing.
"""
from __future__ import annotations

import json
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import ConfigDict, Field
from sqlalchemy import select

from app.api.deps import require_admin
from app.api.schemas import UNAVAILABLE_RESPONSES, ApiModel
from app.core import diagnostics
from app.core.config import get_settings
from app.core.diagnostic_backends import backend_status
from app.core.logging import get_logger
from app.db import models as m
from app.db.dal import now
from app.db.engine import db_session

log = get_logger(__name__)

#: NO router-level auth dependency, deliberately — see the module docstring. The one route that
#: writes carries `require_admin` on itself, so the exception is visible at the route rather than
#: inferred from the absence of something here.
router = APIRouter(prefix="/v1/tsg/diagnostics", tags=["Diagnostics"])

#: Row caps. Low on purpose: a diagnostic row carries a full traceback and a log row carries a
#: JSON blob, so "give me 5000" is megabytes of response and a LOB read per row. The operator
#: query these routes exist for — "why did session X fail" — returns single digits.
_MAX_ROWS = 200
_DEFAULT_ROWS = 50


class DiagnosticRow(ApiModel):
    """One recorded failure, as an operator needs it — including the parts a tenant never sees."""

    diagnostic_id: str
    created_at: str
    kind: str
    #: ALWAYS present, whatever the classifier made of the failure. For 6174F288 this single field
    #: would have ended the investigation: "Timeout" where every durable surface said
    #: "stage processing failed".
    exception_class: str
    exception_message: str | None = None
    traceback: str | None = None
    #: The sanitised text the tenant was actually shown. This is the join: a report of "it said
    #: stage processing failed" becomes one lookup instead of a conversation.
    client_message: str | None = None
    session_id: str | None = None
    tenant_id: str | None = None
    entity_id: str | None = None
    subsystem_id: int | None = None
    task_id: str | None = None
    request_id: str | None = None
    context: dict | None = None
    #: True when `traceback` and `context` were WITHHELD rather than absent. Without this an
    #: engineer reads a redacted row as "there was no traceback" and stops looking — the field
    #: exists so a missing answer is never mistaken for an answered one.
    detail_redacted: bool = False


class DiagnosticList(ApiModel):
    """Newest first. `truncated` says the cap was hit, so a short list is never mistaken for
    "that is all there was" — the difference decides whether an operator narrows the window."""

    model_config = ConfigDict(json_schema_extra={"example": {"rows": [], "truncated": False}})

    rows: list[DiagnosticRow]
    truncated: bool


class LogRow(ApiModel):
    """One captured log line. Only populated while the `logs` category is on."""

    log_id: str
    created_at: str
    level: str
    logger: str | None = None
    event: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    task_id: str | None = None
    fields: dict | None = None
    #: True when `fields` was WITHHELD rather than empty. Same reason as on a diagnostic row.
    detail_redacted: bool = False


class LogList(ApiModel):
    model_config = ConfigDict(json_schema_extra={"example": {"rows": [], "truncated": False}})

    rows: list[LogRow]
    truncated: bool


class DiagnosticConfig(ApiModel):
    """What THIS process believes right now. Per process on purpose — see the route docstring."""

    #: The winner, and the only field that describes actual behaviour.
    effective: str
    #: The runtime override in Redis, or null when none is set.
    override: str | None = None
    #: The deployed default, from TSG_DIAGNOSTIC_DB_CATEGORIES.
    env: str
    #: False means runtime overrides are UNAVAILABLE and `effective` is just the env value. An
    #: operator who does not see this reads a stale answer as a current one.
    redis_reachable: bool
    #: Why Redis could not be reached. WITHHELD unless TSG_DIAGNOSTIC_PUBLIC_DETAIL is on: a
    #: connection error names internal hostnames and ports, and this route is public. The boolean
    #: above is the part support needs, and it carries no infrastructure detail.
    redis_error: str | None = None
    #: How long another process may keep serving its old answer after a change.
    cache_ttl_seconds: float
    #: Rows the background writer discarded because its queue was full. Non-zero means capture is
    #: lossy right now — answerable here rather than by grepping logs.
    dropped_rows: int
    #: Every accepted category name, read from the capture module rather than hand-listed, so this
    #: cannot describe a set the code no longer implements.
    known_categories: list[str]
    #: Every registered destination, INCLUDING the disabled and unavailable ones. A destination
    #: that is silently absent is the hardest observability problem there is to debug — someone
    #: configures Prometheus, sees no data, and has nothing to look at. This is that something.
    #: `failures` above zero means that destination is losing events right now.
    backends: list[dict] = Field(default_factory=list)


class DiagnosticConfigPatch(ApiModel):
    """Set or clear the runtime override.

    `categories`: a comma list of the known names, or "all", or "none". **Null clears the
    override**, which is not the same as "none" — cleared falls back to the deployed env value,
    "none" pins capture off regardless of it.
    """

    model_config = ConfigDict(json_schema_extra={
        "example": {"categories": "exceptions,retries,logs", "ttl_seconds": 3600}})

    categories: str | None = Field(
        default=None,
        description='Comma list of category names, or "all" / "none". Null clears the override.')
    ttl_seconds: int | None = Field(
        default=None, ge=60, le=86_400,
        description="Expire the override by itself after this long. Strongly recommended with "
                    "`logs`: the realistic mistake is not a bad decision but a forgotten one.")


def _window(since_hours: int):
    """A time floor on every query. Not a convenience — Application_Log takes every log line at
    INFO and above, so an unbounded ORDER BY over it is a scan of a table that grows by six
    figures a day. Bounding the window is what keeps these routes safe to call during an incident,
    which is the only time anyone calls them."""
    return now() - timedelta(hours=since_hours)


@router.get("", response_model=DiagnosticList,
            summary="Why did this session fail — the operator's answer",
            description=(
                "The real cause of a failure, including the exception class and traceback that the "
                "tenant-facing surfaces deliberately hide.\n\n"
                "**Call it with `session_id`** when a user reports a failed run. Everything they can see "
                "says `stage processing failed`; `client_message` here holds that same string, so the row "
                "they are describing and the cause of it are the same row.\n\n"
                "**Call it with no filter** to see what has been failing recently across the deployment.\n\n"
                "**Watch out:** rows exist only for the categories being captured — check "
                "`GET /config` first if the result is empty. And only HANDLED failures are recorded; a "
                "worker killed by the OOM killer or a container terminated mid-stage writes nothing here."))
def list_diagnostics(
    session_id: str | None = Query(default=None, description="Exact session id."),
    kind: str | None = Query(default=None, description="stage_error | transient_retry | "
                                                       "retries_exhausted"),
    since_hours: int = Query(default=24, ge=1, le=720, description="How far back to look."),
    limit: int = Query(default=_DEFAULT_ROWS, ge=1, le=_MAX_ROWS),
) -> DiagnosticList:
    """Recorded failures, newest first.

    ONE row per handled failure, carrying what the three tenant-visible surfaces sanitise away.
    Every filter narrows the index, and the time window is applied whether or not the caller
    passed one — see `_window`."""
    stmt = (select(m.Diagnostic_Event)
            .where(m.Diagnostic_Event.CreatedAt >= _window(since_hours))
            .order_by(m.Diagnostic_Event.CreatedAt.desc())
            .limit(limit + 1))          # +1 so `truncated` is a fact, not a guess at the boundary
    if session_id:
        stmt = stmt.where(m.Diagnostic_Event.SessionID == session_id)
    if kind:
        stmt = stmt.where(m.Diagnostic_Event.Kind == kind)
    with db_session() as sess:
        rows = list(sess.execute(stmt).scalars().all())
        detail = _detail()
        return DiagnosticList(rows=[_to_diagnostic(r, detail) for r in rows[:limit]],
                              truncated=len(rows) > limit)


@router.get("/logs", response_model=LogList,
            summary="The captured log stream, filtered",
            description=(
                "Ordinary log lines, durably, for the period the `logs` category was switched on.\n\n"
                "**This is empty unless `logs` is enabled** — it is off in production on purpose, because "
                "log lines in this system carry asset context and prompt text, and capturing them creates a "
                "store of personal data that then enters your backups. The intended workflow is: switch it "
                "on with a `ttl_seconds`, reproduce the problem, read it here, let it expire.\n\n"
                "**`level=ERROR` with no other filter** is the fastest way to see what is currently going "
                "wrong across the deployment."))
def list_logs(
    session_id: str | None = Query(default=None),
    level: str | None = Query(default=None, description="INFO | WARNING | ERROR | CRITICAL"),
    event: str | None = Query(default=None, description="Exact structlog event name, e.g. "
                                                        "\"pipeline.failed\"."),
    since_hours: int = Query(default=6, ge=1, le=168),
    limit: int = Query(default=_DEFAULT_ROWS, ge=1, le=_MAX_ROWS),
) -> LogList:
    """Captured log lines, newest first.

    A SHORTER default window than the diagnostics route above, because this table is orders of
    magnitude larger — the same six hours here is a far bigger read than six hours there."""
    stmt = (select(m.Application_Log)
            .where(m.Application_Log.CreatedAt >= _window(since_hours))
            .order_by(m.Application_Log.CreatedAt.desc())
            .limit(limit + 1))
    if session_id:
        stmt = stmt.where(m.Application_Log.SessionID == session_id)
    if level:
        stmt = stmt.where(m.Application_Log.Level == level.upper())
    if event:
        stmt = stmt.where(m.Application_Log.Event == event)
    with db_session() as sess:
        rows = list(sess.execute(stmt).scalars().all())
        detail = _detail()
        return LogList(rows=[_to_log(r, detail) for r in rows[:limit]],
                       truncated=len(rows) > limit)


@router.get("/config", response_model=DiagnosticConfig,
            summary="What is being captured, in THIS process",
            description=(
                "The categories in force right now, where that answer came from, and whether rows are "
                "being dropped.\n\n"
                "**It reports one process, not the deployment.** TSG runs one API process and N Celery "
                "workers, each holding its own short-lived copy of the override. Right after a change they "
                "legitimately disagree — that is what `cache_ttl_seconds` bounds. If a change seems not to "
                "have landed, wait that long and read again.\n\n"
                "**`redis_reachable: false` is the important failure.** It means runtime overrides are not "
                "working at all and `effective` is simply the deployed env value; changing capture then "
                "needs an environment change and a restart.\n\n"
                "**`dropped_rows` above zero** means the writer's queue filled and diagnostics are being "
                "discarded — the database or the writer cannot keep up. Application behaviour is "
                "unaffected; the record is incomplete."))
def get_config() -> DiagnosticConfig:
    """The live capture configuration of the process that served this request.

    Per process by design. A single global number would hide precisely the case an operator is
    checking for — one worker that has not picked the change up yet."""
    status = diagnostics.override_status()
    if not _detail():
        status["redis_error"] = None      # names hosts and ports; see the field comment
    return DiagnosticConfig(known_categories=list(diagnostics.known_categories()),
                            backends=backend_status(), **status)


@router.patch("/config", response_model=DiagnosticConfig, responses=UNAVAILABLE_RESPONSES,
              dependencies=[Depends(require_admin)],
              summary="Change what is captured, with no restart",
              description=(
                  "Sets the runtime override that every process picks up within `cache_ttl_seconds`.\n\n"
                  "**The UAT workflow this exists for:** switch capture on, reproduce the problem, read the "
                  "rows, switch it off — with no redeploy and no restart, so you never lose the state you "
                  "were trying to reproduce.\n\n"
                  "**Use `ttl_seconds` whenever you enable `logs`.** That category writes personal data "
                  "durably, and the realistic mistake is not a bad decision but a forgotten one: switched "
                  "on to reproduce something, still on a month later, in every backup taken since.\n\n"
                  "**`null` and `\"none\"` are different.** Null CLEARS the override and falls back to the "
                  "deployed environment value; `\"none\"` pins capture off regardless of it.\n\n"
                  "**503 means Redis is unreachable** and the change was NOT made — deliberately loud, "
                  "because an override that silently did nothing is worse than one that failed."))
def patch_config(body: DiagnosticConfigPatch) -> DiagnosticConfig:
    """Set or clear the runtime override, and report the result.

    RAISES on a Redis failure, unlike every other diagnostics path. Everywhere else a swallowed
    error costs a diagnostic row; here it would tell an operator the switch moved when it did
    not — and they would then trust an answer about what is captured that is simply false."""
    categories = _validated(body.categories)
    try:
        diagnostics.set_override(categories, body.ttl_seconds)
    except Exception as exc:  # noqa: BLE001 — reported, never swallowed; see the docstring
        log.warning("diagnostics.override_failed", error=f"{type(exc).__name__}: {exc}"[:300])
        raise HTTPException(
            status_code=503,
            detail="Runtime overrides need Redis, and Redis is unreachable — nothing was changed. "
                   "Set TSG_DIAGNOSTIC_DB_CATEGORIES and restart to change capture without it.",
        ) from exc
    log.info("diagnostics.override_set", categories=categories, ttl_seconds=body.ttl_seconds)
    return get_config()


def _validated(categories: str | None) -> str | None:
    """Reject an unknown category name instead of storing it.

    A typo stored verbatim is the worst outcome available: it is accepted, it changes nothing
    visibly, and capture silently narrows to whatever the typo happened to match. Checked against
    the capture module's own list, never a copy — a copy is how the two drift apart."""
    if categories is None:
        return None
    raw = categories.strip().lower()
    if raw in {"all", "none"}:
        return raw
    names = [p.strip() for p in raw.split(",") if p.strip()]
    known = set(diagnostics.known_categories())
    unknown = [n for n in names if n not in known]
    if not names or unknown:
        raise HTTPException(
            status_code=422,
            detail=f"unknown diagnostic categor{'y' if len(unknown) == 1 else 'ies'} "
                   f"{unknown or names}. Valid names: {sorted(known)}, or \"all\" / \"none\".")
    return ",".join(names)


def _json(blob: str | None) -> dict | None:
    """Stored JSON -> dict. A row whose blob is unreadable must still be RETURNED: this route is
    read during an incident, and dropping the one row that explains it because its context failed
    to parse is the opposite of what it is for."""
    if not blob:
        return None
    try:
        parsed = json.loads(blob)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except Exception:  # noqa: BLE001 — see the docstring
        return {"unparsed": blob[:2000]}


def _detail() -> bool:
    """Are the heavy fields published? ONE function, read by both projections below.

    Not two independent checks: a single source is the only version of this that cannot end up
    redacting a traceback while still publishing the log line that contains the same text."""
    return bool(get_settings().diagnostic_public_detail)


def _to_diagnostic(row, detail: bool) -> DiagnosticRow:
    """Row -> response. `detail` decides ONLY whether the payload-bearing fields come along.

    What is always present is what a support question is actually made of: which session, when,
    what kind of failure, the exception class and message, and the sanitised text the customer
    saw. "Timeout: Connection timed out after 120.0 seconds" is the whole answer to 6174F288, and
    none of it is personal data. What `detail` gates is the traceback and the context blob, which
    carry internal structure and whatever the failing code happened to be holding."""
    return DiagnosticRow(
        diagnostic_id=str(row.DiagnosticID), created_at=row.CreatedAt.isoformat(),
        kind=row.Kind, exception_class=row.ExceptionClass,
        exception_message=row.ExceptionMessage,
        traceback=row.Traceback if detail else None,
        client_message=row.ClientMessage,
        session_id=str(row.SessionID) if row.SessionID else None,
        tenant_id=row.TenantID, entity_id=row.EntityID, subsystem_id=row.SubsystemID,
        task_id=row.TaskID, request_id=row.RequestID,
        context=_json(row.ContextJSON) if detail else None,
        detail_redacted=not detail)


def _to_log(row, detail: bool) -> LogRow:
    """Row -> response. The gate bites HARDER here than on a diagnostic.

    A diagnostic row is a failure with a traceback attached. A captured log line is whatever the
    application was logging at the time, which in this system routinely includes asset context and
    prompt text — tenancy contracts, landlord and tenant data, Emirates ID. So `fields`, the blob
    holding everything structlog bound to the event, is withheld with `detail` off; the event NAME
    and level stay, because "pipeline.failed at 07:23" is a timeline and not a disclosure."""
    return LogRow(
        log_id=str(row.LogID), created_at=row.CreatedAt.isoformat(), level=row.Level,
        logger=row.Logger, event=row.Event, session_id=row.SessionID,
        request_id=row.RequestID, task_id=row.TaskID,
        fields=_json(row.FieldsJSON) if detail else None,
        detail_redacted=not detail)
