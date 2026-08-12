"""Error contract  — a common envelope `{error_code, message, details?}`
and a status-code mapping registered on the FastAPI app.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.admin import AdminValidationError
from app.api.sessions import SSEStreamCapacityExceeded
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import AuthError
from app.db.dal import (
    CancelConflict,
    CapacityExceeded,
    EntityForbidden,
    IdempotencyKeyConflict,
    NotFoundError,
    RegenerateConflict,
    SessionConflict,
)
from app.pipeline import cascade
from app.pipeline.accept import AcceptConflict, MasterInactive
from app.pipeline.embeddings import EmbeddingBusy
from app.pipeline.llm import LLMSlotUnavailable
from app.pipeline.threat_library_import import ThreatLibraryImportError
from app.pipeline.treatment import TreatmentConflict

log = get_logger(__name__)


def _env(code: str, message: str, **details) -> dict:
    """The envelope every handler below returns, so every 4xx/5xx body has the same shape."""
    body: dict[str, Any] = {"error_code": code, "message": message}
    if details:
        body["details"] = details
    return body


async def _handle_auth_error(_: Request, exc: AuthError):
    """Bad/missing/expired credentials -> 401."""
    return JSONResponse(status_code=401, content=_env("unauthorized", str(exc)))


async def _handle_forbidden(_: Request, exc: EntityForbidden):
    """Caller is authenticated but not entitled to the target entity -> 403."""
    return JSONResponse(status_code=403, content=_env("forbidden", str(exc)))


async def _handle_library_conflict(_: Request, exc):  # exc: library_crud.LibraryConflict
    """Threat-library CRUD write would violate a master's natural-key index -> 409.

    Carries the colliding row's id so a client can PATCH the existing row instead of retrying a
    create that can never succeed. Best-effort null: the indexes cover a triple, and a
    category/sector-only clash isn't findable by name alone."""
    return JSONResponse(
        status_code=409,
        content=_env("library_conflict", str(exc), existing_id=exc.existing_id),
    )


async def _handle_session_conflict(_: Request, exc: SessionConflict):
    """Asset already has an active session -> 409, with the existing session id so the client can redirect to it instead of retrying blind."""
    return JSONResponse(
        status_code=409,
        content=_env("active_session_exists", "asset already has an active session",
                    active_session_id=exc.active_session_id),
    )


async def _handle_accept_conflict(_: Request, exc: AcceptConflict):
    """Session accept was attempted from a state that doesn't allow it -> 409. A machine-readable
    cause, when the raise site gave one, rides along as `details.reason`."""
    extra = {"reason": exc.reason} if exc.reason is not None else {}
    return JSONResponse(status_code=409, content=_env("accept_conflict", str(exc), **extra))


async def _handle_master_inactive(_: Request, exc: MasterInactive):
    """Accept was attempted against a master scenario that's no longer active -> 409."""
    return JSONResponse(status_code=409, content=_env("master_inactive", str(exc)))


async def _handle_treatment_conflict(_: Request, exc: TreatmentConflict):
    """Treatment-plan request refused -> 409, with `details.reason` (TreatmentGateReason) when
    the raise site gave one — same shape as accept_conflict."""
    extra = {"reason": exc.reason} if exc.reason is not None else {}
    return JSONResponse(status_code=409, content=_env("treatment_conflict", str(exc), **extra))


async def _handle_not_found(_: Request, exc: NotFoundError):
    """Requested entity doesn't exist (or isn't visible to this caller) -> 404, with whatever
    machine-readable payload the raise site attached as `details` (accept's partial-subset 404
    names each unacceptable OutputID and why). getattr, not exc.details: NotFoundError is raised
    from ~a dozen sites and may still arrive as a bare Exception subclass instance."""
    details = getattr(exc, "details", None)
    body = _env("not_found", str(exc))
    if details:
        body["details"] = details
    return JSONResponse(status_code=404, content=body)


async def _handle_capacity_exceeded(_: Request, exc: CapacityExceeded):
    """Session creation is throttled because the pipeline is at capacity -> 503 with a Retry-After (config-driven) so clients back off instead of hammering the endpoint."""
    retry_after = str(get_settings().capacity_retry_after_seconds)
    return JSONResponse(status_code=503, content=_env("capacity_exceeded",
                        "session creation is temporarily throttled"), headers={"Retry-After": retry_after})


async def _handle_llm_slot_unavailable(_: Request, exc: LLMSlotUnavailable):
    """Confirmed sustained over-capacity on the LLM-call concurrency limiter -> 503, same shape
    as _handle_capacity_exceeded. Only reachable from a SYNCHRONOUS caller — the Celery path
    never surfaces this, since celery_app.py's autoretry_for catches it first."""
    retry_after = str(get_settings().capacity_retry_after_seconds)
    return JSONResponse(status_code=503, content=_env("llm_slot_unavailable",
                        "no free AI-call capacity right now, try again shortly"), headers={"Retry-After": retry_after})


async def _handle_sse_capacity_exceeded(_: Request, exc: SSEStreamCapacityExceeded):
    """SSE stream count is at sse_max_concurrent_streams (item 12) -> 503 with a Retry-After
    (config-driven), same shape/setting as _handle_capacity_exceeded/_handle_llm_slot_unavailable."""
    retry_after = str(get_settings().capacity_retry_after_seconds)
    return JSONResponse(status_code=503, content=_env("sse_capacity_exceeded", str(exc)),
                        headers={"Retry-After": retry_after})


async def _handle_idempotency_conflict(_: Request, exc: IdempotencyKeyConflict):
    """Same Idempotency-Key reused with a different request body -> 409, returning the id of the session created by the original request."""
    return JSONResponse(status_code=409, content=_env(
        "idempotency_key_conflict", "Idempotency-Key already used with a different request body",
        existing_session_id=exc.existing_session_id))


async def _handle_regenerate_conflict(_: Request, exc: RegenerateConflict):
    """Regenerate was requested while the session isn't in a regenerable state -> 409, with
    `details.reason` when the raise site gave one. A reason cascade._REASON_INFO recognizes also
    gets `details.detail` (log-facing) and `details.message` (safe to show the end user) — same
    shape as the matching SSE events. Reasons with no entry there are unaffected.

    Built by hand rather than via _env's **details splat: _reason_info's own "message" key would
    collide with _env's positional `message` parameter."""
    details: dict[str, Any] = {"reason": exc.reason} if exc.reason is not None else {}
    details.update({k: v for k, v in cascade._reason_info(exc.reason).items() if v is not None})
    body = _env("regenerate_conflict", str(exc))
    if details:
        body["details"] = details
    return JSONResponse(status_code=409, content=body)


async def _handle_cancel_conflict(_: Request, exc: CancelConflict):
    """Cancel was requested against a session that's already terminal -> 409."""
    return JSONResponse(status_code=409, content=_env("cancel_conflict", str(exc)))


async def _handle_embedding_busy(_: Request, exc: EmbeddingBusy):
    """A concurrent admin recreate/delete already holds this embedding group's lock -> 409."""
    return JSONResponse(status_code=409, content=_env("embedding_busy", str(exc)))


async def _handle_admin_validation_error(_: Request, exc: AdminValidationError):
    """A structurally-valid but business-rule-invalid admin embedding request -> 422."""
    return JSONResponse(status_code=422, content=_env("admin_validation_error", str(exc)))


async def _handle_threat_library_import_error(_: Request, exc: ThreatLibraryImportError):
    """A structurally-valid but business-rule-invalid threat-library import request
    (unknown source, bad via_taxii combo, oversized/unparseable/mismatched file
    content) -> 422 — one error class, one status code (see app/api/threat_library_import.py)."""
    return JSONResponse(status_code=422, content=_env("threat_library_import_error", str(exc)))


async def _handle_validation_error(_: Request, exc: RequestValidationError):
    """FastAPI/Pydantic request validation failure -> 422 in the [R9] envelope.

    `ctx` is dropped: `exc.errors()` embeds a raw exception instance under `ctx.error` whenever a
    custom `@field_validator` raises ValueError — not JSON-serializable, so passing errors
    through raw 500s on exactly the custom-validator errors this handler exists to report. `msg`
    already repeats the content."""
    errors = [{k: v for k, v in e.items() if k != "ctx"} for e in exc.errors()]
    return JSONResponse(status_code=422, content=_env("validation_error", "request validation failed",
                                                    errors=errors))


async def _handle_unhandled_exception(request: Request, exc: Exception):
    """Catch-all -> 500; always logs the traceback, echoes the exception text only in local/dev.

    request_id comes from `request.state`, not contextvars: Starlette routes the bare-`Exception`
    handler through ServerErrorMiddleware, which sits OUTSIDE RequestIDMiddleware, whose
    `finally` has already cleared the contextvar by the time this runs. Echoed on the response
    header so a client-reported 500 can be grepped straight to its crash log."""
    request_id = getattr(request.state, "request_id", None)
    log.error("unhandled_exception", path=str(request.url), request_id=request_id, exc_info=True)
    s = get_settings()
    detail = str(exc) if s.app_env in ("local", "dev") else "an unexpected error occurred"
    headers = {"X-Request-Id": request_id} if request_id else None
    return JSONResponse(status_code=500, content=_env("internal_error", detail), headers=headers)


def register_error_handlers(app: FastAPI) -> None:
    """Wire every domain exception raised by the pipeline/dal layers to its [R9] status code and envelope; call once at app startup so callers never have to catch these individually."""
    app.exception_handler(AuthError)(_handle_auth_error)
    app.exception_handler(EntityForbidden)(_handle_forbidden)
    app.exception_handler(SessionConflict)(_handle_session_conflict)
    app.exception_handler(AcceptConflict)(_handle_accept_conflict)
    app.exception_handler(MasterInactive)(_handle_master_inactive)
    app.exception_handler(TreatmentConflict)(_handle_treatment_conflict)
    app.exception_handler(NotFoundError)(_handle_not_found)
    app.exception_handler(CapacityExceeded)(_handle_capacity_exceeded)
    app.exception_handler(LLMSlotUnavailable)(_handle_llm_slot_unavailable)
    app.exception_handler(SSEStreamCapacityExceeded)(_handle_sse_capacity_exceeded)
    app.exception_handler(IdempotencyKeyConflict)(_handle_idempotency_conflict)
    app.exception_handler(RegenerateConflict)(_handle_regenerate_conflict)
    app.exception_handler(CancelConflict)(_handle_cancel_conflict)
    app.exception_handler(EmbeddingBusy)(_handle_embedding_busy)
    app.exception_handler(AdminValidationError)(_handle_admin_validation_error)
    app.exception_handler(ThreatLibraryImportError)(_handle_threat_library_import_error)
    # Imported here, not at module scope: library_crud imports admin.py, which would make
    # an errors.py -> crud -> admin -> errors cycle at import time.
    from app.api.library_crud import LibraryConflict
    app.exception_handler(LibraryConflict)(_handle_library_conflict)
    app.exception_handler(RequestValidationError)(_handle_validation_error)
    app.exception_handler(Exception)(_handle_unhandled_exception)
