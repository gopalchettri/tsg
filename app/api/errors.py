"""Error contract  — a common envelope `{error_code, message, details?}`
and a status-code mapping registered on the FastAPI app.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import AuthError
from app.db.dal import (
    CancelConflict, CapacityExceeded, EntityForbidden, IdempotencyKeyConflict, NotFoundError,
    RegenerateConflict, SessionConflict,
)
from app.pipeline.accept import AcceptConflict, MasterInactive

log = get_logger(__name__)


def _env(code: str, message: str, **details) -> dict:
    """Build the error envelope every handler below returns, so every 4xx/5xx body has the same `{error_code, message, details?}` shape regardless of which exception raised it."""
    body: dict[str, Any] = {"error_code": code, "message": message}
    # Only add the "details" key when there's actually extra data to show,
    # so simple errors don't get an empty details field in the response.
    if details:
        body["details"] = details
    return body


async def _handle_auth_error(_: Request, exc: AuthError):
    """Bad/missing/expired credentials -> 401."""
    return JSONResponse(status_code=401, content=_env("unauthorized", str(exc)))


async def _handle_forbidden(_: Request, exc: EntityForbidden):
    """Caller is authenticated but not entitled to the target entity -> 403."""
    return JSONResponse(status_code=403, content=_env("forbidden", str(exc)))


async def _handle_session_conflict(_: Request, exc: SessionConflict):
    """Asset already has an active session -> 409, with the existing session id so the client can redirect to it instead of retrying blind."""
    return JSONResponse(
        status_code=409,
        content=_env("active_session_exists", "asset already has an active session",
                    active_session_id=exc.active_session_id),
    )


async def _handle_accept_conflict(_: Request, exc: AcceptConflict):
    """Session accept was attempted from a state that doesn't allow it -> 409."""
    return JSONResponse(status_code=409, content=_env("accept_conflict", str(exc)))


async def _handle_master_inactive(_: Request, exc: MasterInactive):
    """Accept was attempted against a master scenario that's no longer active -> 409."""
    return JSONResponse(status_code=409, content=_env("master_inactive", str(exc)))


async def _handle_not_found(_: Request, exc: NotFoundError):
    """Requested entity doesn't exist (or isn't visible to this caller) -> 404."""
    return JSONResponse(status_code=404, content=_env("not_found", str(exc)))


async def _handle_capacity_exceeded(_: Request, exc: CapacityExceeded):
    """Session creation is throttled because the pipeline is at capacity -> 503 with a Retry-After (config-driven) so clients back off instead of hammering the endpoint."""
    retry_after = str(get_settings().capacity_retry_after_seconds)
    return JSONResponse(status_code=503, content=_env("capacity_exceeded",
                        "session creation is temporarily throttled"), headers={"Retry-After": retry_after})


async def _handle_idempotency_conflict(_: Request, exc: IdempotencyKeyConflict):
    """Same Idempotency-Key reused with a different request body -> 409, returning the id of the session created by the original request."""
    return JSONResponse(status_code=409, content=_env(
        "idempotency_key_conflict", "Idempotency-Key already used with a different request body",
        existing_session_id=exc.existing_session_id))


async def _handle_regenerate_conflict(_: Request, exc: RegenerateConflict):
    """Regenerate was requested while the session isn't in a regenerable state -> 409."""
    return JSONResponse(status_code=409, content=_env("regenerate_conflict", str(exc)))


async def _handle_cancel_conflict(_: Request, exc: CancelConflict):
    """Cancel was requested against a session that's already terminal -> 409."""
    return JSONResponse(status_code=409, content=_env("cancel_conflict", str(exc)))


async def _handle_validation_error(_: Request, exc: RequestValidationError):
    """FastAPI/Pydantic request validation failure -> 422, wrapped in the [R9] envelope instead of FastAPI's default shape so error responses stay consistent across the API.

    `exc.errors()` can embed a raw exception instance under `ctx.error` whenever a
    custom `@field_validator` raises `ValueError` — not JSON-serializable, so
    `errors=exc.errors()` raw would 500 instead of 422 on exactly the custom-validator
    errors this handler exists to report. Dropping `ctx` (the message text already
    repeats its content in `msg`) fixes this for every current AND future
    field_validator, not just one call site."""
    # In plain terms: copy each validation error but drop its "ctx" field,
    # because "ctx" can hold a raw Python exception object that JSON can't encode.
    errors = [{k: v for k, v in e.items() if k != "ctx"} for e in exc.errors()]
    return JSONResponse(status_code=422, content=_env("validation_error", "request validation failed",
                                                    errors=errors))


async def _handle_unhandled_exception(request: Request, exc: Exception):
    """Catch-all safety net -> 500; logs the full traceback always, but only echoes the exception message back to the client in local/dev to avoid leaking internals in production."""
    log.error("unhandled_exception", path=str(request.url), exc_info=True)
    s = get_settings()
    # Show the real exception text only in local/dev; in other environments
    # (e.g. production) return a generic message so internals aren't exposed.
    detail = str(exc) if s.app_env in ("local", "dev") else "an unexpected error occurred"
    return JSONResponse(status_code=500, content=_env("internal_error", detail))


def register_error_handlers(app: FastAPI) -> None:
    """Wire every domain exception raised by the pipeline/dal layers to its [R9] status code and envelope; call once at app startup so callers never have to catch these individually."""
    app.exception_handler(AuthError)(_handle_auth_error)
    app.exception_handler(EntityForbidden)(_handle_forbidden)
    app.exception_handler(SessionConflict)(_handle_session_conflict)
    app.exception_handler(AcceptConflict)(_handle_accept_conflict)
    app.exception_handler(MasterInactive)(_handle_master_inactive)
    app.exception_handler(NotFoundError)(_handle_not_found)
    app.exception_handler(CapacityExceeded)(_handle_capacity_exceeded)
    app.exception_handler(IdempotencyKeyConflict)(_handle_idempotency_conflict)
    app.exception_handler(RegenerateConflict)(_handle_regenerate_conflict)
    app.exception_handler(CancelConflict)(_handle_cancel_conflict)
    app.exception_handler(RequestValidationError)(_handle_validation_error)
    app.exception_handler(Exception)(_handle_unhandled_exception)
