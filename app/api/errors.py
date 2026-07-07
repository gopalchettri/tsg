"""Error contract ([R9]) — a common envelope `{error_code, message, details?}`
and a status-code mapping registered on the FastAPI app.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import AuthError
from app.db.dal import (
    CapacityExceeded, EntityForbidden, IdempotencyKeyConflict, NotFoundError, RegenerateConflict, SessionConflict,
)
from app.pipeline.accept import AcceptConflict, MasterInactive

log = get_logger(__name__)


def _env(code: str, message: str, **details) -> dict:
    """Build the [R9] error envelope every handler below returns, so every 4xx/5xx body has the same `{error_code, message, details?}` shape regardless of which exception raised it."""
    body = {"error_code": code, "message": message}
    if details:
        body["details"] = details
    return body


def register_error_handlers(app: FastAPI) -> None:
    """Wire every domain exception raised by the pipeline/dal layers to its [R9] status code and envelope; call once at app startup so callers never have to catch these individually."""
    @app.exception_handler(AuthError)
    async def _auth(_: Request, exc: AuthError):
        """Bad/missing/expired credentials -> 401."""
        return JSONResponse(status_code=401, content=_env("unauthorized", str(exc)))

    @app.exception_handler(EntityForbidden)
    async def _forbidden(_: Request, exc: EntityForbidden):
        """Caller is authenticated but not entitled to the target entity -> 403."""
        return JSONResponse(status_code=403, content=_env("forbidden", str(exc)))

    @app.exception_handler(SessionConflict)
    async def _conflict(_: Request, exc: SessionConflict):
        """Asset already has an active session -> 409, with the existing session id so the client can redirect to it instead of retrying blind."""
        return JSONResponse(
            status_code=409,
            content=_env("active_session_exists", "asset already has an active session",
                         active_session_id=exc.active_session_id),
        )

    @app.exception_handler(AcceptConflict)
    async def _accept_conflict(_: Request, exc: AcceptConflict):
        """Session accept was attempted from a state that doesn't allow it -> 409."""
        return JSONResponse(status_code=409, content=_env("accept_conflict", str(exc)))

    @app.exception_handler(MasterInactive)
    async def _master_inactive(_: Request, exc: MasterInactive):
        """Accept was attempted against a master scenario that's no longer active -> 409."""
        return JSONResponse(status_code=409, content=_env("master_inactive", str(exc)))

    @app.exception_handler(NotFoundError)
    async def _not_found(_: Request, exc: NotFoundError):
        """Requested entity doesn't exist (or isn't visible to this caller) -> 404."""
        return JSONResponse(status_code=404, content=_env("not_found", str(exc)))

    @app.exception_handler(CapacityExceeded)
    async def _capacity(_: Request, exc: CapacityExceeded):
        """Session creation is throttled because the pipeline is at capacity -> 503 with a Retry-After (config-driven) so clients back off instead of hammering the endpoint."""
        retry_after = str(get_settings().capacity_retry_after_seconds)
        return JSONResponse(status_code=503, content=_env("capacity_exceeded",
                            "session creation is temporarily throttled"), headers={"Retry-After": retry_after})

    @app.exception_handler(IdempotencyKeyConflict)
    async def _idem_conflict(_: Request, exc: IdempotencyKeyConflict):
        """Same Idempotency-Key reused with a different request body -> 409, returning the id of the session created by the original request."""
        return JSONResponse(status_code=409, content=_env(
            "idempotency_key_conflict", "Idempotency-Key already used with a different request body",
            existing_session_id=exc.existing_session_id))

    @app.exception_handler(RegenerateConflict)
    async def _regen_conflict(_: Request, exc: RegenerateConflict):
        """Regenerate was requested while the session isn't in a regenerable state -> 409."""
        return JSONResponse(status_code=409, content=_env("regenerate_conflict", str(exc)))

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        """FastAPI/Pydantic request validation failure -> 422, wrapped in the [R9] envelope instead of FastAPI's default shape so error responses stay consistent across the API.

        `exc.errors()` can embed a raw exception instance under `ctx.error` whenever a
        custom `@field_validator` raises `ValueError` — not JSON-serializable, so
        `errors=exc.errors()` raw would 500 instead of 422 on exactly the custom-validator
        errors this handler exists to report. Dropping `ctx` (the message text already
        repeats its content in `msg`) fixes this for every current AND future
        field_validator, not just one call site."""
        errors = [{k: v for k, v in e.items() if k != "ctx"} for e in exc.errors()]
        return JSONResponse(status_code=422, content=_env("validation_error", "request validation failed",
                                                           errors=errors))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        """Catch-all safety net -> 500; logs the full traceback always, but only echoes the exception message back to the client in local/dev to avoid leaking internals in production."""
        log.error("unhandled_exception", path=str(request.url), exc_info=True)
        s = get_settings()
        detail = str(exc) if s.app_env in ("local", "dev") else "an unexpected error occurred"
        return JSONResponse(status_code=500, content=_env("internal_error", detail))
