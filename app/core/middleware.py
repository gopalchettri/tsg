""" gives every incoming web request a traceable ID and a
one-line record of what happened — so a slow or silently-failed request can
be found in the logs afterward, instead of leaving no trail at all.

[REVIEW-FIX] this app previously had zero HTTP-level logging (only exceptions were
logged, with no request ID) and structlog's own contextvars processor (logging.py)
was wired in but nothing ever called bind_contextvars — inert scaffolding. This
closes both gaps in one small ASGI middleware, kept in its own file rather than
growing main.py.

[REVIEW-FIX] request_id is ALSO stashed on request.state (not just contextvars): Starlette
pulls the catch-all `Exception` handler out onto its outermost ServerErrorMiddleware, which
wraps this middleware — so on an unhandled exception, the `finally` below clears contextvars
during unwind, before that outer handler (app/api/errors.py::_handle_unhandled_exception) ever
runs. request.state survives that unwind (it's the same Request object, not a contextvar), so
the handler reads request_id from there instead of trusting contextvars to still be bound.
"""
from __future__ import annotations

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.logging import get_logger

log = get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Accepts an inbound `X-Request-Id` header or generates one, binds it into every
    structlog line emitted for the rest of this request (via contextvars), logs a start
    line and an end line (status + duration), and echoes the ID back on the response.
    Not threaded into Celery task kwargs yet — the pipeline's own session_id-scoped
    logging already covers the background-work side; this closes the HTTP-request side."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = request_id  # survives past this middleware's own unwind — see module docstring
        structlog.contextvars.bind_contextvars(request_id=request_id)
        start = time.monotonic()
        try:
            log.info("http.request_started", method=request.method, path=request.url.path)
            try:
                response = await call_next(request)
            except Exception:
                log.warning("http.request_failed", method=request.method, path=request.url.path,
                            duration_ms=round((time.monotonic() - start) * 1000, 1))
                raise
            log.info("http.request_finished", method=request.method, path=request.url.path,
                    status_code=response.status_code,
                    duration_ms=round((time.monotonic() - start) * 1000, 1))
            response.headers["X-Request-Id"] = request_id
            return response
        finally:
            # Always clears, whether the request succeeded, failed, or raised — a leaked
            # binding would otherwise leak this request's ID into the NEXT request handled
            # by the same worker/greenlet.
            structlog.contextvars.clear_contextvars()
