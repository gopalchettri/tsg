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
from starlette.responses import JSONResponse

from app.core.logging import get_logger

log = get_logger(__name__)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects an over-sized request body from the Content-Length header, BEFORE anything reads
    or parses it.

    [REVIEW-FIX] the threat-library import route enforces its own upload cap inside the handler —
    but by then FastAPI has already buffered the whole body and run `json.loads` on it, on the
    event loop, and that happens BEFORE dependencies resolve, i.e. before `require_admin` has
    checked the admin key. So an UNAUTHENTICATED caller could make the server parse an arbitrarily
    large JSON document and stall the loop for every other request on that worker. A per-route
    check cannot fix that: by the time route code runs, the cost is already paid. The guard has to
    sit in front of the body read, which is what this middleware is.

    ponytail: Content-Length only — a chunked upload declares no length, so it still reaches the
    handler's own cap. Add a streaming byte-counter if chunked uploads ever become a real path."""

    async def dispatch(self, request: Request, call_next):
        from app.core.config import get_settings

        declared = request.headers.get("content-length")
        if declared and declared.isdigit():
            cap_bytes = get_settings().threat_library_import_max_upload_mb * 1024 * 1024
            if int(declared) > cap_bytes:
                log.warning("http.body_too_large", path=request.url.path, declared=int(declared),
                            cap_bytes=cap_bytes)
                return JSONResponse(
                    status_code=413,
                    content={"error_code": "payload_too_large",
                            "message": f"request body exceeds the {cap_bytes} byte limit "
                                        "(threat_library_import_max_upload_mb)"})
        return await call_next(request)


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
            if response.media_type == "text/event-stream":
                # A long-lived SSE connection (GET /sessions/{id}/events) — BaseHTTPMiddleware's
                # call_next() returns as soon as headers are available, well before the stream's
                # body is actually sent/closed (it can stay open for minutes/hours), so a duration
                # measured HERE would be near-zero and misleading — a healthy-looking instant
                # request instead of the real, much longer, connection lifetime. Log that the
                # stream started, not a false "finished" duration.
                # ponytail: real close-time tracking would need to wrap the ASGI __call__ that
                # actually sends the stream — EventSourceResponse implements its own __call__
                # rather than StreamingResponse's body_iterator, so BaseHTTPMiddleware can't hook
                # it cheaply; add if SSE-duration observability is ever actually needed.
                log.info("http.stream_started", method=request.method, path=request.url.path,
                        status_code=response.status_code)
                response.headers["X-Request-Id"] = request_id
                return response
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
