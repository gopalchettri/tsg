"""Gives every incoming request a traceable ID and a one-line record of what happened.

request_id is stashed on request.state as well as contextvars: Starlette's catch-all
`Exception` handler lives on the outermost ServerErrorMiddleware, which wraps this one, so the
`finally` below clears contextvars during unwind BEFORE that handler
(app/api/errors.py::_handle_unhandled_exception) runs. request.state survives the unwind.
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

    The import route's own cap cannot replace this: FastAPI buffers and `json.loads` the whole
    body on the event loop before dependencies resolve — i.e. before `require_admin` runs — so
    an unauthenticated caller could stall the loop for every other request on that worker.

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
    Not threaded into Celery task kwargs — background work is scoped by session_id instead."""

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
            if response.headers.get("content-type", "").startswith("text/event-stream"):
                # response.media_type is always None here: BaseHTTPMiddleware's call_next() wraps
                # the real response in a plain StreamingResponse, which never carries the original
                # media_type through — the content-type HEADER is the only place the value
                # survives. call_next() returns as soon as headers are available, long before a
                # long-lived SSE body is closed, so a duration measured here would be a misleading
                # near-zero. Log that the stream started, not a false "finished" duration.
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
            # Unconditional: a leaked binding would carry this request's ID into the NEXT
            # request handled by the same worker/greenlet.
            structlog.contextvars.clear_contextvars()
