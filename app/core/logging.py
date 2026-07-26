"""Structured logging (structlog) — configured once per process (API lifespan +
Celery worker init). JSON output so logs are queryable in production (SDD §13).
"""
from __future__ import annotations

import logging

import structlog

from app.core.config import get_settings


def configure_logging(level: int | None = None) -> None:
    """Wire structlog's processor chain to stdlib logging and set JSON output (SDD §13).
    `level` defaults to the `LOG_LEVEL` setting (DEBUG for local troubleshooting,
    INFO/WARNING to keep production logs lean) when not passed explicitly.

    Idempotent — safe to call again from the FastAPI lifespan or the Celery
    worker_process_init signal without corrupting already-emitted log state.
    """
    if level is None:
        # No explicit level given, so convert the LOG_LEVEL setting (a string like
        # "DEBUG") into the numeric level the stdlib logging module expects.
        level = getattr(logging, get_settings().log_level)
    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]
    # Bridge stdlib-originated records (uvicorn, sqlalchemy, pyodbc, redis-py, httpx, etc. — any
    # library using plain logging.getLogger(), not structlog) into the SAME JSON pipeline
    # structlog's own calls use below. structlog itself uses PrintLoggerFactory (bypasses stdlib
    # logging entirely via a bare print()), so this handler only ever sees foreign/stdlib records —
    # without it, those records only ever got logging.basicConfig's bare "%(message)s" formatter,
    # with no timestamp/level/JSON envelope, invisible to any log pipeline expecting one JSON
    # object per line (this module's own stated goal).
    handler = logging.StreamHandler()
    handler.setFormatter(structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    ))
    root = logging.getLogger()
    root.handlers = [handler]  # replace, not add — configure_logging is safely re-callable
    root.setLevel(level)
    structlog.configure(
        # Processors run top to bottom: merge context vars in, tag the log level,
        # add a timestamp, render stack/exception info, then serialize to JSON last.
        processors=[*shared_processors, structlog.processors.format_exc_info, structlog.processors.JSONRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "tsg"):
    """Bound structlog logger for the given name — the one import every module in
    this service should use instead of `logging.getLogger` directly.

    [REVIEW-FIX] `structlog.get_logger(name)` alone silently drops `name` — this codebase's
    `PrintLoggerFactory` ignores the args passed to it (unlike `structlog.stdlib.LoggerFactory`,
    which ties `name` to a real `logging.Logger`), so every log line looked identical regardless
    of which module emitted it. `structlog.stdlib.add_logger_name` (the usual fix) is NOT the
    answer here — it reads `logger.name` off the wrapped logger object, which `PrintLogger` does
    not have, and crashes every log call with AttributeError (verified directly). Binding `name`
    as a normal context value works with any logger factory and needs no processor-chain change.
    """
    return structlog.get_logger().bind(logger=name)


# Configure eagerly at import time — logging correctness/speed must never depend on
# an optional lifecycle hook firing. `configure_logging()` is ALSO called explicitly
# from the FastAPI lifespan and the Celery worker_process_init signal (harmless
# re-configuration), but that signal is prefork-only and never fires under the
# gevent pool this service actually runs — without this import-time call, every
# worker log (including exception logs) would silently fall back to structlog's
# default `ConsoleRenderer`, which renders `exc_info=True` via `rich`+`pygments`
# syntax highlighting — measured at 10+ seconds per exception on a real ASGI/anyio
# stack trace. That's not just slow logging; under real error load it turns
# exception handling itself into the bottleneck.
configure_logging()
