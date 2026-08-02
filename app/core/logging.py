"""Structured logging (structlog) — configured once per process (API lifespan +
Celery worker init). JSON output so logs are queryable in production.
"""
from __future__ import annotations

import logging

import structlog

from app.core.config import get_settings


def configure_logging(level: int | None = None) -> None:
    """Wire structlog's processor chain to stdlib logging and set JSON output. `level`
    defaults to the `LOG_LEVEL` setting. Idempotent — safe to call again from the FastAPI
    lifespan or the Celery worker_process_init signal.
    """
    if level is None:
        level = getattr(logging, get_settings().log_level)
    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]
    # Bridges stdlib-originated records (uvicorn, sqlalchemy, pyodbc, httpx — anything using
    # logging.getLogger()) into the same JSON pipeline. structlog itself uses PrintLoggerFactory
    # and bypasses stdlib logging entirely, so without this handler those foreign records emit
    # bare "%(message)s" with no timestamp/level/JSON envelope.
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
        processors=[*shared_processors, structlog.processors.format_exc_info, structlog.processors.JSONRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "tsg"):
    """Bound structlog logger for the given name — use this, not `logging.getLogger`.

    `name` is bound as a context value on purpose. `structlog.get_logger(name)` silently drops
    it under `PrintLoggerFactory`, and `structlog.stdlib.add_logger_name` (the usual fix) reads
    `logger.name`, which `PrintLogger` lacks — it AttributeErrors on every log call.
    """
    return structlog.get_logger().bind(logger=name)


# Configure eagerly at import time; the explicit lifespan/worker_process_init calls are
# harmless re-configuration. worker_process_init is prefork-only and never fires under the
# gevent pool this service runs, so without this line worker logs fall back to structlog's
# default ConsoleRenderer — which renders exc_info via rich+pygments at 10+ seconds per
# exception on a real ASGI stack trace, making error handling itself the bottleneck.
configure_logging()
