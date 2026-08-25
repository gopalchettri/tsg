"""Structured logging (structlog) — configured once per process (API lifespan +
Celery worker init). JSON output so logs are queryable in production.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

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
    handlers: list[logging.Handler] = [handler]
    # TSG_LOG_FILE: tee every line into app-<pid>.jsonl for Promtail -> Loki.
    #
    # It has to be done at the FACTORY, not as a processor. A processor appended after
    # JSONRenderer never runs (the renderer returns a str and terminates the chain), and even
    # wrapped it would only see structlog-native events — foreign records from uvicorn/
    # sqlalchemy/pyodbc arrive through the ProcessorFormatter on the root handler above and
    # never enter that chain at all. PrintLogger writes its already-rendered line to whatever
    # file object it is given, so a tee catches every app line, and the same rotating handler on
    # `root` catches the foreign half.
    #
    # This MUST happen inside configure_logging and be right at import time (see the call at the
    # bottom of this module): cache_logger_on_first_use=True plus module-level
    # `log = get_logger(__name__)` means any logger bound before a later re-call keeps the OLD
    # factory, so a lifespan/worker re-call cannot retrofit the tee onto them.
    stream: Any = sys.stdout
    if get_settings().log_file:
        from app.core.tracing import open_rotating_writer  # local: tracing imports config, not us
        file_logger = open_rotating_writer("app-{pid}.jsonl")
        handlers.append(file_logger.handlers[0])
        stream = _Tee(sys.stdout, file_logger)
    root.handlers = handlers  # replace, not add — configure_logging is safely re-callable
    root.setLevel(level)
    structlog.configure(
        processors=[*shared_processors, structlog.processors.format_exc_info, structlog.processors.JSONRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=stream),
        cache_logger_on_first_use=True,
    )


class _Tee:
    """Minimal file-like object: everything structlog prints goes to stdout AND to the rotating
    file logger. Only write/flush are used by structlog's PrintLogger.

    The file half receives the line with its trailing newline stripped — the handler adds its own
    terminator, and without stripping every JSON object would be followed by a blank line, which
    Promtail would ship to Loki as an empty entry."""

    # __weakref__ is REQUIRED, not incidental: structlog's PrintLogger registers its file object
    # in a WeakValueDictionary to share a write lock per file (structlog/_output.py), and a
    # __slots__ class without it cannot be weakly referenced — get_logger() then dies with
    # "cannot create weak reference" the moment the tee is installed.
    __slots__ = ("__weakref__", "_logger", "_stdout")

    def __init__(self, stdout: Any, file_logger: logging.Logger) -> None:
        self._stdout, self._logger = stdout, file_logger

    def write(self, text: str) -> int:
        written = self._stdout.write(text)
        line = text.rstrip("\n")
        if line:
            self._logger.info(line)
        return written

    def flush(self) -> None:
        self._stdout.flush()


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
