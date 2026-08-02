"""Gevent worker bootstrap — the real `-A` target for `celery worker` (NOT `beat`, NOT imported
by the API or anywhere else).

Patches BEFORE `celery_app` and everything it transitively pulls in (pyodbc, litellm's httpx
client, redis-py, pymongo). Kept out of `celery_app.py` because that module is shared with
processes that must NOT be patched: the FastAPI app and `celery beat`, both on asyncio. gevent's
monkey-patch rewrites `select`/`socket` process-wide, which hangs every request there.

A pyodbc query blocking under gevent freezes the WHOLE worker, including the greenlet that would
release whatever lock it waits on. That is why tasks.py commits immediately after each
claim_stage succeeds, before the LLM call — leaving the row lock open across the call gave the
reaper's targeted UPDATE a lock only that greenlet could release.

Residual, deliberate gap: pyodbc is a C extension talking to the ODBC driver manager directly, so
gevent can NEVER make it cooperative. ponytail: if a genuinely slow query is ever observed to
stall the worker, mirror local_models.py's `_offload` threadpool pattern in dal.py.
"""
from __future__ import annotations

import sys


# must run before any other import, or the patch lands too late
if "pytest" not in sys.modules:
    from gevent import monkey  # type: ignore[import]
    monkey.patch_all()

from app.pipeline.celery_app import celery_app  # noqa: E402 -- must import after patching

__all__ = ["celery_app"]