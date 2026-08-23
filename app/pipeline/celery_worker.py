"""Gevent worker bootstrap — the `-A` target for `celery worker` only (NOT `beat`, NOT the API).

Patches before `celery_app` and its transitive imports (pyodbc, httpx, redis-py, pymongo). Kept
out of `celery_app.py`, which the FastAPI app and `celery beat` also import: the patch rewrites
`select`/`socket` process-wide and hangs every request on asyncio.

A blocking pyodbc query freezes the WHOLE worker, including the greenlet holding the lock it
waits on — hence tasks.py commits immediately after claim_stage, before the LLM call.
ponytail: pyodbc is a C extension gevent can never make cooperative; if a slow query is ever
observed to stall the worker, mirror local_models.py's `_offload` threadpool in dal.py.
"""
from __future__ import annotations

import sys

# must run before any other import, or the patch lands too late
if "pytest" not in sys.modules:
    from gevent import monkey  # type: ignore[import]
    monkey.patch_all()

from app.pipeline.celery_app import celery_app

__all__ = ["celery_app"]
