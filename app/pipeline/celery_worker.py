""" this is the file Celery actually runs when we start a
`celery worker` — it switches the process into "handle many things at once"
mode BEFORE anything else loads, then hands off to the real worker setup.

Gevent worker bootstrap — the real `-A` target for `celery worker` (NOT `beat`,
NOT imported by the API or anywhere else).

Patches BEFORE `celery_app` — and everything it transitively pulls in (pyodbc,
litellm's httpx client, redis-py, pymongo) — is imported. Split out of
`celery_app.py` because that module is shared with processes that must NOT be
patched: the FastAPI app (imports `run_pipeline_task`/`regenerate_task` to call
`.delay()`) and `celery beat` (a single-purpose scheduler, no gevent pool), both of
which run on asyncio — gevent's monkey-patch rewrites `select`/`socket` at the
process level, and doing that inside an asyncio process broke every request
(`POST /v1/sessions` hung indefinitely) when the patch briefly lived in the shared
module instead of here.

A second, related freeze was found and fixed after this patch landed: `claim_stage`'s
row lock (in tasks.find_threats/write_scenarios) used to stay open
across the LLM call that followed it, because the caller's only commit came after
the whole stage returned — so any other pyodbc query touching that same row (the
reaper's own targeted UPDATE, if a stage ever ran past its lease) could block-wait
on a lock only that stage's own greenlet could release, freezing the whole worker
the same way. Fixed by committing right after each claim_stage succeeds, before
the LLM call — see the comment there.

Residual, deliberate gap: pyodbc is a C extension that talks to the ODBC driver
manager directly, never through Python's socket module — gevent can NEVER make it
cooperative, patched or not. The routine case above is now closed; a genuinely slow
query could still in principle stall the worker for its own duration. ponytail: if
that's ever observed, mirror local_models.py's `_offload` threadpool pattern in dal.py.
"""
from __future__ import annotations

import sys


#  turn on gevent's "many tasks at once" mode now, before any
# other file gets imported and locks in the normal (patched-too-late) behavior.
if "pytest" not in sys.modules:
    from gevent import monkey  # type: ignore[import]
    monkey.patch_all()

from app.pipeline.celery_app import celery_app  # noqa: E402 -- must import after patching

__all__ = ["celery_app"]