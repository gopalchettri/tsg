"""Shared SSE-streaming machinery for admin job-status routes (embeddings, grounding
calibration, threat-intel feed-refresh).

Each admin router keeps its own `job_events` endpoint — the auth dependency, URL path, and
docstring are legitimately per-router — but the streaming mechanics underneath (authorize via
the job's family marker, gate on the shared SSE concurrency cap, snapshot AsyncResult on
connect, subscribe to the job's own bus channel, and fall back to a tick-based AsyncResult
re-check so the stream still closes if a publish is ever lost) are identical across all three.
Factored here after the SAME defensive-guard bug (an unrecognized bus-published `state` value
raising uncaught inside the stream) was independently copy-pasted into two more endpoints, and
a SEPARATE bug (the authorization check blocking the asyncio event loop, unlike every other I/O
call in the same function) was copy-pasted into all three, including the original. One shared
implementation is the only way either bug class can't recur a fourth time.

API-layer only — deliberately NOT added to admin_jobs.py, which stays dependency-light
(redis + settings + logging only) so celery_app.py, a Celery worker module, can import it
without pulling FastAPI/sse_starlette into the worker process.
"""
from __future__ import annotations

import json
from collections.abc import Callable

from celery.result import AsyncResult
from sse_starlette.event import ServerSentEvent
from sse_starlette.sse import EventSourceResponse
from starlette.concurrency import run_in_threadpool

from app.api.admin_jobs import admin_job_exists
from app.core.config import get_settings
from app.core.enums import CeleryJobState, SSEEventType
from app.db import dal
from app.db.dal import NotFoundError
from app.pipeline.celery_app import celery_app
from app.sse import bus


def _default_extend(result: AsyncResult) -> dict:
    """Covers 2 of 3 current job types (embeddings, grounding): both return a plain dict from
    the task, spread verbatim into the terminal event — same shape their GET status route
    already returns. A job type whose result isn't naturally a dict (intel's bare item count)
    passes its own `extend_terminal` instead of forcing an unnatural shape here."""
    return dict(result.result) if isinstance(result.result, dict) else {}


async def admin_job_event_stream(
    job_id: str, family: str, channel_key: Callable[[str], str], event_type: str,
    *, extend_terminal: Callable[[AsyncResult], dict] = _default_extend,
) -> EventSourceResponse:
    """Build the SSE response for one admin job's event channel.

    `family`/`channel_key` pick which job type this is (FAMILY_EMBEDDINGS/emb_job_channel_key,
    etc.); `event_type` is the SSEEventType value published under the wire `"type"` field.
    `extend_terminal` maps a SUCCESS AsyncResult to the extra fields merged into that terminal
    event — defaults to spreading a dict result; callers whose result isn't a dict (intel)
    override it.

    The 404 check runs in a threadpool — it is a blocking Redis call, and unlike a `def` route
    (which Starlette runs off the event loop automatically), this is `async def` further up the
    stack, so every blocking call in it must be explicitly handed off or it stalls every other
    request this event loop is serving for the round-trip. `sessions.py::session_events` wraps
    its equivalent authorization step (`_load_events_board`) in `run_in_threadpool` for the same
    reason — this matches that established pattern instead of quietly diverging from it."""
    # Function-level import: sessions.py is a sibling router — pulling it at module import time
    # would make this module's import order depend on the whole sessions module tree.
    from app.api.sessions import SSEStreamCapacityExceeded, _sse_semaphore

    if not await run_in_threadpool(admin_job_exists, job_id, family):
        raise NotFoundError(f"unknown or expired job_id: {job_id!r}")
    settings = get_settings()
    # Shared cap across every SSE route in this process: bus._subscriber_pool is sized to
    # sse_max_concurrent_streams TOTAL, not per route.
    sem = _sse_semaphore()
    if sem.locked():
        raise SSEStreamCapacityExceeded(
            f"at the {settings.sse_max_concurrent_streams}-stream SSE concurrency cap")
    await sem.acquire()

    def _state_event() -> tuple[CeleryJobState, dict]:
        """BLOCKING result-backend read — only ever called via run_in_threadpool below."""
        result = AsyncResult(job_id, app=celery_app)
        state = CeleryJobState(result.state)
        ev: dict = {"type": event_type, "job_id": job_id, "state": str(state)}
        if state is CeleryJobState.FAILURE:
            ev["error"] = str(result.result)
        elif state is CeleryJobState.SUCCESS:
            ev.update(extend_terminal(result))
        return state, ev

    async def stream():
        try:
            state, snapshot = await run_in_threadpool(_state_event)
            yield {"event": snapshot["type"], "data": json.dumps(snapshot)}
            if state.is_terminal:
                return
            async for ev in bus.subscribe(channel_key(job_id)):
                if ev is bus.SUBSCRIBE_TICK:
                    state, current = await run_in_threadpool(_state_event)
                    if state.is_terminal:
                        yield {"event": current["type"], "data": json.dumps(current)}
                        return
                    continue
                yield {"event": ev.get("type", "message"), "data": json.dumps(ev)}
                published = ev.get("state")
                try:
                    terminal = published and CeleryJobState(published).is_terminal
                except ValueError:
                    # Not one of ours (unrelated message on this channel, or a future producer
                    # using a value this build doesn't know) — pass it through as a hint, but
                    # never let an unrecognized value decide whether to close the stream. The
                    # tick backstop above is what actually closes it once AsyncResult is terminal.
                    terminal = False
                if terminal:
                    return
        finally:
            # release() is synchronous — no shield needed (same note as session_events).
            sem.release()

    def _heartbeat() -> ServerSentEvent:
        return ServerSentEvent(
            data=json.dumps({"type": str(SSEEventType.heartbeat), "job_id": job_id,
                            "ts": dal.now().isoformat()}),
            event=str(SSEEventType.heartbeat),
        )

    return EventSourceResponse(
        stream(), ping=settings.sse_ping_seconds, ping_message_factory=_heartbeat,
        send_timeout=settings.sse_send_timeout_seconds,
        shutdown_grace_period=settings.sse_shutdown_grace_seconds,
    )
