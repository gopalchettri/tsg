"""SSE event bus over Redis pub/sub.

Workers `publish` (sync, from Celery) to a per-session channel; the API SSE handler
`subscribe`s asynchronously so the FastAPI event loop is never blocked. Publishing is
best-effort but logged — SSE is a hint layer, the DB status board is the source of truth, and
a reconnect reconciles from the DB (no replay log).
"""
from __future__ import annotations

import json
import threading
import time
from functools import lru_cache
from typing import AsyncIterator

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Timestamp (monotonic clock) until which the circuit breaker stays open;
# 0.0 means the breaker is closed (Redis publishing is allowed).
_breaker_until = 0.0

# Single-flight gate for the race the breaker alone can't cover: several greenlets making their
# FIRST attempt in the same instant, before any has failed and opened the breaker, each paying
# the full publish timeout against a down Redis. Plain stdlib Lock, not gevent.lock — the
# monkey-patch makes it cooperative under the worker pool and it stays correct un-patched. Not
# Redis-based: the race is in-process, and guarding against Redis with Redis is circular.
_probe_lock = threading.Lock()


def channel(session_id: str) -> str:
    """Redis pub/sub channel name for a session — the single naming convention shared
    by `publish` and `subscribe` so a worker and the SSE endpoint always agree on it."""
    return f"tsg:sse:{session_id}"


@lru_cache
def _redis():
    """Process-wide sync Redis client for `publish`, cached so the worker reuses one connection.
    Short timeouts and no retry: publish runs INLINE in the pipeline, so a down/slow Redis must
    fail fast rather than stall it."""
    import redis

    from redis.backoff import NoBackoff
    from redis.retry import Retry

    s = get_settings()
    return redis.Redis.from_url(
        s.redis_url, decode_responses=True,
        socket_connect_timeout=s.sse_publish_timeout_seconds, socket_timeout=s.sse_publish_timeout_seconds,
        retry=Retry(NoBackoff(), 0))


def publish(session_id: str, event: dict) -> None:
    """Best-effort SSE publish behind a circuit breaker: a down/slow Redis costs at most one
    timeout per cooldown window, not one per event. `_probe_lock` extends that to the window
    BEFORE the first failure — only the lock winner (the prober) pays the timeout; the rest
    wait for its outcome, then no-op (breaker open) or publish their own event (Redis healthy,
    so nothing is ever silently dropped while Redis is up).

    Worker-only by design: `_probe_lock` is cooperative only under the gevent worker's
    monkey-patched threading. Do NOT call this from the asyncio API process — there it is a
    real OS lock and a contended wait blocks a threadpool thread for the prober's round trip."""
    global _breaker_until
    if time.monotonic() < _breaker_until:
        return
    settings = get_settings()
    is_prober = _probe_lock.acquire(blocking=False)
    if not is_prober:
        # Wait for the in-flight prober's outcome rather than paying our own timeout.
        # Deliberately UNTIMED: the prober's Redis client bounds how long it can hold the lock
        # and its `finally` guarantees release, while any timed wait shorter than the prober's
        # real failure latency (dual-stack connect = 2x connect-timeout, slow DNS) would expire
        # BEFORE the breaker opens — the exact stampede this gate prevents.
        _probe_lock.acquire()
        _probe_lock.release()  # not the prober — release immediately, don't hold up the next waiter
        if time.monotonic() < _breaker_until:
            return  # the prober's attempt failed and opened the breaker — no-op like everyone else
        # else: Redis is healthy — fall through and publish OUR OWN event; the prober's call
        # covered nothing about this session.
    try:
        _redis().publish(channel(session_id), json.dumps(event, default=str))
    except Exception:  # noqa: BLE001 — best-effort, but never silent
        _breaker_until = time.monotonic() + settings.sse_breaker_cooldown_seconds
        logger.warning("sse.publish_failed", session_id=session_id, event_type=event.get("type"),
                    cooldown_seconds=settings.sse_breaker_cooldown_seconds, exc_info=True)
    finally:
        if is_prober:
            _probe_lock.release()


async def subscribe(session_id: str) -> AsyncIterator[dict]:
    """Async event stream for the SSE endpoint — does not block the event loop."""
    import redis.asyncio as aioredis

    r = aioredis.Redis.from_url(get_settings().redis_url, decode_responses=True,
                                socket_connect_timeout=get_settings().sse_subscribe_connect_timeout_seconds)
    pub = r.pubsub()
    try:
        await pub.subscribe(channel(session_id))
        # pub.listen() also yields non-data events (the subscribe confirmation itself).
        async for msg in pub.listen():
            if msg.get("type") == "message":
                yield json.loads(msg["data"])
    finally:
        # Runs even when the caller stops iterating early (client disconnect).
        await pub.aclose()
        await r.aclose()
