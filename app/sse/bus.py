"""SSE event bus over Redis pub/sub ([R4]).

Workers `publish` (sync, from Celery) to a per-session channel; the API SSE
handler `subscribe`s **asynchronously** (redis.asyncio) so the FastAPI event loop
is never blocked. Publishing is best-effort but logged — SSE is a hint layer, the
DB status board is the source of truth. Reconnect reconciles from the DB (chosen
approach: no replay log).
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

# Single-flight gate for the one narrow race the breaker alone can't cover: several greenlets
# making their FIRST attempt in the same instant, before any of them has failed and opened the
# breaker yet — each would otherwise independently pay the full publish timeout against a down
# Redis. A plain stdlib Lock, not gevent.lock: gevent's monkey-patch already makes threading
# primitives cooperative under the worker's gevent pool (same reasoning as llm.py's _llm_slot
# heartbeat thread), and it stays correct un-patched (plain pytest). NOT Redis-based (unlike
# embeddings.py's _group_lock): this race is entirely in-process, and using Redis to guard
# against Redis being down would be circular.
_probe_lock = threading.Lock()


def channel(session_id: str) -> str:
    """Redis pub/sub channel name for a session — the single naming convention shared
    by `publish` and `subscribe` so a worker and the SSE endpoint always agree on it."""
    return f"tsg:sse:{session_id}"


@lru_cache
def _redis():
    """Process-wide sync Redis client for `publish` — cached so the worker reuses one
    connection instead of dialing Redis per event; short timeouts and no retry keep a
    down Redis from stalling the inline pipeline call (§4.2)."""
    import redis

    from redis.backoff import NoBackoff
    from redis.retry import Retry

    # Short timeout + no retry: publish is best-effort and runs INLINE in the worker,
    # so an unreachable/slow Redis must fail fast, never stall the pipeline (§4.2).
    s = get_settings()
    return redis.Redis.from_url(
        s.redis_url, decode_responses=True,
        socket_connect_timeout=s.sse_publish_timeout_seconds, socket_timeout=s.sse_publish_timeout_seconds,
        retry=Retry(NoBackoff(), 0))


def publish(session_id: str, event: dict) -> None:
    """Best-effort SSE publish with a circuit breaker: a down/slow Redis costs at
    most one timeout per cooldown window (not one per event), so it can never stall
    the pipeline. On failure the breaker opens; publishes are instant no-ops until it
    closes.

    Single-flight probing (`_probe_lock`) extends that guarantee to the window BEFORE
    the first failure: when several greenlets race their first attempt against a
    just-died Redis, only the lock winner ("the prober") pays the publish timeout —
    the rest wait for its outcome and then either no-op (breaker now open) or make
    their own call (Redis healthy — no event is ever silently dropped while Redis is up).

    Worker-only by design: every current caller runs inside the gevent Celery worker,
    where `_probe_lock` is cooperative (monkey-patched threading). Do NOT call this
    from the asyncio API process — there the lock is a real OS lock and a contended
    wait would block a threadpool thread for the prober's whole round trip."""
    global _breaker_until
    # Breaker is still open (we're inside the cooldown window from a recent
    # failure) — skip Redis entirely and return immediately, no-op.
    if time.monotonic() < _breaker_until:
        return
    settings = get_settings()
    is_prober = _probe_lock.acquire(blocking=False)
    if not is_prober:
        # Someone else's publish is in flight right now — wait for ITS outcome instead of
        # independently paying a full timeout against a possibly-down Redis. Deliberately
        # UNTIMED: the prober's own Redis client bounds how long it can hold the lock, and
        # its `finally` guarantees release — while a timed wait shorter than the prober's
        # real failure latency (dual-stack connect = 2x connect-timeout, slow DNS, and the
        # follower's clock starting earlier) would expire BEFORE the breaker opens, letting
        # every follower fall through and pay its own full timeout anyway — the exact
        # stampede this gate exists to prevent.
        _probe_lock.acquire()
        _probe_lock.release()  # not the prober — release immediately, don't hold up the next waiter
        if time.monotonic() < _breaker_until:
            return  # the prober's attempt failed and opened the breaker — no-op like everyone else
        # else: the prober succeeded (Redis is healthy) — fall through and publish OUR OWN
        # event (own channel/payload; nothing about this session's event was covered by the
        # prober's call).
    try:
        _redis().publish(channel(session_id), json.dumps(event, default=str))
    except Exception:  # noqa: BLE001 — best-effort, but never silent
        # Publish failed (Redis down/slow) — open the breaker for `cooldown`
        # seconds so we fail fast next time instead of retrying every event.
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
        # pub.listen() also yields non-data events (e.g. the subscribe
        # confirmation itself); only "message" entries are actual published
        # events, so anything else is silently skipped.
        async for msg in pub.listen():
            if msg.get("type") == "message":
                yield json.loads(msg["data"])
    finally:
        # Always clean up, even if the caller stops iterating early
        # (e.g. client disconnects) or an error is raised mid-stream.
        await pub.aclose()
        await r.aclose()
