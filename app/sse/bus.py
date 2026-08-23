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
from collections.abc import AsyncIterator
from functools import lru_cache
from typing import Final

import anyio
import redis
from redis.backoff import NoBackoff
from redis.retry import Retry

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Sentinel `subscribe()` yields once per `sse_ping_seconds` when no Redis message arrived in that
# window — see `subscribe()`'s own docstring for exactly what it means and why Phase 2
# (app/api/sessions.py's `stream_events()`) depends on it. A plain `object()`, not a dict: it is
# never JSON, never carries a "type" key, and must be checked with `is SUBSCRIBE_TICK`, never `==`
# or key access, so it can never be confused with a real published event.
SUBSCRIBE_TICK: Final = object()

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
    """The one naming convention `publish` and `subscribe` share, so worker and SSE agree."""
    return f"tsg:sse:{session_id}"


def _breaker_owner() -> str:
    """Best-effort process-identity label for `sse.publish_failed`'s log line (item 9) — the
    breaker (`_breaker_until` above) is process-global, so "the breaker opened" is ambiguous
    across a deployment with both a worker and an API process each holding their own instance of
    it. The Celery worker entrypoint monkey-patches `threading` at import
    (app/pipeline/celery_worker.py, before `celery_app` and its transitive imports); the API
    process never does — that's the one cheap, already-true-in-this-codebase signal to tell the
    two apart without a new setting or thread-local plumbing."""
    from gevent import monkey
    return "worker" if monkey.is_module_patched("threading") else "api"


@lru_cache
def _redis():
    """Process-wide sync Redis client for `publish`, cached so the worker reuses one connection.
    Short timeouts: publish runs INLINE in the pipeline, so a down/slow Redis must fail fast
    rather than stall it.

    ONE retry, not zero. A pooled connection the peer dropped SILENTLY — no FIN/RST, the normal
    behaviour of a managed-Redis or load-balancer idle timeout, and prod points at a remote
    rediss:// host — is undetectable before use: health_check_interval is off (a PING per publish
    would cost more than the publish) and redis-py's can_read() probe only catches a socket that
    was politely closed. With zero retries that stale connection turns one publish into a dropped
    event AND opens the breaker for every session in this process. The retry costs nothing on a
    healthy Redis, and PUBLISH is idempotent for a hint layer (a duplicate event costs one extra
    client refetch), so re-sending is strictly better than dropping. Worst case against a truly
    dead Redis doubles to 2x the timeout, once per cooldown window.

    This matters most for the LONE publish: a burst (a live session's stage events) self-heals on
    attempt 2 anyway, but treatment_plan_result fires once, after a 10-60s task, on a worker that
    may have idled for hours — structurally the most likely publish in the system to meet a stale
    connection."""
    s = get_settings()
    return redis.Redis.from_url(
        s.redis_url, decode_responses=True,
        socket_connect_timeout=s.sse_publish_timeout_seconds, socket_timeout=s.sse_publish_timeout_seconds,
        retry=Retry(NoBackoff(), 1))


def publish(session_id: str, event: dict) -> None:
    """Best-effort publish behind a circuit breaker: a down Redis costs one connect attempt per
    cooldown window. `_probe_lock` extends that to the window BEFORE the first failure — only the
    prober pays it; the rest wait for its outcome, then no-op (breaker open) or publish their own
    event (Redis healthy, so nothing is dropped while Redis is up).

    That cost is NOT simply sse_publish_timeout_seconds. getaddrinfo() runs before any socket
    timeout applies (unbounded, and prod resolves a hostname), and _connect then loops over every
    address it returned, paying socket_connect_timeout PER ADDRESS — a dual-stack A+AAAA host
    costs 2x. Size the setting against that, not against a single timeout.

    NOT worker-only: `_probe_lock` is cooperative (cheap to park on) only under the Celery
    worker's gevent-monkey-patched threading (celery_worker.py). It is ALSO reached from the
    asyncio API process, synchronously, on a live path: `post_next_set_scenarios` /
    `post_regenerate_scenarios` (plain `def` routes, run on Starlette's threadpool) ->
    `_recover_from_enqueue_failure` -> `tasks.decide_session_outcome` ->
    `_send_to_review`/`_mark_session_failed` -> here. There, `_probe_lock` is a genuine OS lock,
    and a contended wait blocks one of that threadpool's limited threads for the prober's whole
    round trip — see the non-prober wait below for the fix."""
    global _breaker_until
    if time.monotonic() < _breaker_until:
        return
    settings = get_settings()
    is_prober = _probe_lock.acquire(blocking=False)
    if not is_prober:
        # Wait for the in-flight prober's outcome rather than paying our own connect timeout —
        # BOUNDED, unlike the original untimed wait. That older reasoning ("untimed, because a
        # shorter wait would return and fall through to OUR OWN publish attempt before the
        # prober's connect finishes, piling a second slow attempt onto a still-hanging Redis")
        # only holds for the gevent-patched worker, where a parked waiter costs nothing — it does
        # not hold for the API-process path documented above, where the wait is a real OS thread
        # blocked out of a capped pool. Fix: bound the wait to the same dual-stack worst case
        # `_redis()`'s own docstring already sizes against (2x connect timeout), and on timeout
        # SKIP rather than fall through — the stampede the old comment worried about only existed
        # because falling through published; a no-op skip carries no such risk in either process.
        acquired = _probe_lock.acquire(timeout=2 * settings.sse_publish_timeout_seconds)
        if not acquired:
            logger.warning("sse.publish_probe_wait_timeout", session_id=session_id,
                        event_type=event.get("type"))
            return  # prober still in flight past our budget — no-op, don't block indefinitely
        _probe_lock.release()  # not the prober — release immediately, don't hold up the next waiter
        if time.monotonic() < _breaker_until:
            return  # the prober's attempt failed and opened the breaker — no-op like everyone else
        # else: Redis is healthy — fall through and publish OUR OWN event; the prober's call
        # covered nothing about this session.
    try:
        _redis().publish(channel(session_id), json.dumps(event, default=str))
    except Exception:
        _breaker_until = time.monotonic() + settings.sse_breaker_cooldown_seconds
        logger.warning("sse.publish_failed", session_id=session_id, event_type=event.get("type"),
                    breaker_owner=_breaker_owner(),  # item 9: which process's breaker just opened
                    cooldown_seconds=settings.sse_breaker_cooldown_seconds, exc_info=True)
    finally:
        if is_prober:
            _probe_lock.release()


@lru_cache
def _subscriber_pool():
    """Shared `redis.asyncio.ConnectionPool` for every `subscribe()` stream (item 11) — one bounded
    pool instead of one raw connection per open SSE stream. Capped at `sse_max_concurrent_streams`,
    the SAME setting Phase 2's per-process semaphore gates `session_events()` on, so that semaphore
    can never admit more concurrent streams than this pool has connections for.

    `socket_timeout`/`health_check_interval` (item 14) MUST be set HERE, on the pool's own
    construction, and not passed to the per-call `Redis(connection_pool=...)` client in
    `subscribe()` below: redis-py's `Redis.__init__` only builds a pool from its own `**kwargs`
    when no `connection_pool` is given (`if not connection_pool: ...` in
    redis/asyncio/client.py) — with a pool supplied, those kwargs are silently never applied,
    not rejected, not an error, just dropped."""
    import redis.asyncio as aioredis
    s = get_settings()
    return aioredis.ConnectionPool.from_url(
        s.redis_url, decode_responses=True,
        max_connections=s.sse_max_concurrent_streams,
        socket_connect_timeout=s.sse_subscribe_connect_timeout_seconds,
        socket_timeout=s.sse_subscriber_socket_timeout_seconds,
        health_check_interval=s.sse_subscriber_health_check_interval_seconds,
    )


async def subscribe(session_id: str) -> AsyncIterator[dict | object]:
    """Async event stream for the SSE endpoint — does not block the event loop.

    Yields either a decoded event `dict` (a real published message) or the module-level
    `SUBSCRIBE_TICK` sentinel once per `sse_ping_seconds` when nothing arrived in that window
    (item 1's polling primitive). The read is `pub.get_message(timeout=sse_ping_seconds)`, not
    `pub.listen()`, specifically so this loop always regains control on a fixed cadence instead of
    blocking indefinitely on the next message — the subscription itself stays open and does not
    die between ticks.

    `SUBSCRIBE_TICK` is NOT an event: it is what lets the consumer in `stream_events()`
    (app/api/sessions.py, Phase 2) do the two checks a Redis message can never guarantee it will
    ever see — re-read the board's session status and break on a terminal state (item 1), and
    re-check (user, entity) authorization when `verify_membership` is on (item 30) — on a
    guaranteed cadence, independent of whether any `bus.publish` call ever actually arrives.

    Uses the shared subscriber pool (`_subscriber_pool`, item 11) rather than opening a raw
    connection per stream; `decode_responses`/`socket_timeout`/`health_check_interval` all live on
    that pool's construction, not here (see its docstring for why passing them to this per-call
    client would be silently dropped)."""
    import redis.asyncio as aioredis

    settings = get_settings()
    r = aioredis.Redis(connection_pool=_subscriber_pool())
    pub = r.pubsub()
    try:
        await pub.subscribe(channel(session_id))
        while True:
            # ignore_subscribe_messages=True filters the subscribe confirmation itself (and any
            # unsubscribe) the same way the old `msg.get("type") == "message"` check did; it also
            # makes the very first call return None immediately, so the caller gets one tick right
            # after connecting for free, before the first real sse_ping_seconds timeout even starts.
            msg = await pub.get_message(ignore_subscribe_messages=True, timeout=settings.sse_ping_seconds)
            if msg is None:
                yield SUBSCRIBE_TICK
                continue
            yield json.loads(msg["data"])
    finally:
        # Item 15: shielded, not just reordered. A plain `finally` does not guarantee its awaits
        # run to completion under cancellation (a client disconnect cancels the task driving this
        # generator); `CancelScope(shield=True)` is the only fix that actually does. This matters
        # more now than before item 11: the shared pool is a CAPPED resource
        # (sse_max_concurrent_streams), so a cleanup skipped under cancellation permanently
        # consumes one slot of that cap per occurrence — the exact exhaustion items 12/13 exist to
        # prevent, self-inflicted here instead of by unbounded connection growth.
        with anyio.CancelScope(shield=True):
            await pub.aclose()
            await r.aclose()
