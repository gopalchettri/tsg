"""One Redis lock implementation for admin jobs that must not run twice at once.

Extracted from embeddings._group_lock, which solved this correctly and privately: the details
below are subtle enough that a second copy WOULD drift, and the copy that drifts is the one that
silently stops protecting anything.

  * `thread_local=False` on the Lock -- the heartbeat runs on a different thread from the one
    that acquired, and must see the same ownership token or every renewal raises
    LockNotOwnedError.
  * A heartbeat that RESETS the TTL (`replace_ttl=True`), so a slow job cannot outlive its own
    lock and have a second worker start alongside it.
  * Stop the heartbeat BEFORE releasing -- otherwise an in-flight renewal tick can re-extend a
    lock that was just released, locking out the next caller for a full TTL.
  * FAIL-OPEN when Redis is unreachable. These locks guard redundant COST, never correctness:
    every protected operation is independently safe to run twice (the embedding upserts are
    idempotent; the library-import upserts are first-writer). Availability wins, and the same
    reasoning is recorded on llm.py's slot limiter.

Callers pass an already-constructed exception so the message names their own domain, rather than
this module inventing one it has no context for, and they pass their own redis factory so this
core module never imports app.pipeline (a layering inversion) and stays testable with a fake.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import contextmanager

from redis.exceptions import LockNotOwnedError
from redis.lock import Lock

from app.core.logging import get_logger

log = get_logger(__name__)


def _renew_loop(lock: Lock, interval: float, stop_event: threading.Event, key: str) -> None:
    while not stop_event.wait(interval):
        try:
            lock.extend(lock.timeout, replace_ttl=True)  # reset to the full TTL, not additive
        except LockNotOwnedError:  # a stale timeout already let a different caller acquire
            pass
        except Exception:
            log.warning("joblock.renewal_failed", key=key, exc_info=True)


def is_held(key: str, *, redis_factory: Callable[[], object]) -> bool:
    """Best-effort probe: is this lock currently held?

    ADVISORY ONLY, and every caller must treat it that way. It cannot be atomic with a later
    acquire, so a request that passes this probe may still lose the race -- the acquire inside
    the worker is the authoritative guard. Its purpose is a fast, friendly 409 in the common
    case. An unreachable Redis reports False (not held), matching the fail-open contract above:
    a probe must never be the reason a job is refused."""
    try:
        return bool(redis_factory().exists(key))
    except Exception:
        log.warning("joblock.probe_failed", key=key, exc_info=True)
        return False


@contextmanager
def job_lock(key: str, *, ttl: int, busy: Exception, redis_factory: Callable[[], object]):
    """Hold `key` for the duration of the block, or raise `busy` if someone else holds it.

    `ttl` must be an int -- redis-py rejects a float for ex=/EXPIRE.
    """
    try:
        lock = Lock(redis_factory(), key, timeout=ttl, thread_local=False)
        acquired = lock.acquire(blocking=False)
    except Exception:
        log.warning("joblock.redis_unavailable_fail_open", key=key, exc_info=True)
        yield
        return
    if not acquired:
        raise busy
    stop_event = threading.Event()
    # plain threading.Thread, not gevent.spawn -- same portability reasoning as llm.py's _llm_slot
    hb = threading.Thread(target=_renew_loop, args=(lock, ttl / 3, stop_event, key), daemon=True)
    hb.start()
    try:
        yield
    finally:
        stop_event.set()
        hb.join(timeout=ttl)
        try:
            lock.release()
        except LockNotOwnedError:  # already lost ownership to a stale-timeout retry
            pass
        except Exception:
            log.warning("joblock.release_failed", key=key, exc_info=True)
