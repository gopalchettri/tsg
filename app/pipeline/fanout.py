"""Bounded fan-out whose children die with their parent.

`with ThreadPoolExecutor(...)` looked equivalent under the gevent worker (patched threads are
greenlets) but was not: a revoke (reaper, or the hard time limit's gevent.Timeout) kills only the
TASK greenlet. The pool's workers are not its children, `__exit__` joins them, and every queued
item still ran — on 18 Sep a revoked run's scenario/embedding work kept going for 29 minutes and
starved the next run into being reaped too.

Here, under patched gevent, children are spawned into a gevent Pool and killed in `finally` when
the caller is interrupted: in-flight children unwind at their next yield (a DB call, an LLM call,
a wait on the model threadpool) and unspawned items never start. The one thing no one can stop is
a torch job already running on a native thread; it finishes and its result is discarded — bounded
by local_models' own pool size. Outside gevent (the API, tests) this is a plain ThreadPoolExecutor.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, TypeVar

T = TypeVar("T")
Settled = tuple[Any, Exception | None]


def _gevent_patched() -> bool:
    try:
        from gevent import monkey
    except ImportError:
        return False
    return monkey.is_module_patched("threading")


def map_settled(fn: Callable[[T], Any], items: Iterable[T], *, max_workers: int) -> list[Settled]:
    """`fn` over `items`, at most `max_workers` at a time, as (value, None) or (None, exc) pairs in
    INPUT order. An `Exception` is captured per item so one failure never masks its siblings; a
    BaseException (GreenletExit, gevent.Timeout, KeyboardInterrupt) propagates — and under gevent
    takes every running child down with it."""
    items = list(items)
    if not items:
        return []
    workers = max(1, min(max_workers, len(items)))

    def _settled(item: T) -> Settled:
        try:
            return fn(item), None
        except Exception as exc:  # noqa: BLE001 - captured per item, surfaced to the caller
            return None, exc

    if _gevent_patched():
        import gevent
        from gevent.pool import Pool

        pool = Pool(workers)
        spawned = []
        try:
            for item in items:
                spawned.append(pool.spawn(_settled, item))   # blocks while the pool is full
            gevent.joinall(spawned)
        finally:
            pool.kill()   # no-op once every child finished; kills the in-flight ones otherwise
        for g in spawned:
            if not g.successful():   # a child's own BaseException: never swallow it as None
                raise g.exception
        return [g.value for g in spawned]

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(_settled, items))
