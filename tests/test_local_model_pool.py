"""Local-model jobs run on their OWN capped pool, never on gevent's hub threadpool.

THE BUG (18 Sep): torch jobs ran on gevent.get_hub().threadpool — the pool gevent's thread resolver
runs every getaddrinfo on. With it full of model jobs, opening ANY new connection (DB, Redis,
Mongo, HTTP) queued behind them: ~18 s measured, the reaper's own work included. And each job used
~all cores (16 jobs x 10 threads on 12 cores).

No monkey-patching here: gevent's native ThreadPool works in a plain process, and `_offload` takes
the pooled branch whenever it believes `threading` is patched — which is what this pins.
"""
from __future__ import annotations

import os
import sys
import time
from types import SimpleNamespace

import gevent
import pytest

from app.core.config import get_settings
from app.pipeline import local_models


@pytest.fixture
def pooled(monkeypatch):
    """_offload's gevent branch, with a fresh model pool killed afterwards."""
    from gevent import monkey

    monkeypatch.setattr(monkey, "is_module_patched", lambda name: name == "threading")
    local_models._model_pool.cache_clear()
    yield
    local_models._model_pool().kill()
    local_models._model_pool.cache_clear()


def test_saturated_model_pool_leaves_the_resolver_pool_free(pooled) -> None:
    """Fill every model thread (and queue one more). A DNS-style job on the hub pool must still
    run at once. On the hub pool itself this waited for a model job to finish."""
    size = get_settings().local_model_threadpool_size
    hub_pool = gevent.get_hub().threadpool
    old_max = hub_pool.maxsize
    hub_pool.maxsize = max(size, hub_pool.size)   # as small as the model pool: any overlap shows
    try:
        jobs = [gevent.spawn(local_models._offload, lambda: time.sleep(0.6))
                for _ in range(size + 1)]
        gevent.sleep(0.1)   # let every job reach its pool
        t0 = time.monotonic()
        assert hub_pool.apply(lambda: 42) == 42
        assert time.monotonic() - t0 < 0.3, "the resolver's pool waited behind model jobs"
        gevent.joinall(jobs, raise_error=True)
    finally:
        hub_pool.maxsize = old_max


def test_each_job_gets_an_equal_share_of_the_cores(monkeypatch) -> None:
    """pool size x torch threads <= CPUs, applied on the thread that runs the job."""
    calls: list[int] = []
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(set_num_threads=calls.append))
    monkeypatch.setattr(local_models, "_available_cpus", lambda: 12)
    assert local_models._offload(lambda: "ok") == "ok"
    size = get_settings().local_model_threadpool_size
    assert calls == [max(1, 12 // size)]


@pytest.mark.parametrize("files, expected", [
    ({"cpu.max": "400000 100000\n"}, 4),                                   # cgroup v2 limit
    ({"cpu.max": "max 100000\n", "cpu.cfs_quota_us": "200000\n",
      "cpu.cfs_period_us": "100000\n"}, 2),                               # v2 unlimited, v1 limit
    ({"cpu.max": "50000 100000\n"}, 1),                                    # half a CPU -> 1
    ({}, None),                                                            # no limit: the host
])
def test_the_cpu_budget_is_the_containers_not_the_hosts(monkeypatch, tmp_path, files, expected) -> None:
    """os.cpu_count() is the HOST's count: a 4-CPU pod on a 32-core node gave each job 16 threads."""
    for name, body in files.items():
        (tmp_path / name).write_text(body)
    real = local_models.Path
    monkeypatch.setattr(local_models, "Path", lambda p: tmp_path / real(p).name
                        if str(p).startswith("/sys/fs/cgroup") else real(p))
    host = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()
    assert local_models._available_cpus() == (expected if expected is not None else host)


def test_torch_not_loaded_means_nothing_to_cap(monkeypatch) -> None:
    """The proxy path and the API never load torch; _offload must not import it for them."""
    monkeypatch.delitem(sys.modules, "torch", raising=False)
    assert local_models._offload(lambda: 7) == 7
    assert "torch" not in sys.modules
