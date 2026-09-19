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


def _fake_torch(monkeypatch) -> list[int]:
    calls: list[int] = []
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(set_num_threads=calls.append))
    monkeypatch.setattr(local_models, "_torch_threads_set", False)
    return calls


def test_a_model_job_never_touches_torch_threads(monkeypatch, pooled) -> None:
    """THE REGRESSION (19 Sep): every job set torch's thread count from its pool thread, while the
    other job could be mid-computation, and a live control-mapping step stalled for 10+ minutes.
    A job now runs the model call and nothing else, on the pool and inline alike."""
    calls = _fake_torch(monkeypatch)
    assert local_models._offload(lambda: "pooled") == "pooled"
    monkeypatch.setattr(__import__("gevent").monkey, "is_module_patched", lambda name: False)
    assert local_models._offload(lambda: "inline") == "inline"
    assert calls == []


def _local_settings(tmp_path) -> SimpleNamespace:
    return SimpleNamespace(embedding_provider="local", reranker_provider="local",
                           embedding_model=str(tmp_path), reranker_model=str(tmp_path),
                           embedding_prefix_style="e5", embedding_dimensions=3)


def test_torch_threads_are_set_once_at_boot(monkeypatch, tmp_path) -> None:
    """Once per process, on the thread that loads the models, before any job — torch's own rule."""
    calls = _fake_torch(monkeypatch)
    monkeypatch.setattr(local_models, "_available_cpus", lambda: 12)
    monkeypatch.setattr(local_models, "_require_sentence_transformers_installed", lambda: None)
    monkeypatch.setattr(local_models, "_embedder",
                        lambda path: SimpleNamespace(get_embedding_dimension=lambda: 3))
    monkeypatch.setattr(local_models, "_reranker", lambda path: object())
    local_models.validate_local_models(_local_settings(tmp_path), warm=True)
    local_models.validate_local_models(_local_settings(tmp_path), warm=True)   # a second boot call
    assert calls == [12 // (2 * get_settings().local_model_threadpool_size)]


def test_the_api_never_sets_torch_threads(monkeypatch, tmp_path) -> None:
    """warm=False (the API) loads no model, so it has no torch thread count to set."""
    calls = _fake_torch(monkeypatch)
    local_models.validate_local_models(_local_settings(tmp_path), warm=False)
    assert calls == []


@pytest.mark.parametrize("cpus, pool, threads", [(12, 1, 6), (12, 2, 3), (4, 1, 2), (1, 1, 1)])
def test_model_jobs_share_half_the_cpus(monkeypatch, cpus, pool, threads) -> None:
    """Half for the models, half for the event loop and a second model-running worker on the host."""
    monkeypatch.setenv("TSG_LOCAL_MODEL_THREADPOOL_SIZE", str(pool))
    get_settings.cache_clear()
    monkeypatch.setattr(local_models, "_available_cpus", lambda: cpus)
    assert local_models._torch_threads() == threads


def test_one_model_job_at_a_time_by_default(monkeypatch) -> None:
    monkeypatch.delenv("TSG_LOCAL_MODEL_THREADPOOL_SIZE", raising=False)
    from app.core.config import Settings

    assert Settings(_env_file=None).local_model_threadpool_size == 1


def test_no_tokenizer_thread_pool_unless_the_operator_says_otherwise(monkeypatch) -> None:
    """TOKENIZERS_PARALLELISM=false must be in place before torch loads, i.e. when this module is
    imported; an explicit value in the environment wins."""
    import importlib

    monkeypatch.setenv("TOKENIZERS_PARALLELISM", "true")
    importlib.reload(local_models)
    assert os.environ["TOKENIZERS_PARALLELISM"] == "true"          # operator's choice kept
    monkeypatch.delenv("TOKENIZERS_PARALLELISM")
    importlib.reload(local_models)
    assert os.environ["TOKENIZERS_PARALLELISM"] == "false"


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
