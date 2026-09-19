"""Local, in-process embedding + reranker models (no network) — `multilingual-e5-large` and
`bge-reranker-v2-m3`.

Models load once from disk (cached). `sentence-transformers` is an OPTIONAL dependency
(`pip install -e ".[local]"`), imported lazily so the proxy path and tests never require torch.

Torch forward passes are CPU/GPU-bound with no yield point, so they are offloaded to a real OS
thread (see `_offload`). e5 query:/passage: prefixing is applied upstream in `llm.embed`
(provider-agnostic), not here.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Callable, Sequence
from functools import lru_cache
from pathlib import Path

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

#: Project root - app/pipeline/local_models.py -> app/pipeline -> app -> <root>. Same idiom as
#: tracing._ROOT and env_selfcheck: a RELATIVE model path resolves against this, never the CWD.
_ROOT = Path(__file__).resolve().parents[2]


def resolve_model_path(path: str) -> str:
    """EMBEDDING_MODEL / RERANKER_MODEL as an absolute path.

    .env.example ships `models/multilingual-e5-large`. Resolved against the CWD that only works
    when the process happens to start in tsg/ (start.ps1 does; a bare `uvicorn`/`celery` from
    elsewhere, or Docker's WORKDIR /app, does not) and fails at boot with "path not found".
    Anchoring here makes the setting mean the same thing however the process was launched.
    Absolute paths (the Docker bind mounts, /models/e5) pass through untouched.
    """
    return path if os.path.isabs(path) else str(_ROOT / path)


@lru_cache(maxsize=1)
def _model_pool():
    """Local models' OWN native-thread pool, `local_model_threadpool_size` real OS threads.

    NOT gevent's hub.threadpool: gevent's thread resolver runs every getaddrinfo on that pool, so
    torch jobs queued there made every NEW socket connection (DB, Redis, Mongo, HTTP) wait behind
    them — ~18 s measured on 18 Sep, which also delayed the reaper's own work. A separate pool also
    makes the setting a real cap: it used to set hub.threadpool.size, which gevent grows back to
    its maxsize (10) on demand, so it never limited anything."""
    from gevent.threadpool import ThreadPool

    return ThreadPool(get_settings().local_model_threadpool_size)


def _available_cpus() -> int:
    """CPUs this process may actually use. os.cpu_count() is the HOST's count: in a container with
    a CPU limit it overstates the budget (a 4-CPU pod on a 32-core node would give each job 16
    threads). So: a cgroup CPU quota (v2, then v1) first, then the scheduler affinity mask."""
    for quota_file, period_file in (("/sys/fs/cgroup/cpu.max", None),
                                    ("/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
                                     "/sys/fs/cgroup/cpu/cpu.cfs_period_us")):
        try:
            if period_file is None:
                quota, period = Path(quota_file).read_text().split()[:2]
            else:
                quota, period = Path(quota_file).read_text().strip(), Path(period_file).read_text().strip()
            if quota not in ("max", "-1"):
                return max(1, int(quota) // int(period))
        except (OSError, ValueError):
            continue
    if hasattr(os, "sched_getaffinity"):
        return len(os.sched_getaffinity(0)) or 1
    return os.cpu_count() or 1


def _cap_torch_threads() -> None:
    """Give each concurrent model job of THIS process an equal share of the CPUs it may use:
    pool size x torch threads <= available CPUs. Unset, torch took ~all cores per job — 16 jobs x
    10 threads on a 12-core box on 18 Sep; measured on 19 Sep, one job fell from 7.3 cores used to
    5.6 at 6 threads for ~5% more wall time. The budget is per process: the admin worker (one job
    at a time) takes its own share on top, and the tokenizer's own threads are not counted.
    Called on the thread that runs the job, because torch's intra-op thread count is per-thread
    under OpenMP.

    Uses torch only if it is ALREADY loaded: torch is sentence-transformers' dependency, not
    this module's, and it is loaded by the first model load — which the worker does at boot
    (validate_local_models(warm=True)) before any job runs. Not loaded means nothing to cap."""
    torch = sys.modules.get("torch")
    if torch is not None:
        torch.set_num_threads(
            max(1, _available_cpus() // get_settings().local_model_threadpool_size))


def _offload(fn: Callable):
    """Run a CPU-bound model call without freezing a cooperative scheduler.

    Under gevent (patched `threading`), a normal ThreadPoolExecutor runs its workers as
    GREENLETS — torch would still block the hub, stalling every concurrent session. A NATIVE
    threadpool uses real OS threads: the greenlet yields while torch (which releases the GIL)
    runs. Outside gevent there's no shared hub to protect, so run inline.
    """
    patched = False
    try:  # scope: ONLY the gevent-availability probe — never the work below
        from gevent import monkey

        patched = monkey.is_module_patched("threading")
    except ImportError:
        pass

    def _job():
        _cap_torch_threads()
        return fn()

    if patched:
        return _model_pool().apply(_job)  # fn's own errors propagate unchanged
    return _job()


@lru_cache(maxsize=get_settings().local_model_cache_size)
def _embedder(path: str):
    """Load (and cache) the SentenceTransformer at `path` — `lru_cache` keyed on the path string
    means switching `EMBEDDING_MODEL` at runtime gets its own slot instead of a stale model."""
    from sentence_transformers import SentenceTransformer

    log.info("local.embedder.loading", path=path)
    model = SentenceTransformer(path)
    # get_embedding_dimension, not get_sentence_embedding_dimension: the latter is a deprecated
    # alias in sentence-transformers 5.x that emits a FutureWarning on every worker boot. Hence
    # the >=5.0 floor on the [local] extra.
    log.info("local.embedder.loaded", path=path, dim=model.get_embedding_dimension())
    return model


@lru_cache(maxsize=get_settings().local_model_cache_size)
def _reranker(path: str):
    """Load (and cache) the CrossEncoder at `path`, mirroring `_embedder`'s per-path slot."""
    from sentence_transformers import CrossEncoder

    log.info("local.reranker.loading", path=path)
    model = CrossEncoder(path)
    log.info("local.reranker.loaded", path=path)
    return model


def embed(texts: Sequence[str]) -> list[list[float]]:
    """Encode already-prefixed texts on a worker thread. The model lookup runs inside `_run`,
    not before it — a cache-miss disk load is exactly the non-yielding work `_offload` exists to
    keep off the calling greenlet."""
    texts = list(texts)
    if not texts:  # ponytail: empty batch → no model load, no threadpool hop, []-in-[]-out
        return []

    def _run():
        model = _embedder(resolve_model_path(get_settings().embedding_model))
        vectors = model.encode(texts, normalize_embeddings=True, convert_to_numpy=True,
                                show_progress_bar=False)
        return [v.tolist() for v in vectors]

    return _offload(_run)


def rerank(query: str, docs: Sequence[str]) -> list[float]:
    """One query against its docs — thin wrapper over rerank_pairs below."""
    if not docs:  # ponytail: no candidates → no model load, aligns with []-in-[]-out
        return []
    return rerank_pairs([(query, d) for d in docs])


def rerank_pairs(pairs: Sequence[tuple[str, str]]) -> list[float]:
    """Score (query, doc) pairs → 0-100. bge-reranker (num_labels==1) already applies sigmoid in
    `predict`, so its output is a [0,1] probability — scale x100 and clamp, do NOT sigmoid again.
    Re-calibrate the 60/75 bands per §8.4 if the model changes.

    Takes explicit pairs (not one query + docs) so a caller with MANY queries can score them all
    in ONE dispatch — cross-encoders score each pair independently, so batching across queries is
    score-identical, and predict() mini-batches internally (llm.rerank_many)."""
    if not pairs:
        return []

    def _run():
        model = _reranker(resolve_model_path(get_settings().reranker_model))
        scores = [float(x) for x in model.predict(pairs, show_progress_bar=False)]
        out_of_range = [x for x in scores if x < -0.05 or x > 1.05]
        if out_of_range:
            # RERANKER_MODEL is operator-configurable and this transform assumes a sigmoid-bounded
            # [0,1] output. A model that doesn't sigmoid internally would clamp silently to 0/100
            # and destroy relative ranking with no error anywhere downstream — surface it.
            log.warning("local.reranker.score_out_of_expected_range",
                        model=get_settings().reranker_model, sample=out_of_range[:5])
        return [max(0.0, min(100.0, 100.0 * x)) for x in scores]

    return _offload(_run)


def _require_path_exists(setting_name: str, path: str) -> None:
    """Raise if a configured local-model path (EMBEDDING_MODEL / RERANKER_MODEL) doesn't exist on disk."""
    if not os.path.exists(path):
        raise RuntimeError(f"{setting_name} path not found: {path}")


def _check_embedding_prefix_style(model_path: str, prefix_style: str) -> None:
    """Reject EMBEDDING_PREFIX_STYLE=auto when the model name can't be used to infer the scheme,
    so query:/passage: prefixes aren't silently dropped."""
    if prefix_style == "auto" and "e5" not in model_path.lower():
        raise RuntimeError(
            f"EMBEDDING_PREFIX_STYLE=auto cannot infer the prefix scheme from '{model_path}'. "
            "Set EMBEDDING_PREFIX_STYLE explicitly to 'e5' or 'none' so prefixes aren't silently dropped.")


def _require_sentence_transformers_installed() -> None:
    """The package must be installed before we load models (warm-only load-time check)."""
    if importlib.util.find_spec("sentence_transformers") is None:
        raise RuntimeError(
            "EMBEDDING/RERANKER_PROVIDER=local but 'sentence-transformers' is not installed. "
            'Build the image with `--build-arg EXTRAS=prod,local` (or `pip install -e ".[local]"`).')


def validate_local_models(settings: Settings | None = None, *, warm: bool) -> None:
    """Fail fast at startup when a 'local' provider is misconfigured — a missing path, missing
    `sentence-transformers`, or a dimension mismatch surfaces here instead of crashing deep in
    the pipeline. `warm=True` (workers) also loads the models so the first request doesn't pay
    the load; `warm=False` (API) only checks the path exists — the API doesn't ground, so it
    needn't hold the model in RAM."""
    s = settings or get_settings()
    local_used = s.embedding_provider == "local" or s.reranker_provider == "local"

    # Config-level checks (always): paths exist, e5 prefix scheme is unambiguous.
    # Resolved ONCE, up front, and the same string is what _embedder/_reranker are cached on
    # here and in embed()/rerank_pairs() - a relative setting cannot warm one cache slot here and
    # miss it at request time.
    embedding_path = resolve_model_path(s.embedding_model)
    reranker_path = resolve_model_path(s.reranker_model)
    if s.embedding_provider == "local":
        _require_path_exists("EMBEDDING_MODEL", embedding_path)
        _check_embedding_prefix_style(s.embedding_model, s.embedding_prefix_style)
    if s.reranker_provider == "local":
        _require_path_exists("RERANKER_MODEL", reranker_path)

    # Load-time checks (warm only): the package must be installed before we load models.
    if warm and local_used:
        _require_sentence_transformers_installed()
        if s.embedding_provider == "local":
            dim = _embedder(embedding_path).get_embedding_dimension()
            if dim != s.embedding_dimensions:
                raise RuntimeError(f"EMBEDDING_DIMENSIONS={s.embedding_dimensions} but model reports {dim}")
        if s.reranker_provider == "local":
            _reranker(reranker_path)


if __name__ == "__main__":  # self-check: offload returns the same values (inline path here)
    assert _offload(lambda: [1.0, 2.0]) == [1.0, 2.0]
    print("local_models self-check ok")
