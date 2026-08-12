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
from functools import lru_cache
from typing import Callable, Sequence

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


def _offload(fn: Callable):
    """Run a CPU-bound model call without freezing a cooperative scheduler.

    Under gevent (patched `threading`), a normal ThreadPoolExecutor runs its workers as
    GREENLETS — torch would still block the hub, stalling every concurrent session. gevent's
    NATIVE threadpool uses real OS threads: the greenlet yields while torch (which releases the
    GIL) runs. Outside gevent there's no shared hub to protect, so run inline.
    """
    patched = False
    try:  # scope: ONLY the gevent-availability probe — never the work below
        from gevent import monkey

        patched = monkey.is_module_patched("threading")
    except ImportError:
        pass
    if patched:
        import gevent

        return gevent.get_hub().threadpool.apply(fn)  # fn's own errors propagate unchanged
    return fn()


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
        model = _embedder(get_settings().embedding_model)
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
        model = _reranker(get_settings().reranker_model)
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
    if s.embedding_provider == "local":
        _require_path_exists("EMBEDDING_MODEL", s.embedding_model)
        _check_embedding_prefix_style(s.embedding_model, s.embedding_prefix_style)
    if s.reranker_provider == "local":
        _require_path_exists("RERANKER_MODEL", s.reranker_model)

    # Load-time checks (warm only): the package must be installed before we load models.
    if warm and local_used:
        _require_sentence_transformers_installed()
        if s.embedding_provider == "local":
            dim = _embedder(s.embedding_model).get_embedding_dimension()
            if dim != s.embedding_dimensions:
                raise RuntimeError(f"EMBEDDING_DIMENSIONS={s.embedding_dimensions} but model reports {dim}")
        if s.reranker_provider == "local":
            _reranker(s.reranker_model)


if __name__ == "__main__":  # self-check: offload returns the same values (inline path here)
    assert _offload(lambda: [1.0, 2.0]) == [1.0, 2.0]
    print("local_models self-check ok")
