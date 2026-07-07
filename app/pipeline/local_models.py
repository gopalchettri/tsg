""" runs the AI models that don't need the internet — they
live directly on this machine's disk and do their thinking right here.

Local, in-process embedding + reranker models (no network) — lists
`multilingual-e5-large` and `bge-reranker-v2-m3` as local models.

Models load once from disk (cached). `sentence-transformers` is an OPTIONAL
dependency (`pip install -e ".[local]"`), imported lazily so the proxy path and
tests never require torch.

Torch forward passes are CPU/GPU-bound with no yield point, so running them on a
gevent greenlet would freeze the whole worker hub (all concurrent sessions). They
are therefore offloaded to a real OS thread: torch releases the GIL during the
forward pass, and gevent's patched `future.result()` yields the hub while it runs.
e5 query:/passage: prefixing is applied upstream in `llm.embed` (provider-agnostic),
not here.
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
    """ runs a slow AI calculation on a separate real thread
    so it doesn't freeze the rest of the worker while it's thinking.

    Run a CPU-bound model call without freezing a cooperative scheduler.

    Under gevent (patched `threading`), a normal ThreadPoolExecutor would run its
    workers as GREENLETS — so torch would still block the hub. The correct offload
    is gevent's NATIVE threadpool (real OS threads): the greenlet yields while a real
    thread runs the forward pass (torch releases the GIL), so the hub keeps ticking.
    Outside gevent (prefork worker / sync / tests) there's no shared hub to protect,
    so run inline.
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
    """ loads the local text-to-vector model from disk (once),
    and remembers it so it's never reloaded on every call.

    Load (and cache) the SentenceTransformer at `path` — `lru_cache` keyed on the
    path string means switching `EMBEDDING_MODEL` at runtime gets its own cache slot
    instead of silently reusing a stale model."""
    from sentence_transformers import SentenceTransformer

    log.info("local.embedder.loading", path=path)
    model = SentenceTransformer(path)
    log.info("local.embedder.loaded", path=path, dim=model.get_sentence_embedding_dimension())
    return model


@lru_cache(maxsize=get_settings().local_model_cache_size)
def _reranker(path: str):
    """ loads the local relevance-scoring model from disk
    (once), same idea as `_embedder` above.

    Load (and cache) the CrossEncoder at `path`, mirroring `_embedder`'s
    per-path `lru_cache` slot for `RERANKER_MODEL`."""
    from sentence_transformers import CrossEncoder

    log.info("local.reranker.loading", path=path)
    model = CrossEncoder(path)
    log.info("local.reranker.loaded", path=path)
    return model


def embed(texts: Sequence[str]) -> list[list[float]]:
    """ turns a batch of text into vectors, using the local model.

    Encode already-prefixed texts on a worker thread (keeps the gevent hub alive)."""
    texts = list(texts)
    if not texts:  # ponytail: empty batch → no model load, no threadpool hop, []-in-[]-out
        return []
    model = _embedder(get_settings().embedding_model)

    def _run():
        """The actual torch forward pass, closed over `model`/`texts` so `_offload` can
        run it as a zero-arg callable on the native threadpool."""
        vectors = model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
        return [v.tolist() for v in vectors]

    return _offload(_run)


def rerank(query: str, docs: Sequence[str]) -> list[float]:
    """ scores how relevant each document is to the query,
    using the local model.

    Score (query, doc) pairs → 0-100. bge-reranker (num_labels==1) already applies
    sigmoid in `predict`, so its output is a [0,1] probability — scale x 100 and clamp
    (do NOT sigmoid again). Re-calibrate the 60/75 bands per §8.4 if the model changes."""
    if not docs:  # ponytail: no candidates → no model load, aligns with []-in-[]-out
        return []
    model = _reranker(get_settings().reranker_model)
    pairs = [(query, d) for d in docs]

    def _run():
        """The actual torch forward pass, closed over `model`/`pairs` so `_offload` can
        run it as a zero-arg callable on the native threadpool."""
        scores = model.predict(pairs)
        return [max(0.0, min(100.0, 100.0 * float(x))) for x in scores]

    return _offload(_run)


def validate_local_models(settings: Settings | None = None, *, warm: bool) -> None:
    """ checks at startup that the local AI models are
    actually present and set up correctly, so a mistake is caught right away
    instead of causing a confusing crash later, deep in the pipeline.

    Fail fast at startup when a 'local' provider is misconfigured — a missing
    path, missing `sentence-transformers`, or a dimension mismatch surfaces here
    instead of crashing deep in the pipeline. `warm=True` (workers) also loads the
    models so the first request doesn't pay the load; `warm=False` (API) only checks
    the path exists (the API doesn't ground, so it needn't hold the model in RAM)."""
    s = settings or get_settings()
    local_used = s.embedding_provider == "local" or s.reranker_provider == "local"

    # Config-level checks (always): paths exist, e5 prefix scheme is unambiguous.
    if s.embedding_provider == "local":
        if not os.path.exists(s.embedding_model):
            raise RuntimeError(f"EMBEDDING_MODEL path not found: {s.embedding_model}")
        if s.embedding_prefix_style == "auto" and "e5" not in s.embedding_model.lower():
            raise RuntimeError(
                f"EMBEDDING_PREFIX_STYLE=auto cannot infer the prefix scheme from '{s.embedding_model}'. "
                "Set EMBEDDING_PREFIX_STYLE explicitly to 'e5' or 'none' so prefixes aren't silently dropped.")
    if s.reranker_provider == "local":
        if not os.path.exists(s.reranker_model):
            raise RuntimeError(f"RERANKER_MODEL path not found: {s.reranker_model}")

    # Load-time checks (warm only): the package must be installed before we load models.
    if warm and local_used:
        if importlib.util.find_spec("sentence_transformers") is None:
            raise RuntimeError(
                "EMBEDDING/RERANKER_PROVIDER=local but 'sentence-transformers' is not installed. "
                'Build the image with `--build-arg EXTRAS=prod,local` (or `pip install -e ".[local]"`).')
        if s.embedding_provider == "local":
            dim = _embedder(s.embedding_model).get_sentence_embedding_dimension()
            if dim != s.embedding_dimensions:
                raise RuntimeError(f"EMBEDDING_DIMENSIONS={s.embedding_dimensions} but model reports {dim}")
        if s.reranker_provider == "local":
            _reranker(s.reranker_model)


if __name__ == "__main__":  # self-check: offload returns the same values (inline path here)
    assert _offload(lambda: [1.0, 2.0]) == [1.0, 2.0]
    print("local_models self-check ok")
