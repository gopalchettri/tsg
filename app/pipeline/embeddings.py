""" turns text into a list of numbers (a "vector") that
computers can compare for similarity, and remembers each result so the exact
same text is never sent to the AI model twice.

Master-library embedding cache.

Two tiers: L1 = in-process dict (fast, per-worker); L2 = MongoDB (persists across
restarts, shared across workers) when `EMBEDDING_STORE=mongo` (default). The vector
for a text is computed at most once ever; a Mongo outage degrades to compute + L1
(best-effort persistence, never breaks grounding).

Mongo doc: `{k, text, model_id, group, kind, dim, vector[]}` — `k` = a stable key over
(model_id, group, kind, sha256(text)) so a model swap or re-embed never reuses a stale
vector. `# ponytail: lazy write-through, not a precompute job — add a startup precompute
only if cold-start latency on the tiny library ever matters.`
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import Sequence

from app.core.config import get_settings
from app.core.logging import get_logger
from app.pipeline.llm import LLMClient

log = get_logger(__name__)

_L1: dict[tuple[str, str, str], dict[str, list[float]]] = {}


@lru_cache
def _vector_store():
    """ connects to the shared database (MongoDB) that stores
    these cached vectors, so they survive a restart and are shared across workers.

    L2 store handle, memoized for process lifetime (SDD §7.6) — one Mongo client/index-ensure per
    worker rather than per lookup; `@lru_cache` is safe here since the collection is only ever read
    lazily inside `get_vectors`'s try/except, so a Mongo outage never bubbles up from here."""
    import pymongo

    s = get_settings()
    col = pymongo.MongoClient(s.mongo_url, serverSelectionTimeoutMS=s.mongo_connect_timeout_ms)[s.mongo_db]["embeddings"]
    col.create_index("k", unique=True)
    return col


def _cache_key(model_id: str, group: str, kind: str, text: str) -> str:
    """ builds a unique label for one cached vector, so
    switching AI models (or re-embedding the same text differently) never
    accidentally reuses an old, wrong vector.

    L1/L2 cache key: model + group + kind + text hash, so switching embedding models or
    re-embedding under a different group/kind never collides with (or reuses) a stale vector."""
    return f"{model_id}|{group}|{kind}|" + hashlib.sha256(text.encode()).hexdigest()


def get_vectors(llm: LLMClient, texts: Sequence[str], *, model_id: str, group: str,
                kind: str = "passage") -> dict[str, list[float]]:
    """ for a list of texts, returns their vectors — reusing
    any that are already cached, and only asking the AI model for the ones
    that are genuinely missing.

    Return {text: vector}, computing each vector at most once (L1 → L2 Mongo → embed)."""
    l1 = _L1.setdefault((model_id, group, kind), {})
    use_mongo = get_settings().embedding_store == "mongo"
    result: dict[str, list[float]] = {}
    missing: list[str] = []
    for t in dict.fromkeys(texts):
        if t in l1:
            result[t] = l1[t]
        else:
            missing.append(t)

    # L2: MongoDB (one batched read)
    if missing and use_mongo:
        try:
            keys = {_cache_key(model_id, group, kind, t): t for t in missing}
            for doc in _vector_store().find({"k": {"$in": list(keys)}}):
                t = keys[doc["k"]]
                l1[t] = result[t] = doc["vector"]
        except Exception:  # noqa: BLE001 — Mongo down → compute + L1
            log.warning("embedding store (mongo) read failed; computing in-process", exc_info=True)
            use_mongo = False
    # Drop whatever L2 served — UNCONDITIONAL so a mid-cursor failure still trims the rows
    # we did get, instead of redundantly re-embedding them below.
    missing = [t for t in missing if t not in result]

    # Compute whatever is still missing; write through to Mongo.
    # ponytail: no lock — under the gevent pool two greenlets may both compute an
    # overlapping text; harmless (deterministic vectors + idempotent upsert), just
    # redundant work. Add a per-key lock only if duplicate embed cost ever matters.
    if missing:
        vecs = llm.embed(missing, kind=kind)
        if len(vecs) != len(missing):  # partial/short provider response → fail loud HERE,
            raise RuntimeError(        # not as an opaque KeyError at the return below.
                f"embed returned {len(vecs)} vectors for {len(missing)} texts")
        docs = []
        for t, vec in zip(missing, vecs):
            l1[t] = result[t] = vec
            docs.append({"k": _cache_key(model_id, group, kind, t), "text": t, "model_id": model_id,
                         "group": group, "kind": kind, "dim": len(vec), "vector": vec})
        if use_mongo and docs:
            try:
                from pymongo import UpdateOne

                _vector_store().bulk_write([UpdateOne({"k": d["k"]}, {"$set": d}, upsert=True) for d in docs])
            except Exception:  # noqa: BLE001 — persistence is best-effort
                log.warning("embedding store (mongo) write failed", exc_info=True)

    # ponytail: returned vectors ALIAS the L1/Mongo cache entries (shared list objects) —
    # callers use them read-only (similarity/rerank dot products); copy before mutating in place.
    return {t: result[t] for t in texts}


def clear_cache(group: str | None = None) -> None:
    """ wipes the fast in-worker cache (not the shared
    database) — for when the cached vectors might be stale. Not currently
    called by any code path; a future master-edit feature would call this.

    Clear L1 (Mongo persists by design; delete Mongo docs explicitly if a master's text changes)."""
    if group is None:
        _L1.clear()
    else:
        for key in [k for k in _L1 if k[1] == group]:
            _L1.pop(key, None)
