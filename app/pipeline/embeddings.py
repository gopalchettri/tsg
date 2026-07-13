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
import time
from functools import lru_cache
from typing import Sequence

from app.core.config import get_settings
from app.core.logging import get_logger
from app.pipeline.llm import LLMClient

log = get_logger(__name__)

# L1 cache: one small dict per (model_id, group, kind), mapping text -> its vector.
_L1: dict[tuple[str, str, str], dict[str, list[float]]] = {}

# Circuit breaker around _vector_store(): @lru_cache never memoizes an exception, so
# without this a sustained Mongo outage re-runs the full MongoClient+create_index
# handshake (bounded by mongo_connect_timeout_ms) on every single get_vectors() call.
# Once that handshake fails, skip retrying it until the cooldown elapses.
# ponytail: fixed cooldown, not exponential backoff — add growth only if outages are
# routinely long enough that even one retry every 30s is a measurable cost.
_BREAKER_COOLDOWN_S = 30.0
_breaker_open_until = 0.0


@lru_cache
def _vector_store():
    """ connects to the shared database (MongoDB) that stores
    these cached vectors, so they survive a restart and are shared across workers.

    L2 store handle, memoized for process lifetime (SDD §7.6) — one Mongo client/index-ensure per
    worker rather than per lookup; `@lru_cache` is safe here since the collection is only ever read
    lazily inside `get_vectors`'s try/except, so a Mongo outage never bubbles up from here."""
    # imported here, not at module top, so pymongo is only required when the Mongo store is actually used
    import pymongo

    s = get_settings()
    # embeddings should be read from the .env file similar to the connection string
    # serverSelectionTimeoutMS only bounds picking a server; without socketTimeoutMS a
    # reachable-but-stuck server (overloaded, stuck lock) can hang find()/bulk_write()
    # forever, bypassing the except-Exception fallback below. Bound both.
    col = pymongo.MongoClient(
        s.mongo_url,
        serverSelectionTimeoutMS=s.mongo_connect_timeout_ms,
        connectTimeoutMS=s.mongo_connect_timeout_ms,
        socketTimeoutMS=s.mongo_connect_timeout_ms,
    )[s.mongo_db]["embeddings"]
    col.create_index("k", unique=True)
    return col


def _store_if_healthy():
    """`_vector_store()`, unless the breaker is open (a recent connect attempt failed
    and the cooldown hasn't elapsed yet) — in which case return None without paying
    for another connect+create_index handshake against a still-down Mongo. Resets the
    breaker on success so a recovered Mongo is used again immediately."""
    global _breaker_open_until
    now = time.monotonic()
    if now < _breaker_open_until:
        return None
    try:
        col = _vector_store()
    except Exception:  # noqa: BLE001 — Mongo down → open the breaker, compute + L1
        _breaker_open_until = now + _BREAKER_COOLDOWN_S
        log.warning("embedding store (mongo) unreachable; backing off %.0fs",
                    _BREAKER_COOLDOWN_S, exc_info=True)
        return None
    _breaker_open_until = 0.0
    return col


def _cache_key(model_id: str, group: str, kind: str, text: str) -> str:
    """ builds a unique label for one cached vector, so
    switching AI models (or re-embedding the same text differently) never
    accidentally reuses an old, wrong vector.

    L1/L2 cache key: model + group + kind + text hash, so switching embedding models or
    re-embedding under a different group/kind never collides with (or reuses) a stale vector."""
    return f"{model_id}|{group}|{kind}|" + hashlib.sha256(text.encode()).hexdigest()


def _l1_lookup(l1: dict[str, list[float]],
                texts: Sequence[str]) -> tuple[dict[str, list[float]], list[str]]:
    """ checks the fast in-worker cache first, so a text
    already seen by this worker skips both Mongo and the AI model entirely.

    L1 tier: split deduped input texts into already-cached (result) and missing."""
    result: dict[str, list[float]] = {}
    missing: list[str] = []
    # dict.fromkeys(texts) removes duplicate texts while keeping their order, so each
    # unique text is only looked up/embedded once even if it appears twice in the input.
    for t in dict.fromkeys(texts):
        if t in l1:
            result[t] = l1[t]
        else:
            missing.append(t)
    return result, missing


def _l2_read(l1: dict[str, list[float]], result: dict[str, list[float]], missing: list[str],
            model_id: str, group: str, kind: str) -> bool:
    """ checks the shared database (Mongo) for any texts the
    fast in-worker cache didn't have, so other workers' (or a past restart's)
    already-computed vectors get reused instead of recomputed.

    L2 tier: one batched Mongo read for texts missing from L1. Mutates l1/result in place with
    whatever Mongo serves; returns whether Mongo is still usable for the write-back tier below."""
    col = _store_if_healthy()
    if col is None:
        return False
    try:
        keys = {_cache_key(model_id, group, kind, t): t for t in missing}
        for doc in col.find({"k": {"$in": list(keys)}}):
            t = keys[doc["k"]]
            l1[t] = result[t] = doc["vector"]
        return True
    except Exception:  # noqa: BLE001 — Mongo down → compute + L1
        log.warning("embedding store (mongo) read failed; computing in-process", exc_info=True)
        return False


def _embed_missing(llm: LLMClient, missing: list[str], kind: str) -> list[list[float]]:
    """ asks the AI model for vectors for whatever text is still
    missing after checking both caches — the only tier that actually costs
    money/latency.

    External embedding-service tier: embed every text still missing after L1 + L2."""
    vecs = llm.embed(missing, kind=kind)
    if len(vecs) != len(missing):  # partial/short provider response → fail loud HERE,
        raise RuntimeError(        # not as an opaque KeyError at the return below.
            f"embed returned {len(vecs)} vectors for {len(missing)} texts")
    return vecs


def _stage_for_write(l1: dict[str, list[float]], result: dict[str, list[float]], missing: list[str],
                    vecs: list[list[float]], model_id: str, group: str, kind: str) -> list[dict]:
    """ saves each freshly computed vector into the fast
    in-worker cache and prepares it to be written to the shared database.

    For each newly computed vector: save it into L1/result, and stage a matching
    document so it can be written through to Mongo below."""
    docs = []
    for t, vec in zip(missing, vecs):
        l1[t] = result[t] = vec
        docs.append({"k": _cache_key(model_id, group, kind, t), "text": t, "model_id": model_id,
                    "group": group, "kind": kind, "dim": len(vec), "vector": vec})
    return docs


def _l2_write(docs: list[dict]) -> None:
    """ saves freshly computed vectors into the shared database
    so other workers (and this one, after a restart) can reuse them instead of
    recomputing.

    L2 write-back tier: best-effort upsert of newly computed vectors into Mongo."""
    col = _store_if_healthy()
    if col is None:
        return
    try:
        from pymongo import UpdateOne

        col.bulk_write([UpdateOne({"k": d["k"]}, {"$set": d}, upsert=True) for d in docs])
    except Exception:  # noqa: BLE001 — persistence is best-effort
        log.warning("embedding store (mongo) write failed", exc_info=True)


def get_vectors(llm: LLMClient, texts: Sequence[str], *, model_id: str, group: str,
                kind: str = "passage") -> dict[str, list[float]]:
    """ for a list of texts, returns their vectors — reusing
    any that are already cached, and only asking the AI model for the ones
    that are genuinely missing.

    Return {text: vector}, computing each vector at most once (L1 → L2 Mongo → embed)."""
    # Get (or create) this model/group/kind combo's own L1 dict.
    l1 = _L1.setdefault((model_id, group, kind), {})
    use_mongo = get_settings().embedding_store == "mongo"
    result, missing = _l1_lookup(l1, texts)

    # L2: MongoDB (one batched read)
    if missing and use_mongo:
        use_mongo = _l2_read(l1, result, missing, model_id, group, kind)
    # Drop whatever L2 served — UNCONDITIONAL so a mid-cursor failure still trims the rows
    # we did get, instead of redundantly re-embedding them below.
    missing = [t for t in missing if t not in result]

    # Compute whatever is still missing; write through to Mongo.
    # ponytail: no lock — under the gevent pool two greenlets may both compute an
    # overlapping text; harmless (deterministic vectors + idempotent upsert), just
    # redundant work. Add a per-key lock only if duplicate embed cost ever matters.
    if missing:
        vecs = _embed_missing(llm, missing, kind)
        docs = _stage_for_write(l1, result, missing, vecs, model_id, group, kind)
        if use_mongo and docs:
            _l2_write(docs)

    # returned vectors ALIAS the L1/Mongo cache entries (shared list objects) —
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
        # Each L1 key is (model_id, group, kind); k[1] is the group, so this only
        # drops entries belonging to the requested group and leaves the rest alone.
        for key in [k for k in _L1 if k[1] == group]:
            _L1.pop(key, None)
