"""Master-library embedding cache.

Two tiers: L1 = in-process dict (per worker). L2 = MongoDB (shared across workers, survives
restarts) when EMBEDDING_STORE=mongo (default). If Mongo is down, falls back to compute + L1 —
grounding still works, just without persistence.

Mongo doc shape: {k, text, model_id, group, kind, dim, vector[], created_at, created_by}.
`k` = hash of (model_id, group, kind, text), so a model swap or re-embed never reuses a stale
vector.

ponytail: writes lazily on first use, not precomputed at startup — add precompute only if
cold-start latency becomes a real problem.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Sequence
from contextlib import contextmanager
from functools import lru_cache
from types import ModuleType
from typing import Any

from redis.exceptions import LockNotOwnedError
from redis.lock import Lock
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# numpy comes with the optional sentence-transformers extra — a litellm-proxy-only deployment
# may not have it. get_matrix() returns None without it; callers fall back to per-vector dicts.
try:
    import numpy
    _np: ModuleType | None = numpy
except ImportError:  # pragma: no cover — exercised only in numpy-less deployments
    _np = None

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db import models as m
from app.db.dal import now
from app.pipeline.llm import LLMClient, LLMSlotUnavailable, _slot_redis

log = get_logger(__name__)

# Written into each new Mongo doc's created_by. Overridden by non-API entrypoints:
# celery_app sets "worker", scripts/refresh_embeddings.py sets "cli".
process_role = "api"

# Control embed text = "Name: Description". coalesce() because a NULL description would NULL
# the whole concat and drop the control from the corpus. Every reader shares this expression so
# the refresh and query paths always embed the identical text (same cache key).
_CONTROL_TEXT = m.Control_Library.ControlName + ": " + func.coalesce(m.Control_Library.ControlDescription, "")

# group name -> (table, name column). Single source of truth — the admin API and
# scripts/refresh_embeddings.py both use this instead of re-deriving it. Groups whose text is
# gathered through a JOIN (threat_catalogue) carry a None column and are handled by
# _group_texts' special case instead. That case survives the removal of Description: the passage
# is now name-only, but the eligibility filter still needs the join, because a catalogue row whose
# TYPE is inactive must not be warmed (retrieval will not query it either — warm set == query set).
# The text itself comes from the shared catalogue_passage_text so warm-cache and query bytes cannot
# drift (G10: the pre-2026-08 group warmed bare names while retrieval embedded name+description, so
# retrieval vectors were never pre-warmed; sharing the composer removed that class of bug).
_GROUPS = {
    "threat_type": (m.Threat_Type, m.Threat_Type.ThreatTypeName),
    "threat_catalogue": (m.Threat_Catalogue, None),
    "control_library": (m.Control_Library, _CONTROL_TEXT),
    # Actor names for the nearest-match fallback (library-first actors): bare labels — the
    # table has no description column. Name-only vectors are weak alone, so the consumer
    # pairs them with the BM25 keyword leg via hybrid_search.hybrid_match.
    "threat_actor": (m.Threat_Actor, m.Threat_Actor.ThreatActorName),
}


def catalogue_passage_text(name, limit: int) -> str:
    """THE passage text for one catalogue threat — the name, truncated to the embed limit.

    Was name + ": " + description until Threat_Catalogue.Description was removed as unused; the
    passage is now name-only. Kept as a function rather than inlined because its whole job is that
    retrieval's corpus build and this module's warm/refresh path produce the SAME BYTES (G10) —
    including the same truncation. Two call sites each doing their own [:limit] is exactly the
    drift this prevents."""
    return str(name or "").strip()[:limit]


def _catalogue_texts(sess: Session) -> list[str]:
    """Composed passage texts for every RETRIEVABLE catalogue threat (live row, active type —
    the same eligibility retrieval applies, so the warm set is exactly the query set)."""
    limit = get_settings().max_embed_chars
    tc, tt = m.Threat_Catalogue, m.Threat_Type
    return [catalogue_passage_text(name, limit)
            for (name,) in sess.execute(
                select(tc.ThreatName)
                .select_from(tc.__table__.join(tt.__table__, tt.ThreatTypeID == tc.ThreatTypeID))
                .where(tc.IsActive == True, tc.IsDeleted == False,
                    tt.IsActive == True, tt.IsDeleted == False)
                .order_by(tc.ThreatCatalogueID)).all()]


def _group_texts(sess: Session, group: str) -> list[str]:
    """The authoritative embeddable texts for one group — composed for threat_catalogue,
    single-column via _active_names for everything else."""
    if group == "threat_catalogue":
        return _catalogue_texts(sess)
    table, name_col = _GROUPS[group]
    return _active_names(sess, table, name_col)


class EmbeddingBusy(Exception):
    """Another admin call is already recreating/deleting this group's cache -> 409."""

# L1 cache: one small dict per (model_id, group, kind), mapping text -> its vector.
_L1: dict[tuple[str, str, str], dict[str, list[float]]] = {}

# Matrix cache: pre-normalized float32 matrices per (model_id, group, kind), so similarity
# search doesn't re-pack vectors on every query. Value = {texts-digest: (normalized matrix,
# row -> text-index map)}, insertion-ordered and bounded to _MATRIX_SHAPES entries per key:
# one group legitimately serves SEVERAL text-list shapes at once (threat_catalogue holds the
# relevance gate's Top-K subset AND regrounding's full corpus), and the previous one-slot
# design made those two evict each other on every single run — up to
# threat_llm_max_generation full-matrix rebuilds per run that never warmed across runs.
# clear_cache() drops whole keys, unchanged.
_MATRIX: dict[tuple[str, str, str], dict[str, tuple[Any, list[int]]]] = {}
#: Distinct text-list shapes kept warm per (model, group, kind); oldest evicted beyond this.
_MATRIX_SHAPES = 4

# Circuit breaker for _vector_store(): @lru_cache doesn't memoize exceptions, so without this
# a Mongo outage retries the full connect handshake on every get_vectors() call. Once it fails,
# skip retrying until mongo_breaker_cooldown_seconds elapses (default 30s).
# ponytail: fixed cooldown, not backoff — add growth only if outages regularly outlast it.
_breaker_open_until = 0.0


@lru_cache
def _vector_store():
    """L2 store handle, memoized for process lifetime — one Mongo client/index-ensure per worker
    rather than per lookup."""
    # imported here, not at module top, so pymongo is only required when Mongo is actually used
    import pymongo

    s = get_settings()
    # serverSelectionTimeoutMS only bounds picking a server — without socketTimeoutMS too, a
    # stuck-but-reachable server can hang find()/bulk_write() forever. Bound both.
    col = pymongo.MongoClient(
        s.mongo_url,
        serverSelectionTimeoutMS=s.mongo_connect_timeout_ms,
        connectTimeoutMS=s.mongo_connect_timeout_ms,
        socketTimeoutMS=s.mongo_connect_timeout_ms,
    )[s.mongo_db]["embeddings"]
    col.create_index("k", unique=True)
    return col


def _store_if_healthy():
    """_vector_store(), or None while the breaker is open (skip retrying a still-down Mongo).
    Resets on success so a recovered Mongo is used again."""
    global _breaker_open_until
    now = time.monotonic()
    if now < _breaker_open_until:
        return None
    try:
        col = _vector_store()
    except Exception:
        cooldown = get_settings().mongo_breaker_cooldown_seconds
        _breaker_open_until = now + cooldown
        log.warning("embeddings.mongo_breaker_open", cooldown_seconds=cooldown, exc_info=True)
        return None
    _breaker_open_until = 0.0
    return col


def _cache_key(model_id: str, group: str, kind: str, text: str) -> str:
    """L1/L2 cache key: model + group + kind + text hash, so switching embedding models or
    re-embedding under a different group/kind never reuses a stale vector."""
    return f"{model_id}|{group}|{kind}|" + hashlib.sha256(text.encode()).hexdigest()


def _l1_lookup(l1: dict[str, list[float]],
                texts: Sequence[str]) -> tuple[dict[str, list[float]], list[str]]:
    """L1 tier: split deduped input texts into already-cached (result) and missing."""
    result: dict[str, list[float]] = {}
    missing: list[str] = []
    # dict.fromkeys dedupes while keeping order, so a repeated text is only embedded once
    for t in dict.fromkeys(texts):
        if t in l1:
            result[t] = l1[t]
        else:
            missing.append(t)
    return result, missing


def _l2_read(l1: dict[str, list[float]], result: dict[str, list[float]], missing: list[str],
            model_id: str, group: str, kind: str) -> bool:
    """L2 tier: one batched Mongo read for texts missing from L1. Mutates l1/result in place with
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
    except Exception:
        log.warning("embedding store (mongo) read failed; computing in-process", exc_info=True)
        return False


def _embed_missing(llm: LLMClient, missing: list[str], kind: str) -> list[list[float]]:
    """External embedding-service tier: embed ONE batch of texts missing from L1 + L2.

    Embeds exactly the slice get_vectors hands it and caps nothing of its own — the provider's
    per-request limit belongs to LiteLLMClient.embed, which applies it to every caller rather than
    only the ones that remember to. The length guard stays: embed() asserts alignment per provider
    request, and this catches a non-conforming LLMClient implementation before it becomes a
    confusing KeyError in _stage_for_write's zip.
    """
    vecs = llm.embed(missing, kind=kind)
    if len(vecs) != len(missing):  # fail loud here, not as a confusing KeyError later
        raise RuntimeError(f"embed returned {len(vecs)} vectors for {len(missing)} texts")
    return vecs


def _stage_for_write(l1: dict[str, list[float]], result: dict[str, list[float]], missing: list[str],
                    vecs: list[list[float]], model_id: str, group: str, kind: str) -> list[dict]:
    """Save each newly computed vector into L1/result and stage its Mongo doc for write-back."""
    docs = []
    for t, vec in zip(missing, vecs):
        l1[t] = result[t] = vec
        docs.append({"k": _cache_key(model_id, group, kind, t), "text": t, "model_id": model_id,
                    "group": group, "kind": kind, "dim": len(vec), "vector": vec})
    return docs


def _l2_write(docs: list[dict]) -> None:
    """L2 write-back tier: best-effort upsert of newly computed vectors into Mongo."""
    col = _store_if_healthy()
    if col is None:
        return
    try:
        from pymongo import UpdateOne

        # $setOnInsert keeps creation provenance across re-upserts — a recompute updates the
        # vector but not who/when first created the doc.
        prov = {"created_at": now(), "created_by": process_role}
        col.bulk_write([UpdateOne({"k": d["k"]}, {"$set": d, "$setOnInsert": prov}, upsert=True)
                        for d in docs])
    except Exception:
        log.warning("embedding store (mongo) write failed", exc_info=True)


def get_vectors(llm: LLMClient, texts: Sequence[str], *, model_id: str, group: str,
                kind: str = "passage") -> dict[str, list[float]]:
    """Return {text: vector}, computing each vector at most once (L1 → L2 Mongo → embed)."""
    l1 = _L1.setdefault((model_id, group, kind), {})
    use_mongo = get_settings().embedding_store == "mongo"
    result, missing = _l1_lookup(l1, texts)

    if missing and use_mongo:
        use_mongo = _l2_read(l1, result, missing, model_id, group, kind)
    # unconditional: even a mid-cursor Mongo failure still trims whatever rows we did get,
    # so they aren't redundantly re-embedded below
    missing = [t for t in missing if t not in result]

    # ponytail: no per-key lock — two greenlets computing the same text is harmless
    # (deterministic vectors, idempotent upsert), just redundant work. Add a lock only if
    # that cost matters.
    if missing:
        # Persist per batch, not once at the end. A full recreate is ~1100 distinct texts across
        # ~37 provider calls, so writing only after ALL of them means a timeout or 429 on the last
        # call discards every vector already paid for — and the Celery retry re-embeds all 1100.
        # Writing as we go makes a retry cheap instead: _l2_read above finds whatever the failed
        # run already persisted and only the genuinely missing tail is re-embedded.
        #
        # This loop exists for DURABLE PROGRESS, not to cap anything — the provider's per-request
        # limit belongs solely to LiteLLMClient.embed, which enforces it whether or not anyone
        # batches here. Reusing embedding_batch_size just keeps the two aligned 1:1 on the proxy
        # path, so each pass is one provider call and one Mongo write; on the `local` path, where
        # no request cap exists, the value is purely this write-back granularity.
        #
        # The cost is one LLM-slot acquisition per batch instead of one for the whole run (see
        # LiteLLMClient.embed). That trade is deliberate: losing a slot mid-run now costs only the
        # batch in flight, where before it discarded every vector already paid for.
        s = get_settings()
        batch, conc = s.embedding_batch_size, s.embedding_concurrency

        def _embed_and_persist(chunk: list[str]) -> None:
            """One batch, end to end: embed it, stage it, persist it. Safe to run concurrently —
            _stage_for_write only assigns into l1/result by TEXT KEY and performs no I/O, so it
            cannot interleave into a corrupt dict under gevent greenlets (cooperative, no yield
            point inside it) or under real threads (each dict store is one atomic bytecode)."""
            vecs = _embed_missing(llm, chunk, kind)
            docs = _stage_for_write(l1, result, chunk, vecs, model_id, group, kind)
            if use_mongo and docs:
                _l2_write(docs)

        chunks = [missing[i:i + batch] for i in range(0, len(missing), batch)]
        if conc <= 1 or len(chunks) == 1:
            for chunk in chunks:  # sequential: no pool, no threads, no behaviour change
                _embed_and_persist(chunk)
        else:
            # Bounded pool, same shape as llm.rerank_many: every concurrent embed() call takes
            # its own _llm_slot, so the Redis semaphore stays the global authority and this is
            # only a local politeness cap. Batches are independent — each persists its own work,
            # and get_vectors returns a dict keyed by text, so completion order is irrelevant.
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=min(conc, len(chunks))) as pool:
                futures = [pool.submit(_embed_and_persist, c) for c in chunks]
            # Pool exited => every future is done (shutdown waits). Retrieve EVERY exception
            # before re-raising the first: an unretrieved future logs a spurious warning when it
            # is garbage-collected, and a sibling's failure must not mask the one we report.
            # Batches that did succeed stay persisted, so the retry re-embeds only the tail.
            failures = [e for e in (f.exception() for f in futures) if e is not None]
            if failures:
                raise failures[0]

    # returned vectors are the SAME list objects as the cache entries — callers must treat
    # them read-only (copy before mutating in place)
    return {t: result[t] for t in texts}


def get_matrix(llm: LLMClient, texts: Sequence[str], *, model_id: str, group: str,
            kind: str = "passage") -> tuple[Any, list[int]] | None:
    """Pre-normalized similarity matrix over `texts`, cached per (model, group, kind).

    Returns (matrix, row_indexes): matrix rows are L2-normalized float32 vectors, and
    row_indexes[i] is the position in `texts` that row i came from (mismatched-dimension
    vectors are skipped, same as grounding._shortlist_candidates). Cosine similarity against
    every text is then one `matrix @ q_unit`. Returns None if numpy is unavailable or nothing
    is usable.
    """
    if _np is None or not texts:
        return None
    digest = hashlib.sha256("\x1f".join(texts).encode()).hexdigest()
    key = (model_id, group, kind)
    slot = _MATRIX.get(key)
    if slot is not None:
        hit = slot.get(digest)
        if hit is not None:
            return hit
    vecs = get_vectors(llm, texts, model_id=model_id, group=group, kind=kind)
    dim = len(vecs[texts[0]])
    rows, row_indexes = [], []
    for i, t in enumerate(texts):
        v = vecs[t]
        if len(v) != dim:
            log.warning("embeddings.matrix_dimension_mismatch_skipped", group=group, text=t[:80])
            continue
        rows.append(v)
        row_indexes.append(i)
    if not rows:
        return None
    mat = _np.asarray(rows, dtype=_np.float32)
    norms = _np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0  # zero-magnitude rows stay all-zero -> cosine 0, hybrid_search.cosine's convention
    mat = mat / norms
    slot = _MATRIX.setdefault(key, {})
    slot[digest] = (mat, row_indexes)
    while len(slot) > _MATRIX_SHAPES:  # insertion-ordered dict: oldest shape goes first
        slot.pop(next(iter(slot)))
    return mat, row_indexes


def clear_cache(group: str | None = None) -> None:
    """Clear L1 only — Mongo persists by design; use delete_cached to drop the L2 docs too."""
    if group is None:
        _L1.clear()
        _MATRIX.clear()
    else:
        for key in [k for k in _L1 if k[1] == group]:  # k[1] is the group
            _L1.pop(key, None)
        # dropping the matrix here catches a recreate that re-embeds the SAME texts to different
        # vectors — the digest check in get_matrix alone wouldn't notice that
        for key in [k for k in _MATRIX if k[1] == group]:
            _MATRIX.pop(key, None)


def delete_cached(group: str, names: list[str] | None = None, *, strict: bool = False,
                sess: Session | None = None) -> int:
    """Wipe both tiers for a group (or just `names` within it): L1 plus the persisted Mongo docs.
    For a genuine recreate/delete — a plain model bump needs none of this, since get_vectors'
    cache key already includes model_id and just misses.

    `names` only scopes the L2 delete; L1 has no per-text filter, so the whole group's L1 is
    cleared (a few extra recomputes, not a correctness problem).

    Returns the number of Mongo docs deleted (0 if Mongo is unreachable).
    """
    col = _store_if_healthy()
    if col is None:
        clear_cache(group)  # L2 unreachable — still drop L1 so a stale vector isn't served from it
        if strict and names:
            # can't verify a named delete without the store — reporting 0-with-SUCCESS would
            # hide that the vector still exists in Mongo. Fail instead; safe to retry later.
            raise UnknownEmbeddingNames(
                f"vector store unreachable — cannot verify or delete {group} name(s): "
                f"{sorted(names)}; nothing was deleted, retry when it recovers")
        return 0
    query: dict[str, Any] = {"group": group}
    if names is not None:
        # resolve to the spelling(s) actually stored: Mongo `text` matches byte-exact (no
        # collation), so a case-/whitespace-different name would delete 0 docs and still report
        # success. Resolve once, here, against the collection we already hold.
        resolved, unmatched = _resolve_names(_stored_texts(col, group), names)
        # strict is the delete route's contract; recreate stays lenient since its names come
        # from the master table and may legitimately have no vector cached yet
        if strict and unmatched:
            # a name whose vector a prior cleanup already deleted must SUCCEED with 0 deleted;
            # a name matching nothing anywhere is a typo and must fail loudly
            known = _known_master_names(sess, group, unmatched)
            if known:
                log.info("embeddings.delete_already_clean", group=group, names=sorted(known))
            unmatched = [n for n in unmatched if n not in known]
            if unmatched:
                # raise before clear_cache below — a rejected request must not wipe L1 as a side effect
                raise UnknownEmbeddingNames(
                    f"name(s) match neither a cached {group} vector nor an active master row: "
                    f"{sorted(unmatched)} — nothing was deleted")
        query["text"] = {"$in": resolved}
    clear_cache(group)  # L1 has no per-text filter, so the whole group goes (extra recomputes only)
    return col.delete_many(query).deleted_count


# The grounding threshold NO LONGER LIVES HERE. `_thresholds_col`/`load_thresholds`/
# `store_thresholds` used to keep it in a sibling `grounding_thresholds` collection; they are gone
# and the collection is retired (see scripts/TSG_Migration_GroundingCalibration.sql). It is now a
# column on Grounding_Calibration_Run, read by grounding.latest_successful_run.
#
# Not a preference — three real defects went with them. (1) store_thresholds was best-effort and
# swallowed its own failures, so a finished 15-minute sweep could lose its answer to a Mongo blip
# and leave only a log line. (2) The upsert filter had no unique index, so concurrent writes could
# create duplicate docs and find_one would then return an arbitrary one. (3) _thresholds_col
# reached Mongo VIA the embeddings handle, so a failure ensuring the `embeddings` index made the
# threshold unreachable too — an unrelated cache problem silently downgrading every grounding
# decision. The `embeddings` collection above is unaffected; only the threshold left Mongo.


def _known_master_names(sess: Session | None, group: str, names: list[str]) -> set[str]:
    """Subset of `names` that resolves (case/space-insensitive) to an active master row. Lets
    delete_cached's strict check tell "already clean" (success) from "typo" (failure). No sess
    means we can't check, so treat none as known (fail-strict).
    """
    if sess is None or not names:
        return set()
    resolved_pairs = _resolve_names(_group_texts(sess, group), names)
    # _resolve_names returns master spellings; fold to find which INPUT names matched
    unmatched_folded = {str(u).strip().lower() for u in resolved_pairs[1]}
    return {n for n in names if str(n).strip().lower() not in unmatched_folded}


class UnknownEmbeddingNames(ValueError):
    """One or more client-supplied `names` matched no authoritative row/vector. Surfaces via
    _for_each_group as an "error: ..." per-group result, not a false SUCCESS count.
    """


def _resolve_names(candidates: list[str], names: list[str]) -> tuple[list[str], list[str]]:
    """Map client-supplied `names` onto the authoritative spelling in `candidates` (case-/
    whitespace-insensitive match). Returns (resolved, unmatched).

    Needed because names come from MSSQL NVARCHAR (case-/space-insensitive collation) but are
    used as byte-exact MongoDB keys. Without resolution, a name that looks identical in the UI
    matches nothing — delete removes 0 vectors, recreate embeds an orphan under a key grounding
    never looks up, and both report SUCCESS.

    One folded key can map to MULTIPLE stored spellings, e.g. "Denial of Service" and "denial
    of service" are separate Mongo docs (the unique index includes the raw text). Keep all of
    them, or a delete would remove one and silently leave the other live.
    """
    index: dict[str, list[str]] = {}
    for c in candidates:
        index.setdefault(str(c).strip().lower(), []).append(c)
    resolved: list[str] = []
    # prefix keys let control_library be addressed by its human name — that group's stored text
    # is the full "ControlName: ControlDescription", which no one types verbatim. A full-text
    # match always wins over a prefix match.
    prefix_index: dict[str, list[str]] = {}
    for c in candidates:
        text = str(c)
        if ": " in text:
            prefix_index.setdefault(text.split(": ", 1)[0].strip().lower(), []).append(c)
    unmatched: list[str] = []
    for n in names:
        folded = str(n).strip().lower()
        actual = index.get(folded) or prefix_index.get(folded)
        if actual:
            # dedupe: two client spellings of one name resolve to the SAME stored spelling(s),
            # and a repeat is a redundant paid embed on the create/recreate path
            resolved.extend(a for a in actual if a not in resolved)
        else:
            unmatched.append(n)
    return resolved, unmatched


def _stored_texts(col, group: str) -> list[str]:
    """text values this group actually has vectors for — the candidate set for a delete, since a
    vector can outlive its master row (clearing that orphan is fine). Takes the caller's
    collection handle so a named delete costs one `distinct` round-trip.
    """
    return list(col.distinct("text", {"group": group}))


def _active_names(sess: Session, table, name_col) -> list[str]:
    """Active (IsActive, not IsDeleted) names for one embedding group's table — the DB-side
    counterpart to _GROUPS above.

    Over-limit rows are SKIPPED here, loudly. llm.embed rejects text above max_embed_chars rather
    than truncating it, and it embeds in BATCHES — so without this one oversized row raises for the
    whole call, the entire group fails to embed, and for control_library that stops control mapping
    across every asset and every session until somebody finds the offending row.

    The API caps control_name/control_description (schemas.py) so such a row cannot be CREATED
    there, but scripts/Seed_to_Control_library.sql writes rows with direct INSERT and bypasses
    Pydantic entirely. This is the guard that covers every writer, whatever route it took.

    Deliberately generic rather than control-specific: an over-long threat-type name fails the
    same way, and this is the one gatherer every group already shares. Skipping costs that ONE row
    its vector (it drops out of the semantic leg; the keyword leg still finds it); NOT skipping
    costs the entire group.
    """
    limit = get_settings().max_embed_chars
    names: list[str] = []
    oversized: list[str] = []
    for n in sess.execute(
        select(name_col).where(table.IsActive == True, table.IsDeleted == False)
    ).scalars().all():
        if n is not None and len(str(n)) > limit:
            oversized.append(str(n)[:120])
            continue
        names.append(n)
    if oversized:
        # ERROR, not warning: the row is silently absent from the corpus until it is fixed, and
        # the prefix is included so it can actually be found.
        log.error("embeddings.row_too_long_skipped", table=table.__tablename__,
                limit=limit, skipped=len(oversized), samples=oversized[:3])
    return names

def _renew_group_lock_loop(lock: Lock, interval: float, stop_event: threading.Event) -> None:
    """Refreshes the group lock's TTL every `interval` seconds, so a slow embed call doesn't
    outlive the lock's fixed TTL and have it expire mid-operation. Same idea as llm.py's
    _heartbeat_loop.

    Runs on a separate thread from the one that called lock.acquire() — thread_local=False on
    the Lock (see _group_lock) is what lets this thread see the same ownership token.
    """
    while not stop_event.wait(interval):
        try:
            lock.extend(lock.timeout, replace_ttl=True)  # reset to the full TTL, not additive
        except LockNotOwnedError:  # a stale timeout already let a different caller acquire
            pass
        except Exception:
            log.warning("embeddings.group_lock_renewal_failed", exc_info=True)


@contextmanager
def _group_lock(group: str):
    """Serializes recreate_group/delete_group per group via a Redis lock. Without it, two
    concurrent admin calls on the same group would both wipe then both re-embed (redundant
    paid LLM calls) — the second caller gets EmbeddingBusy (409) instead of racing.

    Fails open if Redis is unreachable, same as the LLM-slot limiter: this only guards against
    redundant cost, not correctness, so availability wins.
    """
    ttl = get_settings().embedding_group_lock_ttl_seconds  # must stay int — redis-py rejects a float for ex=/EXPIRE
    key = f"tsg:embed-lock:{group}"
    try:
        # thread_local=False: the heartbeat thread below must see the same ownership token the
        # acquiring thread set, or every renewal tick raises LockNotOwnedError.
        lock = Lock(_slot_redis(), key, timeout=ttl, thread_local=False)
        acquired = lock.acquire(blocking=False)
    except Exception:
        log.warning("embeddings.group_lock_redis_unavailable_fail_open", group=group, exc_info=True)
        yield
        return
    if not acquired:
        raise EmbeddingBusy(f"group {group!r} is already being recreated/deleted")
    stop_event = threading.Event()
    # plain threading.Thread, not gevent.spawn — same portability reasoning as llm.py's _llm_slot
    hb_thread = threading.Thread(
        target=_renew_group_lock_loop, args=(lock, ttl / 3, stop_event),
        daemon=True)
    hb_thread.start()
    try:
        yield
    finally:
        # stop the renewal thread before releasing — otherwise an in-flight renewal tick
        # could re-extend a lock we just released
        stop_event.set()
        hb_thread.join(timeout=ttl)
        try:
            lock.release()
        except LockNotOwnedError:  # already lost ownership to a stale-timeout retry
            pass
        except Exception:  # best-effort release; the TTL is the backstop
            log.warning("embeddings.group_lock_release_failed", group=group, exc_info=True)


class EmbeddingGroupsFailed(Exception):
    """At least one group's action failed, after every group was attempted.

    Raised by _for_each_group so admin_embedding_action_task's `except Exception` reports
    state=FAILURE. Before this existed, a failed group was folded into the results dict as an
    "error: ..." string and the job completed as SUCCESS carrying it — which is exactly how an
    embedding batch exceeding the provider's per-request cap went unnoticed.

    `results` holds the FULL per-group outcome (int rows, or an "error: ..." string) and is
    rendered into str(self), because that string is the only surface that survives to the API:
    Celery serializes results as JSON, admin.py renders a failed job via str(result.result), and
    EmbeddingJobStatus.rows_processed is populated on SUCCESS only. Without it in the message the
    operator cannot tell which groups did succeed.
    """

    def __init__(self, results: dict[str, int | str] | str) -> None:
        # Celery's result backend reconstructs an exception as cls(*args) — i.e. with the MESSAGE
        # STRING this class passes to super(), never the dict. Rejecting that form makes
        # exception_to_python fall back to a generic Exception, and the operator polling
        # GET .../embeddings/status/{job_id} sees a mangled "<class '...'>(('...',))" wrapper
        # instead of the message. Accept both shapes so the round trip is lossless where it
        # counts. `.results` is empty on the rebuilt side — nothing reads it cross-process
        # (scripts/refresh_embeddings.py catches this in the SAME process).
        if isinstance(results, str):
            self.results: dict[str, int | str] = {}
            super().__init__(results)
            return
        self.results = results
        failed = {g: v for g, v in results.items() if isinstance(v, str)}
        ok = {g: v for g, v in results.items() if not isinstance(v, str)}
        super().__init__(
            f"{len(failed)} of {len(results)} embedding group(s) failed: {failed}"
            + (f"; succeeded: {ok}" if ok else ""))


def _for_each_group(group: str | None, fn) -> dict[str, int | str]:
    """Fan-out for group=None ("all groups"): call fn(group) per group, isolating a per-group
    failure into an error string so one group's failure doesn't sink the others — then raising
    EmbeddingGroupsFailed at the END if any of them did fail.

    Isolate-then-raise, rather than raising on the spot, is deliberate: every group still gets
    attempted (a later group isn't punished for an earlier one's failure), but the JOB still
    reports the truth. Returning a dict with an error string in it, as this used to, meant a job
    that embedded nothing still reported state=SUCCESS.

    The three re-raises below must run before the generic except — they are per-group terminal
    conditions with their own contracts, not "one group among several failed".
    """
    groups = sorted(_GROUPS) if group is None else [group]
    results: dict[str, int | str] = {}
    for g in groups:
        try:
            results[g] = fn(g)
        except UnknownEmbeddingNames:
            raise  # a named action names exactly ONE group — no siblings to protect
        except EmbeddingBusy:
            raise  # a real conflict; must surface as FAILURE on GET .../status/{job_id}
        except LLMSlotUnavailable:
            raise  # transient; admin_embedding_action_task's autoretry_for retries the action
        except Exception as exc:
            log.warning("embeddings.group_action_failed", group=g, exc_info=True)
            results[g] = f"error: {exc}"
    if any(isinstance(v, str) for v in results.values()):
        raise EmbeddingGroupsFailed(results)
    return results


def create_items(sess: Session, llm: LLMClient, group: str, names: list[str]) -> int:
    """Embed specific new item(s) by name, without rescanning the whole group. Already-cached
    names are skipped by get_vectors itself.

    Names resolve against the active master rows first: grounding embeds the DB's own text, so
    embedding the operator's raw spelling would cache an orphan under a key grounding never
    looks up — a paid embed that reports SUCCESS for an item that's still effectively un-embedded.
    """
    resolved, unmatched = _resolve_names(_group_texts(sess, group), names)
    if unmatched:
        raise UnknownEmbeddingNames(
            f"no active {group} row matches name(s): {sorted(unmatched)} — nothing was embedded")
    if resolved:
        get_vectors(llm, resolved, model_id=get_settings().embedding_model, group=group, kind="passage")
    return len(resolved)


def update_group(sess: Session, llm: LLMClient, group: str) -> int:
    """Whole-group sync: embed whatever's missing across every active row. Rows already
    cached (same model + text) are skipped by get_vectors itself — cheap, always safe."""
    names = _group_texts(sess, group)
    if names:
        get_vectors(llm, names, model_id=get_settings().embedding_model, group=group, kind="passage")
    return len(names)


def recreate_group(sess: Session, llm: LLMClient, group: str, names: list[str] | None = None) -> int:
    """Force a full re-embed — deletes cached vectors first (scoped to `names` if given, else
    the whole group), then re-embeds. Serialized per group (see _group_lock)."""
    with _group_lock(group):
        active = _group_texts(sess, group)
        if names is None:
            target_names = active
        else:
            # resolve against the master rows and use that spelling for both delete and embed —
            # the client's raw spelling would delete nothing (byte-exact match) then embed an
            # orphan, leaving the stale vector live while reporting SUCCESS
            target_names, unmatched = _resolve_names(active, names)
            if unmatched:
                raise UnknownEmbeddingNames(
                    f"no active {group} row matches name(s): {sorted(unmatched)} — nothing was recreated")
        delete_cached(group, names=target_names if names is not None else None)
        if target_names:
            get_vectors(llm, target_names, model_id=get_settings().embedding_model, group=group, kind="passage")
        return len(target_names)


def delete_group(sess: Session, group: str, names: list[str] | None = None, *,
                strict: bool = True) -> int:
    """Wipe cached vectors only — no re-embed. Serialized per group (see _group_lock).

    Named deletes resolve against vectors that actually exist (a vector can outlive its master
    row). A name with no vector is then checked against active master rows: already-clean
    succeeds with 0 deleted; a name matching nothing anywhere is a typo and fails loudly.

    strict=False is for machine-derived names, where that typo check is wrong: a caller retiring
    a vector for a row it just renamed or soft-deleted reads the old text straight off the row it
    just changed, so it can't have mistyped it — even though that old text is no longer an active
    master row by the time the delete runs, indistinguishable from a typo without this escape hatch.
    """
    with _group_lock(group):
        # delete_cached already resolves once against the collection it holds — a pre-check
        # here would cost a second `distinct` and could disagree with the actual delete
        return delete_cached(group, names=names, strict=strict, sess=sess)
