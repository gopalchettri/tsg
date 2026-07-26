""" turns text into a list of numbers (a "vector") that
computers can compare for similarity, and remembers each result so the exact
same text is never sent to the AI model twice.

Master-library embedding cache.

Two tiers: L1 = in-process dict (fast, per-worker); L2 = MongoDB (persists across
restarts, shared across workers) when `EMBEDDING_STORE=mongo` (default). The vector
for a text is computed at most once ever; a Mongo outage degrades to compute + L1
(best-effort persistence, never breaks grounding).

Mongo doc: `{k, text, model_id, group, kind, dim, vector[], created_at, created_by}` — `k` = a stable key over
(model_id, group, kind, sha256(text)) so a model swap or re-embed never reuses a stale
vector. `# ponytail: lazy write-through, not a precompute job — add a startup precompute
only if cold-start latency on the tiny library ever matters.`
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid
from contextlib import contextmanager
from functools import lru_cache
from typing import Any, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

# numpy rides in with the optional sentence-transformers extra; a litellm-proxy-only
# deployment may not have it. get_matrix() returns None without it and callers fall back
# to the per-vector dict path (grounding._shortlist_candidates).
try:
    import numpy as _np
except ImportError:  # pragma: no cover — exercised only in numpy-less deployments
    _np = None

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db import models as m
from app.db.dal import now
from app.pipeline.llm import LLMClient, LLMSlotUnavailable, _slot_redis

log = get_logger(__name__)

# group name -> (table, name column) — the single source of truth for "which table/column
# each embedding group means". Both the admin API (app/api/admin.py) and the CLI script
# (scripts/refresh_embeddings.py) call the functions below rather than re-deriving this
# mapping, so they can never drift into embedding different things under the same group name.
# Control embed text = name + description: the semantic payload lives in ControlDescription,
# so embedding the short name alone would ground poorly. coalesce() because a NULL description
# would otherwise NULL the whole concat and silently drop the control from the corpus. Defined
# once at module level and shared by every reader (refresh, grounding) — cache-key equality
# between the refresh and query paths depends on both selecting the IDENTICAL text.
_CONTROL_TEXT = m.Control_Library.ControlName + ": " + func.coalesce(m.Control_Library.ControlDescription, "")

_GROUPS = {
    "threat_type": (m.Threat_Type, m.Threat_Type.ThreatTypeName),
    "threat_catalogue": (m.Threat_Catalogue, m.Threat_Catalogue.ThreatName),
    "control_library": (m.Control_Library, _CONTROL_TEXT),
}

# Who computed a vector, stamped into each new Mongo doc's created_by (provenance only).
# Module global overwritten at the non-API entrypoints (celery_app → "worker",
# scripts/refresh_embeddings.py → "cli"); the FastAPI process keeps the default.
process_role = "api"


class EmbeddingBusy(Exception):
    """Another admin call is already recreating/deleting this group's cache -> 409."""

# L1 cache: one small dict per (model_id, group, kind), mapping text -> its vector.
_L1: dict[tuple[str, str, str], dict[str, list[float]]] = {}

# Matrix cache: one pre-normalized float32 numpy matrix per (model_id, group, kind), so
# similarity search doesn't re-pack the same vectors into the same matrix on every query
# (at Control_Library scale that repack cost ~30ms x every query). Value =
# (digest of the texts it was built from, L2-row-normalized matrix, row->text-index map).
# Staleness: a changed library changes the digest -> rebuilt on next use; a re-embed of the
# SAME texts (admin recreate) routes through clear_cache() below, which drops this too.
_MATRIX: dict[tuple[str, str, str], tuple[str, Any, list[int]]] = {}

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
        log.warning("embeddings.mongo_breaker_open", cooldown_seconds=_BREAKER_COOLDOWN_S, exc_info=True)
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


_MAX_EMBED_BATCH = 100  # per-call item cap, same spirit as llm.py's _MAX_EMBED_CHARS/_MAX_CHAT_CHARS:
                        # bound one external call so a large recreate can't exceed a real provider's
                        # own batch-size limit and fail the whole group with zero partial progress.


def _embed_missing(llm: LLMClient, missing: list[str], kind: str) -> list[list[float]]:
    """ asks the AI model for vectors for whatever text is still
    missing after checking both caches — the only tier that actually costs
    money/latency.

    External embedding-service tier: embed every text still missing after L1 + L2, in
    `_MAX_EMBED_BATCH`-sized chunks so a large batch can't exceed a provider's own request-size
    limit; a single chunk failing still leaves every earlier chunk's vectors already returned."""
    vecs: list[list[float]] = []
    for i in range(0, len(missing), _MAX_EMBED_BATCH):
        chunk = missing[i:i + _MAX_EMBED_BATCH]
        chunk_vecs = llm.embed(chunk, kind=kind)
        if len(chunk_vecs) != len(chunk):  # partial/short provider response → fail loud HERE,
            raise RuntimeError(             # not as an opaque KeyError at the return below.
                f"embed returned {len(chunk_vecs)} vectors for {len(chunk)} texts")
        vecs.extend(chunk_vecs)
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

        # $setOnInsert: creation provenance survives re-upserts — a recompute refreshes the
        # vector but never rewrites who/when first created the doc.
        prov = {"created_at": now(), "created_by": process_role}
        col.bulk_write([UpdateOne({"k": d["k"]}, {"$set": d, "$setOnInsert": prov}, upsert=True)
                        for d in docs])
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


def get_matrix(llm: LLMClient, texts: Sequence[str], *, model_id: str, group: str,
               kind: str = "passage") -> tuple[Any, list[int]] | None:
    """Pre-normalized similarity matrix over `texts`, cached per (model, group, kind).

    Returns (matrix, row_indexes) — matrix rows are L2-normalized float32 vectors, and
    row_indexes[i] is the position in `texts` that matrix row i came from (rows whose cached
    vector has a mismatched dimension are skipped with a warning, same policy as
    grounding._shortlist_candidates). Cosine against every text is then one `matrix @ q_unit`.

    Cache validity is a digest over the texts themselves — a changed library rebuilds on next
    use; a re-embed of unchanged texts is invalidated via clear_cache() (see _MATRIX above).
    Returns None when numpy is unavailable or nothing usable — callers fall back to the
    per-vector dict path."""
    if _np is None or not texts:
        return None
    digest = hashlib.sha256("\x1f".join(texts).encode()).hexdigest()
    key = (model_id, group, kind)
    hit = _MATRIX.get(key)
    if hit is not None and hit[0] == digest:
        return hit[1], hit[2]
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
    norms[norms == 0] = 1.0  # zero-magnitude rows stay all-zero -> cosine 0, how_similar's convention
    mat = mat / norms
    _MATRIX[key] = (digest, mat, row_indexes)
    return mat, row_indexes


def clear_cache(group: str | None = None) -> None:
    """ wipes the fast in-worker cache (not the shared
    database) — for when the cached vectors might be stale.

    [REVIEW-FIX] this docstring previously claimed "not currently called by any code
    path" — false: `delete_cached` below already calls this on every group
    recreate/delete. What's actually true: no in-app write path ever UPDATEs an
    existing master's embedded text (`upsert_threat_type`/`upsert_threat_catalogue`
    in dal.py are strictly insert-if-absent — a natural-key collision resolves to the
    existing row's id and never rewrites its name column), so the cache can't go stale
    from anything this app itself does. The only staleness scenario is an out-of-band
    DB edit outside this codebase, which is exactly what the admin
    `/v1/tsg/threat-library/embeddings/{recreate,delete}` routes (and
    `scripts/refresh_embeddings.py --recreate`) exist to remediate manually — both
    already route through `delete_cached` -> this function.

    Clear L1 (Mongo persists by design; delete Mongo docs explicitly if a master's text changes)."""
    if group is None:
        _L1.clear()
        _MATRIX.clear()
    else:
        # Each L1 key is (model_id, group, kind); k[1] is the group, so this only
        # drops entries belonging to the requested group and leaves the rest alone.
        for key in [k for k in _L1 if k[1] == group]:
            _L1.pop(key, None)
        # The matrix is derived from those vectors — same lifecycle, same invalidation.
        # This is what catches a recreate that re-embeds the SAME texts to different
        # vectors; the texts-digest check in get_matrix alone would not notice that.
        for key in [k for k in _MATRIX if k[1] == group]:
            _MATRIX.pop(key, None)


def delete_cached(group: str, names: list[str] | None = None, *, strict: bool = False,
                sess: Session | None = None) -> int:
    """ forces a full re-embed of one group (e.g. "threat_type",
    "threat_catalogue"), or just specific named items within it, by wiping BOTH tiers —
    L1 (via clear_cache) and, unlike clear_cache alone, the persisted Mongo docs too. Use
    this for a genuine "recreate"/"delete" (a master's text changed under the same model,
    or a vector needs regenerating) — a plain model/version bump needs no deletion at all,
    since get_vectors' cache key already includes model_id and simply misses on its own.

    `names`, when given, scopes the delete to just those texts (the Mongo docs already store
    `text` — see _stage_for_write) instead of the whole group; L1 has no per-text filter, so
    it's still cleared for the whole group (a few extra recomputes on next use, not a
    correctness issue).

    Returns the number of Mongo docs deleted (0 if Mongo is unreachable — best-effort,
    same degrade-safe posture as every other Mongo access in this file)."""
    col = _store_if_healthy()
    if col is None:
        clear_cache(group)  # L2 unreachable — still drop L1 so a stale vector isn't served from it
        if strict and names:
            # A named delete cannot be VERIFIED without the store, and reporting 0-with-SUCCESS
            # is the exact silent-no-op this strictness exists to prevent: the operator is told
            # the vector is gone while it survives in Mongo and is served again on recovery.
            # Fail the job instead — it is safely retryable once Mongo is back.
            raise UnknownEmbeddingNames(
                f"vector store unreachable — cannot verify or delete {group} name(s): "
                f"{sorted(names)}; nothing was deleted, retry when it recovers")
        return 0
    query: dict[str, Any] = {"group": group}
    if names is not None:
        # Resolve to the spelling(s) actually stored: the Mongo `text` match is byte-exact (no
        # collation on this collection), so a case-/whitespace-different name deleted 0 docs and
        # still reported success. Resolution happens HERE, once, against the collection handle we
        # already hold — callers must not pre-resolve, or the group pays a second `distinct`.
        resolved, unmatched = _resolve_names(_stored_texts(col, group), names)
        # `strict` is the delete route's contract (a name matching no vector is an operator error
        # worth failing on); recreate stays lenient because its names come from the master table
        # and may legitimately have no vector cached yet.
        if strict and unmatched:
            # Two DIFFERENT situations land here, and conflating them made delete non-idempotent:
            # (a) the name IS a real master row that simply has no cached vector — e.g. the vector
            #     was already deleted by a previous run of the same cleanup. Deleting what is
            #     already clean must SUCCEED (0 deleted), or every re-run of an operator's script
            #     pages someone for nothing.
            # (b) the name matches nothing anywhere — a typo. That must still fail loudly; the
            #     silent-no-op-with-SUCCESS it used to produce is the original bug here.
            known = _known_master_names(sess, group, unmatched)
            if known:
                log.info("embeddings.delete_already_clean", group=group, names=sorted(known))
            unmatched = [n for n in unmatched if n not in known]
            if unmatched:
                # raise BEFORE clear_cache below: a rejected request must not wipe L1 as a side effect
                raise UnknownEmbeddingNames(
                    f"name(s) match neither a cached {group} vector nor an active master row: "
                    f"{sorted(unmatched)} — nothing was deleted")
        query["text"] = {"$in": resolved}
    clear_cache(group)  # L1 has no per-text filter, so the whole group goes (extra recomputes only)
    return col.delete_many(query).deleted_count


def _thresholds_col():
    """Sibling collection to the vector cache holding per-model-pair grounding thresholds
    (grounding.resolve_thresholds). None when Mongo is unavailable — callers degrade to the
    static defaults, same posture as the vector cache itself."""
    col = _store_if_healthy()
    if col is None:
        return None
    return col.database["grounding_thresholds"]


def load_thresholds(model_pair: tuple[str, str]) -> tuple[float, float] | None:
    """Stored (grounded_th, confirm_th) for this exact (embedding_model, reranker_model) pair,
    or None (not calibrated yet / Mongo unreachable)."""
    try:
        col = _thresholds_col()
        if col is None:
            return None
        doc = col.find_one({"embedding_model": model_pair[0], "reranker_model": model_pair[1]})
        return (float(doc["grounded_th"]), float(doc["confirm_th"])) if doc else None
    except Exception:  # noqa: BLE001 — degrade-safe: an unreadable store means "not calibrated"
        log.warning("embeddings.load_thresholds_failed", exc_info=True)
        return None


def store_thresholds(model_pair: tuple[str, str], grounded_th: float, confirm_th: float) -> None:
    """Persist a calibration so every OTHER worker (and every later boot) reuses it instead of
    re-running the paraphrase+scoring pass. Upsert keyed on the model pair — two workers racing
    the same calibration simply write the same answer twice (bounded duplicate cost, no lock)."""
    try:
        col = _thresholds_col()
        if col is None:
            return
        col.update_one(
            {"embedding_model": model_pair[0], "reranker_model": model_pair[1]},
            {"$set": {"grounded_th": grounded_th, "confirm_th": confirm_th,
                    "computed_at": now().isoformat()}},
            upsert=True)
    except Exception:  # noqa: BLE001 — losing the write only costs a later re-calibration
        log.warning("embeddings.store_thresholds_failed", exc_info=True)


def _known_master_names(sess: Session | None, group: str, names: list[str]) -> set[str]:
    """The subset of `names` that resolves (case/space-insensitively) to an ACTIVE master row.
    Used by delete_cached's strict check to tell "already clean" (idempotent success) apart from
    "typo" (loud failure). No sess → can't tell → treat none as known (fail-strict, the safer
    default for a check that guards against silent no-ops)."""
    if sess is None or not names:
        return set()
    table, name_col = _GROUPS[group]
    resolved_pairs = _resolve_names(_active_names(sess, table, name_col), names)
    # _resolve_names returns (resolved master spellings, unmatched); we need which INPUT names
    # matched, so re-derive by folding: an input is "known" iff it did not come back unmatched.
    unmatched_folded = {str(u).strip().lower() for u in resolved_pairs[1]}
    return {n for n in names if str(n).strip().lower() not in unmatched_folded}


class UnknownEmbeddingNames(ValueError):
    """One or more client-supplied `names` matched no authoritative row/vector. Surfaces via
    _for_each_group as `"error: ..."` in the job's per-group result, so an operator sees a named
    failure instead of a SUCCESS count for work that never happened."""


def _resolve_names(candidates: list[str], names: list[str]) -> tuple[list[str], list[str]]:
    """Map client-supplied `names` onto the authoritative spelling in `candidates`, comparing
    case- and whitespace-insensitively; returns (resolved, unmatched).

    Why this is required: the names originate from MSSQL NVARCHAR columns, whose default
    collation is case-insensitive AND trailing-space-insensitive, but they are used as
    byte-exact MongoDB keys (`{"text": {"$in": names}}` — the collection carries no collation)
    and as the text whose sha256 becomes the cache key. So a name that looks identical in every
    UI ("Denial of Service" vs "denial of service", or a master row stored with a trailing
    space) matched nothing: delete removed 0 vectors, recreate deleted nothing and embedded an
    orphan under a key grounding never looks up — both reporting SUCCESS. Resolving to the
    authoritative spelling before acting is what makes the action actually hit its target.

    One folded key maps to EVERY spelling stored under it, not just the first: the Mongo unique
    index is sha256(model|group|kind|text), so "Denial of Service" and "denial of service" coexist
    as separate docs — exactly the duplicate this bug class used to create. Keeping only one would
    delete one and silently leave the other live, re-creating the very symptom being fixed."""
    index: dict[str, list[str]] = {}
    for c in candidates:
        index.setdefault(str(c).strip().lower(), []).append(c)
    resolved: list[str] = []
    # Prefix keys make control_library candidates addressable by their human name: that
    # group's "name" is the full `ControlName: ControlDescription` embed text, which nobody
    # can type into an admin call. A candidate containing ": " also registers its name-part
    # (before the first ": ") as a lookup key — mapping to EVERY candidate sharing that name,
    # the same every-spelling semantics as the folded full-text keys above. A full-text key
    # always wins over a prefix key (never shadow a real name with someone's prefix).
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
            # dedupe: two client spellings of one name resolve to the SAME stored spelling(s), and
            # a repeat would mean a redundant paid embed on the create/recreate path
            resolved.extend(a for a in actual if a not in resolved)
        else:
            unmatched.append(n)
    return resolved, unmatched


def _stored_texts(col, group: str) -> list[str]:
    """The `text` values this group actually has vectors for — the authoritative candidate set
    for a DELETE (a vector can outlive its master row, and cleaning up exactly such an orphan is
    a legitimate delete). Takes the caller's already-health-checked collection so one named
    delete costs ONE `distinct` round-trip, not one per resolution site."""
    return list(col.distinct("text", {"group": group}))


def _active_names(sess: Session, table, name_col) -> list[str]:
    """Active (IsActive, not IsDeleted) names for one embedding group's table — the DB-side
    counterpart to _GROUPS above. Shared by update_group/recreate_group so the CLI script and
    the admin API resolve "every real item in this group" identically."""
    return list(sess.execute(
        select(name_col).where(table.IsActive == True, table.IsDeleted == False)  # noqa: E712
    ).scalars().all())


# int, not float: redis-py rejects a float for SET's `ex=` and for EXPIRE (DataError). As a float
# this lock NEVER acquired against a real Redis — every call raised, hit _group_lock's fail-open
# handler, and ran unserialized, so the per-group mutex was silently inert in production (tests
# use a fake Redis that tolerates floats, so they never caught it).
_GROUP_LOCK_TTL_SECONDS = 30


def _renew_group_lock_loop(r, key: str, token: str, interval: float, stop_event: threading.Event) -> None:
    """Runs on a background thread for the lifetime of one held group lock: refreshes the key's
    TTL every `interval` seconds so a legitimately slow guarded operation (delete_cached +
    get_vectors, whose embed call can run well past the lock's own fixed TTL — see
    llm_timeout_seconds) never has its lock silently expire out from under it. Mirrors llm.py's
    _heartbeat_loop for the identical 'duration vs. aliveness' problem, applied to this single-key
    SET lock instead of a ZSET semaphore."""
    while not stop_event.wait(interval):
        try:
            if r.get(key) == token:  # only renew OUR OWN lock — never extend one a stale timeout
                r.expire(key, _GROUP_LOCK_TTL_SECONDS)  # already let a different caller acquire
        except Exception:  # noqa: BLE001 — a missed renewal self-heals next tick
            log.warning("embeddings.group_lock_renewal_failed", exc_info=True)


@contextmanager
def _group_lock(group: str):
    """Serializes recreate_group/delete_group per group via a short-lived Redis lock (reuses
    the same dedicated client Part A's LLM-slot limiter uses). Without this, two concurrent
    admin calls for the SAME group would both wipe then both re-embed (redundant paid LLM
    calls), and any NORMAL grounding lookup mid-recreate could find the cache empty and be
    forced to eagerly embed on what should have been a hit. A second concurrent call for the
    same group raises EmbeddingBusy (409) instead of racing.

    Fails OPEN if Redis itself is unreachable (same posture as the LLM-slot limiter): this
    guards against redundant cost/a stampede, not correctness, so availability wins.
    """
    key = f"tsg:embed-lock:{group}"
    token = str(uuid.uuid4())
    try:
        r = _slot_redis()
        acquired = r.set(key, token, nx=True, ex=_GROUP_LOCK_TTL_SECONDS)
    except Exception:  # noqa: BLE001 — Redis down → fail open, don't block an admin action on it
        log.warning("embeddings.group_lock_redis_unavailable_fail_open", group=group, exc_info=True)
        yield
        return
    if not acquired:
        raise EmbeddingBusy(f"group {group!r} is already being recreated/deleted")
    stop_event = threading.Event()
    # plain threading.Thread, not gevent.spawn — same portability reasoning as llm.py's _llm_slot.
    hb_thread = threading.Thread(
        target=_renew_group_lock_loop, args=(r, key, token, _GROUP_LOCK_TTL_SECONDS / 3, stop_event),
        daemon=True)
    hb_thread.start()
    try:
        yield
    finally:
        # Stop the renewal thread BEFORE releasing: if release ran first, a renewal tick still
        # in flight could re-extend a lock we just deleted.
        stop_event.set()
        hb_thread.join(timeout=_GROUP_LOCK_TTL_SECONDS)
        try:
            if r.get(key) == token:  # only release OUR OWN lock, never one a retry-after-TTL-expiry took
                r.delete(key)
        except Exception:  # noqa: BLE001 — best-effort release; the TTL is the backstop
            pass


def _for_each_group(group: str | None, fn) -> dict[str, int | str]:
    """Shared fan-out for the group=None ("all groups") case every admin action supports:
    resolves it to every real group, calls fn(group) for each, and isolates a per-group
    failure so one group's error doesn't take down the other's result — the failing group's
    slot holds an error string instead of a count."""
    groups = sorted(_GROUPS) if group is None else [group]
    results: dict[str, int | str] = {}
    for g in groups:
        try:
            results[g] = fn(g)
        except UnknownEmbeddingNames:
            # Same reasoning as EmbeddingBusy below: a named action names exactly ONE group
            # (admin.py refuses `names` without `group`), so there are no sibling groups to
            # protect — and folding this into a results-dict string made a wholly-failed
            # delete/recreate poll back as state=SUCCESS with error=null, the exact
            # silent-success symptom this whole change set exists to remove.
            raise
        except EmbeddingBusy:
            # A real conflict app/api/celery_app.py's admin task must let propagate (surfaces as
            # a FAILURE state on GET .../status/{job_id}, see app/api/admin.py) — not swallow
            # into a results-dict string, unlike a generic per-group failure below.
            raise
        except LLMSlotUnavailable:
            # A CONFIRMED, transient "no free LLM call slot" — Celery's autoretry_for on
            # admin_embedding_action_task (celery_app.py) retries the whole action shortly.
            # Swallowing this into "error: ..." would misreport a self-healing capacity squeeze
            # as a permanent per-group failure, the exact bug tasks.py/cascade.py's own
            # re-raise-before-generic-handler already exists to prevent elsewhere.
            raise
        except Exception as exc:  # noqa: BLE001 — one group's failure must not sink the others
            log.warning("embeddings.group_action_failed", group=g, exc_info=True)
            results[g] = f"error: {exc}"
    return results


def create_items(sess: Session, llm: LLMClient, group: str, names: list[str]) -> int:
    """Fingerprint specific NEW item(s) by name — for right after a threat is added, without
    rescanning the whole group. Already-cached names are skipped by get_vectors itself.

    Names are resolved against the ACTIVE master rows first: embedding the operator's spelling
    verbatim cached the vector under a key grounding never looks up (grounding embeds the DB's
    own text), so a case-different name produced a paid embed, an orphan vector, and a SUCCESS
    report while the item stayed effectively un-embedded."""
    table, name_col = _GROUPS[group]
    resolved, unmatched = _resolve_names(_active_names(sess, table, name_col), names)
    if unmatched:
        raise UnknownEmbeddingNames(
            f"no active {group} row matches name(s): {sorted(unmatched)} — nothing was embedded")
    if resolved:
        get_vectors(llm, resolved, model_id=get_settings().embedding_model, group=group, kind="passage")
    return len(resolved)


def update_group(sess: Session, llm: LLMClient, group: str) -> int:
    """Whole-group sync: embed whatever's missing across every active row. Rows already
    cached (same model + text) are skipped by get_vectors itself — cheap, always safe."""
    table, name_col = _GROUPS[group]
    names = _active_names(sess, table, name_col)
    if names:
        get_vectors(llm, names, model_id=get_settings().embedding_model, group=group, kind="passage")
    return len(names)


def recreate_group(sess: Session, llm: LLMClient, group: str, names: list[str] | None = None) -> int:
    """Force a full re-embed — deletes cached vectors first (scoped to `names` if given, else
    the whole group), then re-embeds. Serialized per group (see _group_lock)."""
    with _group_lock(group):
        table, name_col = _GROUPS[group]
        active = _active_names(sess, table, name_col)
        if names is None:
            target_names = active
        else:
            # Resolve against the master rows and act on THAT spelling for both halves. Using the
            # client's raw spelling deleted nothing (byte-exact Mongo match) and then embedded an
            # orphan — so the "force a clean re-embed" remediation left the stale vector live and
            # still reported SUCCESS.
            target_names, unmatched = _resolve_names(active, names)
            if unmatched:
                raise UnknownEmbeddingNames(
                    f"no active {group} row matches name(s): {sorted(unmatched)} — nothing was recreated")
        delete_cached(group, names=target_names if names is not None else None)
        if target_names:
            get_vectors(llm, target_names, model_id=get_settings().embedding_model, group=group, kind="passage")
        return len(target_names)


def delete_group(sess: Session, group: str, names: list[str] | None = None) -> int:
    """Wipe cached vectors only — no re-embed. Serialized per group (see _group_lock).

    Named deletes resolve against the vectors that actually exist (a vector can outlive its
    master row — clearing exactly that orphan is a legitimate delete). A name with no vector is
    then checked against the ACTIVE master rows: a real master name that's simply already clean
    succeeds idempotently with 0 deleted (an operator's cleanup script may run twice); a name
    matching nothing anywhere is a typo and fails loudly — the silent no-op-with-SUCCESS it
    used to produce is the original bug this strictness exists to prevent."""
    with _group_lock(group):
        # strict=True: delete_cached resolves once, with the collection it already holds, and
        # raises on a truly unknown name. A pre-check here would cost a second `distinct` for
        # the same data — and could disagree with what delete_cached then actually deletes.
        return delete_cached(group, names=names, strict=True, sess=sess)
