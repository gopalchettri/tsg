"""Grounding — matches an AI-proposed threat to a real library entry
(Threat_Category/Threat_Type/Threat_Catalogue/Threat_Actor), so the same
threat described in different words always resolves to the same
ThreatTypeID/ThreatCatalogueID instead of being treated as new each time.

Every match bands into GroundingStatus.verified/unverified against one cutoff
(see label_match_from_score). What happens to an unverified threat at accept
depends on promotion_auto_approve_enabled (accept.py): OFF routes it through
the admin queue, ON lets banded triage auto-promote. Either way, the
asset-embedded name itself never enters the library — only its
curator-generalized generic form is promoted or queued.

sector_ids is always [own_sector_id, parent_sector_id] (empty = no sector
context) — see visible_to_this_sector / how_specific_is_this_sector.
"""
from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, NamedTuple

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import GroundingStatus
from app.core.logging import get_logger
from app.db import models as m
from app.pipeline import embeddings, hybrid_search
from app.pipeline.llm import LLMClient, LLMSlotUnavailable

log = get_logger(__name__)

# numpy comes with the optional sentence-transformers extra (requirements' `local` provider) —
# a litellm-proxy-only deployment may not have it. _shortlist_candidates uses it when present:
# pure-Python cosine is fine for the small threat library, but too slow at Control_Library scale
# (1000+ rows x 1024 dims) on a gevent worker. Pure-Python branch below is the no-numpy fallback.
try:
    import numpy
    _np: ModuleType | None = numpy
except ImportError:  # pragma: no cover — exercised only in numpy-less deployments
    _np = None

# Gives each grounding band a rank so two statuses can be compared (see pick_worse_of_two).
_BAND_ORDER = {GroundingStatus.verified: 1, GroundingStatus.unverified: 0}


# --- self-calibrating threshold ---------------------------------------------------------------
# The match cutoff is model-specific: a different embedding+reranker pair scores the same
# match differently, so a static number silently misclassifies after any model change. The
# resolver below derives the cutoff from the live models + live library, per model pair, so a
# stale threshold can't recur.

_RESOLVED_THRESHOLDS: dict[tuple[str, str], float] = {}

# Sample size / paraphrases-per-name: Settings.calibration_sample_size / calibration_paraphrases_per_name.
# near_duplicate_score (Settings): a negative at/above it is a duplicate catalogue entry, not an
# impostor — calibration is unwinnable until the library is deduped. See _auto_calibrate.


def how_similar(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity; 0.0 for a zero-magnitude vector instead of raising.

    [Fix] Raises ValueError on a length mismatch instead of letting zip() silently truncate
    to the shorter vector — a mismatch always means a real embedding-dimension problem (e.g.
    a stale cached vector from before an EMBEDDING_PROVIDER/EMBEDDING_DIMENSIONS change).
    Silent truncation would give a meaningless score with no error. The caller
    (_shortlist_candidates) decides how broadly one bad vector should fail, not this function.
    """
    if len(a) != len(b):
        raise ValueError(f"how_similar received vectors of different lengths ({len(a)} vs {len(b)})")
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return 0.0 if na == 0 or nb == 0 else dot / (na * nb)


def label_match_from_score(score: float, s: Settings, *, match_th: float | None = None) -> GroundingStatus:
    """The one place the score cutoff is applied. `match_th` overrides the static
    setting with resolve_thresholds' per-model-pair value (find_threat_in_library
    passes it); left None, direct callers and tests use the static default."""
    th = s.grounding_match_threshold if match_th is None else match_th
    return GroundingStatus.verified if score >= th else GroundingStatus.unverified


def pick_worse_of_two(a: GroundingStatus, b: GroundingStatus) -> GroundingStatus:
    """Overall confidence is only as good as the weaker of two checks (type vs name):
    verified + unverified -> unverified."""
    return a if _BAND_ORDER[a] <= _BAND_ORDER[b] else b


def visible_to_this_sector(col, sector_ids: list[int]):
    """Filter: a row is visible if SectorID is NULL (global) or in sector_ids
    (own/parent). Tie-breaking among visible rows is a separate job — see
    how_specific_is_this_sector.
    """
    if sector_ids:
        return or_(col.is_(None), col.in_(sector_ids))
    return col.is_(None)


def how_specific_is_this_sector(sector_id: int | None, sector_ids: list[int]) -> int:
    """Tiebreak rank for rows that already passed visible_to_this_sector:
    2 = exact sub-sector match, 1 = parent-sector match, 0 = global (NULL).
    """
    if sector_id is None:
        return 0
    return 2 if sector_ids and sector_id == sector_ids[0] else 1


def find_category(sess: Session, proposed: str) -> int | None:
    """Case-insensitive match against a real category name/code. [R6] `None`
    means nothing matched — callers treat that as "search every category",
    not as an error.
    """
    p = (proposed or "").strip().lower()
    if not p:
        return None
    row = sess.execute(
        select(m.Threat_Category.ThreatCategoryID)
        .where(
            m.Threat_Category.IsActive == True,
            m.Threat_Category.IsDeleted == False,
            or_(
                func.lower(m.Threat_Category.ThreatCategoryName) == p,
                func.lower(m.Threat_Category.ThreatCategoryCode) == p,
            ),
        )
        .order_by(m.Threat_Category.ThreatCategoryID)
    ).first()
    return row[0] if row else None


def get_possible_types(sess: Session, category_id: int | None, sector_ids: list[int]) -> list[dict[str, Any]]:
    """Candidate Threat_Type rows for find_closest_match: sector-filtered, and
    narrowed to category_id (or every category if None, [R6]). Pre-sorted by
    how_specific_is_this_sector so a later scoring tie breaks toward the more
    specific row.
    """
    q = select(
        m.Threat_Type.ThreatTypeID,
        m.Threat_Type.ThreatTypeName,
        m.Threat_Type.SectorID,
    ).where(
        m.Threat_Type.IsActive == True,
        m.Threat_Type.IsDeleted == False,
        visible_to_this_sector(m.Threat_Type.SectorID, sector_ids),
    )
    if category_id is not None:  # else fall back to searching all categories ([R6])
        # [A2] Threat_Type.ThreatCategoryID is just a rough default — a Threat_Catalogue row
        # under a type can carry a different/extra STRIDE category via
        # Threat_Catalogue_Category_Map (true for most curated threats). Narrowing on the
        # type's default alone would drop a type whose real match is via one of those other
        # mapped categories, so a type counts as a candidate if either matches.
        mapped_type_ids = (
            select(m.Threat_Catalogue.ThreatTypeID)
            .join(m.Threat_Catalogue_Category_Map,
                m.Threat_Catalogue_Category_Map.ThreatCatalogueID == m.Threat_Catalogue.ThreatCatalogueID)
            .where(m.Threat_Catalogue_Category_Map.ThreatCategoryID == category_id,
                m.Threat_Catalogue.IsActive == True, m.Threat_Catalogue.IsDeleted == False)
        )
        q = q.where(or_(m.Threat_Type.ThreatCategoryID == category_id,
                        m.Threat_Type.ThreatTypeID.in_(mapped_type_ids)))
    # ORDER BY makes row order deterministic, so the stable sort below breaks
    # same-specificity ties the same way every time instead of SQL Server's scan order.
    q = q.order_by(m.Threat_Type.ThreatTypeID)
    rows = [dict(r) for r in sess.execute(q).mappings()]
    rows.sort(key=lambda r: how_specific_is_this_sector(r["SectorID"], sector_ids), reverse=True)
    return rows


def get_possible_names(sess: Session, type_id: int, sector_ids: list[int]) -> list[dict[str, Any]]:
    """Candidate Threat_Catalogue rows under the already-matched type only —
    keeps the name match consistent with the type match instead of searching
    the whole library, where an unrelated type's entry could win on text
    similarity alone.
    """
    q = select(
        m.Threat_Catalogue.ThreatCatalogueID,
        m.Threat_Catalogue.ThreatName,
        m.Threat_Catalogue.SectorID,
    ).where(
        m.Threat_Catalogue.IsActive == True,
        m.Threat_Catalogue.IsDeleted == False,
        m.Threat_Catalogue.ThreatTypeID == type_id,
        visible_to_this_sector(m.Threat_Catalogue.SectorID, sector_ids),
    ).order_by(m.Threat_Catalogue.ThreatCatalogueID)  # deterministic tie-break, see get_possible_types
    rows = [dict(r) for r in sess.execute(q).mappings()]
    rows.sort(key=lambda r: how_specific_is_this_sector(r["SectorID"], sector_ids), reverse=True)
    return rows


def get_control_candidates(sess: Session, itot: str | None) -> list[dict[str, Any]]:
    """Active Control_Library rows for Step-4 grounding (control_mapping.map_controls).
    `text` uses the same name+description expression the embedding cache was built from
    (embeddings._CONTROL_TEXT) — must match, or cache keys won't line up.

    `itot` narrows to IT-only/OT-only controls only when the asset's declared type is
    literally 'IT'/'OT' (caller case-folds it); any other value searches the whole library.
    Fetch once per session and reuse across every suggestion, not once per query."""
    q = select(
        m.Control_Library.ControlLibraryID,
        m.Control_Library.ControlCode,
        m.Control_Library.Domain,
        m.Control_Library.ControlName,
        embeddings._CONTROL_TEXT.label("text"),
    ).where(
        m.Control_Library.IsActive == True,
        m.Control_Library.IsDeleted == False,
    ).order_by(m.Control_Library.ControlLibraryID)  # deterministic tie-break, see get_possible_types
    if itot in ("IT", "OT"):
        q = q.where(m.Control_Library.ITOT == itot)
    return [dict(r) for r in sess.execute(q).mappings()]


class ControlMatches(NamedTuple):
    """One control query's OUTCOME — deliberately not a bare list.

    `answered=False` means we never got a verdict for this query (its rerank item failed).
    `answered=True` with `matches == []` means we DID rerank it and nothing scored: a real,
    reportable library gap.

    Why a type and not `None`: those two states used to share the value `[]`, and that single
    conflation was the worst defect in this file (see ground_control_queries). Replacing one
    overloaded sentinel with another — `None` vs `[]` — would leave the distinction resting on
    convention, so the next reader can re-conflate it exactly as this one was. A named field
    cannot be conflated by accident, and a caller who forgets it and iterates the result
    directly fails loudly on the tuple unpack instead of silently treating "no answer" as
    "no match"."""
    matches: list[tuple[dict[str, Any], float]]
    answered: bool


def ground_control_queries(llm: LLMClient, queries: list[tuple[str, list[float] | None]],
                        rows: list[dict[str, Any]], s: Settings) -> list[ControlMatches]:
    """Batch Step-4 grounding: every query shortlists against the same candidate set, then
    all shortlists rerank in one llm.rerank_many call instead of one round trip per query.

    `queries` = (text, optionally pre-embedded qv). Returns, PER QUERY, a ControlMatches
    carrying the full reranked shortlist best-first — never collapsed to a single best: the
    caller sends ONE scenario-text query per output and needs control_map_top_k distinct
    matches from it, so collapsing here would silently cap every output at one control.

    ANSWERED vs MATCHED are different questions and this return type keeps them apart. Both
    used to be `[]`, and map_controls could not tell them apart: it stamped ControlsMappedAt
    for an output whose rerank had merely FAILED, `ControlsMappedAt IS NULL` then excluded that
    output from every later run, and the API published `ControlsMapped=true` with an empty
    control list — which schemas.py documents, three times over, as "a genuine library-gap
    signal, not an error". One 429 became a permanent curated fact about the control library.

    Per-item fail-open is retained deliberately (one bad query must not lose the batch);
    rerank_many still raises when the WHOLE batch failed, which map_controls turns into a
    rollback with nothing stamped — already correct, and pinned by a test.

    HYBRID shortlist: the cosine leg (existing) is UNIONED with a BM25 keyword leg over the
    same "ControlName: Description" corpus — rare exact tokens (product names, acronyms)
    carry strong signal that embeddings dilute. The reranker stays the final arbiter of
    order, so no score fusion is needed; the legs only decide what gets reranked.
    Falls back to per-query llm.rerank when the client has no rerank_many (test fakes)."""
    if not rows or not queries:
        return [[] for _ in queries]
    names = [r["text"] for r in rows]
    # Resolve the cached matrix once for the whole batch (cheap once, wasteful per query);
    # dict-path vectors only if the matrix is unavailable.
    matrix_info = embeddings.get_matrix(llm, names, model_id=s.embedding_model,
                                        group="control_library", kind="passage")
    name_vecs = None if matrix_info is not None else embeddings.get_vectors(
        llm, names, model_id=s.embedding_model, group="control_library", kind="passage")
    # BM25 keyword leg: corpus tokenized once per batch; per query, the top-shortlist_k
    # keyword hits are UNIONED into the cosine shortlist before the rerank. Zero-score docs
    # never enter (hybrid_search._ranked_indices excludes them), so an all-miss query adds
    # nothing and behaves exactly as before.
    docs_tokens = [hybrid_search.tokenize(r["text"]) for r in rows]
    shortlists: list[list[dict[str, Any]]] = []
    for query, qv in queries:
        if qv is None:
            vecs = llm.embed([query], kind="query")
            if len(vecs) != 1:
                raise RuntimeError(f"embed returned {len(vecs)} vectors for 1 query")
            qv = vecs[0]
        sl = _shortlist_via_matrix(qv, rows, matrix_info, s) if matrix_info is not None else None
        if sl is None:
            if name_vecs is None:
                name_vecs = embeddings.get_vectors(llm, names, model_id=s.embedding_model,
                                                group="control_library", kind="passage")
            sl = _shortlist_candidates(qv, rows, name_vecs, "text", s)
        kw_scores = hybrid_search.bm25_scores(hybrid_search.tokenize(query), docs_tokens)
        kw_top = hybrid_search._ranked_indices(kw_scores)[:s.grounding_shortlist_k]
        seen_ids = {id(r) for r in sl}
        sl = sl + [rows[i] for i in kw_top if id(rows[i]) not in seen_ids]
        shortlists.append(sl)
    # Rerank only the queries that actually have a shortlist; map results back by position.
    todo = [i for i, sl in enumerate(shortlists) if sl]
    items = [(queries[i][0], [r["text"] for r in shortlists[i]]) for i in todo]
    rerank_many = getattr(llm, "rerank_many", None)
    if rerank_many is not None:
        scored = rerank_many(items)
    else:  # test fakes / older clients: same per-item fail-open contract, sequentially
        scored = []
        failures = 0
        for q, docs in items:
            try:
                scored.append(llm.rerank(q, docs))
            except Exception:
                failures += 1
                log.warning("controls.rerank_item_failed", query=q[:80], exc_info=True)
                scored.append(None)
        if items and failures == len(items):
            raise RuntimeError(f"all {len(items)} control rerank calls failed")
    # Seeded answered=True: a query with NO shortlist genuinely matched nothing, which is a
    # real answer. Only a FAILED rerank below flips one to answered=False.
    results: list[ControlMatches] = [ControlMatches([], True) for _ in queries]
    for i, rr in zip(todo, scored):
        if rr is None:
            results[i] = ControlMatches([], False)   # no answer — NOT "no match"
            continue
        docs = shortlists[i]
        if len(rr) != len(docs):  # same fail-loud guard as find_closest_match
            raise RuntimeError(f"rerank returned {len(rr)} scores for {len(docs)} docs")
        # Full reranked list, best-first — the caller filters by min score, dedups by
        # ControlLibraryID and caps at control_map_top_k. Collapsing to max() here would
        # silently cap every scenario at ONE mapped control under the one-query design.
        results[i] = ControlMatches(
            sorted(zip(docs, rr), key=lambda rs: rs[1], reverse=True), True)
    return results


def get_allowed_actor_names(sess: Session, type_id: int) -> list[str]:
    """The actors LINKED to this Threat_Type — the PRIMARY source of a threat's actors.

    Library-first: the LLM never proposes an adversary, so this list (or
    nearest_library_actors' fallback when it is empty) is the whole answer. Ordered by
    ThreatActorID, not a set: Stage 1 runs at temperature 0 so two identical runs must
    store byte-identical ThreatActorsJSON, and set iteration order would break that.
    """
    rows = sess.execute(
        select(m.Threat_Actor.ThreatActorName)
        .join(m.ThreatType_ThreatActor_Map,
            m.ThreatType_ThreatActor_Map.ThreatActorID == m.Threat_Actor.ThreatActorID)
        .where(m.ThreatType_ThreatActor_Map.ThreatTypeID == type_id,
            m.Threat_Actor.IsActive == True, m.Threat_Actor.IsDeleted == False)
        .order_by(m.Threat_Actor.ThreatActorID)
    )
    return [r[0] for r in rows]


def nearest_library_actors(sess: Session, llm: LLMClient, query: str,
                        top_n: int = 3) -> list[str]:
    """Nearest active Threat_Actor rows to `query` — the fallback when a threat's type has
    no linked actors (or is unverified). NEVER invents: every returned name is a real
    library row, and an empty actor table yields [].

    Hybrid (BM25 + embedding cosine) because actor names are bare 2-3 word labels with no
    description column: the keyword leg carries most of the signal ("APT33" vs "APT 33"),
    the vector leg catches wording drift. Best-effort on the vector half — an embedding
    failure degrades to keyword-only rather than dropping the actor entirely.

    # ponytail: top-3 fixed. Make it a setting only if reviewers ask for a different width.
    """
    rows = [r[0] for r in sess.execute(
        select(m.Threat_Actor.ThreatActorName)
        .where(m.Threat_Actor.IsActive == True, m.Threat_Actor.IsDeleted == False)
        .order_by(m.Threat_Actor.ThreatActorID))]
    if not rows or not (query or "").strip():
        return []
    s = get_settings()
    candidates: list[dict[str, Any]] = [{"text": n, "name": n, "vector": None} for n in rows]
    query_vec = None
    try:
        vecs = embeddings.get_vectors(llm, rows, model_id=s.embedding_model,
                                    group="threat_actor", kind="passage")
        for c in candidates:
            c["vector"] = vecs.get(c["text"])
        qv = llm.embed([query], kind="query")
        if len(qv) == 1:
            query_vec = qv[0]
    except Exception:
        log.warning("actors.nearest_embed_failed_keyword_only", exc_info=True)
    ranked = hybrid_search.hybrid_match(query, candidates, query_vec=query_vec, top_n=top_n)
    return [rows[i] for i, _score in ranked]


def _shortlist_candidates(qv: list[float], rows: list[dict[str, Any]], name_vecs: dict[str, list[float]],
                        name_key: str, s: Settings) -> list[dict[str, Any]]:
    """Cosine-scores every candidate against the query embedding, best match first.
    Keeps only candidates above `semantic_match_threshold`, falling back to the top-K
    anyway if nothing clears it, so a bad match still reaches label_match_from_score
    instead of returning nothing.

    [Fix] A dimension-mismatched cached vector (see how_similar's ValueError) is skipped
    with a warning instead of blowing up scoring for every other candidate — one bad cache
    entry should only cost that one candidate, not the whole lookup.
    """
    # Vectorized when numpy is available: one matrix multiply replaces len(rows) pure-Python
    # dot products — same scores, same dimension-mismatch skip, same zero-magnitude
    # convention as how_similar.
    scored = []
    if _np is not None:
        ok_rows, vecs = [], []
        for r in rows:
            v = name_vecs[r[name_key]]
            if len(v) != len(qv):
                log.warning("grounding.dimension_mismatch_skipped", candidate=r.get(name_key))
                continue
            ok_rows.append(r)
            vecs.append(v)
        if ok_rows:
            mat = _np.asarray(vecs, dtype=_np.float32)
            q = _np.asarray(qv, dtype=_np.float32)
            denom = _np.linalg.norm(mat, axis=1) * _np.linalg.norm(q)
            sims = _np.zeros(len(ok_rows), dtype=_np.float32)
            nz = denom > 0
            sims[nz] = (mat @ q)[nz] / denom[nz]
            scored = list(zip(ok_rows, sims.tolist()))
    else:
        for r in rows:
            try:
                scored.append((r, how_similar(qv, name_vecs[r[name_key]])))
            except ValueError:
                log.warning("grounding.dimension_mismatch_skipped", candidate=r.get(name_key))
    if rows and not scored:
        # Every candidate got skipped — systemic embedding-dimension drift, not a real no-match.
        # Left silent, this reads as a healthy run while raw AI text gets mass-promoted into the
        # library (score 0.0 clears no threshold). ERROR, not raise: the session still yields
        # usable unverified threats, so degrading is fine — degrading silently is not.
        log.error("grounding.all_candidates_skipped", candidates=len(rows), name_key=name_key)
    return _apply_shortlist(scored, s)


def _apply_shortlist(scored: list[tuple[dict[str, Any], float]], s: Settings) -> list[dict[str, Any]]:
    """Shared floor/top-K tail for both scoring paths (dict loop above, matrix below)."""
    scored.sort(key=lambda rc: rc[1], reverse=True)
    above = [rc for rc in scored if rc[1] >= s.semantic_match_threshold]
    # Prefer candidates that clear the similarity floor; if none do, fall back to the
    # top-K overall so we still return something (to be scored as "flagged" downstream).
    return [r for r, _ in (above or scored)[: s.grounding_shortlist_k]]


def _shortlist_via_matrix(qv: list[float], rows: list[dict[str, Any]],
                        matrix_info: tuple[Any, list[int]], s: Settings) -> list[dict[str, Any]] | None:
    """Matrix-path scoring: one `matrix @ q_unit` against embeddings.get_matrix's cached,
    pre-normalized matrix instead of len(rows) dot products. Returns None on a query/matrix
    dimension mismatch — caller falls back to the dict path, which logs per candidate."""
    if _np is None:  # unreachable via get_matrix (it returns None without numpy) — typed fallback
        return None
    mat, row_indexes = matrix_info
    if mat.shape[1] != len(qv):
        return None
    q = _np.asarray(qv, dtype=_np.float32)
    qn = _np.linalg.norm(q)
    sims = (mat @ (q / qn)) if qn else _np.zeros(mat.shape[0], dtype=_np.float32)
    return _apply_shortlist([(rows[i], float(sim)) for i, sim in zip(row_indexes, sims.tolist())], s)


def find_closest_match(llm: LLMClient, query: str, rows: list[dict[str, Any]], name_key: str, s: Settings,
                        group: str, qv: list[float] | None = None) -> tuple[dict[str, Any] | None, float]:
    """Embeds the query and every candidate, ranks by cosine similarity,
    shortlists, then reranks. Called twice by find_threat_in_library — once
    for the type match, once for the name match.

    `qv`: pass an already-computed embedding when the caller batched it with a
    sibling query (see find_threat_in_library, which embeds type+name together
    in one round trip). Omit for a one-off call — embeds `query` here instead.

    embeddings.get_vectors() caches candidate vectors per (model, group), so the
    library is embedded once, not per call. The final sort is stable, so an exact
    rerank-score tie falls back to the sector-specificity order from
    get_possible_types/get_possible_names ([R6]).
    """
    if not rows:
        return None, 0.0
    names = [r[name_key] for r in rows]
    if qv is None:
        vecs = llm.embed([query], kind="query")
        if len(vecs) != 1:  # fail loud rather than a bare IndexError — same guard as the rerank check below
            raise RuntimeError(f"embed returned {len(vecs)} vectors for 1 query")
        qv = vecs[0]
    # Fast path: the cached pre-normalized matrix turns the per-candidate cosine loop into
    # one matvec. Falls back to the per-vector dict path when numpy is absent or the query
    # dimension doesn't match the cached matrix.
    shortlist = None
    matrix_info = embeddings.get_matrix(llm, names, model_id=s.embedding_model, group=group, kind="passage")
    if matrix_info is not None:
        shortlist = _shortlist_via_matrix(qv, rows, matrix_info, s)
    if shortlist is None:
        name_vecs = embeddings.get_vectors(llm, names, model_id=s.embedding_model, group=group, kind="passage")
        shortlist = _shortlist_candidates(qv, rows, name_vecs, name_key, s)
    if not shortlist:  # e.g. grounding_shortlist_k == 0 → no rerank, no ranked[0] IndexError
        return None, 0.0
    docs = [r[name_key] for r in shortlist]
    rr = llm.rerank(query, docs)
    if len(rr) != len(docs):  # fail loud rather than silently mispair scores to candidates
        raise RuntimeError(f"rerank returned {len(rr)} scores for {len(docs)} docs")
    ranked = sorted(zip(shortlist, rr), key=lambda rs: rs[1], reverse=True)
    return ranked[0]  # (row, score)


@dataclass
class GroundingResult:
    """Verdict for one proposed threat, returned by find_threat_in_library().

    score/status         — the weaker of the type-match and name-match confidence.
    type_id/catalogue_id — the real library IDs matched, set ONLY when that half verified:
                            an unverified type yields type_id=None; an unverified name
                            yields catalogue_id=None and library_name=None even if a
                            best-scoring candidate existed (shortlist is fail-open, rerank
                            has no minimum — a candidate existing isn't evidence of a match).
    actors_validated      — provenance of `actors`, which are ALWAYS real library rows
                            (library-first: the model never proposes an adversary).
                            True: taken from the matched type's curator-maintained links.
                            False: nearest-match fallback (no linked actors, or the type
                            itself was unverified) — a similarity guess among real rows,
                            so it must never be written back as a curated link.
    """

    status: GroundingStatus
    type_id: int | None = None
    catalogue_id: int | None = None
    library_type: str | None = None
    library_name: str | None = None
    score: float | None = None
    actors: list[str] = field(default_factory=list)
    actors_validated: bool = True


def ensure_actor_list(raw: Any) -> list[str]:
    """Defends against malformed AI JSON: a bare string would explode into
    single characters via list(raw), and a non-str list element could break
    downstream set lookups. Both handled safely here instead of crashing.
    """
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, str)]
    return []


# The one identity key for actor-name dedup everywhere (accept_actors' memo/triage/card
# identity and pending-card fold) — an identity remembered by one layer is never missed by
# another. Unicode-aware on purpose: actor names are NVARCHAR, and Cyrillic/CJK names are
# real names, not junk to strip.
_ACTOR_NORM_RE = re.compile(r"[\W_]+")
# Letter<->digit boundaries count as separators, so "APT41", "APT-41", "APT 41" are one
# identity regardless of which spelling the library stores.
_ALNUM_BOUNDARY_RE = re.compile(r"(?<=[^\W\d_])(?=\d)|(?<=\d)(?=[^\W\d_])")


def norm_actor_name(name: str) -> str:
    """Comparison key for actor-name identity: casefold, NFKD-decompose and drop combining
    marks (so 'Fáncy Bear' == 'Fancy Bear'), split letter<->digit boundaries, collapse
    non-word runs to one space. Letters in any script survive; only junk folds to ''."""
    decomposed = unicodedata.normalize("NFKD", name.casefold())
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return _ACTOR_NORM_RE.sub(" ", _ALNUM_BOUNDARY_RE.sub(" ", stripped)).strip()


def _actors_meta(threat_actors_json: str | None) -> dict:
    """The one parser for `Identified_Threat.ThreatActorsJSON` — a dict shaped
    {"actors": [...], "validated": bool} (written by tasks.py). A corrupt, absent, or
    mis-shaped blob returns {} instead of crashing. Both readers below go through here
    so the shape can't drift per-reader."""
    try:
        meta = json.loads(threat_actors_json or "{}")
    except (TypeError, ValueError):
        return {}
    return meta if isinstance(meta, dict) else {}


def stored_actors(threat_actors_json: str | None) -> list[str]:
    """The raw stored actor list, regardless of the validated flag — for paths that need
    what Stage 1 proposed: scenario prompts, API display, promotion actor-linking
    (accept.py), and treatment plans. Gating any of these would return [] for every
    unverified threat."""
    return ensure_actor_list(_actors_meta(threat_actors_json).get("actors", []))


def validated_actors(threat_actors_json: str | None) -> list[str]:
    """`stored_actors` gated on `validated` (GroundingResult.actors_validated): actors are
    trusted only when the type verified.

    No production caller today — treatment plans use `stored_actors` instead, so a plan
    sees the adversaries its own scenario names. Kept as the one place expressing the trust
    distinction, for any future path that needs only grounded actors."""
    meta = _actors_meta(threat_actors_json)
    return ensure_actor_list(meta.get("actors", []) if meta.get("validated") else [])


def ensure_text(v: Any, default: str = "") -> str:
    """Same defense as ensure_actor_list, for single text fields — a
    non-string value from the AI becomes `default` instead of crashing later.
    """
    return v if isinstance(v, str) else default


def prime_query_embeddings(llm: LLMClient, proposals: list[dict[str, Any]], cache: dict[Any, Any]) -> None:
    """Embed every proposal's type/name text in ONE call, into the shared per-run `cache`.

    Otherwise find_threat_in_library embeds its own pair per proposal — one round trip per
    threat when all the texts are known upfront. Deduped, so a repeated STRIDE type embeds
    once, not once per proposal. Best-effort: on failure the cache stays unprimed and each
    proposal embeds its own pair as before — this can only save work, never break the run."""
    texts: list[str] = []
    seen: set[str] = set()
    for p in proposals:
        for t in (ensure_text(p.get("type")), ensure_text(p.get("name"))):
            if t and t not in seen and ("qv", t) not in cache:
                seen.add(t)
                texts.append(t)
    if not texts:
        return
    try:
        vecs = llm.embed(texts, kind="query")
    except Exception:
        log.warning("grounding.prime_embeddings_failed", count=len(texts), exc_info=True)
        return
    if len(vecs) != len(texts):  # same fail-loud guard find_closest_match applies to its own embed
        raise RuntimeError(f"embed returned {len(vecs)} vectors for {len(texts)} queries")
    for t, v in zip(texts, vecs):
        cache[("qv", t)] = v


def boundary_between(below: list[float], above: list[float]) -> float | None:
    """Midpoint cutoff strictly between two score classes, or None when they overlap/are
    empty. Shared by _auto_calibrate and scripts/calibrate_grounding.py — a midpoint sits
    inside the measured gap by construction, so it can't land on or past a measured score."""
    if not below or not above:
        return None
    lo, hi = max(below), min(above)
    if lo >= hi:
        return None
    # NOT round()-ed: scores are continuous floats, and an integer midpoint can land back on
    # or outside a gap under ~1 point (max(neg)=71.2, min(pos)=71.4 → round(71.3)=71 ≤ 71.2,
    # banding a measured impostor as verified). Return the true midpoint; it's only compared.
    return (lo + hi) / 2


def resolve_thresholds(sess: Session | None, llm: LLMClient | None,
                        s: Settings | None = None, *,
                        allow_calibration: bool = False) -> float:
    """The match cutoff for the current embedding+reranker pair. Precedence:
      1. operator set it explicitly in env (in model_fields_set) → static wins;
      2. stored calibration for this model pair (embeddings.load_thresholds, Mongo);
      3. auto-calibrate now from the live library, store for later workers;
      4. unavailable (Mongo down, library too small, no sess/llm) → static default + WARNING.
    Memoized per process; celery_app._init_worker warms it at boot so calibration cost
    lands at deploy time, never inside a leased pipeline stage."""
    s = s or get_settings()
    if "grounding_match_threshold" in s.model_fields_set:
        return s.grounding_match_threshold
    key = (s.embedding_model, s.reranker_model)
    hit = _RESOLVED_THRESHOLDS.get(key)
    if hit is not None:
        return hit
    resolved = embeddings.load_thresholds(key)
    if resolved is None and allow_calibration:
        # ONLY the boot warm-up passes allow_calibration=True. Calibration costs ~30 chat
        # calls + ~180 embed/rerank calls; run lazily inside a leased THREATS stage (lease
        # covers ~2 chat calls) the lease would expire mid-pass, the reaper would ERROR and
        # close the session, and the run's spend would be discarded for nothing. Deploy-time
        # work belongs at deploy time.
        resolved = _auto_calibrate(sess, llm, s)
        if resolved is not None:
            embeddings.store_thresholds(key, resolved)
            log.info("grounding.thresholds_calibrated", embedding_model=key[0],
                    reranker_model=key[1], match_th=resolved)
    if resolved is None:
        log.warning("grounding.thresholds_uncalibrated_fallback", embedding_model=key[0],
                    reranker_model=key[1], match_th=s.grounding_match_threshold,
                    note="static default in use — it was tuned for a DIFFERENT model pair "
                        "and may misclassify; seed the threat library (>=5 entries) so worker "
                        "boot can calibrate, or set the threshold explicitly in env")
        # Deliberately NOT memoized: memoizing the fallback would pin a worker to the static
        # default even after a sibling worker stores a real calibration seconds later. Costs
        # one small indexed find_one per call, but lets the worker self-heal.
        return s.grounding_match_threshold
    _RESOLVED_THRESHOLDS[key] = resolved
    return resolved


def _paraphrase(llm: LLMClient, name: str, s: Settings) -> list[str]:
    """Up to s.calibration_paraphrases_per_name rewordings of a threat name — the
    auto-labelled POSITIVES for calibration (a real query is a paraphrase, never the exact
    library string, so exact-match self-scores would overstate a genuine match).
    Best-effort: an unparseable/failed reply contributes nothing, doesn't fail calibration."""
    n = s.calibration_paraphrases_per_name
    try:
        text, _prov = llm.chat([{
            "role": "user",
            "content": (f"Reword this cybersecurity threat name {n} different "
                        f"ways, keeping the same meaning: {name!r}. "
                        f"Reply with ONLY a json array of {n} strings.")}],
            # ARRAY, not object — without this, provider JSON mode would force json_object and
            # every paraphrase call would fail wherever TSG_LLM_JSON_MODE is enabled.
            expected_type=list)
        out = json.loads(text)
        if not isinstance(out, list):
            return []
        return [p for p in out if isinstance(p, str) and p.strip()][:n]
    except LLMSlotUnavailable:
        # NEVER swallowed — codebase-wide contract (see llm.py, tasks/cascade/embeddings).
        # Swallowed here, a transient slot squeeze would look like "every paraphrase failed"
        # -> empty positives -> permanent fallback misreported as a class overlap.
        raise
    except Exception:
        log.warning("grounding.calibration_paraphrase_failed", name=name, exc_info=True)
        return []


def _auto_calibrate(sess: Session | None, llm: LLMClient | None,
                    s: Settings) -> float | None:
    """Derive the match cutoff from the LIVE library + CURRENT models, no labelled data:
    POSITIVES = scores of LLM paraphrases of sampled catalogue names against the full library
    (what a genuine match scores under these models); NEGATIVES = each sampled name scored with
    itself removed (the best an impostor achieves). The cutoff is the midpoint between the two
    classes.
    # ponytail: heuristic band placement — a labelled-CSV run of scripts/calibrate_grounding.py
    # beats it when curators have ground truth; its env override then wins."""
    if sess is None or llm is None:
        return None
    table, name_col = embeddings._GROUPS["threat_catalogue"]
    names = embeddings._active_names(sess, table, name_col)
    if len(names) < 5:
        return None  # too little library to say anything meaningful
    sample = names[:s.calibration_sample_size]
    rows_all = [{"ThreatName": n} for n in names]
    negatives: list[float] = []
    collisions: list[tuple[float, str, str]] = []  # (score, name, nearest other) — see the warnings below

    # NEGATIVES FIRST and separately from positives: a negative is a free local embed+rerank,
    # a positive needs a BILLED paraphrase call. This lets a hopeless library (see the
    # near-duplicate bail-out below) fail before spending anything, on every boot.
    for n in sample:
        others = [r for r in rows_all if r["ThreatName"] != n]
        row, neg = find_closest_match(llm, n, others, "ThreatName", s, group="threat_catalogue")
        negatives.append(neg)
        collisions.append((neg, n, (row or {}).get("ThreatName", "")))

    # Bail BEFORE spending anything when the library itself makes success impossible. A
    # negative at/above near_duplicate_score isn't an impostor — it's a second catalogue
    # entry for the same threat (e.g. two near-duplicate names scored 99.5 on the real
    # library). boundary_between needs max(negatives) < min(positives), so one such pair
    # would need every paraphrase to clear ~100 on a 0-100 scale — unattainable. This is a
    # property of the LIBRARY, so it recurs every boot until a curator dedupes it.
    worst = max(collisions) if collisions else None
    if worst is not None and worst[0] >= s.near_duplicate_score:
        log.warning("grounding.calibration_impossible_near_duplicate_library",
                    negatives=len(negatives), highest_negative=worst[0],
                    collides=f"{worst[1]!r} ~ {worst[2]!r} @ {worst[0]:.1f}",
                    paraphrase_calls_skipped=len(sample),
                    note="two catalogue entries name the same threat, so no paraphrase can ever "
                        "outscore them — skipped the billed paraphrase pass entirely. Dedupe the "
                        "pair in `collides`, or pin TSG_GROUNDING_MATCH_THRESHOLD "
                        "(see scripts/calibrate_grounding.py)")
        return None

    positives: list[float] = []
    for n in sample:
        for p in _paraphrase(llm, n, s):
            _row, score = find_closest_match(llm, p, rows_all, "ThreatName", s, group="threat_catalogue")
            positives.append(score)
    match_th = boundary_between(negatives, positives)
    if match_th is None:
        # Counts alone cannot tell the failure modes apart, and they need opposite fixes: a
        # fractional overlap (one stray paraphrase — resample), a wide one, or an EMPTY class
        # (every paraphrase call failed — nothing was measured at all). Emit the deciding scores
        # AND the colliding pair, because the usual cause is neither the models nor the
        # paraphrases: measured on the real 85-entry catalogue the worst "impostors" are
        # reciprocal near-synonyms ('Shared, stale or orphaned account misuse' vs 'Shared,
        # default or stale OT account abuse' → 99.5) — TRUE matches mislabelled as negatives by
        # the minus-itself sampling, and one such pair alone puts strict separation out of reach
        # for ANY model pair. Naming it turns an unactionable warning into a concrete task.
        log.warning("grounding.calibration_classes_overlap",
                    positives=len(positives), negatives=len(negatives),
                    highest_negative=max(negatives, default=None),
                    lowest_positive=min(positives, default=None),
                    overlap=(round(max(negatives) - min(positives), 2)
                            if positives and negatives else None),
                    collides=(f"{worst[1]!r} ~ {worst[2]!r} @ {worst[0]:.1f}"
                            if worst is not None else None),
                    note="the highest-scoring 'impostor' is usually a near-duplicate library "
                        "entry, not a model failure — dedupe the pair in `collides`, or supply "
                        "ground truth via scripts/calibrate_grounding.py, or set the threshold "
                        "explicitly in env; falling back to the static threshold")
        return None
    return float(match_th)


def _cached(cache: dict[Any, Any], key: Any, compute: Callable[[], Any]) -> Any:
    """Cache-on-first-use: compute() runs only if key hasn't been seen this call;
    later hits reuse the stored result. See find_threat_in_library for why (a
    repeated category/type across proposals reuses the earlier DB lookup).
    """
    if key not in cache:
        cache[key] = compute()
    return cache[key]


def find_threat_in_library(sess: Session, llm: LLMClient, proposed: dict[str, Any], sector_ids: list[int],
                            settings: Settings | None = None, cache: dict[Any, Any] | None = None) -> GroundingResult:
    """Matches one AI-proposed threat ({"category", "type", "name"})
    against the real library. Matches TYPE first; if unverified, stops immediately
    (no confident ThreatTypeID to scope a name search by) and falls back to the nearest
    LIBRARY actors. Otherwise matches NAME within that type ([R6]), takes the actors
    LINKED to that type (nearest-match fallback when none are linked), and reports the
    weaker of the two confidences. Actors are library rows in every branch — the model
    is not asked for them.

    `cache`: optional dict shared across every proposal in one find_threats()
    call. sector_ids is fixed for that call, so a repeated category/type
    (common — only ~6 STRIDE categories) reuses the earlier DB lookup instead
    of re-querying. Pass None for a one-off call.
    """
    s = settings or get_settings()
    cache = {} if cache is None else cache
    # Per-model-pair cutoff (memoized; worker boot warms it) — the static setting is
    # only the fallback. See resolve_thresholds.
    match_th = resolve_thresholds(sess, llm, s)
    category_text = ensure_text(proposed.get("category"))

    ckey = ("category", category_text)
    category_id = _cached(cache, ckey, lambda: find_category(sess, category_text))

    tkey = ("types", category_id)
    types = _cached(cache, tkey, lambda: get_possible_types(sess, category_id, sector_ids))

    # Type and name query text are both known up front, so embed them together in ONE round
    # trip instead of find_closest_match's two separate single-item calls. Skipped when
    # `types` is empty since find_closest_match returns (None, 0.0) without embedding anyway.
    type_text = ensure_text(proposed.get("type"))
    name_text = ensure_text(proposed.get("name"))
    type_qv: list[float] | None = None
    name_qv: list[float] | None = None
    if types:
        # Prefer vectors primed in one batched call (prime_query_embeddings, called by
        # find_threats before its loop) — otherwise embed this proposal's pair here, so a
        # direct one-off caller still works.
        type_qv, name_qv = cache.get(("qv", type_text)), cache.get(("qv", name_text))
        if type_qv is None or name_qv is None:
            type_qv, name_qv = llm.embed([type_text, name_text], kind="query")

    # Memoized per (query text, candidate set): only ~6 STRIDE categories exist, so a repeated
    # type across proposals would rerun an identical rerank — the most expensive call in this
    # path. `types` derives from category_id (cached above) with sector_ids fixed for the
    # whole call, so the same key really does mean the same candidates.
    trow, tscore = _cached(cache, ("match_type", type_text, category_id),
                        lambda: find_closest_match(llm, type_text, types, "ThreatTypeName", s,
                                                    group="threat_type", qv=type_qv))
    tstatus = label_match_from_score(tscore, s, match_th=match_th)

    if trow is None or tstatus == GroundingStatus.unverified:
        # Unverified type: no trusted ThreatTypeID, so no linked actor set exists. Fall back
        # to the nearest LIBRARY actors for the proposal's own wording — never the model's
        # (it is no longer asked for actors at all). actors_validated=False records that this
        # came from similarity, not from a curator's link.
        return GroundingResult(
            status=GroundingStatus.unverified, score=tscore,
            actors=nearest_library_actors(sess, llm, (type_text + " " + name_text).strip()),
            actors_validated=False,
        )

    type_id = trow["ThreatTypeID"]
    nkey = ("names", type_id)
    cats = _cached(cache, nkey, lambda: get_possible_names(sess, type_id, sector_ids))
    crow, cscore = _cached(cache, ("match_name", name_text, type_id),
                        lambda: find_closest_match(llm, name_text, cats, "ThreatName", s,
                                                    group="threat_catalogue", qv=name_qv))
    # crow is None when this type has no candidate catalogue names at all (cats was empty).
    cstatus = (label_match_from_score(cscore, s, match_th=match_th)
            if crow is not None else GroundingStatus.unverified)

    akey = ("actors", type_id)
    # LIBRARY-ONLY actors: the curator's links for this type are the answer. When the type
    # has none linked yet, fall back to the nearest library actors so a threat is never
    # actor-less — validated=False marks that provenance (see GroundingResult).
    linked = _cached(cache, akey, lambda: get_allowed_actor_names(sess, type_id))
    actors = linked or nearest_library_actors(
        sess, llm, (trow["ThreatTypeName"] + " " + name_text).strip())
    actors_validated = bool(linked)

    # Symmetric with the TYPE branch: unverified type already yields type_id=None, so an
    # unverified NAME must likewise yield no id/wording. `crow` is only the best candidate,
    # never necessarily a real match — shortlisting is fail-open and rerank has no minimum,
    # so a 22/100 row is stored indistinguishably from a 97/100 one. That id is authoritative
    # downstream in three places (API display, scenario prompt, tasks._dedup_key's `cat:`
    # rung), so withholding the claim (not the score) is what matters here.
    matched = crow if cstatus == GroundingStatus.verified else None
    return GroundingResult(
        status=pick_worse_of_two(tstatus, cstatus),
        type_id=type_id,
        catalogue_id=matched["ThreatCatalogueID"] if matched else None,
        library_type=trow["ThreatTypeName"],
        library_name=matched["ThreatName"] if matched else None,
        score=min(tscore, cscore),
        actors=actors,
        actors_validated=actors_validated,
    )
