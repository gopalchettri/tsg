"""Grounding — matches an AI-proposed threat to a real library entry
(Threat_Category / Threat_Type / Threat_Catalogue / Threat_Actor), so the same
threat described in different words always resolves to the same
ThreatTypeID/ThreatCatalogueID instead of being treated as new each time.

Every match bands into GroundingStatus.verified/unverified against one cutoff
(see label_match_from_score). An unverified threat stays session-local: the ONLY
way anything enters the shared library is the deliberate promote API
(pipeline/promote.py), which reads the ids this module stored at generation time
and never re-identifies. The asset-embedded name itself never enters the library
— only its generalized generic form is promoted.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from itertools import pairwise
from types import ModuleType
from typing import Any, NamedTuple

from sqlalchemy import func, insert, or_, select, update
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import CalibrationStatus, GroundingStatus
from app.core.logging import get_logger
from app.core.naming import normalize_name
from app.db import dal
from app.db import models as m
from app.db.dal import guid, now
from app.pipeline import embeddings, hybrid_search
from app.pipeline.llm import LLMClient, LLMSlotUnavailable
from app.pipeline.validation import parse_json

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
# cutoff is therefore MEASURED per model pair (calibrate) and stored in Mongo, so a stale
# threshold can't recur — resolve_thresholds only reads; calibrate() does the measuring.
#
# Split on purpose: measuring costs minutes, reading costs one indexed find_one. It used to be
# one function that measured on demand, and worker boot called it — which put a multi-minute
# sweep in front of the worker's broker registration. See celery_app.py::_init_worker.

# NO per-process memo. One was tried and removed: nothing could invalidate it from another
# process, so the first resolve in each worker pinned that worker for its lifetime and an admin
# re-calibrating left every already-warm worker serving the superseded cutoff, silently and
# indefinitely. See resolve_thresholds for the full reasoning.

# Sample size / paraphrases-per-name: Settings.calibration_sample_size / calibration_paraphrases_per_name.
# near_duplicate_score (Settings): a negative at/above it is a duplicate catalogue entry rather
# than a true impostor. It is REPORTED as curation work and drags the cutoff down, but no longer
# aborts the run — boundary_between tolerates overlap now. See calibrate.


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


def get_possible_types(sess: Session, category_id: int | None) -> list[dict[str, Any]]:
    """Candidate Threat_Type rows for find_closest_match, narrowed to category_id (or every
    category if None, [R6]). No sector dimension: the register model scopes threats by asset
    type, and identification searches the masters as a flat namespace.

    ThreatCategoryID rides along because find_threat_in_library uses the matched type's own
    category as the fallback when the AI's category text resolved to nothing — the old select
    omitted it, so that documented fallback silently never fired.

    Category narrowing admits a type through EITHER door: its own default ThreatCategoryID,
    OR the category map ([A2] — Threat_Catalogue ⋈ Threat_Catalogue_Category_Map links a
    catalogue threat of this category to the type, making the type a legitimate candidate
    even when its default category differs). [R6]'s all-categories fallback protects the
    no-match case."""
    q = select(
        m.Threat_Type.ThreatTypeID,
        m.Threat_Type.ThreatTypeName,
        m.Threat_Type.ThreatCategoryID,
    ).where(
        m.Threat_Type.IsActive == True,
        m.Threat_Type.IsDeleted == False,
    )
    if category_id is not None:  # else fall back to searching all categories ([R6])
        # [A2]: the category MAP can admit a type whose own default category differs.
        mapped_type_ids = (
            select(m.Threat_Catalogue.ThreatTypeID)
            .join(m.Threat_Catalogue_Category_Map,
                  m.Threat_Catalogue_Category_Map.ThreatCatalogueID
                  == m.Threat_Catalogue.ThreatCatalogueID)
            .where(m.Threat_Catalogue_Category_Map.ThreatCategoryID == category_id,
                   m.Threat_Catalogue.IsActive == True,
                   m.Threat_Catalogue.IsDeleted == False)
        ).scalar_subquery()
        q = q.where(or_(m.Threat_Type.ThreatCategoryID == category_id,
                        m.Threat_Type.ThreatTypeID.in_(mapped_type_ids)))
    # ORDER BY makes row order deterministic — SQL Server scan order is not.
    q = q.order_by(m.Threat_Type.ThreatTypeID)
    return [dict(r) for r in sess.execute(q).mappings()]


def get_possible_names(sess: Session, type_id: int) -> list[dict[str, Any]]:
    """Candidate Threat_Catalogue rows under the already-matched type only — keeps the name
    match consistent with the type match instead of searching the whole library, where an
    unrelated type's entry could win on text similarity alone."""
    tc = m.Threat_Catalogue
    q = select(
        tc.ThreatCatalogueID,
        tc.ThreatName,
    ).where(
        tc.IsActive == True, tc.IsDeleted == False,
        tc.ThreatTypeID == type_id,
    ).order_by(tc.ThreatCatalogueID)  # deterministic tie-break, see get_possible_types
    return [dict(row) for row in sess.execute(q).mappings()]


def control_itot_vocabulary(sess: Session) -> set[str]:
    """DISTINCT ITOT labels the active control library actually carries (today 'IT'/'OT';
    eyshield will add labels for the other ctm_scan_category kinds). control_mapping uses it
    to decide whether a session's categories can be represented by a filter at all — a
    session category with NO labeled controls means no filter (whole library), never a
    silently narrowed pool."""
    return {v.strip() for (v,) in sess.execute(
        select(m.Control_Library.ITOT).distinct().where(
            m.Control_Library.IsActive == True, m.Control_Library.IsDeleted == False))
        if v and v.strip()}


def get_control_candidates(sess: Session, itot_labels: list[str] | None) -> list[dict[str, Any]]:
    """Active Control_Library rows for Step-4 grounding (control_mapping.map_controls).
    `text` uses the same name+description expression the embedding cache was built from
    (embeddings._CONTROL_TEXT) — must match, or cache keys won't line up.

    `itot_labels` is the DATA-DRIVEN filter control_mapping resolved from the session's asset
    categories against control_itot_vocabulary — None/empty means no filter (whole library).
    Nothing here hardcodes IT/OT: a future 'PHY_INFRA'-labeled control narrows exactly the
    same way. Fetch once per session and reuse across every suggestion, not once per query."""
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
    if itot_labels:
        q = q.where(m.Control_Library.ITOT.in_(sorted(set(itot_labels))))
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

    HYBRID shortlist: a cosine leg and a BM25 keyword leg over the same
    "ControlName: Description" corpus — rare exact tokens (product names, acronyms) carry
    strong signal that embeddings dilute — FUSED by reciprocal-rank fusion into a single
    ranked `control_map_shortlist_k`. Rank-based fusion, so the two legs' incomparable score
    scales never need calibrating against each other. The reranker stays the final arbiter of
    order; the legs only decide what gets reranked.
    Falls back to per-query llm.rerank when the client has no rerank_many (test fakes)."""
    if not rows or not queries:
        # ANSWERED, not failed: an empty library (or an empty query list) is a definitive
        # "nothing to match against", the same class of fact the docstring above describes
        # for a reranked-but-empty shortlist — never the "we never got a verdict" case. Every
        # caller trusting the `list[ControlMatches]` return type (map_controls reads
        # `.answered` on every item unconditionally) would otherwise crash with
        # AttributeError the moment this path fired, instead of the type-safe contract this
        # NamedTuple exists to guarantee.
        return [ControlMatches([], True) for _ in queries]
    names = [r["text"] for r in rows]
    # Resolve the cached matrix once for the whole batch (cheap once, wasteful per query);
    # dict-path vectors only if the matrix is unavailable.
    matrix_info = embeddings.get_matrix(llm, names, model_id=s.embedding_model,
                                        group="control_library", kind="passage")
    name_vecs = None if matrix_info is not None else embeddings.get_vectors(
        llm, names, model_id=s.embedding_model, group="control_library", kind="passage")
    # BM25 keyword leg: corpus tokenized once per batch; per query its top-ck hits are one of
    # the two rankings fed to RRF below. Zero-score docs never enter
    # (hybrid_search._ranked_indices excludes them), so an all-miss query contributes no
    # ranking and the fused order collapses to the cosine leg's — exactly as before.
    docs_tokens = [hybrid_search.tokenize(r["text"]) for r in rows]
    # Control mapping's OWN shortlist width, never grounding_shortlist_k. At the shared value
    # only ~3% of the library reached the reranker and controls it would have accepted were
    # discarded unscored — see control_map_shortlist_k. Each leg is bounded by ck and the FUSED
    # result is bounded by ck too, so this is now the true number of cross-encoder pairs per
    # query — it used to be up to 2x this, because the legs were unioned rather than fused.
    ck = s.control_map_shortlist_k
    shortlists: list[list[dict[str, Any]]] = []
    for query, qv in queries:
        if qv is None:
            vecs = llm.embed([query], kind="query")
            if len(vecs) != 1:
                raise RuntimeError(f"embed returned {len(vecs)} vectors for 1 query")
            qv = vecs[0]
        sl = (_shortlist_via_matrix(qv, rows, matrix_info, s, ck)
            if matrix_info is not None else None)
        if sl is None:
            if name_vecs is None:
                name_vecs = embeddings.get_vectors(llm, names, model_id=s.embedding_model,
                                                group="control_library", kind="passage")
            sl = _shortlist_candidates(qv, rows, name_vecs, "text", s, ck)
        kw_scores = hybrid_search.bm25_scores(hybrid_search.tokenize(query), docs_tokens)
        kw_top = hybrid_search._ranked_indices(kw_scores)[:ck]
        # RRF, not a union. The union appended the BM25 top-ck to the cosine top-ck, so the
        # shortlist was up to 2*ck — `control_map_shortlist_k` did not mean what it said, and
        # the reranker (the expensive part: a CPU cross-encoder) silently did ~40% more work
        # than the configured number implies. Fusing to ONE ranked ck makes the setting honest
        # and cuts cross-encoder pairs, WITHOUT the recall loss of simply truncating the union:
        # RRF is rank-based, so a control the keyword leg ranks first still lands near the top
        # even when cosine misses it — the exact case the BM25 leg was added for. What drops
        # out is the tail ranked weak by BOTH legs.
        # This is also the fusion threat retrieval and threat grounding already use
        # (hybrid_search.hybrid_match); control mapping was the one path doing its own thing.
        # Both legs arrive in RANK order — _apply_shortlist sorts descending before truncating
        # — which is all rrf_fuse needs; it never compares the two legs' raw scores.
        idx_of = {id(r): i for i, r in enumerate(rows)}
        cos_rank = [idx_of[id(r)] for r in sl]
        fused = hybrid_search.rrf_fuse([cos_rank, kw_top])
        sl = [rows[i] for i in sorted(fused, key=lambda i: (-fused[i], i))[:ck]]
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


def nearest_library_actors(sess: Session, llm: LLMClient, query: str,
                        top_n: int = 3) -> list[str]:
    """Nearest live Threat_Actor rows to `query` — the fallback when a threat matched no
    catalogue type with linked actors (or its type was unverified). NEVER invents: every
    returned name is a real library row, and an empty actor table yields []. Returns
    (id, name) PAIRS — actor_ids must stay intact end to end.

    HONEST LIMITATION, corrected 2026-08-24. The line below used to claim this "degrades to
    keyword-only rather than dropping the actor entirely" on an embed failure. It does not.
    Threat_Actor rows are bare 2-3 word labels with no description column, so BM25 between a
    threat sentence and "APT33" scores zero, and hybrid_search excludes zero-score docs by
    design (a leg that knows nothing must not vote). An embed failure therefore returns [] —
    a populated actor table reads as an empty one. The WARNING below is the only signal;
    lower stakes than the threat and control paths (actors annotate a threat rather than
    deciding whether it exists), so it is recorded rather than restructured.

    Hybrid (BM25 + embedding cosine) because actor names are bare 2-3 word labels with no
    description column: the keyword leg carries most of the signal ("APT33" vs "APT 33"),
    the vector leg catches wording drift. Best-effort on the vector half — but see the
    limitation above: with no description column the keyword leg usually scores zero against
    threat prose, so an embed failure returns [] rather than a weaker list.

    # ponytail: top-3 fixed. Make it a setting only if reviewers ask for a different width.
    """
    pairs = [(r[0], r[1]) for r in sess.execute(
        select(m.Threat_Actor.ThreatActorID, m.Threat_Actor.ThreatActorName)
        .where(m.Threat_Actor.IsActive == True, m.Threat_Actor.IsDeleted == False)
        .order_by(m.Threat_Actor.ThreatActorID))]
    rows = [name for _aid, name in pairs]
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
    return [pairs[i] for i, _score in ranked]


def _shortlist_candidates(qv: list[float], rows: list[dict[str, Any]], name_vecs: dict[str, list[float]],
                        name_key: str, s: Settings, k: int | None = None) -> list[dict[str, Any]]:
    """Cosine-scores every candidate against the query embedding, best match first.
    Keeps only candidates above `semantic_match_threshold`, falling back to the top-K
    anyway if nothing clears it, so a bad match still reaches label_match_from_score
    instead of returning nothing.

    [Fix] A dimension-mismatched cached vector is detected explicitly and skipped with a
    warning instead of blowing up scoring for every other candidate — one bad cache entry
    should only cost that one candidate, not the whole lookup.
    """
    # Vectorized when numpy is available: one matrix multiply replaces len(rows) pure-Python
    # dot products — same scores, same dimension-mismatch skip, same zero-magnitude
    # convention as hybrid_search.cosine.
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
            v = name_vecs[r[name_key]]
            if len(v) != len(qv):
                log.warning("grounding.dimension_mismatch_skipped", candidate=r.get(name_key))
                continue
            scored.append((r, hybrid_search.cosine(qv, v)))
    if rows and not scored:
        # Every candidate got skipped — systemic embedding-dimension drift, not a real no-match.
        # Left silent, this reads as a healthy run while raw AI text gets mass-promoted into the
        # library (score 0.0 clears no threshold). ERROR, not raise: the session still yields
        # usable unverified threats, so degrading is fine — degrading silently is not.
        log.error("grounding.all_candidates_skipped", candidates=len(rows), name_key=name_key)
    return _apply_shortlist(scored, s, k)


def _apply_shortlist(scored: list[tuple[dict[str, Any], float]], s: Settings,
                    k: int | None = None) -> list[dict[str, Any]]:
    """Shared floor/top-K tail for both scoring paths (dict loop above, matrix below).

    `k` defaults to `grounding_shortlist_k` (threat grounding, whose thresholds are calibrated
    against that value) and is passed explicitly by control mapping, which matches a scenario
    PARAGRAPH against the whole control library and needs a far wider shortlist — see
    `control_map_shortlist_k`. Making the caller name its own K is the point: one shared number
    silently starved control mapping, discarding controls the reranker would have accepted.
    """
    scored.sort(key=lambda rc: rc[1], reverse=True)
    above = [rc for rc in scored if rc[1] >= s.semantic_match_threshold]
    # Prefer candidates that clear the similarity floor; if none do, fall back to the
    # top-K overall so we still return something (to be scored as "flagged" downstream).
    return [r for r, _ in (above or scored)[: k if k is not None else s.grounding_shortlist_k]]


def _shortlist_via_matrix(qv: list[float], rows: list[dict[str, Any]],
                        matrix_info: tuple[Any, list[int]], s: Settings,
                        k: int | None = None) -> list[dict[str, Any]] | None:
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
    return _apply_shortlist([(rows[i], float(sim)) for i, sim in zip(row_indexes, sims.tolist())],
                            s, k)


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
    rerank-score tie falls back to the deterministic id order from
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

    score/status          — the weaker of the type-match and name-match confidence.
    type_id/catalogue_id  — the real library IDs matched, set ONLY when that half verified:
                            an unverified type yields type_id=None; an unverified name
                            yields catalogue_id=None and library_name=None even if a
                            best-scoring candidate existed (shortlist is fail-open, rerank
                            has no minimum — a candidate existing isn't evidence of a match).
                            catalogue_id set ⟺ status verified: the invariant every "is it a
                            library threat?" gate downstream relies on.
    actors_validated      — provenance of `actors`, which are ALWAYS real library rows
                            (library-first: the model never proposes an adversary).
                            True: taken from the matched TYPE's curated map
                            (ThreatType_ThreatActor_Map).
                            False: nearest-match fallback (no verified match, or the type has
                            no linked actors) — a similarity guess among real rows, so it
                            must never be written back as a curated link.
    """

    status: GroundingStatus
    type_id: int | None = None
    catalogue_id: int | None = None
    library_type: str | None = None
    library_name: str | None = None
    score: float | None = None
    actors: list[str] = field(default_factory=list)
    actors_validated: bool = True
    # The Threat_Actor primary keys for `actors`, same order, same length. Both actor sources
    # already SELECT ... ORDER BY ThreatActorID and used to discard the id; keeping it means every
    # consumer reads a key instead of resolving a name at read time (which returns NULL the moment
    # a name is renamed or soft-deleted).
    actor_ids: list[int] = field(default_factory=list)
    # The category id resolved to scope the type search. Previously computed and thrown away,
    # forcing accept.py to re-derive it from text three separate times.
    category_id: int | None = None
    # WHICH cutoff produced `status` — Threshold.origin ('calibrated' | 'static_default' |
    # 'env_pinned'), or 'not_applicable' where a library-first identity match consulted no cutoff
    # at all. Carried, not discarded, because those values collide numerically: a calibrated
    # 75.0 and the untuned default 75.0 are the same float, so without this there is no way to
    # find the threats graded on a default meant for a DIFFERENT model pair once a deployment
    # finally calibrates. tasks.py persists it as Identified_Threat.GroundingThresholdOrigin.
    threshold_origin: str | None = None


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


def norm_actor_name(name: str) -> str:
    """Comparison key for actor-name identity — the actor-facing name for core.naming.
    normalize_name, which is now shared with db/dal's master-row dedup so an identity
    remembered by one layer is never missed by another. Kept as a thin delegate rather than
    renamed: accept_actors' memo/triage/card-identity fold all import it by this name."""
    return normalize_name(name)


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


def stored_actor_ids(threat_actors_json: str | None) -> list[int]:
    """The Threat_Actor keys stored alongside `actors`, in the same order.

    Returns [] for a legacy blob written before actor_ids existed, and [] on any length
    mismatch with `actors` — callers fall back to name resolution rather than risk pairing a
    name with another actor's id. Goes through the same `_actors_meta` parser as the readers
    above so the shape cannot drift per-reader.
    """
    meta = _actors_meta(threat_actors_json)
    ids = meta.get("actor_ids")
    if not isinstance(ids, list) or not ids:
        return []
    if not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
        return []
    if len(ids) != len(ensure_actor_list(meta.get("actors", []))):
        log.warning("actors.id_name_length_mismatch", n_ids=len(ids))
        return []
    return ids


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


def _cut_candidates(below: list[float], above: list[float]) -> list[float]:
    """Every threshold worth evaluating: the midpoint between each pair of consecutive
    OBSERVED scores, plus one below the lowest and one above the highest. Derived from the
    data rather than a fixed grid, so a clean gap yields exactly ONE candidate inside it —
    that gap's midpoint — which is what keeps boundary_between's separable case identical to
    the hard-margin version it replaces."""
    cuts = sorted({*below, *above})
    return [cuts[0] - 0.5] + [(a + b) / 2 for a, b in pairwise(cuts)] + [cuts[-1] + 0.5]


def separation_quality(below: list[float], above: list[float], th: float) -> float:
    """Youden's J at `th`: (fraction of `above` at/over it) - (fraction of `below` at/over it).

    1.0 = separates the classes perfectly, 0.0 = no better than chance, negative = the classes
    are the wrong way round. Reported alongside every calibration so a weak-but-usable cutoff
    stays DISTINGUISHABLE from a strong one — the number alone cannot say whether it was
    measured on cleanly-separated data or scraped out of heavy overlap."""
    tpr = sum(x >= th for x in above) / len(above)
    fpr = sum(x >= th for x in below) / len(below)
    return tpr - fpr


def boundary_between(below: list[float], above: list[float]) -> float | None:
    """Best cutoff between two score classes, or None when no cutoff beats chance.

    Shared by calibrate() and scripts/calibrate_grounding.py.

    WAS a hard margin — `max(below) < min(above)` or nothing. That demanded PERFECT separation
    across every measurement, so one outlier vetoed the entire calibration, and on a real
    library there is always one. Measured live: 100 impostors, 99 of them under 85, plus a
    single reciprocal near-synonym pair at 99.5 ('Mobile, QR or collaboration-channel
    compromise' ~ 'Removable media or portable device compromise') — and calibration reported
    "impossible" on EVERY boot for it. Overlap is the normal condition of real score
    distributions, not a fault to abort on.

    So: take the cutoff that classifies the most samples correctly (maximum Youden's J), and let
    one outlier cost one sample's worth of accuracy instead of the whole run. This is a strict
    GENERALISATION of the old behaviour — on cleanly separated classes exactly one candidate
    sits in the gap and it is that gap's midpoint (see _cut_candidates), so separable inputs are
    unchanged, including the sub-1-point gap the old comment called out.

    Still returns None when nothing beats chance (J <= 0): inverted classes, identical classes
    and an empty class have no signal to find, and a fabricated cutoff would read as advice
    while separating nothing. Callers log separation_quality() next to the number so a cutoff
    scraped out of heavy overlap is never mistaken for a clean measurement."""
    if not below or not above:
        return None
    cands = _cut_candidates(below, above)
    best = max(separation_quality(below, above, t) for t in cands)
    if best <= 0:
        return None
    # Widest plateau achieving `best`: with duplicate scores several candidates tie, and the
    # middle of the winning run is the most robust of them. NOT round()-ed — scores are
    # continuous floats, and an integer midpoint can land back on or outside a gap under ~1
    # point (max(neg)=71.2, min(pos)=71.4 → round(71.3)=71 <= 71.2, banding a measured impostor
    # as verified). Return the true midpoint; it is only ever compared.
    winners = [t for t in cands if separation_quality(below, above, t) == best]
    return (min(winners) + max(winners)) / 2


class Threshold(NamedTuple):
    """A match cutoff AND where it came from — never just the number.

    `origin` is one of:
        calibrated      measured for THIS embedding+reranker pair (stored, or just computed).
                        Always wins when one exists — a paid measurement is never ignored.
        env_pinned      the operator's env value governed because NO calibration is stored for
                        this model pair — the pre-calibration bootstrap, not an override.
        static_default  the Settings default, tuned for a DIFFERENT model pair. NOT a
                        measurement. Treat any conclusion drawn from it as provisional.

    Why the number alone is not enough: the three origins collide numerically. A calibrated
    75.0, the static default 75.0 and library_promotion_threshold's unrelated 75.0 are the
    same float, so a stored `min_score: 75.0` in an audit row cannot be interrogated after the
    fact — and "the cutoff was tuned for a different model pair" is exactly the kind of thing
    a reviewer needs to know when a threat comes back `unverified`. Same reasoning as
    ControlMatches.answered: make the distinction a field, not something the caller infers."""
    value: float
    origin: str


def resolve_thresholds(sess: Session | None, llm: LLMClient | None,
                        s: Settings | None = None) -> Threshold:
    """The match cutoff for the current embedding+reranker pair, WITH its provenance.

    READ-ONLY, always. Precedence (DB FIRST — flipped 2026-08 at the operator's direction):
      1. the DATABASE — MatchTh on the latest successful run for THIS model pair. A paid
         calibration can never be silently ignored by a forgotten env line;
      2. else the env value, when set (model_fields_set) — the pre-calibration bootstrap;
      3. else the static default + WARNING, and the pipeline carries on.
    Recovery from a BAD stored calibration is a re-run (POST /v1/tsg/grounding/calibrate,
    force=true, after curating the library) — config cannot out-vote the ledger any more.

    THIS FUNCTION NEVER CALIBRATES. It used to, behind an `allow_calibration` flag, and worker
    boot set that flag — which put a 10-15 minute sweep in front of the worker's broker
    registration, where it was invisible to every readiness probe and pushed cold starts past
    start.ps1's 180s budget. The flag is DELETED rather than merely unused: measuring is
    calibrate(), reached only through the admin route, and a reader with no switch cannot be
    talked into becoming a writer again.

    `llm` is accepted but unused — kept so the many call sites need no edit, and so this stays
    signature-compatible with the reader it now is.

    NOT memoized per process, deliberately. A module-level memo was tried and removed: it had no
    invalidation reachable from another process, so the FIRST resolve in each worker pinned that
    worker for its lifetime. An admin re-calibrating after curating the library would have left
    every already-warm worker serving the superseded cutoff — silently, and indefinitely — which
    is precisely the "no restart needed" promise this feature makes. The read is one small
    indexed SELECT, and both hot callers already batch it into their per-call `cache` dict
    (see find_threat_in_library), so a fresh read per resolve is what makes every process
    converge on the newest successful run.

    Returns a Threshold, not a float, so branches 1-2-3 stay distinguishable downstream — they
    all collapse to the same handful of numbers otherwise."""
    s = s or get_settings()
    key = (s.embedding_model, s.reranker_model)
    resolved = latest_successful_run(sess, key) if sess is not None else None
    if resolved is not None:
        return Threshold(resolved, "calibrated")
    if "grounding_match_threshold" in s.model_fields_set:
        return Threshold(s.grounding_match_threshold, "env_pinned")
    log.warning("grounding.thresholds_uncalibrated_fallback", embedding_model=key[0],
                reranker_model=key[1], match_th=s.grounding_match_threshold,
                note="static default in use — it was tuned for a DIFFERENT model pair and "
                    "may misclassify. Seed the threat library (>=5 entries) and run a "
                    "calibration: POST /v1/tsg/grounding/calibrate (or "
                    "scripts/calibrate_grounding.py --recalibrate). Setting "
                    "TSG_GROUNDING_MATCH_THRESHOLD bootstraps this value until then.")
    return Threshold(s.grounding_match_threshold, "static_default")


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
        # parse_json, NOT json.loads: glm-5 returns the array inside a ```json fence, and a bare
        # json.loads then throws on the backtick at char 0 -- silently failing EVERY paraphrase,
        # which empties the POSITIVES set and leaves calibration deriving a threshold from
        # nothing. Provider-side JSON mode cannot cover this: llm.py only applies it for
        # expected_type=dict (json_object rejects a list), so fence-stripping on our side is the
        # only defence for array calls. parse_json also enforces the top-level type, so the
        # isinstance check that used to follow is now redundant.
        out = parse_json(text, stage="calibration_paraphrase", expected_type=list)
        return [p for p in out if isinstance(p, str) and p.strip()][:n]
    except LLMSlotUnavailable:
        # NEVER swallowed — codebase-wide contract (see llm.py, tasks/cascade/embeddings).
        # Swallowed here, a transient slot squeeze would look like "every paraphrase failed"
        # -> empty positives -> permanent fallback misreported as a class overlap.
        raise
    except Exception:
        log.warning("grounding.calibration_paraphrase_failed", name=name, exc_info=True)
        return []


class CalibrationResult(NamedTuple):
    """One completed calibration sweep — the cutoff AND everything needed to judge it.

    `match_th` is None when no cutoff beat chance (see boundary_between); every other field is
    still populated so the caller can say WHY. `quality` is Youden's J at `match_th` (1.0 =
    perfect separation, 0.0 = chance): the number alone can't distinguish a cutoff measured on
    clean data from one scraped out of heavy overlap, and those need different responses —
    the first is trustworthy, the second says the model pair is struggling on this library.
    `near_duplicates` is a curation to-do list, not an error (see calibrate)."""
    match_th: float | None
    quality: float
    negatives: int
    positives: int
    highest_negative: float | None
    lowest_positive: float | None
    near_duplicates: list[str]


def calibrate(sess: Session | None, llm: LLMClient | None, s: Settings | None = None,
            *, progress: Callable[[str, int, int], None] | None = None) -> CalibrationResult:
    """Derive the match cutoff from the LIVE library + CURRENT models, with no labelled data.

    NEGATIVES = each sampled name scored against the library with ITSELF REMOVED (the best an
    impostor achieves). POSITIVES = LLM paraphrases of the same names scored against the FULL
    library (what a genuine match achieves). The cutoff is the best split between the two
    classes — see boundary_between.

    EXPENSIVE and deliberately so: `calibration_sample_size` negatives (a local embed+rerank
    each) plus that many BILLED paraphrase calls. Measured live at ~106s for the negatives and
    ~5.8s per paraphrase call, so a 100-name sample runs into the minutes. This is why it is a
    JOB (celery_app.py::calibrate_grounding_task), stored once per model pair in Mongo, and
    never on the worker boot path — a worker that had to calibrate before registering on the
    broker missed start.ps1's readiness window on every cold start.

    `progress(phase, done, total)` is an optional hint for the job's SSE stream; never load-bearing.
    ponytail: heuristic band placement — a labelled-CSV run of scripts/calibrate_grounding.py
    beats it when curators have ground truth, and its env override then wins."""
    s = s or get_settings()
    empty = CalibrationResult(None, 0.0, 0, 0, None, None, [])
    if sess is None or llm is None:
        return empty
    tc = m.Threat_Catalogue
    names = [n for (n,) in sess.execute(
        select(tc.ThreatName).where(tc.IsActive == True, tc.IsDeleted == False)
        .order_by(tc.ThreatCatalogueID))]
    if len(names) < 5:
        return empty  # too little library to say anything meaningful
    sample = names[:s.calibration_sample_size]
    rows_all = [{"ThreatName": n} for n in names]
    negatives: list[float] = []
    collisions: list[tuple[float, str, str]] = []  # (score, name, nearest other)

    # NEGATIVES FIRST and separately from positives: a negative is a free local embed+rerank, a
    # positive needs a BILLED paraphrase call — so the cheap half of the evidence lands first
    # and shows up in the progress stream while the expensive half is still to come.
    for i, n in enumerate(sample, 1):
        others = [r for r in rows_all if r["ThreatName"] != n]
        row, neg = find_closest_match(llm, n, others, "ThreatName", s, group="threat_catalogue")
        negatives.append(neg)
        collisions.append((neg, n, (row or {}).get("ThreatName", "")))
        if progress:
            progress("negatives", i, len(sample))

    # A negative at/above near_duplicate_score is not an impostor — it is a second catalogue
    # entry for the same threat. This USED TO ABORT the whole calibration, because the old
    # hard-margin boundary_between needed max(negatives) < min(positives) and one such pair put
    # that out of reach for any model pair. It aborted on every boot, forever, and never stored
    # anything. boundary_between now tolerates overlap, so a near-duplicate costs one sample's
    # accuracy instead of the run: report the pairs as CURATION WORK and carry on measuring.
    dupes = [f"{n!r} ~ {other!r} @ {score:.1f}"
            for score, n, other in sorted(collisions, reverse=True)
            if score >= s.near_duplicate_score]
    if dupes:
        log.warning("grounding.calibration_near_duplicate_library",
                    pairs=len(dupes), worst=dupes[0],
                    note="these catalogue entries name the same threat, so each is scored as an "
                        "impostor against its own twin and drags the measured cutoff down. "
                        "Calibration CONTINUES (it no longer aborts on this) — dedupe them and "
                        "re-run for a tighter threshold.")

    positives: list[float] = []
    for i, n in enumerate(sample, 1):
        for p in _paraphrase(llm, n, s):
            _row, score = find_closest_match(llm, p, rows_all, "ThreatName", s, group="threat_catalogue")
            positives.append(score)
        if progress:
            progress("positives", i, len(sample))

    match_th = boundary_between(negatives, positives)
    quality = separation_quality(negatives, positives, match_th) if match_th is not None else 0.0
    result = CalibrationResult(
        match_th=float(match_th) if match_th is not None else None,
        quality=round(quality, 4),
        negatives=len(negatives), positives=len(positives),
        highest_negative=max(negatives, default=None),
        lowest_positive=min(positives, default=None),
        near_duplicates=dupes)
    if match_th is None:
        # Reaching here now means something much stronger than "the classes overlap" — it means
        # NO cutoff anywhere beat chance. Either a class is empty (every paraphrase call failed,
        # so nothing was measured at all) or the paraphrases score no higher than the impostors,
        # which indicts the model pair rather than the library. Both need the deciding numbers.
        log.warning("grounding.calibration_no_signal",
                    positives=len(positives), negatives=len(negatives),
                    highest_negative=result.highest_negative,
                    lowest_positive=result.lowest_positive,
                    worst_near_duplicate=dupes[0] if dupes else None,
                    note="no threshold classified better than chance. If `positives` is 0 every "
                        "paraphrase call failed — check the chat model. Otherwise this model "
                        "pair cannot tell a paraphrase from an impostor on this library: supply "
                        "ground truth via scripts/calibrate_grounding.py, or pin "
                        "TSG_GROUNDING_MATCH_THRESHOLD.")
    return result


# --- the calibration ledger: history AND the threshold store ------------------------------------
# Grounding_Calibration_Run is both "who calibrated, when, did it pass" and the home of the
# measured cutoff itself. One table, because the alternative — a ledger plus a separate best-effort
# write of the number — is what previously let a finished 15-minute sweep lose its answer silently.


def latest_successful_run(sess: Session, model_pair: tuple[str, str]) -> float | None:
    """MatchTh from the newest successful calibration for this embedding+reranker pair, or None.

    The read half of resolve_thresholds' branch 3. Newest-wins rather than "the one true row":
    re-calibrating after curating the library appends, so history is preserved and the latest
    measurement is simply the one in force. Never raises — a broken read must degrade to the
    static default, exactly like a missing calibration, not take the pipeline down."""
    try:
        r = m.Grounding_Calibration_Run
        return sess.execute(
            select(r.MatchTh)
            .where(r.EmbeddingModel == model_pair[0], r.RerankerModel == model_pair[1],
                r.Status == CalibrationStatus.success, r.MatchTh.is_not(None))
            .order_by(r.StartedAt.desc())
            .limit(1)
        ).scalar()
    except Exception:
        log.warning("grounding.calibration_read_failed", exc_info=True)
        return None


def _utc_naive(dt: datetime) -> datetime:
    """Strip tzinfo, so a DB value and a `dal.now()` value are comparable.

    NOT cosmetic. `dal.now()` returns `datetime.now(UTC)` — timezone-AWARE — while every
    timestamp column here is a plain `DateTime`/`datetime2`, which every driver reads back
    NAIVE. Subtracting one from the other raises
    `TypeError: can't subtract offset-naive and offset-aware datetimes`, and it raises on the
    ORDINARY path: settled_status() runs for every row the calibration-history route returns.
    Both sides are UTC, so dropping the marker is lossless and the comparison is exact.

    ponytail: normalise at the comparison, not at the boundary — a converter on the column would
    touch every table in the schema. The same latent mismatch exists in
    the retired importer's _is_abandoned; fixing that one belongs with that feature, not here."""
    return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


def _is_abandoned(row, s: Settings | None = None) -> bool:
    """True for a `running` row too old for any live worker to still hold it.

    A sweep is minutes long, so `running` alone cannot mean "in progress" — a worker killed
    mid-sweep leaves the row forever. Without this the filtered unique index, which is what makes
    concurrent sweeps impossible, would also make ALL future sweeps impossible."""
    s = s or get_settings()
    stale_after = timedelta(seconds=s.calibration_stale_after_seconds)
    return (row.Status == CalibrationStatus.running and row.StartedAt is not None
            and _utc_naive(now()) - _utc_naive(row.StartedAt) > stale_after)


def settled_status(row, s: Settings | None = None) -> str:
    """`row.Status`, except an abandoned run reads as `failed` — it cannot still be running, and
    reporting it as such misleads every consumer."""
    return CalibrationStatus.failed if _is_abandoned(row, s) else row.Status


def settled_error(row, s: Settings | None = None) -> str | None:
    """`row.ErrorMessage`, plus a synthesized cause for an abandoned run — which has none of its
    own precisely because nothing got the chance to record one."""
    if row.ErrorMessage or not _is_abandoned(row, s):
        return row.ErrorMessage
    return ("calibration did not report an outcome within the stale window — the worker was "
            "killed or hung; start a new one")


def running_run(sess: Session, model_pair: tuple[str, str]):
    """The LIVE `running` row for this pair, or None (an abandoned one does not count).

    Read by the admin route to answer 409 with a useful body. It is NOT the concurrency guard —
    that is the unique index, because any check-then-insert here has a window in which a second
    request also sees None."""
    r = m.Grounding_Calibration_Run
    row = sess.execute(
        select(r).where(r.EmbeddingModel == model_pair[0], r.RerankerModel == model_pair[1],
                        r.Status == CalibrationStatus.running)
        .order_by(r.StartedAt.desc()).limit(1)
    ).scalars().first()
    return None if row is None or _is_abandoned(row) else row


def settle_abandoned_runs(sess: Session, model_pair: tuple[str, str]) -> int:
    """Flip this pair's abandoned `running` rows to `failed`; returns how many.

    Must run BEFORE inserting a new run: the filtered unique index counts an abandoned row just
    the same as a live one, so a worker that died mid-sweep would otherwise block calibration
    permanently. Writes the synthesized cause so the ledger says why."""
    r = m.Grounding_Calibration_Run
    # _utc_naive on the BOUND parameter too, not just the Python comparison in _is_abandoned:
    # StartedAt is stored naive, and binding an aware datetime against a naive column compares
    # wrongly rather than raising — on SQLite it is a string compare where the "+00:00" suffix
    # sorts every stored value below the cutoff, which would settle LIVE runs as abandoned and
    # hand two admins two concurrent billed sweeps. A silent wrong answer, so it is worth pinning.
    cutoff = _utc_naive(now()) - timedelta(seconds=get_settings().calibration_stale_after_seconds)
    res = sess.execute(
        update(r)
        .where(r.EmbeddingModel == model_pair[0], r.RerankerModel == model_pair[1],
            r.Status == CalibrationStatus.running, r.StartedAt < cutoff)
        .values(Status=CalibrationStatus.failed, FinishedAt=now(),
                ErrorMessage="calibration did not report an outcome within the stale window — "
                            "the worker was killed or hung; superseded by a later run"))
    return res.rowcount or 0


def recent_runs(sess: Session, limit: int = 50) -> list[Any]:
    """Newest-first calibration history for the admin route — every run, including failures,
    for as long as the rows are kept. This is the whole point of the table: Celery's own result
    expires after an hour, so without it "did last Tuesday's calibration pass?" is unanswerable."""
    r = m.Grounding_Calibration_Run
    return list(sess.execute(
        select(r).order_by(r.StartedAt.desc()).limit(limit)).scalars().all())


def record_calibration_started(model_pair: tuple[str, str], *, job_id: str | None,
                            started_by: str | None, started_by_client: str | None,
                            forced: bool) -> str:
    """Open a `running` row for this sweep and return its RunID.

    Its OWN session, deliberately separate from the sweep's: the row must survive the sweep's
    transaction rolling back, or a failed calibration leaves no trace — the single case an
    operator most needs to see.

    NOT best-effort, unlike its threat-library-import counterpart: this INSERT is what the
    filtered unique index arbitrates, so swallowing its failure would silently re-open the
    double-sweep window. The caller converts an IntegrityError into a 409."""
    from app.db.engine import db_session

    run_id = guid()
    with db_session() as sess:
        settle_abandoned_runs(sess, model_pair)
        sess.execute(insert(m.Grounding_Calibration_Run).values(
            RunID=run_id, Status=CalibrationStatus.running, JobID=job_id,
            StartedBy=started_by, StartedByClient=started_by_client,
            StartedAt=now(), EmbeddingModel=model_pair[0], RerankerModel=model_pair[1],
            Forced=forced))
    return run_id


def record_calibration_finished(run_id: str, *, result: CalibrationResult | None = None,
                                error: str | None = None, skipped: float | None = None) -> None:
    """Close the run row, and — on success — STORE THE MEASURED THRESHOLD in the same write.

    Four terminal states, because they need four different responses:
      failed     an exception; fix the infrastructure and re-run
      no_signal  ran clean, nothing beat chance; curate the library or change models
      skipped    a non-forced request over an already-calibrated pair; NOTHING was measured
      success    MatchTh is the cutoff every worker will now read

    `skipped` is not pedantry. This table is the audit trail, so a row saying a calibration
    succeeded when no sweep ran is exactly the falsehood it exists to prevent — and it would carry
    fabricated Quality/counts alongside. It still CLOSES the row, which is the point: leaving it
    `running` would hold UX_GroundingCalibration_Running against the next real calibration until
    the stale window expired.

    Best-effort EXCEPT on success. On every other status this write is bookkeeping and must not
    mask the sweep's real outcome; on success the write IS the threshold, so swallowing a failure
    would lose a 10-15 minute, ~100-billed-call measurement while the caller cheerfully reported
    SUCCESS for a number nobody stored — the precise "measured but not saved" state this design
    exists to make unreachable. Letting it out makes the task fail honestly and the sweep re-runnable.

    Note the asymmetry with record_calibration_started, which must never swallow: there the write
    IS the concurrency guard."""
    from app.db.engine import db_session

    if skipped is not None:
        status = CalibrationStatus.skipped
    elif error:
        status = CalibrationStatus.failed
    elif result is None or result.match_th is None:
        status = CalibrationStatus.no_signal
    else:
        status = CalibrationStatus.success
    values: dict[str, Any] = {
        "Status": status, "FinishedAt": now(),
        "ErrorMessage": str(error)[:4000] if error else None,
    }
    if skipped is not None:
        # The value it declined to re-measure, so the row still says WHAT is in force. Quality and
        # the counts stay NULL — nothing was measured, and inventing zeros would read as a real
        # sweep that separated nothing.
        values["MatchTh"] = skipped
    elif result is not None:
        values.update(
            MatchTh=result.match_th, Quality=result.quality,
            NegativesCount=result.negatives, PositivesCount=result.positives,
            HighestNegative=result.highest_negative, LowestPositive=result.lowest_positive,
            NearDuplicatesJSON=json.dumps(result.near_duplicates) if result.near_duplicates else None)
    try:
        with db_session() as sess:
            sess.execute(update(m.Grounding_Calibration_Run)
                        .where(m.Grounding_Calibration_Run.RunID == run_id)
                        .values(**values))
    except Exception:
        if status == CalibrationStatus.success:
            raise  # see the docstring: on success this write is the measurement, not a note
        log.warning("grounding.calibration_history_finish_failed", run_id=run_id, exc_info=True)


def _cached(cache: dict[Any, Any], key: Any, compute: Callable[[], Any]) -> Any:
    """Cache-on-first-use: compute() runs only if key hasn't been seen this call;
    later hits reuse the stored result. See find_threat_in_library for why (a
    repeated category/type across proposals reuses the earlier DB lookup).
    """
    if key not in cache:
        cache[key] = compute()
    return cache[key]


def find_threat_in_library(sess: Session, llm: LLMClient, proposed: dict[str, Any],
                            settings: Settings | None = None, cache: dict[Any, Any] | None = None) -> GroundingResult:
    """Matches one AI-proposed threat ({"category", "type", "name", optional "description"})
    against the real library. Matches TYPE first; if unverified, stops immediately
    (no confident ThreatTypeID to scope a name search by) and falls back to the nearest
    LIBRARY actors. Otherwise matches NAME within that type against the catalogue ([R6]),
    takes the matched type's curated actors (nearest-match fallback when none are linked),
    and reports the weaker of the two confidences. Actors are library rows in every
    branch — the model is not asked for them.

    `cache`: optional dict shared across every proposal in one find_threats() call, so a
    repeated category/type (common — only ~6 STRIDE categories) reuses the earlier DB lookup
    instead of re-querying. Pass None for a one-off call.
    """
    s = settings or get_settings()
    cache = {} if cache is None else cache
    # Per-model-pair cutoff — the static setting is only the fallback. See resolve_thresholds.
    # Cached per CALL BATCH, not just per process: resolve_thresholds deliberately re-reads while
    # on the static default (so a worker self-heals the moment an admin calibrates), and this runs
    # once per proposed threat — without this an uncalibrated deployment issues one SELECT per
    # threat. The same `cache` dict already exists for exactly this repeated-lookup case.
    threshold = _cached(cache, ("threshold",), lambda: resolve_thresholds(sess, llm, s))
    match_th = threshold.value
    category_text = ensure_text(proposed.get("category"))

    ckey = ("category", category_text)
    category_id = _cached(cache, ckey, lambda: find_category(sess, category_text))

    tkey = ("types", category_id)
    types = _cached(cache, tkey, lambda: get_possible_types(sess, category_id))

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
    # path. `types` derives from category_id (cached above), so the same key really does mean
    # the same candidates.
    trow, tscore = _cached(cache, ("match_type", type_text, category_id),
                        lambda: find_closest_match(llm, type_text, types, "ThreatTypeName", s,
                                                    group="threat_type", qv=type_qv))
    tstatus = label_match_from_score(tscore, s, match_th=match_th)

    if trow is None or tstatus == GroundingStatus.unverified:
        # Unverified type: no trusted ThreatTypeID, so no linked actor set exists. Fall back
        # to the nearest LIBRARY actors for the proposal's own wording — never the model's
        # (it is no longer asked for actors at all). actors_validated=False records that this
        # came from similarity, not from a curator's link.
        fallback = nearest_library_actors(sess, llm, (type_text + " " + name_text).strip())
        return GroundingResult(
            status=GroundingStatus.unverified, score=tscore,
            actors=[nm for _aid, nm in fallback],
            actor_ids=[aid for aid, _nm in fallback],
            actors_validated=False,
            category_id=category_id,
            threshold_origin=threshold.origin,
        )

    type_id = trow["ThreatTypeID"]
    nkey = ("names", type_id)
    cands = _cached(cache, nkey, lambda: get_possible_names(sess, type_id))
    crow, cscore = _cached(cache, ("match_name", name_text, type_id),
                        lambda: find_closest_match(llm, name_text, cands, "ThreatName", s,
                                                    group="threat_catalogue", qv=name_qv))
    # crow is None when this type has no candidate register names at all (cands was empty).
    cstatus = (label_match_from_score(cscore, s, match_th=match_th)
            if crow is not None else GroundingStatus.unverified)

    # Symmetric with the TYPE branch: unverified type already yields type_id=None, so an
    # unverified NAME must likewise yield no id/wording. `crow` is only the best candidate,
    # never necessarily a real match — shortlisting is fail-open and rerank has no minimum,
    # so a 22/100 row is stored indistinguishably from a 97/100 one. That id is authoritative
    # downstream in three places (API display, scenario prompt, tasks._dedup_key's `cat:`
    # rung), so withholding the claim (not the score) is what matters here.
    matched = crow if cstatus == GroundingStatus.verified else None

    # LIBRARY-ONLY actors: the matched threat's TYPE map is the answer (actors attach per
    # type in this model). No verified match (or a type with no links) falls back to the
    # nearest library actors so a threat is never actor-less — validated=False marks that
    # provenance (GroundingResult).
    linked: list[tuple[int, str]] = []
    if matched is not None:
        linked = _cached(cache, ("actors", type_id),
                        lambda: dal.type_actor_pairs(sess, [type_id]).get(type_id, []))
    actor_pairs = linked or nearest_library_actors(
        sess, llm, (trow["ThreatTypeName"] + " " + name_text).strip())
    actors = [nm for _aid, nm in actor_pairs]
    actor_ids = [aid for aid, _nm in actor_pairs]
    actors_validated = bool(linked)

    return GroundingResult(
        status=pick_worse_of_two(tstatus, cstatus),
        type_id=type_id,
        catalogue_id=matched["ThreatCatalogueID"] if matched else None,
        library_type=trow["ThreatTypeName"],
        library_name=matched["ThreatName"] if matched else None,
        score=min(tscore, cscore),
        actors=actors,
        actor_ids=actor_ids,
        actors_validated=actors_validated,
        # Fall back to the TYPE's own category when the AI's category text matched nothing:
        # Threat_Type.ThreatCategoryID is a documented rough default (see models.py), and a
        # rough id beats the NULL that would silently cost the catalogue its category link.
        category_id=category_id if category_id is not None else trow.get("ThreatCategoryID"),
        threshold_origin=threshold.origin,
    )
