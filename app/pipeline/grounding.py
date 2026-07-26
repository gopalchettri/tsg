"""Grounding — matches an AI-proposed threat to a real entry in the org's
threat library (Threat_Category/Threat_Type/Threat_Catalogue/Threat_Actor),
so the same real-world threat described in different words always resolves
to the same ThreatTypeID/ThreatCatalogueID instead of being treated as new
each time.

Every match bands into GroundingStatus.grounded/confirm/flagged (cutoffs are
configurable Settings, see label_match_from_score) — flagged means "not in
the library yet"; accept.py promotes it to a new entry once a human accepts it.

sector_ids is always [own_sector_id, parent_sector_id] (fewer/empty = no
sector context) — see visible_to_this_sector / how_specific_is_this_sector.
"""
from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import GroundingStatus
from app.core.logging import get_logger
from app.db import models as m
from app.pipeline import embeddings
from app.pipeline.llm import LLMClient, LLMSlotUnavailable

log = get_logger(__name__)

# numpy rides in with the optional sentence-transformers extra (requirements' `local` provider);
# a litellm-proxy-only deployment may not have it. _shortlist_candidates uses it when present —
# pure-Python cosine is fine for the ~85-row threat library but O(candidates x dims) per query,
# which at Control_Library scale (1,288 rows x 1,024 dims) costs whole seconds of CPU per query
# on a gevent worker. The pure-Python branch below stays as the no-numpy fallback.
try:
    import numpy as _np
except ImportError:  # pragma: no cover — exercised only in numpy-less deployments
    _np = None

# Gives each grounding band a rank so two statuses can be compared (see pick_worse_of_two).
_BAND_ORDER = {GroundingStatus.grounded: 2, GroundingStatus.confirm: 1, GroundingStatus.flagged: 0}


def how_similar(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity; 0.0 for a zero-magnitude vector instead of raising.

    [Fix] raises ValueError on a LENGTH mismatch rather than letting zip(a, b) silently
    truncate to the shorter vector. A length mismatch is never legitimate input — it always
    means a real embedding-dimension problem (e.g. a cached vector left over from before an
    EMBEDDING_PROVIDER/EMBEDDING_DIMENSIONS change; llm.py's verify_litellm_models catches a
    boot-time MISCONFIGURATION, but not a vector already sitting in the cache from before
    that). Silently truncating would produce a numerically plausible but meaningless score
    with no error anywhere — the caller (_shortlist_candidates) is what decides how broadly
    a single bad vector should be allowed to fail, not this function.
    """
    if len(a) != len(b):
        raise ValueError(f"how_similar received vectors of different lengths ({len(a)} vs {len(b)})")
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return 0.0 if na == 0 or nb == 0 else dot / (na * nb)


def label_match_from_score(score: float, s: Settings, *, grounded_th: float | None = None,
                        confirm_th: float | None = None) -> GroundingStatus:
    """The one place the confirm/grounded score cutoffs are applied. The optional overrides carry
    resolve_thresholds' per-model-pair values (find_threat_in_library passes them); left None,
    the static settings fields apply — direct callers and tests are unchanged."""
    g = s.grounding_grounded_threshold if grounded_th is None else grounded_th
    c = s.grounding_confirm_threshold if confirm_th is None else confirm_th
    if score >= g:
        return GroundingStatus.grounded
    if score >= c:
        return GroundingStatus.confirm
    return GroundingStatus.flagged


def pick_worse_of_two(a: GroundingStatus, b: GroundingStatus) -> GroundingStatus:
    """Overall confidence is only as good as the weaker of two checks (type vs name)."""
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
        # [A2] Threat_Type.ThreatCategoryID is only a rough single default — an individual
        # Threat_Catalogue row under a type can carry a DIFFERENT/additional STRIDE category
        # via Threat_Catalogue_Category_Map (74/75 real curated threats do). Narrowing on the
        # Type's default alone would wrongly drop a type whose real match is via one of its
        # OTHER mapped categories, so a type counts as a candidate if EITHER matches.
        mapped_type_ids = (
            select(m.Threat_Catalogue.ThreatTypeID)
            .join(m.Threat_Catalogue_Category_Map,
                m.Threat_Catalogue_Category_Map.ThreatCatalogueID == m.Threat_Catalogue.ThreatCatalogueID)
            .where(m.Threat_Catalogue_Category_Map.ThreatCategoryID == category_id,
                m.Threat_Catalogue.IsActive == True, m.Threat_Catalogue.IsDeleted == False)
        )
        q = q.where(or_(m.Threat_Type.ThreatCategoryID == category_id,
                        m.Threat_Type.ThreatTypeID.in_(mapped_type_ids)))
    # ORDER BY makes the underlying row order deterministic (same reason find_category
    # above orders by ThreatCategoryID) so the stable sort below breaks same-specificity
    # ties the same way every time, instead of following SQL Server's arbitrary scan order.
    q = q.order_by(m.Threat_Type.ThreatTypeID)
    rows = [dict(r) for r in sess.execute(q).mappings()]
    rows.sort(key=lambda r: how_specific_is_this_sector(r["SectorID"], sector_ids), reverse=True)
    return rows


def get_possible_names(sess: Session, type_id: int, sector_ids: list[int]) -> list[dict[str, Any]]:
    """Candidate Threat_Catalogue rows under the already-matched type ONLY
    keeps the name match consistent with the type match instead of
    searching the whole library, where an unrelated type's entry could win on
    text similarity alone.
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
    """Active Control_Library rows as candidates for Step-4 grounding (control_mapping.map_controls),
    each carrying `text` = the SAME name+description expression the embedding cache was built
    from (embeddings._CONTROL_TEXT — sharing it is load-bearing for cache-key equality).

    `itot` pre-filter is tolerant: it narrows to IT-only or OT-only controls ONLY when the
    asset's declared type is literally 'IT'/'OT' (case folded by the caller); any other value
    searches the whole library rather than guessing a family. Fetch once per session and reuse
    across every suggestion — not once per query."""
    q = select(
        m.Control_Library.ControlLibraryID,
        m.Control_Library.ControlCode,
        m.Control_Library.Domain,
        m.Control_Library.ControlName,
        embeddings._CONTROL_TEXT.label("text"),
    ).where(
        m.Control_Library.IsActive == True,  # noqa: E712
        m.Control_Library.IsDeleted == False,  # noqa: E712
    ).order_by(m.Control_Library.ControlLibraryID)  # deterministic tie-break, see get_possible_types
    if itot in ("IT", "OT"):
        q = q.where(m.Control_Library.ITOT == itot)
    return [dict(r) for r in sess.execute(q).mappings()]


def ground_control_queries(llm: LLMClient, queries: list[tuple[str, list[float] | None]],
                           rows: list[dict[str, Any]], s: Settings) -> list[tuple[dict[str, Any], float] | None]:
    """Batch Step-4 grounding: every query shortlists against the SAME candidate set, then all
    shortlists rerank in one llm.rerank_many call (one local model dispatch, or
    bounded-concurrent remote calls) instead of one rerank round trip per query.

    `queries` = (text, optionally pre-embedded qv). Returns the best (row, score) per query,
    in order, or None for a query that produced no shortlist or whose rerank failed —
    PER-ITEM fail-open (a dropped suggestion, logged) matching Step 4's enrichment posture;
    raises only when rerank_many itself decides the failure is systemic (every item failed).
    Falls back to per-query llm.rerank when the client has no rerank_many (test fakes)."""
    if not rows or not queries:
        return [None] * len(queries)
    names = [r["text"] for r in rows]
    # Resolve the cached matrix ONCE for the whole batch (the digest check costs ~ms — fine
    # once, wasteful once per query); dict-path vectors only if the matrix is unavailable.
    matrix_info = embeddings.get_matrix(llm, names, model_id=s.embedding_model,
                                        group="control_library", kind="passage")
    name_vecs = None if matrix_info is not None else embeddings.get_vectors(
        llm, names, model_id=s.embedding_model, group="control_library", kind="passage")
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
            except Exception:  # noqa: BLE001
                failures += 1
                log.warning("controls.rerank_item_failed", query=q[:80], exc_info=True)
                scored.append(None)
        if items and failures == len(items):
            raise RuntimeError(f"all {len(items)} control rerank calls failed")
    results: list[tuple[dict[str, Any], float] | None] = [None] * len(queries)
    for i, rr in zip(todo, scored):
        if rr is None:
            continue
        docs = shortlists[i]
        if len(rr) != len(docs):  # same fail-loud guard as find_closest_match
            raise RuntimeError(f"rerank returned {len(rr)} scores for {len(docs)} docs")
        results[i] = max(zip(docs, rr), key=lambda rs: rs[1])
    return results


def get_allowed_actor_names(sess: Session, type_id: int) -> set[str]:
    """Real, pre-approved actor names for this Threat_Type — used to drop any
    actor the AI invented that doesn't belong to it.
    """
    rows = sess.execute(
        select(m.Threat_Actor.ThreatActorName)
        .join(m.ThreatType_ThreatActor_Map,
            m.ThreatType_ThreatActor_Map.ThreatActorID == m.Threat_Actor.ThreatActorID)
        .where(m.ThreatType_ThreatActor_Map.ThreatTypeID == type_id,
            m.Threat_Actor.IsActive == True, m.Threat_Actor.IsDeleted == False)
    )
    return {r[0] for r in rows}


def _shortlist_candidates(qv: list[float], rows: list[dict[str, Any]], name_vecs: dict[str, list[float]],
                           name_key: str, s: Settings) -> list[dict[str, Any]]:
    """Cosine-scores every candidate against the query embedding, best match
    first. The semantic-match floor keeps only candidates above
    `semantic_match_threshold`, but falls back to the top-K anyway if nothing
    clears it, so a bad match still reaches label_match_from_score as
    `flagged` instead of silently returning nothing.
    [Fix] a single dimension-mismatched cached vector (see how_similar's ValueError) is
    skipped with a warning, not allowed to blow up scoring for every OTHER candidate — the
    blast radius of one corrupted cache entry should be "this one candidate isn't considered
    this time," not "the whole grounding lookup fails." If every candidate ends up skipped,
    the caller's own `if not shortlist: return None, 0.0` already handles that gracefully.
    """
    # Score every candidate against the query by cosine similarity, best match first.
    # Vectorized when numpy is available (see the guarded import at module top): one matrix
    # multiply replaces len(rows) pure-Python dot products — same scores, same
    # dimension-mismatch skip, same 0.0-for-zero-magnitude convention as how_similar.
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

    `qv`: an already-computed embedding for `query`. Pass this when the caller has
    batched `query`'s embed together with a sibling query text (see
    find_threat_in_library, which embeds the type+name text in one round trip
    instead of two) — omit it (default None) for a one-off call, which embeds
    `query` here exactly as before.

    embeddings.get_vectors() caches candidate vectors per (model, group), so
    the library is embedded once, not on every call. The final sort is stable,
    so an exact rerank-score tie falls back to the sector-specificity order set
    by get_possible_types/get_possible_names ([R6]).
    """
    if not rows:
        return None, 0.0
    names = [r[name_key] for r in rows]
    if qv is None:
        vecs = llm.embed([query], kind="query")
        if len(vecs) != 1:  # fail loud rather than a bare IndexError — same guard as the rerank check below
            raise RuntimeError(f"embed returned {len(vecs)} vectors for 1 query")
        qv = vecs[0]
    # Fast path: the cached pre-normalized matrix (built once per library state) turns the
    # per-candidate cosine loop into a single matvec. Falls back to the per-vector dict path
    # when numpy is absent or the query dimension doesn't match the cached matrix.
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
    # Pair each shortlisted row back up with its rerank score and pick the best.
    ranked = sorted(zip(shortlist, rr), key=lambda rs: rs[1], reverse=True)
    return ranked[0]  # (row, score)


@dataclass
class GroundingResult:
    """Verdict for one proposed threat, returned by find_threat_in_library().

    score/status         — the weaker of the type-match and name-match confidence.
    type_id/catalogue_id — the real library IDs matched, or None if flagged.
    actors_validated      — False means the type was flagged, so `actors` is
                            the AI's raw/unchecked proposal, not confirmed
                            against the library's allowed set.
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
    single characters via `list(raw)`, and a non-str list element isn't
    hashable against the allowed-actor set — both are handled safely here
    instead of crashing.
    """
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, str)]
    return []


def ensure_text(v: Any, default: str = "") -> str:
    """Same defense as ensure_actor_list, for single text fields — a
    non-string value from the AI becomes `default` instead of crashing later.
    """
    return v if isinstance(v, str) else default


def prime_query_embeddings(llm: LLMClient, proposals: list[dict[str, Any]], cache: dict[Any, Any]) -> None:
    """Embed every proposal's type/name text in ONE call, into the shared per-run `cache`.

    find_threat_in_library otherwise embeds its own pair per proposal — one round trip per
    proposed threat (up to max_threats_per_asset) for texts that are all known before the loop
    even starts. Deduped, so a repeated STRIDE type is embedded once, not once per proposal.
    Best-effort: a failure here leaves the cache unprimed and each proposal embeds its own pair
    exactly as before, so this can only ever save work, never break the run."""
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
    except Exception:  # noqa: BLE001 — pure optimization; the per-proposal path still works
        log.warning("grounding.prime_embeddings_failed", count=len(texts), exc_info=True)
        return
    if len(vecs) != len(texts):  # same fail-loud guard find_closest_match applies to its own embed
        raise RuntimeError(f"embed returned {len(vecs)} vectors for {len(texts)} queries")
    for t, v in zip(texts, vecs):
        cache[("qv", t)] = v


# --- self-calibrating thresholds -------------------------------------------------------------
# The grounded/confirm cutoffs are MODEL-SPECIFIC: a different embedding+reranker pair scores the
# SAME threat/library match differently, so static numbers silently misclassify after any model
# change (a threat that grounds in dev can flag in prod, with no error anywhere — and flagged
# threats are what library promotion feeds on). The resolver below derives the cutoffs from the
# live models + live library, per model pair, so stale thresholds structurally cannot recur.

_RESOLVED_THRESHOLDS: dict[tuple[str, str], tuple[float, float]] = {}
_CALIBRATION_SAMPLE = 30
# A "negative" at/above this is a DUPLICATE catalogue entry, not an impostor — on the 0-100 rerank
# scale nothing a paraphrase can score reliably clears it, so calibration is unwinnable until the
# library is deduped. Measured: the real catalogue's worst pair scores 99.5. See _auto_calibrate.
_NEAR_DUPLICATE_SCORE = 99.0
_PARAPHRASES_PER_NAME = 2


def boundary_between(below: list[float], above: list[float]) -> float | None:
    """Midpoint cutoff strictly between two score classes, or None when they overlap/are empty.
    Shared by _auto_calibrate and scripts/calibrate_grounding.py — deriving each threshold
    independently (min-margin / max+margin) can emit an inverted CONFIRM >= GROUNDED pair that
    config's own validator rejects; a midpoint between ADJACENT classes cannot invert."""
    if not below or not above:
        return None
    lo, hi = max(below), min(above)
    if lo >= hi:
        return None
    # NOT round()-ed: scores are continuous floats, so an integer midpoint can land back ON or
    # OUTSIDE the measured gap when it is under ~1 point (max(neg)=71.2, min(pos)=71.4 →
    # round(71.3)=71 ≤ 71.2, and label_match_from_score's `score >= th` would then band a
    # measured IMPOSTOR as grounded — auto-accepted with no human review). Return the true
    # midpoint; the value is only ever compared, never displayed as a whole number.
    return (lo + hi) / 2


def resolve_thresholds(sess: Session | None, llm: LLMClient | None,
                        s: Settings | None = None, *,
                        allow_calibration: bool = False) -> tuple[float, float]:
    """(grounded_th, confirm_th) for the CURRENT embedding+reranker pair. Precedence:
      1. operator explicitly set them in env (they appear in model_fields_set) → static wins;
      2. stored calibration for this exact model pair (embeddings.load_thresholds, Mongo);
      3. auto-calibrate now from the live library, store for every later worker;
      4. anything unavailable (Mongo down, library too small, no sess/llm) → the static
         defaults + a WARNING — degrade-safe, never blocks a run.
    Memoized per process; celery_app._init_worker warms it at boot so the one-time calibration
    cost lands at deploy time, never inside a leased pipeline stage."""
    s = s or get_settings()
    if ("grounding_grounded_threshold" in s.model_fields_set
            or "grounding_confirm_threshold" in s.model_fields_set):
        return s.grounding_grounded_threshold, s.grounding_confirm_threshold
    key = (s.embedding_model, s.reranker_model)
    hit = _RESOLVED_THRESHOLDS.get(key)
    if hit is not None:
        return hit
    resolved = embeddings.load_thresholds(key)
    if resolved is None and allow_calibration:
        # ONLY the boot warm-up passes allow_calibration=True. Calibration is ~30 sequential
        # chat calls plus ~180 embed/rerank calls; run lazily from find_threat_in_library it
        # would execute INSIDE a leased THREATS stage whose lease covers roughly two chat calls,
        # so the lease expires mid-pass, the reaper ERRORs the row and closes out the session,
        # and the worker's eventual finish_stage loses its CAS — a healthy run cancelled and its
        # spend discarded. Deploy-time work belongs at deploy time.
        resolved = _auto_calibrate(sess, llm, s)
        if resolved is not None:
            embeddings.store_thresholds(key, *resolved)
            log.info("grounding.thresholds_calibrated", embedding_model=key[0],
                    reranker_model=key[1], grounded_th=resolved[0], confirm_th=resolved[1])
    if resolved is None:
        log.warning("grounding.thresholds_uncalibrated_fallback", embedding_model=key[0],
                    reranker_model=key[1], grounded_th=s.grounding_grounded_threshold,
                    confirm_th=s.grounding_confirm_threshold,
                    note="static defaults in use — they were tuned for a DIFFERENT model pair "
                        "and may misclassify; seed the threat library (>=5 entries) so worker "
                        "boot can calibrate, or set the thresholds explicitly in env")
        # Deliberately NOT memoized: memoizing the fallback pinned a worker to static defaults
        # for its whole life, even after a SIBLING worker stored a real calibration seconds
        # later. Leaving it unmemoized costs one small indexed find_one per grounding call and
        # lets the worker self-heal the moment a calibration exists.
        return (s.grounding_grounded_threshold, s.grounding_confirm_threshold)
    _RESOLVED_THRESHOLDS[key] = resolved
    return resolved


def _paraphrase(llm: LLMClient, name: str) -> list[str]:
    """Up to _PARAPHRASES_PER_NAME rewordings of a threat name — the auto-labelled POSITIVES
    for calibration (a real-world query is a paraphrase, never the exact library string, so
    exact-string self-matches would overstate what a genuine match scores). Best-effort: an
    unparseable/failed reply contributes nothing rather than failing calibration."""
    try:
        text, _prov = llm.chat([{
            "role": "user",
            "content": (f"Reword this cybersecurity threat name {_PARAPHRASES_PER_NAME} different "
                        f"ways, keeping the same meaning: {name!r}. "
                        f"Reply with ONLY a json array of {_PARAPHRASES_PER_NAME} strings.")}])
        out = json.loads(text)
        if not isinstance(out, list):
            return []
        return [p for p in out if isinstance(p, str) and p.strip()][:_PARAPHRASES_PER_NAME]
    except LLMSlotUnavailable:
        # NEVER swallowed — the codebase-wide contract (llm.py's own docstring; the explicit
        # re-raises in tasks/cascade/embeddings). Swallowed here it would turn a coordinated
        # restart's transient slot squeeze into "every paraphrase failed" → empty positives →
        # a permanent static-threshold fallback, misreported as a class-overlap. Propagating it
        # lets the boot warm-up's retry loop do its job.
        raise
    except Exception:  # noqa: BLE001 — a malformed/failed reply just contributes no positives
        log.warning("grounding.calibration_paraphrase_failed", name=name, exc_info=True)
        return []


def _auto_calibrate(sess: Session | None, llm: LLMClient | None,
                    s: Settings) -> tuple[float, float] | None:
    """Derive (grounded_th, confirm_th) from the LIVE library + CURRENT models, no labelled data:
    POSITIVES = scores of LLM paraphrases of sampled catalogue names against the full library
    (what a genuine match scores under THESE models); NEGATIVES = each sampled name scored with
    itself removed (the best an impostor achieves). grounded_th = midpoint between the classes;
    confirm_th = midpoint between the negatives' median and grounded_th (the "plausible but
    unsure" band lives in the negatives' upper tail).
    # ponytail: heuristic band placement; a labelled-CSV run of scripts/calibrate_grounding.py
    # beats it when curators can supply ground truth — its env override then wins."""
    if sess is None or llm is None:
        return None
    table, name_col = embeddings._GROUPS["threat_catalogue"]  # noqa: SLF001 — deliberate internal reuse
    names = embeddings._active_names(sess, table, name_col)  # noqa: SLF001
    if len(names) < 5:
        return None  # too little library to say anything meaningful
    sample = names[:_CALIBRATION_SAMPLE]
    rows_all = [{"ThreatName": n} for n in names]
    negatives: list[float] = []
    collisions: list[tuple[float, str, str]] = []  # (score, name, nearest other) — see the warnings below

    # NEGATIVES FIRST, and separately from the positives, because the two cost wildly different
    # things: a negative is a local embed+rerank (free, in-process), while every positive needs a
    # BILLED paraphrase call. Interleaved — as this loop used to be — the pass paid for ~30 LLM
    # requests before it could discover that separation was unreachable, and repeated that spend
    # on EVERY worker boot, forever, in any environment that had not pinned the thresholds.
    for n in sample:
        others = [r for r in rows_all if r["ThreatName"] != n]
        row, neg = find_closest_match(llm, n, others, "ThreatName", s, group="threat_catalogue")
        negatives.append(neg)
        collisions.append((neg, n, (row or {}).get("ThreatName", "")))

    # Bail BEFORE spending anything when the library itself makes success impossible. A negative
    # at/above _NEAR_DUPLICATE_SCORE is not an impostor at all: it is a second catalogue entry for
    # the same threat ('Shared, stale or orphaned account misuse' ~ 'Shared, default or stale OT
    # account abuse' scored 99.5 on the real 85-entry library). boundary_between needs
    # max(negatives) < min(positives), so ONE such pair would require every paraphrase to clear
    # ~100 on a 0-100 scale — unattainable for any model. This is a property of the LIBRARY, so it
    # recurs identically every boot until a curator dedupes; detecting it here is what stops the
    # symptom from coming back rather than just reporting it after the fact.
    worst = max(collisions) if collisions else None
    if worst is not None and worst[0] >= _NEAR_DUPLICATE_SCORE:
        log.warning("grounding.calibration_impossible_near_duplicate_library",
                    negatives=len(negatives), highest_negative=worst[0],
                    collides=f"{worst[1]!r} ~ {worst[2]!r} @ {worst[0]:.1f}",
                    paraphrase_calls_skipped=len(sample),
                    note="two catalogue entries name the same threat, so no paraphrase can ever "
                        "outscore them — skipped the billed paraphrase pass entirely. Dedupe the "
                        "pair in `collides`, or pin TSG_GROUNDING_GROUNDED_THRESHOLD / "
                        "TSG_GROUNDING_CONFIRM_THRESHOLD (see scripts/calibrate_grounding.py)")
        return None

    positives: list[float] = []
    for n in sample:
        for p in _paraphrase(llm, n):
            _row, score = find_closest_match(llm, p, rows_all, "ThreatName", s, group="threat_catalogue")
            positives.append(score)
    grounded_th = boundary_between(negatives, positives)
    if grounded_th is None:
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
                        "ground truth via scripts/calibrate_grounding.py, or set the thresholds "
                        "explicitly in env; falling back to static thresholds")
        return None
    # Annotated float, not left to inference: round() returns int, so the degenerate-spacing
    # branch below (`grounded_th - 1`, a float) was assigning float into an int-inferred local.
    confirm_th: float = round((statistics.median(negatives) + grounded_th) / 2)
    if confirm_th >= grounded_th:  # degenerate spacing — preserve config's confirm < grounded invariant
        confirm_th = grounded_th - 1
    return float(grounded_th), float(confirm_th)


def _cached(cache: dict[Any, Any], key: Any, compute: Callable[[], Any]) -> Any:
    """Cache-on-first-use: `compute()` only runs if `key` hasn't been seen yet
    this call, then every later hit reuses the stored result — see
    find_threat_in_library's docstring for why (repeat category/type across
    proposals in one find_threats() call reuses the earlier DB lookup).
    """
    if key not in cache:
        cache[key] = compute()
    return cache[key]


def find_threat_in_library(sess: Session, llm: LLMClient, proposed: dict[str, Any], sector_ids: list[int],
                            settings: Settings | None = None, cache: dict[Any, Any] | None = None) -> GroundingResult:
    """Matches one AI-proposed threat ({"category", "type", "name", "actors"})
    against the real library. Matches TYPE first; if that's flagged, stops
    immediately — there's no confident ThreatTypeID to scope a name/actor
    search by — and returns actors raw/unvalidated. Otherwise matches NAME
    within that type only ([R6]), filters actors to the type's allowed set,
    and reports the weaker of the type/name confidence.

    `cache`: optional dict, shared by the caller across every proposal in one
    find_threats() call. sector_ids is fixed for that whole call, so a repeat
    category/type across proposals (common — the AI only has ~6 STRIDE
    categories to choose from) can reuse the earlier DB lookup instead of
    re-querying. Pass None for a one-off call; each key is looked up fresh.
    """
    s = settings or get_settings()
    cache = {} if cache is None else cache
    # Per-model-pair cutoffs (memoized; worker boot warms them) — static settings numbers are
    # only the fallback. See resolve_thresholds.
    grounded_th, confirm_th = resolve_thresholds(sess, llm, s)
    actors_in = ensure_actor_list(proposed.get("actors", []))
    category_text = ensure_text(proposed.get("category"))

    ckey = ("category", category_text)
    category_id = _cached(cache, ckey, lambda: find_category(sess, category_text))

    tkey = ("types", category_id)
    types = _cached(cache, tkey, lambda: get_possible_types(sess, category_id, sector_ids))

    # Both the type and name query text are known up front, regardless of the type-match
    # outcome, so embed them together in ONE round trip instead of find_closest_match doing
    # two separate single-item llm.embed() calls — one per proposal instead of up to two.
    # Skipped when `types` is empty since find_closest_match would return (None, 0.0)
    # without embedding anything anyway (see its `if not rows` guard).
    type_text = ensure_text(proposed.get("type"))
    name_text = ensure_text(proposed.get("name"))
    type_qv: list[float] | None = None
    name_qv: list[float] | None = None
    if types:
        # Prefer vectors primed in ONE batched call for every proposal (prime_query_embeddings,
        # called by find_threats before its loop) — otherwise embed this proposal's pair here,
        # exactly as before, so a direct one-off caller still works.
        type_qv, name_qv = cache.get(("qv", type_text)), cache.get(("qv", name_text))
        if type_qv is None or name_qv is None:
            type_qv, name_qv = llm.embed([type_text, name_text], kind="query")

    # Memoized per (query text, candidate set): the AI only has ~6 STRIDE categories to choose
    # from, so a repeated type across proposals re-ran an IDENTICAL rerank — the single most
    # expensive model call in this path. `types` is itself derived from category_id (cached
    # above) with sector_ids fixed for the whole find_threats() call, so the same key really
    # does mean the same candidates.
    trow, tscore = _cached(cache, ("match_type", type_text, category_id),
                        lambda: find_closest_match(llm, type_text, types, "ThreatTypeName", s,
                                                    group="threat_type", qv=type_qv))
    tstatus = label_match_from_score(tscore, s, grounded_th=grounded_th, confirm_th=confirm_th)

    if trow is None or tstatus == GroundingStatus.flagged:
        # Flagged type: no grounded ThreatTypeID → actors cannot be map-filtered ([R6]).
        return GroundingResult(
            status=GroundingStatus.flagged, score=tscore,
            actors=list(actors_in), actors_validated=False,
        )

    type_id = trow["ThreatTypeID"]
    nkey = ("names", type_id)
    cats = _cached(cache, nkey, lambda: get_possible_names(sess, type_id, sector_ids))
    crow, cscore = _cached(cache, ("match_name", name_text, type_id),
                        lambda: find_closest_match(llm, name_text, cats, "ThreatName", s,
                                                    group="threat_catalogue", qv=name_qv))
    # crow is None when this type has no candidate catalogue names at all (cats was empty).
    cstatus = (label_match_from_score(cscore, s, grounded_th=grounded_th, confirm_th=confirm_th)
            if crow is not None else GroundingStatus.flagged)

    akey = ("actors", type_id)
    allowed = _cached(cache, akey, lambda: get_allowed_actor_names(sess, type_id))
    actors = [a for a in actors_in if a in allowed]  # drop out-of-set (§8.4 step 5)

    return GroundingResult(
        status=pick_worse_of_two(tstatus, cstatus),
        type_id=type_id,
        catalogue_id=crow["ThreatCatalogueID"] if crow else None,
        library_type=trow["ThreatTypeName"],
        library_name=crow["ThreatName"] if crow else None,
        score=min(tscore, cscore),
        actors=actors,
        actors_validated=True,
    )


if __name__ == "__main__":  # cosine self-check
    assert abs(how_similar([1, 0], [1, 0]) - 1.0) < 1e-9
    assert abs(how_similar([1, 0], [0, 1])) < 1e-9
    try:
        how_similar([1, 0, 0], [1, 0])  # [Fix] length mismatch must raise, never silently truncate
        raise AssertionError("how_similar must raise ValueError on a length mismatch")
    except ValueError:
        pass
    print("grounding self-check ok")
