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

import math
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import GroundingStatus
from app.core.logging import get_logger
from app.db import models as m
from app.pipeline import embeddings
from app.pipeline.llm import LLMClient

log = get_logger(__name__)

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


def label_match_from_score(score: float, s: Settings) -> GroundingStatus:
    """The one place the confirm/grounded score cutoffs are applied."""
    if score >= s.grounding_grounded_threshold:
        return GroundingStatus.grounded
    if score >= s.grounding_confirm_threshold:
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
            .where(m.Threat_Catalogue_Category_Map.ThreatCategoryID == category_id)
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
        m.Threat_Catalogue.ThreatTypeID == type_id,
        visible_to_this_sector(m.Threat_Catalogue.SectorID, sector_ids),
    ).order_by(m.Threat_Catalogue.ThreatCatalogueID)  # deterministic tie-break, see get_possible_types
    rows = [dict(r) for r in sess.execute(q).mappings()]
    rows.sort(key=lambda r: how_specific_is_this_sector(r["SectorID"], sector_ids), reverse=True)
    return rows


def get_allowed_actor_names(sess: Session, type_id: int) -> set[str]:
    """Real, pre-approved actor names for this Threat_Type — used to drop any
    actor the AI invented that doesn't belong to it.
    """
    rows = sess.execute(
        select(m.Threat_Actor.ThreatActorName)
        .join(m.ThreatType_ThreatActor_Map,
            m.ThreatType_ThreatActor_Map.ThreatActorID == m.Threat_Actor.ThreatActorID)
        .where(m.ThreatType_ThreatActor_Map.ThreatTypeID == type_id,
            m.Threat_Actor.IsActive == True)
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
    scored = []
    for r in rows:
        try:
            scored.append((r, how_similar(qv, name_vecs[r[name_key]])))
        except ValueError:
            log.warning("grounding.dimension_mismatch_skipped", candidate=r.get(name_key))
    scored.sort(key=lambda rc: rc[1], reverse=True)
    above = [rc for rc in scored if rc[1] >= s.semantic_match_threshold]
    # Prefer candidates that clear the similarity floor; if none do, fall back to the
    # top-K overall so we still return something (to be scored as "flagged" downstream).
    return [r for r, _ in (above or scored)[: s.grounding_shortlist_k]]


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
        qv = llm.embed([query], kind="query")[0]
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
        type_qv, name_qv = llm.embed([type_text, name_text], kind="query")

    trow, tscore = find_closest_match(llm, type_text, types, "ThreatTypeName", s, group="threat_type", qv=type_qv)
    tstatus = label_match_from_score(tscore, s)

    if trow is None or tstatus == GroundingStatus.flagged:
        # Flagged type: no grounded ThreatTypeID → actors cannot be map-filtered ([R6]).
        return GroundingResult(
            status=GroundingStatus.flagged, score=tscore,
            actors=list(actors_in), actors_validated=False,
        )

    type_id = trow["ThreatTypeID"]
    nkey = ("names", type_id)
    cats = _cached(cache, nkey, lambda: get_possible_names(sess, type_id, sector_ids))
    crow, cscore = find_closest_match(llm, name_text, cats, "ThreatName", s, group="threat_catalogue", qv=name_qv)
    # crow is None when this type has no candidate catalogue names at all (cats was empty).
    cstatus = label_match_from_score(cscore, s) if crow is not None else GroundingStatus.flagged

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
