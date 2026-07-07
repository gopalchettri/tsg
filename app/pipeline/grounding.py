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
from typing import Any, Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import GroundingStatus
from app.db import models as m
from app.pipeline import embeddings
from app.pipeline.llm import LLMClient

_BAND_ORDER = {GroundingStatus.grounded: 2, GroundingStatus.confirm: 1, GroundingStatus.flagged: 0}


def how_similar(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity; 0.0 for a zero-magnitude vector instead of raising."""
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
        select(m.Threat_Category.c.ThreatCategoryID)
        .where(
            m.Threat_Category.c.IsActive == True,
            or_(
                func.lower(m.Threat_Category.c.ThreatCategoryName) == p,
                func.lower(m.Threat_Category.c.ThreatCategoryCode) == p,
            ),
        )
        .order_by(m.Threat_Category.c.ThreatCategoryID)
    ).first()
    return row[0] if row else None


def get_possible_types(sess: Session, category_id: int | None, sector_ids: list[int]) -> list[dict[str, Any]]:
    """Candidate Threat_Type rows for find_closest_match: sector-filtered, and
    narrowed to category_id (or every category if None, [R6]). Pre-sorted by
    how_specific_is_this_sector so a later scoring tie breaks toward the more
    specific row.
    """
    q = select(m.Threat_Type).where(
        m.Threat_Type.c.IsActive == True,
        visible_to_this_sector(m.Threat_Type.c.SectorID, sector_ids),
    )
    if category_id is not None:  # else fall back to searching all categories ([R6])
        q = q.where(m.Threat_Type.c.PrimaryThreatCategoryID == category_id)
    rows = [dict(r) for r in sess.execute(q).mappings()]
    rows.sort(key=lambda r: how_specific_is_this_sector(r["SectorID"], sector_ids), reverse=True)
    return rows


def get_possible_names(sess: Session, type_id: int, sector_ids: list[int]) -> list[dict[str, Any]]:
    """Candidate Threat_Catalogue rows under the already-matched type ONLY
    ([R6]) — keeps the name match consistent with the type match instead of
    searching the whole library, where an unrelated type's entry could win on
    text similarity alone.
    """
    q = select(m.Threat_Catalogue).where(
        m.Threat_Catalogue.c.IsActive == True,
        m.Threat_Catalogue.c.ThreatTypeID == type_id,
        visible_to_this_sector(m.Threat_Catalogue.c.SectorID, sector_ids),
    )
    rows = [dict(r) for r in sess.execute(q).mappings()]
    rows.sort(key=lambda r: how_specific_is_this_sector(r["SectorID"], sector_ids), reverse=True)
    return rows


def get_allowed_actor_names(sess: Session, type_id: int) -> set[str]:
    """Real, pre-approved actor names for this Threat_Type — used to drop any
    actor the AI invented that doesn't belong to it.
    """
    rows = sess.execute(
        select(m.Threat_Actor.c.ThreatActorName)
        .join(m.ThreatType_ThreatActor_Map,
              m.ThreatType_ThreatActor_Map.c.ThreatActorID == m.Threat_Actor.c.ThreatActorID)
        .where(m.ThreatType_ThreatActor_Map.c.ThreatTypeID == type_id,
               m.Threat_Actor.c.IsActive == True)
    )
    return {r[0] for r in rows}


def find_closest_match(llm: LLMClient, query: str, rows: list[dict], name_key: str, s: Settings, group: str):
    """Embeds the query and every candidate, ranks by cosine similarity,
    shortlists, then reranks. Called twice by find_threat_in_library — once
    for the type match, once for the name match.

    embeddings.get_vectors() caches candidate vectors per (model, group), so
    the library is embedded once, not on every call. The semantic-match floor
    keeps only candidates above `semantic_match_threshold`, but falls back to
    the top-K anyway if nothing clears it, so a bad match still reaches
    label_match_from_score as `flagged` instead of silently returning nothing.
    The final sort is stable, so an exact rerank-score tie falls back to the
    sector-specificity order set by get_possible_types/get_possible_names ([R6]).
    """
    if not rows:
        return None, 0.0
    names = [r[name_key] for r in rows]
    qv = llm.embed([query], kind="query")[0]
    name_vecs = embeddings.get_vectors(llm, names, model_id=s.embedding_model, group=group, kind="passage")
    scored = sorted(((r, how_similar(qv, name_vecs[r[name_key]])) for r in rows), key=lambda rc: rc[1], reverse=True)
    above = [rc for rc in scored if rc[1] >= s.semantic_match_threshold]
    shortlist = [r for r, _ in (above or scored)[: s.grounding_shortlist_k]]
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


def find_threat_in_library(sess: Session, llm: LLMClient, proposed: dict[str, Any], sector_ids: list[int],
                            settings: Settings | None = None) -> GroundingResult:
    """Matches one AI-proposed threat ({"category", "type", "name", "actors"})
    against the real library. Matches TYPE first; if that's flagged, stops
    immediately — there's no confident ThreatTypeID to scope a name/actor
    search by — and returns actors raw/unvalidated. Otherwise matches NAME
    within that type only ([R6]), filters actors to the type's allowed set,
    and reports the weaker of the type/name confidence.
    """
    s = settings or get_settings()
    actors_in = ensure_actor_list(proposed.get("actors", []))
    category_id = find_category(sess, ensure_text(proposed.get("category")))

    types = get_possible_types(sess, category_id, sector_ids)
    trow, tscore = find_closest_match(llm, ensure_text(proposed.get("type")), types, "ThreatTypeName", s, group="threat_type")
    tstatus = label_match_from_score(tscore, s)

    if trow is None or tstatus == GroundingStatus.flagged:
        # Flagged type: no grounded ThreatTypeID → actors cannot be map-filtered ([R6]).
        return GroundingResult(
            status=GroundingStatus.flagged, score=tscore,
            actors=list(actors_in), actors_validated=False,
        )

    type_id = trow["ThreatTypeID"]
    cats = get_possible_names(sess, type_id, sector_ids)
    crow, cscore = find_closest_match(llm, ensure_text(proposed.get("name")), cats, "ThreatName", s, group="threat_catalogue")
    cstatus = label_match_from_score(cscore, s) if crow is not None else GroundingStatus.flagged

    allowed = get_allowed_actor_names(sess, type_id)
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
    print("grounding self-check ok")
