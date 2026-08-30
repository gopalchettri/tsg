"""Stage-1a: deterministic library-threat retrieval — the library-first funnel.

Selects candidate Threat_Catalogue rows for an asset BEFORE any generation happens:

    1. LIBRARY FILTER    live catalogue rows (IsActive=1, IsDeleted=0) whose parent
                        Threat_Type is also active. No sector filter (removed 2026-08,
                        user instruction) and no asset-type filter (the catalogue has no
                        asset-type column) — eligibility is the whole active library,
                        and the validator decides relevance.
    2. HYBRID RANKING    per-supporting-system queries + one asset-level query, each
                        scored by BM25 keyword + embedding cosine, RRF-fused
                        (hybrid_search.hybrid_match); a candidate keeps its best
                        score across queries — per-system queries stop one blended
                        asset vector diluting a 16-system asset (GAP-3). The ranked
                        text is the threat's name + description, composed by the ONE
                        shared function (embeddings.catalogue_passage_text) so warm
                        vectors and query vectors are the same bytes (G10).
    3. NO CAP            every eligible candidate goes forward to the validator —
                        exhaustive, provable coverage at today's library size.

Multi-STRIDE category membership comes from Threat_Catalogue_Category_Map (authoritative
when populated) with the type's own category as the fallback, re-sorted into canonical
STRIDE order — map row order encodes the seed alphabet and must not survive.

Actors ride per TYPE (ThreatType_ThreatActor_Map — every catalogue threat under one type
shares the list), as (id, name) pairs so actor_ids stay intact end to end.

The LLM validator (tasks._validate_candidates) then judges what this returns; nothing
here calls a model for chat. Scoring here is RANKING ONLY — eligibility is decided by
the validator, never by a similarity number.

Empty library / failed embeds degrade loudly to keyword-only or to [] — the caller
(find_threats) then runs generation-only, which is exactly the cold-start behaviour:
an empty system means the AI generates everything, threat types included.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.stride import in_stride_order
from app.core.tracing import trace_step
from app.db import dal
from app.db import models as m
from app.pipeline import embeddings, hybrid_search
from app.pipeline.llm import LLMClient

log = get_logger(__name__)

# Text-typed fields that aren't descriptive content — excluded from retrieval query text even
# though they're strings. Found 2026-08-29: the previous hardcoded field-name allowlist here
# (_SUBSYSTEM_QUERY_FIELDS/_ASSET_QUERY_FIELDS) had 2 DEAD entries — "name" and "description" —
# that never matched any real asset_context key (the real key is "cii_asset_description"), so
# the asset-level query silently missed the asset's own description text for as long as this
# file existed. Root cause: a hand-maintained second copy of "which fields matter", disconnected
# from what context.py actually builds. Fixed by using every field context.py resolves instead
# of re-picking a subset by name — see _is_query_text below.
_NON_DESCRIPTIVE_TEXT_KEYS = frozenset({"last_dr_test_date"})  # a raw ISO date, not search text


def _is_query_text(value: Any) -> bool:
    """True for a string or a list/tuple of strings — the shape a resolved context field takes
    (context.py already turns ids into names before this ever sees the dict). False for ids,
    counts, booleans, floats — anything that isn't descriptive text."""
    if isinstance(value, str):
        return True
    return isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value)


def _compose(values: list[Any]) -> str:
    parts: list[str] = []
    for v in values:
        for item in v if isinstance(v, (list, tuple)) else [v]:
            text = str(item).strip() if item is not None else ""
            if text:
                parts.append(text)
    return " ".join(parts)


def build_queries(subsystems: list[dict] | None, asset_context: dict) -> list[str]:
    """One query per supporting system + one asset-level query, empties dropped.
    Per-system on purpose: a single blended query under-represents every system of a
    multi-system asset (GAP-3). Every text-shaped field already resolved onto each dict feeds
    the query — no hardcoded field-name list to keep in sync with context.py."""
    def _text_values(d: dict) -> list[Any]:
        return [v for k, v in d.items() if k not in _NON_DESCRIPTIVE_TEXT_KEYS and _is_query_text(v)]

    queries = [_compose(_text_values(sub)) for sub in subsystems or []]
    queries.append(_compose(_text_values(asset_context)))
    return [q for q in queries if q]


def session_category_ids(subsystems: list[dict] | None, asset_context: dict | None) -> set[int]:
    """The session's asset-category set: the asset's own ctm_scan_category id UNIONED with
    every supporting system's. Consumed by the data-driven control ITOT filter
    (control_mapping._resolve_control_labels) — threat retrieval itself no longer filters by
    category (the catalogue carries no asset-type column). Both fields are stamped by
    context.py at session creation and persisted in the session JSON."""
    ids = {sub.get("asset_type_id") for sub in subsystems or []}
    ids.add((asset_context or {}).get("asset_type_id"))
    return {int(i) for i in ids if i is not None}


def _load_candidates(sess: Session) -> list[dict]:
    """Live catalogue rows with their (active) parent type and category memberships.

    Categories come from Threat_Catalogue_Category_Map (authoritative, multi-category by
    design) with the type's single category as the fallback so a threat is never
    grid-unplaceable — dal.categories_for_catalogue_threats documents the per-threat rule."""
    tc, tt = m.Threat_Catalogue, m.Threat_Type
    rows = [dict(row) for row in sess.execute(
        select(tc.ThreatCatalogueID, tc.ThreatName, tc.Description,
            tc.ThreatTypeID, tt.ThreatTypeName, tt.ThreatCategoryID)
        .select_from(tc.__table__.join(tt.__table__, tt.ThreatTypeID == tc.ThreatTypeID))
        .where(tc.IsActive == True, tc.IsDeleted == False,
            tt.IsActive == True, tt.IsDeleted == False)
        .order_by(tc.ThreatCatalogueID)  # deterministic base order
    ).mappings()]
    if not rows:
        return []
    cat_names = {row[0]: row[1] for row in sess.execute(
        select(m.Threat_Category.ThreatCategoryID, m.Threat_Category.ThreatCategoryName)
        .where(m.Threat_Category.IsActive == True, m.Threat_Category.IsDeleted == False))}
    mapped = dal.categories_for_catalogue_threats(
        sess, [row["ThreatCatalogueID"] for row in rows])
    for row in rows:
        # Map categories are authoritative (multi-category by design); the type's category is
        # the fallback so a threat is never grid-unplaceable. CANONICAL STRIDE order either
        # way — nothing may treat categories[0] as "the" category (stride.assign decides that
        # per coverage slot), but the list leaves here meaning something.
        fallback = cat_names.get(row["ThreatCategoryID"])
        row["categories"] = in_stride_order(
            mapped.get(row["ThreatCatalogueID"]) or ([fallback] if fallback else []))
    return rows


def all_subsystem_ids(subsystems: list[dict] | None) -> list[int]:
    """Every supporting system's onboarding id, in context order. The asset itself
    (tasks.ASSET_UNIT_ID = 0) is NOT in here — it is always recorded separately."""
    return [int(s["id"]) for s in subsystems or [] if s.get("id") is not None]


def attribute_to_subsystems(subsystems: list[dict] | None,
                            type_ids: list[int]) -> dict[int, list[int]]:
    """type_id -> the supporting systems this threat is RECORDED against: ALL of them.

    ONE rule, stated once so it can be argued with: a threat reaches the asset AND every
    supporting system. Fail-OPEN by design, and that direction is chosen, not incidental:
    over-attribution puts a row in front of a reviewer who can dismiss it in a second;
    under-attribution removes a real exposure from the grid with no trace -- precisely the
    silent failure the coverage matrix exists to make impossible. The tech_gate narrowing
    that used to carve exceptions here left with Config_Threat_Rule (2026-08); its own
    docstring already called every-system the correct default, so this is that default,
    everywhere, with no gate able to silently shrink the grid again."""
    every = all_subsystem_ids(subsystems)
    return {tid: every for tid in type_ids}


def retrieve_library_threats(sess: Session, llm: LLMClient, subsystems: list[dict] | None,
                            asset_context: dict,
                            session_id: str | None = None) -> list[dict]:
    """The funnel. Returns candidate dicts best-first (score desc, then catalogue id):

        {"catalogue_id", "type_id", "type_name", "threat_name", "description",
        "categories": [names], "retrieval_score": 0..1,
        "actors": [names], "actor_ids": [Threat_Actor keys],
        "subsystem_ids": [supporting systems this threat is recorded against],
        "selection_source": "hybrid", "ranking_degraded": bool}

    [] when the catalogue holds nothing eligible — the caller degrades to generation-only
    (the cold-start guarantee: the AI generates everything, types included)."""
    s = get_settings()
    # The `return []` below sits INSIDE the block on purpose: a context manager still emits its
    # END on an early return, where paired IN/OUT calls would leave a dangling BEGIN.
    with trace_step("LIBRARY FILTER", session_id) as _t:
        rows = _load_candidates(sess)
        if not rows:
            log.warning("threat_retrieval.library_empty", session_id=session_id)
            _t.result(candidates_after_type_filter=0, library_empty=True)
            return []
        _t.result(candidates_after_type_filter=len(rows))

    corpus = [{"text": embeddings.catalogue_passage_text(
                r["ThreatName"], r["Description"], s.max_embed_chars),
            "name": r["ThreatName"], "vector": None} for r in rows]
    queries = build_queries(subsystems, asset_context)
    # Embeddings are best-effort: corpus passage vectors through the shared cache, query
    # vectors in one batch. Any failure degrades to keyword-only — ranking gets weaker,
    # eligibility is untouched.
    query_vecs: list[list[float] | None] = [None] * len(queries)
    ranking_degraded = False
    try:
        texts = [c["text"] for c in corpus]
        vecs = embeddings.get_vectors(llm, texts, model_id=s.embedding_model,
                                    group="threat_catalogue", kind="passage")
        for c in corpus:
            c["vector"] = vecs.get(c["text"])
        if queries:
            qvs = llm.embed(queries, kind="query")
            if len(qvs) == len(queries):
                query_vecs = list(qvs)
            else:
                # Same outcome as the except below — every query vector stays None, so ranking
                # falls back to BM25 alone. It has to be RECORDED the same way too: without this
                # branch a short embed response produced keyword-only ranking that was
                # indistinguishable from a healthy run in both the trace and the result payload.
                ranking_degraded = True
                log.warning("threat_retrieval.embed_length_mismatch_keyword_only",
                            session_id=session_id, queries=len(queries), vectors=len(qvs))
    except Exception:
        # Keyword-only is a WEAKER ANSWER, not a failure — eligibility is untouched and the
        # session still completes. That is exactly why it has to be recorded: a run ranked by
        # BM25 alone selects a materially different candidate set, and without this flag it is
        # indistinguishable from a healthy one afterwards.
        ranking_degraded = True
        log.warning("threat_retrieval.embed_failed_keyword_only",
                    session_id=session_id, candidates=len(rows), exc_info=True)

    best: dict[int, float] = {}  # row index -> best fused score across queries
    for q, qv in zip(queries, query_vecs):
        with trace_step("HYBRID SEARCH", session_id, query_text=q, candidate_count=len(corpus),
                        query_vec_present=qv is not None,
                        ranking_degraded=ranking_degraded) as _t:
            results = hybrid_search.hybrid_match(q, corpus, query_vec=qv)
            _t.result(matches=len(results), top=results[:5])
        for idx, score in results:
            if score > best.get(idx, 0.0):
                best[idx] = score

    # No cap: every eligible candidate is forwarded, best-first — the validator decides
    # relevance. See the module docstring for why there is no top-k.
    order = sorted(range(len(rows)),
                key=lambda i: (-best.get(i, 0.0), rows[i]["ThreatCatalogueID"]))

    attribution = attribute_to_subsystems(
        subsystems, sorted({r["ThreatTypeID"] for r in rows}))
    actors_by_type = dal.type_actor_pairs(sess, sorted({r["ThreatTypeID"] for r in rows}))
    out: list[dict] = []
    for i in order:
        r = rows[i]
        pairs = actors_by_type.get(r["ThreatTypeID"], [])[:s.max_actors_per_threat]
        out.append({
            "catalogue_id": r["ThreatCatalogueID"],
            "type_id": r["ThreatTypeID"], "type_name": r["ThreatTypeName"],
            "threat_name": r["ThreatName"],
            "description": r["Description"] or "",
            "categories": r["categories"],
            "retrieval_score": round(best.get(i, 0.0), 6),
            "subsystem_ids": attribution.get(r["ThreatTypeID"], []),
            # Retrieved-vs-generated marker consumed by the summary tallies.
            "selection_source": "hybrid",
            # Rides on every candidate rather than being returned separately, so the caller
            # cannot receive the threats and drop the caveat. find_threats folds it into the
            # grounding_summary audit row.
            "ranking_degraded": ranking_degraded,
            "actors": [nm for _aid, nm in pairs],
            "actor_ids": [aid for aid, _nm in pairs],
        })
    log.info("threat_retrieval.candidates", total=len(rows), forwarded=len(out))
    return out
