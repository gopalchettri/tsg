"""Stage-1a: deterministic library-threat retrieval — the library-first funnel.

Selects candidate Threat_Catalogue rows for an asset BEFORE any generation happens:

    1. METADATA FILTER   active + sector-visible rows; Config_Threat_Rule tech_gates
                         hard-exclude types that do not apply (scoping._apply_rules —
                         reused, not reimplemented)
    2. HYBRID RANKING    per-supporting-system queries + one asset-level query, each
                         scored by BM25 keyword + embedding cosine, RRF-fused
                         (hybrid_search.hybrid_match); a candidate keeps its best
                         score across queries — per-system queries stop one blended
                         asset vector diluting a 16-system asset (GAP-3)
    2b. ACTOR LEG        ThreatType_ThreatActor_Map read BACKWARDS: the actors linked to
                         sector-visible types, then EVERY type those actors use. Admits
                         techniques the sector filter alone would have dropped, with a
                         principled reason recorded on the candidate
                         (selection_source / actor_evidence) - see actor_reachable_types
    3. CAP (optional)    threat_retrieval_top_k unset = ALL gate-passing candidates
                         go forward (exhaustive — provable coverage at today's
                         library size). When capped, gate-UNGATED types bypass the
                         cap: universal threats (phishing/ransomware) score ~0.3
                         against any specific asset text and would otherwise be
                         structurally unreachable (GAP-A)

The LLM validator (tasks._validate_candidates) then judges what this returns; nothing
here calls a model for chat. Scoring here is RANKING ONLY — eligibility is decided by
the gates and the validator, never by a similarity number.

# ponytail: no reranker stage while top_k is unset — when every candidate is validated,
# rerank order changes nothing. Wire bge-reranker between steps 2 and 3 when the library
# outgrows validate-everything and the cap starts cutting.

Empty library / failed embeds degrade loudly to keyword-only or to [] — the caller
(find_threats) then runs generation-only, which is exactly the pre-redesign behaviour.
The production fail-loud posture for a BROKEN library (rows exist but infra is down)
lives at boot in invariants.verify_startup, not per-session here.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import ThreatRuleType
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.pipeline import embeddings, hybrid_search
from app.pipeline.grounding import get_allowed_actor_names, visible_to_this_sector
from app.pipeline.llm import LLMClient
from app.pipeline.scoping import _apply_rules, gate_matching_subsystems

log = get_logger(__name__)

#: Subsystem fields composed into that system's retrieval query — the same technology
#: vocabulary _intel_vocabulary trusts, plus the name and IT/OT label.
_SUBSYSTEM_QUERY_FIELDS = ("name", "asset_type", "technology_used", "vendor_name",
                           "database_platforms", "saas_platform_list", "public_cloud_platforms")

#: Asset-level fields composed into the one asset-wide query.
_ASSET_QUERY_FIELDS = ("name", "asset_type", "sector", "sub_sector", "critical_service",
                       "description")


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
    multi-system asset (GAP-3)."""
    queries = [_compose([sub.get(f) for f in _SUBSYSTEM_QUERY_FIELDS])
               for sub in subsystems or []]
    queries.append(_compose([asset_context.get(f) for f in _ASSET_QUERY_FIELDS]))
    return [q for q in queries if q]


def actor_reachable_types(sess: Session, sector_ids: list[int]) -> dict[int, list[str]]:
    """Threat types reachable by reading ThreatType_ThreatActor_Map BACKWARDS, mapped to the
    actors that reach them. The threat-INTELLIGENCE direction (Phase 2c).

    Asset-centric retrieval asks "what can go wrong with a SCADA system". This asks the other
    question, which for critical infrastructure is often the more predictive one: "who
    actually attacks assets in this sector, and what ELSE do they do". Two hops, both over
    rows the seeds already populate:

        sector-visible Threat_Types  ->  the actors linked to them        (hop 1)
        those actors                 ->  EVERY type they are linked to    (hop 2)

    Hop 2 is what earns this leg its place: it returns types the sector filter alone would
    have excluded. Spear-phishing enters because APT33 uses it, not because someone hard-coded
    it into a list, and the audit trail can say exactly that.

    Nothing is admitted blindly: everything this adds goes through the SAME validator as every
    other candidate, and NOT_RELEVANT is still a hard drop. The leg can only WIDEN the set the
    model judges - it can never smuggle a threat past the judgement.

    # ponytail: no actor->sector table is needed, because sector reaches actors THROUGH the
    # type link that already exists. When the MISP/OTX import lands real actor->sector
    # targeting, replace hop 1 with that join; hop 2 and every caller stay as they are.
    """
    mp, ta, tt = m.ThreatType_ThreatActor_Map, m.Threat_Actor, m.Threat_Type
    seed_actors = (select(mp.ThreatActorID)
                .join(tt, tt.ThreatTypeID == mp.ThreatTypeID)
                .where(tt.IsActive == True, tt.IsDeleted == False,
                        visible_to_this_sector(tt.SectorID, sector_ids)))
    out: dict[int, list[str]] = {}
    for type_id, actor_name in sess.execute(
            select(mp.ThreatTypeID, ta.ThreatActorName)
            .join(ta, ta.ThreatActorID == mp.ThreatActorID)
            .where(mp.ThreatActorID.in_(seed_actors),
                ta.IsActive == True, ta.IsDeleted == False)
            .order_by(mp.ThreatTypeID, ta.ThreatActorID)):   # deterministic, like get_allowed_actor_names
        out.setdefault(int(type_id), []).append(actor_name)
    return out


def _load_candidates(sess: Session, sector_ids: list[int],
                    actor_type_ids: set[int] | None = None) -> list[dict]:
    """Active catalogue rows with their (active) parent type, the multi-category STRIDE
    memberships, and the type's default category as fallback.

    A type is admitted when it is sector-visible OR an actor operating in this sector uses it
    (actor_type_ids, from actor_reachable_types). The CATALOGUE row keeps its own sector rule
    either way: the actor evidence is about the technique, not about which curated write-up of
    it belongs to another sector."""
    tc, tt = m.Threat_Catalogue, m.Threat_Type
    rows = [dict(r) for r in sess.execute(
        select(tc.ThreatCatalogueID, tc.ThreatName, tc.Description,
               tc.ThreatTypeID, tt.ThreatTypeName, tt.ThreatCategoryID)
        .join(tt, tt.ThreatTypeID == tc.ThreatTypeID)
        .where(tc.IsActive == True, tc.IsDeleted == False,
               tt.IsActive == True, tt.IsDeleted == False,
               visible_to_this_sector(tc.SectorID, sector_ids),
               or_(visible_to_this_sector(tt.SectorID, sector_ids),
                   tt.ThreatTypeID.in_(actor_type_ids or set())))
        .order_by(tc.ThreatCatalogueID)  # deterministic base order
    ).mappings()]
    if not rows:
        return []
    cat_names = {r[0]: r[1] for r in sess.execute(
        select(m.Threat_Category.ThreatCategoryID, m.Threat_Category.ThreatCategoryName)
        .where(m.Threat_Category.IsActive == True, m.Threat_Category.IsDeleted == False))}
    mapped: dict[int, list[str]] = {}
    mp = m.Threat_Catalogue_Category_Map
    for cid, cat_id in sess.execute(
            select(mp.ThreatCatalogueID, mp.ThreatCategoryID)
            .where(mp.ThreatCatalogueID.in_([r["ThreatCatalogueID"] for r in rows]))
            .order_by(mp.ThreatCategoryID)):
        name = cat_names.get(cat_id)
        if name:
            mapped.setdefault(cid, []).append(name)
    for r in rows:
        # The map is authoritative (multi-category by design); the type's default is the
        # fallback for unmapped rows so a threat is never grid-unplaceable.
        fallback = cat_names.get(r["ThreatCategoryID"])
        r["categories"] = mapped.get(r["ThreatCatalogueID"]) or ([fallback] if fallback else [])
    return rows


def _gate_types(sess: Session, rows: list[dict], subsystems: list[dict] | None,
                default_rule_weight: float) -> tuple[dict[int, dict], set[int], dict[int, list[dict]]]:
    """Evaluate each distinct type's Config_Threat_Rule rows once. Returns
    (type_id -> {"factors": [...], "delta": float}) for types that pass their gates,
    the set of type_ids that carry NO tech_gate at all (the always-eligible tier), and the
    loaded rules themselves so the caller can derive per-subsystem attribution without a
    second query."""
    type_ids = sorted({r["ThreatTypeID"] for r in rows})
    rules_by_type: dict[int, list[dict]] = {}
    for rule in dal.active_threat_rules(sess, type_ids):
        rules_by_type.setdefault(rule["ThreatTypeID"], []).append(rule)
    passed: dict[int, dict] = {}
    ungated: set[int] = set()
    for tid in type_ids:
        delta, selected, gate_failures, factors = _apply_rules(
            {"threat_type_id": tid}, subsystems, rules_by_type, default_rule_weight)
        if not any(r["RuleType"] == ThreatRuleType.tech_gate for r in rules_by_type.get(tid, [])):
            ungated.add(tid)
        if selected:
            passed[tid] = {"factors": factors, "delta": delta}
        else:
            log.info("threat_retrieval.type_gated_out", threat_type_id=tid,
                     gates=gate_failures)
    return passed, ungated, rules_by_type


def all_subsystem_ids(subsystems: list[dict] | None) -> list[int]:
    """Every supporting system's onboarding id, in context order. The asset itself
    (tasks.ASSET_UNIT_ID = 0) is NOT in here — it is always recorded separately."""
    return [int(s["id"]) for s in subsystems or [] if s.get("id") is not None]


def attribute_to_subsystems(subsystems: list[dict] | None, type_ids: list[int],
                            rules_by_type: dict[int, list[dict]]) -> dict[int, list[int]]:
    """type_id -> the supporting systems this threat is RECORDED against.

    ONE rule, stated once so it can be argued with:

        a threat reaches the asset AND every supporting system, EXCEPT where a tech_gate
        proves it does not reach that system.

    Fail-OPEN by design, and that direction is chosen, not incidental. Over-attribution puts
    a row in front of a reviewer who can dismiss it in a second; under-attribution removes a
    real exposure from the grid with no trace, which is precisely the silent failure the
    coverage matrix exists to make impossible. Gates are the ONLY narrowing evidence the
    system has, and they only ever narrow.

    Types with no tech_gate (the seeded universal threats — phishing, ransomware, supply
    chain) therefore land on every system. That is correct, not a fallback: they are
    universal because nothing gates them."""
    every = all_subsystem_ids(subsystems)
    out: dict[int, list[int]] = {}
    for tid in type_ids:
        matched = gate_matching_subsystems(tid, subsystems, rules_by_type)
        out[tid] = every if matched is None else matched
    return out


def subsystem_attribution(sess: Session, subsystems: list[dict] | None,
                          type_ids: list[int]) -> dict[int, list[int]]:
    """attribute_to_subsystems for callers that do not already hold the rules — one query.
    Used by the GENERATED half of find_threats, whose types are only known after grounding."""
    if not type_ids:
        return {}
    rules_by_type: dict[int, list[dict]] = {}
    for rule in dal.active_threat_rules(sess, sorted(set(type_ids))):
        rules_by_type.setdefault(rule["ThreatTypeID"], []).append(rule)
    return attribute_to_subsystems(subsystems, list(type_ids), rules_by_type)


def retrieve_library_threats(sess: Session, llm: LLMClient, subsystems: list[dict] | None,
                             asset_context: dict, sector_ids: list[int],
                             session_id: str | None = None) -> list[dict]:
    """The funnel. Returns candidate dicts best-first (score desc, then catalogue id):

        {"catalogue_id", "type_id", "type_name", "threat_name", "description",
         "categories": [names], "retrieval_score": 0..1, "rule_factors": [...],
         "always_eligible": bool, "actors": [names],
         "subsystem_ids": [supporting systems this threat is recorded against],
         "selection_source": "actor_intel" | "rules" | "hybrid",
         "actor_evidence": [actors whose technique set reaches this type]}

    [] when the library holds nothing visible — the caller degrades to generation-only."""
    s = get_settings()
    # Phase 2c: the actor leg runs FIRST, because it decides which types are eligible at all.
    # Pure DB joins - no model, no embeddings, negligible cost.
    actor_types = actor_reachable_types(sess, sector_ids)
    rows = _load_candidates(sess, sector_ids, set(actor_types))
    if not rows:
        log.warning("threat_retrieval.library_empty", sector_ids=sector_ids)
        return []
    # Which types the ordinary sector filter would have admitted on its own. Queried rather
    # than recomputed in Python so the visibility rule lives in exactly one place
    # (grounding.visible_to_this_sector) and the two can never drift apart.
    sector_visible = {int(r[0]) for r in sess.execute(
        select(m.Threat_Type.ThreatTypeID).where(
            visible_to_this_sector(m.Threat_Type.SectorID, sector_ids)))}
    passed, ungated, rules_by_type = _gate_types(sess, rows, subsystems, s.default_rule_weight)
    rows = [r for r in rows if r["ThreatTypeID"] in passed]
    if not rows:
        log.warning("threat_retrieval.all_types_gated_out")
        return []

    corpus = [{"text": (r["ThreatName"] + ": " + (r["Description"] or ""))[:s.max_embed_chars],
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
    except Exception:
        # Keyword-only is a WEAKER ANSWER, not a failure — eligibility is untouched and the
        # session still completes. That is exactly why it has to be recorded: a run ranked by
        # BM25 alone selects a materially different candidate set, and without this flag it is
        # indistinguishable from a healthy one afterwards. session_id so it joins to something;
        # this log line used to carry none, unlike its siblings above.
        ranking_degraded = True
        log.warning("threat_retrieval.embed_failed_keyword_only",
                    session_id=session_id, candidates=len(rows), exc_info=True)

    best: dict[int, float] = {}  # row index -> best fused score across queries
    for q, qv in zip(queries, query_vecs):
        for idx, score in hybrid_search.hybrid_match(q, corpus, query_vec=qv):
            if score > best.get(idx, 0.0):
                best[idx] = score

    top_k = s.threat_retrieval_top_k
    order = sorted(range(len(rows)), key=lambda i: (-best.get(i, 0.0), rows[i]["ThreatCatalogueID"]))
    if top_k is not None:
        keep = set(order[:top_k])
        # GAP-A: gate-ungated types (universal threats) bypass the cap — they score ~0.3
        # against any specific asset text and would otherwise never reach the validator.
        # Actor-leg-admitted types (Phase 2c, `tid not in sector_visible` below) must ALSO
        # bypass: they were admitted BECAUSE the sector filter alone would have excluded
        # them, so a low hybrid score against the asset's own text is the expected case for
        # them, not evidence they don't belong. Without this, the cap silently undoes the
        # actor leg's entire purpose — the exact GAP-A failure, for a second admission path.
        keep |= {i for i in range(len(rows))
                if rows[i]["ThreatTypeID"] in ungated
                or rows[i]["ThreatTypeID"] not in sector_visible}
        order = [i for i in order if i in keep]

    attribution = attribute_to_subsystems(
        subsystems, sorted({r["ThreatTypeID"] for r in rows}), rules_by_type)
    actor_memo: dict[int, list[str]] = {}
    out: list[dict] = []
    for i in order:
        r = rows[i]
        tid = r["ThreatTypeID"]
        if tid not in actor_memo:
            actor_memo[tid] = sorted(get_allowed_actor_names(sess, tid))
        # WHY this candidate is in the pool - the distinguishing reason, not just a label.
        # actor_intel is the strongest claim (the sector filter alone would have dropped it),
        # so it wins; rules marks the ungated universal tier that bypasses the cap; hybrid is
        # the ordinary metadata + ranking path.
        if tid not in sector_visible:
            source = "actor_intel"
        elif tid in ungated:
            source = "rules"
        else:
            source = "hybrid"
        out.append({
            "catalogue_id": r["ThreatCatalogueID"], "type_id": tid,
            "type_name": r["ThreatTypeName"], "threat_name": r["ThreatName"],
            "description": r["Description"] or "", "categories": r["categories"],
            "retrieval_score": round(best.get(i, 0.0), 6),
            "rule_factors": passed[tid]["factors"],
            "always_eligible": tid in ungated,
            "subsystem_ids": attribution.get(tid, []),
            "selection_source": source,
            # Rides on every candidate rather than being returned separately, so the caller
            # cannot receive the threats and drop the caveat. find_threats folds it into the
            # grounding_summary audit row.
            "ranking_degraded": ranking_degraded,
            # The actors whose technique set reaches this type. Turns the audit answer from
            # "cosine 0.78" into "APT33 operates in this sector and uses this technique".
            "actor_evidence": actor_types.get(tid, []),
            "actors": actor_memo[tid][:s.max_actors_per_threat],
        })
    by_source: dict[str, int] = {}
    for c in out:
        by_source[c["selection_source"]] = by_source.get(c["selection_source"], 0) + 1
    log.info("threat_retrieval.candidates", total=len(rows), forwarded=len(out),
             capped=top_k is not None, by_source=by_source,
             actor_reachable_types=len(actor_types))
    return out
