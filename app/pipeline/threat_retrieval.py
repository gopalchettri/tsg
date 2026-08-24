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

from sqlalchemy import select
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


def _load_candidates(sess: Session, sector_ids: list[int]) -> list[dict]:
    """Active, sector-visible catalogue rows with their (active) parent type, the
    multi-category STRIDE memberships, and the type's default category as fallback."""
    tc, tt = m.Threat_Catalogue, m.Threat_Type
    rows = [dict(r) for r in sess.execute(
        select(tc.ThreatCatalogueID, tc.ThreatName, tc.Description,
               tc.ThreatTypeID, tt.ThreatTypeName, tt.ThreatCategoryID)
        .join(tt, tt.ThreatTypeID == tc.ThreatTypeID)
        .where(tc.IsActive == True, tc.IsDeleted == False,
               tt.IsActive == True, tt.IsDeleted == False,
               visible_to_this_sector(tc.SectorID, sector_ids),
               visible_to_this_sector(tt.SectorID, sector_ids))
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
                             asset_context: dict, sector_ids: list[int]) -> list[dict]:
    """The funnel. Returns candidate dicts best-first (score desc, then catalogue id):

        {"catalogue_id", "type_id", "type_name", "threat_name", "description",
         "categories": [names], "retrieval_score": 0..1, "rule_factors": [...],
         "always_eligible": bool, "actors": [names],
         "subsystem_ids": [supporting systems this threat is recorded against]}

    [] when the library holds nothing visible — the caller degrades to generation-only."""
    s = get_settings()
    rows = _load_candidates(sess, sector_ids)
    if not rows:
        log.warning("threat_retrieval.library_empty", sector_ids=sector_ids)
        return []
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
        log.warning("threat_retrieval.embed_failed_keyword_only", exc_info=True)

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
        keep |= {i for i in range(len(rows)) if rows[i]["ThreatTypeID"] in ungated}
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
        out.append({
            "catalogue_id": r["ThreatCatalogueID"], "type_id": tid,
            "type_name": r["ThreatTypeName"], "threat_name": r["ThreatName"],
            "description": r["Description"] or "", "categories": r["categories"],
            "retrieval_score": round(best.get(i, 0.0), 6),
            "rule_factors": passed[tid]["factors"],
            "always_eligible": tid in ungated,
            "subsystem_ids": attribution.get(tid, []),
            "actors": actor_memo[tid][:s.max_actors_per_threat],
        })
    log.info("threat_retrieval.candidates", total=len(rows), forwarded=len(out),
             capped=top_k is not None)
    return out
