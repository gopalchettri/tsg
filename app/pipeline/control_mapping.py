"""Step 4 (spec): map each generated scenario to the Control_Library.

Propose→ground, the same idiom find_threats uses for threats: the LLM's free-text `controls`
suggestions (scenario_prompt v1.3) become retrieval queries; each grounds to its best library
row via cached-matrix cosine shortlist + batched rerank (grounding.ground_control_queries);
matches under the min-score cutoff are dropped, the rest dedupe by ControlLibraryID and the
top control_map_top_k get ranked Threat_Scenario_Control_Map rows.

Lives in its own module (not tasks.py) because it is a self-contained enrichment stage with
its own vocabulary/threshold concerns — tasks.py stays the pipeline driver.
"""
from __future__ import annotations

import json

from sqlalchemy import insert, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import AuditEventType, ScenarioStatus, SubsystemLevel, WorkflowStage
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import guid, now
from app.pipeline import embeddings, grounding
from app.pipeline.llm import LLMClient

log = get_logger(__name__)


def itot_family(value: object) -> str | None:
    """Fold a platform asset/subsystem type onto the control library's IT/OT axis, or None.

    The platform's controlled vocabulary for the subsystem-level `asset_type` is
    'Information Technology (IT)' / 'Operational Technology (OT)' (the exact strings the
    seeded Config_Threat_Rule tech_gates match on — scripts/Seed_to_Threat_library.sql);
    the asset-level `type` is free text that MAY also carry these markers. Recognizing the
    real vocabulary (plus bare IT/OT) is what makes the pre-filter actually engage on
    production data instead of silently never matching."""
    v = grounding.ensure_text(value).strip().upper()
    if not v:
        return None
    if v in ("IT", "OT"):
        return v
    if "(IT)" in v or "INFORMATION TECHNOLOGY" in v:
        return "IT"
    if "(OT)" in v or "OPERATIONAL TECHNOLOGY" in v:
        return "OT"
    return None


def _resolve_itot(asset_context: dict, subsystems: list[dict] | None) -> str | None:
    """One IT/OT family for the asset, from every signal that carries one: the asset's own
    type plus each supporting system's resolved asset_type category. Filter only when the
    signals AGREE on a single family — a mixed IT+OT asset searches the whole library rather
    than guessing (dropping the right OT control because one subsystem said IT would be a
    correctness bug, not an optimization)."""
    families = {itot_family(asset_context.get("asset_type"))}
    for sub in subsystems or []:
        families.add(itot_family(sub.get("asset_type")))
    families.discard(None)
    return families.pop() if len(families) == 1 else None


def _min_score(sess: Session, llm: LLMClient, s) -> float:
    """The rerank cutoff below which a suggestion is dropped. Rerank scores are MODEL-specific
    (a different reranker scores on a different distribution), so a fixed default cannot fit
    every environment. Precedence: an operator-pinned TSG_CONTROL_MAP_MIN_SCORE wins; otherwise
    reuse the per-(embedding, reranker)-pair CONFIRM threshold grounding already resolves and
    stores per model pair (grounding.resolve_thresholds — memoized, degrade-safe), so the
    cutoff follows the models in every environment instead of needing manual recalibration."""
    if "control_map_min_score" in s.model_fields_set:
        return s.control_map_min_score
    _, confirm = grounding.resolve_thresholds(sess, llm, s)
    return confirm


def collect_control_queries(scenario_json: str | None, top_k: int) -> tuple[list[tuple[str, str | None]], bool]:
    """Parse one output's ScenarioJSON into control-grounding queries.

    Returns (queries, used_fallback): each query is (text to ground, SuggestedControl to store).
    Suggestions ground as `name: why`; an output with no usable suggestions (pre-1.3 prompt,
    parse variance) falls back to the scenario text itself as a single query with no stored
    suggestion. An empty list means the output has nothing groundable at all — skip it."""
    try:
        scenario = json.loads(scenario_json or "{}")
    except ValueError:
        scenario = {}
    queries: list[tuple[str, str | None]] = []
    for c in scenario.get("controls") or []:
        if not isinstance(c, dict):
            continue
        name = grounding.ensure_text(c.get("name")).strip()
        why = grounding.ensure_text(c.get("why")).strip()
        if name:
            queries.append((f"{name}: {why}" if why else name, name[:500]))
    if queries:
        return queries[:top_k], False
    text = " ".join(t for t in (grounding.ensure_text(scenario.get("scenario_title")).strip(),
                                grounding.ensure_text(scenario.get("scenario_statement")).strip()) if t)
    return ([(text, None)] if text else []), bool(text)


def map_controls(sess: Session, scenario_session: dict, asset_context: dict,
                 subsystems: list[dict] | None, llm: LLMClient, subsystem_id: int,
                 task_id: str, epoch: int) -> None:
    """Map every not-yet-attempted active complete output of this session to library controls.

    Runs as a tail step of the SCENARIOS stage. Idempotency = `ControlsMappedAt IS NULL`:
    every output this run processes gets stamped — INCLUDING ones that produced zero map rows
    (nothing groundable, or every suggestion below the cutoff) — so no output is ever
    re-scanned/re-reranked on later runs; regen/next-set mint fresh OutputIDs (stamp NULL)
    and are picked up naturally. The extra NOT-EXISTS guard covers pre-stamp-column rows that
    already have map rows: they must be neither reprocessed (PK collision) nor re-stamped.
    """
    # ponytail: mapping is enrichment; a scenario without controls beats a failed stage — any
    # failure below logs and returns, never raises into the stage.
    try:
        s = get_settings()
        sid, ss = scenario_session["SessionID"], subsystem_id
        itot = _resolve_itot(asset_context, subsystems)
        candidates = grounding.get_control_candidates(sess, itot)
        if not candidates:
            log.warning("controls.no_candidates", session_id=sid, itot=itot)
            return
        already_mapped = select(m.Threat_Scenario_Control_Map.OutputID).where(
            m.Threat_Scenario_Control_Map.OutputID == m.Threat_Scenario_Output.OutputID)
        outputs = sess.execute(
            select(m.Threat_Scenario_Output.OutputID, m.Threat_Scenario_Output.ScenarioJSON)
            .where(m.Threat_Scenario_Output.SessionID == sid,
                   m.Threat_Scenario_Output.Superseded == 0,
                   m.Threat_Scenario_Output.Status == ScenarioStatus.complete,
                   m.Threat_Scenario_Output.ControlsMappedAt.is_(None),
                   ~already_mapped.exists())
        ).all()
        if not outputs:
            return
        # Parse every output's suggestions FIRST so all query texts embed in one batched call
        # (same round-trip-saving idea as grounding.prime_query_embeddings).
        per_output: list[tuple[str, list[tuple[str, str | None]]]] = []
        fallbacks = 0
        for output_id, scenario_json in outputs:
            queries, used_fallback = collect_control_queries(scenario_json, s.control_map_top_k)
            if not queries:
                continue
            fallbacks += used_fallback
            per_output.append((output_id, queries))
        skipped = len(outputs) - len(per_output)
        min_score = _min_score(sess, llm, s)
        inserted = dropped = 0
        if per_output:
            texts = list(dict.fromkeys(q for _, qs in per_output for q, _ in qs))
            qv_map: dict[str, list[float]] = {}
            try:  # best-effort batch prime, chunked so a big session can't exceed a remote
                # provider's per-request batch limit — a failure just means per-query embeds below
                for i in range(0, len(texts), embeddings._MAX_EMBED_BATCH):
                    chunk = texts[i:i + embeddings._MAX_EMBED_BATCH]
                    qv_map.update(zip(chunk, llm.embed(chunk, kind="query")))
            except Exception:  # noqa: BLE001
                log.warning("controls.query_prime_failed", session_id=sid, exc_info=True)
            # One lease renewal covers the whole batched grounding call (the only long operation
            # left — shortlisting is a cached-matrix matvec and the rerank is one batched local
            # dispatch / bounded-concurrent remote calls; the inserts below are milliseconds).
            if not dal.renew_lease(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id):
                log.warning("controls.lease_lost", session_id=sid)
                return
            flat = [(q, qv_map.get(q)) for _, qs in per_output for q, _ in qs]
            matches = grounding.ground_control_queries(llm, flat, candidates, s)
            pos = 0
            for output_id, queries in per_output:
                best: dict[int, dict] = {}
                for (query, suggested), match in zip(queries, matches[pos:pos + len(queries)]):
                    if match is None:
                        dropped += 1
                        continue
                    row, score = match
                    if score < min_score:
                        dropped += 1
                        continue
                    cid = row["ControlLibraryID"]
                    if cid not in best or score > best[cid]["Score"]:
                        best[cid] = {"OutputID": output_id, "ControlLibraryID": cid, "SessionID": sid,
                                     "Score": score, "SuggestedControl": suggested, "CreatedAt": now()}
                pos += len(queries)
                keep = sorted(best.values(), key=lambda r: r["Score"], reverse=True)[: s.control_map_top_k]
                for rank, rec in enumerate(keep, start=1):
                    rec["MapRank"] = rank
                if keep:
                    sess.execute(insert(m.Threat_Scenario_Control_Map), keep)
                    inserted += len(keep)
        # Stamp EVERY fetched output as attempted — including nothing-groundable and
        # zero-survivor ones — so none of them is ever re-scanned on a later run. Rides the
        # caller's transaction: a crash before commit rolls back stamps and map rows together.
        sess.execute(update(m.Threat_Scenario_Output)
                     .where(m.Threat_Scenario_Output.OutputID.in_([oid for oid, _ in outputs]))
                     .values(ControlsMappedAt=now()))
        if not per_output:
            # No audit event: a controls_mapped row reporting 0 processed outputs reads as
            # work done. The stamp above still prevents any future re-scan of these outputs.
            log.warning("controls.nothing_groundable", session_id=sid, skipped=skipped)
            return
        dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                         EntityID=scenario_session["EntityID"], Stage=WorkflowStage.SCENARIO_GENERATION,
                         SubsystemID=ss, EventType=AuditEventType.controls_mapped,
                         DetailJSON=json.dumps({"outputs": len(per_output), "mapped": inserted,
                                                "dropped": dropped, "fallback_queries": fallbacks,
                                                "skipped": skipped, "itot": itot or "",
                                                "itot_filter_applied": itot is not None,
                                                "min_score": min_score}))
        log.info("controls.mapped", session_id=sid, outputs=len(per_output), mapped=inserted,
                 dropped=dropped, fallbacks=fallbacks, skipped=skipped, itot=itot,
                 min_score=min_score)
    except Exception:  # noqa: BLE001
        # Roll back FIRST: a DBAPI error mid-write (deadlock, constraint conflict) marks the
        # session's transaction inactive, and without this the caller's very next
        # finish_stage would die on PendingRollbackError — turning an enrichment failure
        # into a whole-stage failure, the exact outcome this catch-all exists to prevent.
        # This run's committed scenarios are safe (write_scenarios commits them per scenario).
        sess.rollback()
        log.warning("controls.mapping_failed", session_id=scenario_session.get("SessionID"), exc_info=True)
