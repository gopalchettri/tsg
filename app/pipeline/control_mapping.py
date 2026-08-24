"""Create control-library mappings for generated scenario outputs.

The module grounds each scenario's own text (title + statement) against the control
library and stores the highest-scoring matches — the LLM never proposes controls.
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
from app.pipeline import grounding
from app.pipeline.llm import LLMClient

log = get_logger(__name__)


def itot_family(value: object) -> str | None:
    """Return ``IT`` or ``OT`` for a recognized technology label, otherwise ``None``.

    Accepts the bare labels and the platform labels ``Information Technology (IT)`` and
    ``Operational Technology (OT)``.
    """
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
    """Return one shared IT/OT family from the asset and its supporting subsystems.

    Returns ``IT`` or ``OT`` only when all recognized values agree. Returns ``None`` when
    no value is recognized or when both families are present, so mixed assets are not filtered.
    """
    families = {itot_family(asset_context.get("asset_type"))}
    for sub in subsystems or []:
        families.add(itot_family(sub.get("asset_type")))
    families.discard(None)
    return families.pop() if len(families) == 1 else None


def _min_score(sess: Session, llm: LLMClient, s) -> float:
    """Return the score required before a grounded control is stored.

    Use ``control_map_min_score`` when explicitly configured. Otherwise use the threshold
    resolved for the current embedding and reranker models.
    """
    if "control_map_min_score" in s.model_fields_set:
        return s.control_map_min_score
    return grounding.resolve_thresholds(sess, llm, s)


def collect_control_query(scenario_json: str | None) -> str | None:
    """One grounding query per output: the scenario's own title + statement.

    The LLM no longer proposes controls (library-first redesign) — the narrative text is
    matched directly against Control_Library, so control selection never depends on the
    model's control wording. The json.loads guard stays: ScenarioJSON is NULL on error
    cards and must yield None, not a crash. Legacy rows still carrying a model-authored
    "controls" key are deliberately ignored here — the map row is the source of truth.
    """
    try:
        scenario = json.loads(scenario_json or "{}")
    except ValueError:
        scenario = {}
    if not isinstance(scenario, dict):
        return None
    text = " ".join(t for t in (grounding.ensure_text(scenario.get("scenario_title")).strip(),
                                grounding.ensure_text(scenario.get("scenario_statement")).strip()) if t)
    return text or None


def map_controls(sess: Session, scenario_session: dict, asset_context: dict,
                subsystems: list[dict] | None, llm: LLMClient, subsystem_id: int,
                task_id: str, epoch: int, *, durable: bool = False) -> None:
    """Store top control matches for active, complete scenario outputs.

    Reads outputs with a null ``ControlsMappedAt`` value and no existing map rows, grounds
    each output's SCENARIO TEXT (title + statement — the LLM no longer proposes controls)
    against Control_Library via the hybrid shortlist + reranker, filters matches by score,
    removes duplicate control IDs, and inserts the top ``control_map_top_k`` rows. It
    timestamps every selected output, including outputs with no valid query. A mapping error
    is logged without failing scenario generation. With ``durable=True``, mapping writes are
    committed before this function returns.
    """
    # A savepoint prevents mapping errors from rolling back scenario writes.
    sp = sess.begin_nested()
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
                dal.active(m.Threat_Scenario_Output.Superseded),
                m.Threat_Scenario_Output.Status == ScenarioStatus.complete,
                m.Threat_Scenario_Output.ControlsMappedAt.is_(None),
                ~already_mapped.exists())
        ).all()
        if not outputs:
            return
        # ONE query per output — the scenario's own text. Built before calling the
        # embedding service once per batch.
        per_output: list[tuple[str, str]] = []
        for output_id, scenario_json in outputs:
            query = collect_control_query(scenario_json)
            if not query:
                continue
            per_output.append((output_id, query))
        skipped = len(outputs) - len(per_output)
        min_score = _min_score(sess, llm, s)
        inserted = dropped = unanswered = 0
        answered: list[str] = []
        if per_output:
            texts = list(dict.fromkeys(q for _, q in per_output))
            qv_map: dict[str, list[float]] = {}
            try:  # Cache query vectors; grounding still works if this warm-up fails.
                batch = get_settings().embedding_batch_size
                for i in range(0, len(texts), batch):
                    chunk = texts[i:i + batch]
                    qv_map.update(zip(chunk, llm.embed(chunk, kind="query")))
            except Exception:
                log.warning("controls.query_prime_failed", session_id=sid, exc_info=True)

            if not (dal.renew_lease(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id)
                    or dal.stage_settled_at_epoch(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch)):
                log.warning("controls.lease_lost", session_id=sid)
                return
            sess.commit()  # End the lease transaction before the slow grounding call.
            flat = [(q, qv_map.get(q)) for _, q in per_output]
            match_lists = grounding.ground_control_queries(llm, flat, candidates, s)
            for (output_id, _query), result in zip(per_output, match_lists):
                if not result.answered:
                    # NO ANSWER for this output (its rerank item failed) — as opposed to an
                    # answer of "nothing matched". Leave it completely alone: no map rows, and
                    # crucially NOT in `answered`, so the stamp below skips it and the next
                    # mapping run picks it straight back up.
                    unanswered += 1
                    continue
                answered.append(output_id)
                matches = result.matches
                # KEEP the best[cid] dedup: the PK (OutputID, ControlLibraryID) turns any
                # duplicate into an IntegrityError the outer except would swallow into
                # controls.mapping_failed — losing the whole output's mapping on one
                # WARNING. One guard here is cheaper than trusting every upstream path.
                best: dict[int, dict] = {}
                for row, score in matches:
                    if score < min_score:
                        dropped += 1
                        continue
                    cid = row["ControlLibraryID"]
                    if cid not in best or score > best[cid]["Score"]:
                        # SuggestedControl deliberately not written (column stays, legacy
                        # rows keep theirs): the LLM no longer suggests controls.
                        best[cid] = {"OutputID": output_id, "ControlLibraryID": cid, "SessionID": sid,
                                    "Score": score, "CreatedAt": now()}
                keep = sorted(best.values(), key=lambda r: r["Score"], reverse=True)[: s.control_map_top_k]
                for rank, rec in enumerate(keep, start=1):
                    rec["MapRank"] = rank
                if keep:
                    sess.execute(insert(m.Threat_Scenario_Control_Map), keep)
                    inserted += len(keep)
        # Timestamp the outputs we ACTUALLY ANSWERED, plus the ones that had no groundable
        # query at all — those are answered by definition, there is nothing to retry for them.
        #
        # NOT the whole `outputs` list, which is what this used to be. The stamp is permanent
        # (nothing anywhere clears it) and `ControlsMappedAt IS NULL` is the ONLY thing that
        # keeps an output eligible for a later run — so stamping an output whose rerank had
        # merely failed converted one transient 429 into a permanent, unrecoverable,
        # authoritative-looking "the control library has nothing for this threat". Leaving it
        # NULL is the entire fix: the row just stays in the queue and the next run retries it.
        groundable = {oid for oid, _ in per_output}
        to_stamp = answered + [oid for oid, _ in outputs if oid not in groundable]
        if to_stamp:
            sess.execute(update(m.Threat_Scenario_Output)
                        .where(m.Threat_Scenario_Output.OutputID.in_(to_stamp))
                        .values(ControlsMappedAt=now()))
        if unanswered:
            # Loud, attributable and joined to the session — unlike llm.rerank_many's
            # `rerank_item_failed`, which logs an anonymous batch index that joins to nothing.
            log.warning("controls.unanswered_left_for_retry", session_id=sid,
                        unanswered=unanswered, of=len(per_output))
        if not per_output:
            if durable:
                sess.commit()
            log.warning("controls.nothing_groundable", session_id=sid, skipped=skipped)
            return
        dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                        EntityID=scenario_session["EntityID"], Stage=WorkflowStage.SCENARIO_GENERATION,
                        SubsystemID=ss, EventType=AuditEventType.controls_mapped,
                        # fallback_queries dropped from the detail: every query is scenario-text
                        # now, the metric was constant. Historical rows keep the old key.
                        DetailJSON=json.dumps({"outputs": len(per_output), "mapped": inserted,
                                                "dropped": dropped,
                                                # Same discipline as tasks._validate_candidates'
                                                # `degraded`: a fail-open path must PERSIST how
                                                # often it degraded, or afterwards a degraded run
                                                # is indistinguishable from a clean one.
                                                "unanswered": unanswered,
                                                "skipped": skipped, "itot": itot or "",
                                                "itot_filter_applied": itot is not None,
                                                "min_score": min_score}))
        log.info("controls.mapped", session_id=sid, outputs=len(per_output), mapped=inserted,
                dropped=dropped, unanswered=unanswered, skipped=skipped, itot=itot,
                min_score=min_score)
        if durable:
            sess.commit()
    except Exception:
        # Roll back mapping changes and allow scenario generation to finish.
        (sp.rollback() if sp.is_active else sess.rollback())
        log.warning("controls.mapping_failed", session_id=scenario_session.get("SessionID"), exc_info=True)
    finally:
        # Close the savepoint after normal returns and early returns.
        if sp.is_active:
            sp.commit()
