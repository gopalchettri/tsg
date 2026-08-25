"""Create control-library mappings for generated scenario outputs.

The module grounds each scenario's own text (title + statement) against the control
library and stores the highest-scoring matches — the LLM never proposes controls.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import insert, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    AuditEventType,
    ScenarioStatus,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
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


def _min_score(sess: Session, llm: LLMClient, s) -> grounding.Threshold:
    """The score a grounded control must clear, WITH where that number came from.

    ``control_map_min_score`` when explicitly configured, else the threshold resolved for the
    current embedding+reranker pair.

    The origin matters more here than anywhere else. The fallback was calibrated
    label-vs-label, but this stage now queries with a scenario PARAGRAPH (library-first
    redesign) - a materially different score distribution. A cutoff too high drops every
    match, and an empty control list is documented as a healthy library gap, so the failure is
    invisible. Recording "this number was never measured for this question" alongside the
    number is what makes that reviewable afterwards."""
    if "control_map_min_score" in s.model_fields_set:
        return grounding.Threshold(s.control_map_min_score, "env_pinned")
    return grounding.resolve_thresholds(sess, llm, s)


def collect_control_query(scenario_json: str | None, threat_name: str | None = None,
                        threat_type: str | None = None) -> str | None:
    """One grounding query per output: the THREAT's identity, then the scenario's own
    title + statement.

    The threat identity leads deliberately, and leaving it out was a measured defect, not a
    style choice. A scenario narrative describes the IMPACT ("denial of service", "telemetry
    severed", "availability degraded"); controls address the MECHANISM ("compromised vendor
    firmware"). Querying on narrative alone therefore matched impact-shaped controls and buried
    mechanism-shaped ones: for a real "Compromised OT supply chain or hardware" scenario the
    reranker scored `Telecommunications Services Availability` 14.0 and the actually-correct
    `Signed Components` 1.9, so NOTHING cleared the cutoff and the API published `controls: []`
    — which schemas.py documents as a genuine library gap. Prefixing the threat moved
    `Supply Chain Risk Assessment` to 90.98 and `Signed Components` to 60.6 against the SAME
    library, SAME reranker, SAME threshold.

    That also explains why the same catalogue threat could map controls on one scenario and
    none on another: the only thing distinguishing them was narrative phrasing, because the
    threat itself never entered the query.

    Both threat fields are optional so a caller with no threat context (the measurement script's
    --text-file mode) still gets the narrative-only query rather than a crash. The json.loads
    guard stays: ScenarioJSON is NULL on error cards and must yield None. Legacy rows still
    carrying a model-authored "controls" key are deliberately ignored — the map row is the
    source of truth.
    """
    try:
        scenario = json.loads(scenario_json or "{}")
    except ValueError:
        scenario = {}
    if not isinstance(scenario, dict):
        return None
    parts = [grounding.ensure_text(threat_name).strip(),
            grounding.ensure_text(threat_type).strip(),
            grounding.ensure_text(scenario.get("scenario_title")).strip(),
            grounding.ensure_text(scenario.get("scenario_statement")).strip()]
    text = " ".join(t for t in parts if t)
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
        # The threat rides along on the SAME row as the scenario text: collect_control_query
        # needs both, and a second lookup per output would be an N+1 on a batch endpoint.
        # OUTER join — an output whose scoped/threat chain is missing still gets mapped on its
        # narrative alone rather than being silently skipped.
        out_t, st_t, it_t = m.Threat_Scenario_Output, m.Scoped_Threat, m.Identified_Threat
        outputs = sess.execute(
            select(out_t.OutputID, out_t.ScenarioJSON,
                it_t.ThreatName, it_t.ThreatType,
                it_t.LibraryThreatName, it_t.LibraryThreatType)
            .select_from(out_t.__table__
                        .outerjoin(st_t, out_t.ScopedThreatID == st_t.ScopedThreatID)
                        .outerjoin(it_t, st_t.ThreatID == it_t.ThreatID))
            .where(out_t.SessionID == sid,
                dal.active(out_t.Superseded),
                out_t.Status == ScenarioStatus.complete,
                out_t.ControlsMappedAt.is_(None),
                ~already_mapped.exists())
        ).all()
        if not outputs:
            return
        # ONE query per output — the threat identity plus the scenario's own text. Built before
        # calling the embedding service once per batch.
        per_output: list[tuple[str, str]] = []
        for output_id, scenario_json, tname, ttype, ltname, lttype in outputs:
            # Library spelling first, same preference the API uses for display: the curator's
            # wording is the one the control library was written against.
            query = collect_control_query(scenario_json, ltname or tname, lttype or ttype)
            if not query:
                continue
            per_output.append((output_id, query))
        skipped = len(outputs) - len(per_output)
        threshold = _min_score(sess, llm, s)
        min_score = threshold.value
        inserted = dropped = unanswered = 0
        answered: list[str] = []
        if per_output:
            texts = list(dict.fromkeys(q for _, q in per_output))
            qv_map: dict[str, list[float]] = {}
            try:  # Cache query vectors; grounding still works if this warm-up fails.
                # llm.embed chunks to the provider's per-request cap internally, and asserts each
                # chunk came back aligned — so this zip can't pair a text with another's vector.
                qv_map.update(zip(texts, llm.embed(texts, kind="query")))
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
        # Index, not tuple-unpack: this row carries the joined threat columns too, and a
        # positional `for oid, _ in outputs` silently became a ValueError the moment the SELECT
        # grew — swallowed by the outer except into "controls.mapping_failed", i.e. every output
        # left unstamped and unmapped.
        to_stamp = answered + [row[0] for row in outputs if row[0] not in groundable]
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
                                                "min_score": min_score,
                                                # WHERE the cutoff came from. Without it a
                                                # stored 75.0 cannot be told apart from a
                                                # measured one, and "static_default" means it
                                                # was tuned for a different model pair AND a
                                                # different question (label vs paragraph).
                                                "min_score_origin": threshold.origin}))
        log.info("controls.mapped", session_id=sid, outputs=len(per_output), mapped=inserted,
                dropped=dropped, unanswered=unanswered, skipped=skipped, itot=itot,
                min_score=min_score, min_score_origin=threshold.origin)
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


#: Sessions created before this are NEVER swept. The sweep exists to give the retry queue a
#: consumer GOING FORWARD, not to retro-map work already delivered — an explicit owner decision
#: ("i do not want controls to mapped to the already created sessions"). Moving it backwards
#: would silently start re-examining historical sessions, so it is a constant, not a setting.
CONTROL_MAP_SWEEP_FROM = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)

#: (session, subsystem) pairs handled per sweep tick. Bounded because every mapped output costs a
#: CPU-bound rerank, and one tick must not monopolise a worker slot foreground requests need.
SWEEP_LIMIT = 5


def sessions_awaiting_control_mapping(sess: Session, limit: int = SWEEP_LIMIT) -> list[tuple[str, int, int]]:
    """(SessionID, SubsystemID, GenerationEpoch) for work stranded in the control-mapping queue.

    THE QUEUE HAD NO CONSUMER. `map_controls` selects on `ControlsMappedAt IS NULL` and three of
    its paths deliberately return without stamping — `controls.no_candidates`,
    `controls.lease_lost`, and a per-output unanswered rerank — each documented as safe because
    "the row just stays in the queue and the next run retries it". But `map_controls` is called
    only from `_finalize_scenario_batch`, i.e. the tail of a scenario batch for that same session,
    so once a session finished nothing ever mapped it again. Every "recoverable" path was in fact
    permanent: one 429 during a session's only pass and that scenario had no controls forever,
    published as `controls: []`, which the API documents as a genuine library gap. This function
    is the missing SELECT that makes "left for retry" true.

    Two fences make a swept row provably nobody else's work:

    * the SCENARIOS stage must be SETTLED (AWAITING_DECISION/COMPLETE) — a RUNNING stage means a
      live batch owns the session and will map at its own tail;
    * settled for longer than one `stage_lease_seconds` — `_finalize_scenario_batch` calls
      `finish_stage` BEFORE `map_controls`, so settledness alone leaves a window where the
      in-pipeline mapping is still running. The lease is the codebase's own definition of "a work
      step this old is no longer alive", so no second grace knob is invented.

    The epoch comes from that same settled row, which is what lets the reused `map_controls` pass
    its own `stage_settled_at_epoch` fallback: the sweep holds no stage claim, so `renew_lease`
    correctly fails and the settled check is what authorises it.
    """
    out, ses, st = m.Threat_Scenario_Output, m.Scenario_Session, m.Subsystem_Stage_State
    cutoff = now() - timedelta(seconds=get_settings().stage_lease_seconds)
    rows = sess.execute(
        select(out.SessionID, out.SubsystemID, st.GenerationEpoch)
        .join(ses, ses.SessionID == out.SessionID)
        .join(st, (st.SessionID == out.SessionID)
                & (st.SubsystemID == out.SubsystemID)
                & (st.Level == SubsystemLevel.SCENARIOS))
        .where(out.Status == ScenarioStatus.complete,
            dal.active(out.Superseded),
            out.ControlsMappedAt.is_(None),
            ses.CreatedAt >= CONTROL_MAP_SWEEP_FROM,
            st.Status.in_([StageStatus.AWAITING_DECISION, StageStatus.COMPLETE]),
            st.UpdatedAt < cutoff)
        .group_by(out.SessionID, out.SubsystemID, st.GenerationEpoch)
        .limit(limit)
    ).all()
    return [(str(r[0]), int(r[1]), int(r[2])) for r in rows]
