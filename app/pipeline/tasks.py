from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from sqlalchemy import insert, update
from sqlalchemy.orm import Session

from app.core.enums import (
    AuditEventType, ScenarioStatus, SessionStatus, SSEEventType, StageStatus, SubsystemLevel, WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import execute_dml, guid, now
from app.core.config import get_settings
from app.pipeline import grounding, prompts, scoping, validation
from app.pipeline.llm import LLMClient, LLMSlotUnavailable, Provenance, moderate
from app.sse import bus

log = get_logger(__name__)

_EPOCH = 1
_WORK_LEVELS = (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS)
_SCENARIO_TEXT_FIELDS = ("scenario_title", "scenario_statement", "business_impact",
                        "operational_impact", "risk_statement")


def _ask_ai(sess: Session, llm: LLMClient, messages: list[dict], *, scenario_session: dict,
            subsystem_id: int, stage: str, level: SubsystemLevel, epoch: int, task_id: str,
            expected_type: type, temperature: float | None = None) -> tuple[Any, Provenance | None]:
    """Send a prompt to the LLM, log the raw request/response to Prompt_Log, and parse the
    reply into the expected type. If parsing fails, the failed attempt is still logged before
    the error is re-raised.

    Renews the stage's lease right before the call: claim_stage sets LeaseExpiresAt once, but
    a stage can make several of these calls in a row (write_scenarios, one per selected
    threat) — without renewal, a still-alive worker deep in that loop can have its own lease
    expire under entirely normal per-call latency and get reaped out from under it. Best-
    effort: if the lease was already lost, the caller's own finish_stage fencing at the end
    catches it exactly as it always has — this only lowers how often that path is reached
    under normal operation, it doesn't add a new failure mode.
    """
    if not dal.renew_lease(sess, scenario_session["SessionID"], subsystem_id, level, epoch, task_id):
        log.warning("stage.lease_renewal_failed", session_id=scenario_session["SessionID"],
                    subsystem=subsystem_id, level=str(level))
    sess.commit()
    text, prov = llm.chat(messages, temperature=temperature)
    if prov is not None:
        prov.prompt_version = prompts.PROMPT_VERSION
    row = {
        "LogID": guid(), "SessionID": scenario_session["SessionID"], "TenantID": scenario_session["TenantID"],
        "EntityID": scenario_session["EntityID"], "UserID": scenario_session.get("UserID"),
        "SubsystemID": subsystem_id, "Stage": stage, "PromptVersion": prompts.PROMPT_VERSION,
        "Messages": json.dumps(messages), "ResponseText": text,
        "Model": prov.model if prov else None, "ModelVersion": prov.model_version if prov else None,
        "CreatedAt": now(),
    }
    try:
        parsed = validation.parse_json(text, stage=stage, expected_type=expected_type)
    except validation.LLMResponseParseError:
        sess.rollback()
        dal.insert_row(sess, m.Prompt_Log, {**row, "ParseSucceeded": False})
        sess.commit()
        log.warning("llm_response.parse_failed", session_id=scenario_session["SessionID"],
                    subsystem=subsystem_id, stage=stage)
        raise
    dal.insert_row(sess, m.Prompt_Log, {**row, "ParseSucceeded": True})
    return parsed, prov


def _summarize_ai_call(p: Provenance | None) -> dict | None:
    """Turn an AI call's Provenance details into a small dict for audit logs, or None if there
    was no AI call."""
    return None if p is None else {"model": p.model, "version": p.model_version,
                                "params": p.params, "prompt_version": p.prompt_version}


def _send_live_update(session_id: str, sse_type: SSEEventType, subsystem_id: int,
        level: SubsystemLevel, status: StageStatus, epoch: int = _EPOCH) -> None:
    """Push a real-time status event to the session's SSE stream so the UI can show progress."""
    bus.publish(session_id, {
        "type": str(sse_type), "session_id": session_id, "subsystem_id": subsystem_id,
        "stage": str(level), "status": str(status), "generation_epoch": epoch,
        "ts": now().isoformat(),
    })


def set_up_progress_tracking(sess: Session, session_id: str, tenant_id: str, entity_id: str, subsystems: list[dict]) -> None:
    """Create the initial 'IDLE' progress rows (one per subsystem per work stage, plus a lock
    row) that the rest of the pipeline updates as it runs."""
    rows = [{
        "StateID": guid(), "SessionID": session_id, "TenantID": tenant_id, "EntityID": str(entity_id),
        "SubsystemID": sub["id"], "Level": level, "Status": StageStatus.IDLE,
        "GenerationEpoch": _EPOCH, "UpdatedAt": now(),
    } for sub in subsystems for level in (*_WORK_LEVELS, SubsystemLevel.LOCK)]
    if rows:
        sess.execute(insert(m.Subsystem_Stage_State), rows)


def _safe_text(v: Any, default: str | None) -> str | None:
    """Coerce a value from the AI's JSON response into a plain string, or fall back to
    `default` if it isn't usable text."""
    if default is None:
        return v if isinstance(v, str) else None
    return grounding.ensure_text(v, default)


def _build_threat_records(tid: str, sid: str, tenant: str, ss: int, ptype: str | None, pcat: str | None,
                        pname: str | None, gr: grounding.GroundingResult, entity_id: str | None,
                        user_id: str | None) -> tuple[dict, dict]:
    """Build the Identified_Threat DB row and its in-memory summary for one AI-proposed threat,
    given its grounding result. Pure dict-building — no I/O."""
    row = {
        "ThreatID": tid, "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ThreatCategory": pcat, "ThreatType": ptype,
        "ThreatName": pname,
        "ThreatActorsJSON": json.dumps({"actors": gr.actors, "validated": gr.actors_validated}),
        "LibraryThreatType": gr.library_type, "LibraryThreatName": gr.library_name,
        "ThreatTypeID": gr.type_id, "ThreatCatalogueID": gr.catalogue_id,
        "GroundingStatus": gr.status, "GroundingScore": gr.score,
        "Superseded": 0, "CreatedAt": now(),
    }
    summary = {
        "threat_id": tid, "grounding_status": str(gr.status),
        "threat_type": ptype, "threat_name": pname,
        "library_threat_type": gr.library_type, "library_threat_name": gr.library_name,
        "threat_type_id": gr.type_id,  # the real threat type this was matched to, needed later so the scoring step knows what kind of threat this is
        "catalogue_id": gr.catalogue_id,  # finer-grained than type_id — the per-(session,subsystem) dedup key (write_scenarios/_dedup_key)
        "actors": gr.actors,  # carried through to scenario generation so the write-up can be grounded in who's behind the threat
    }
    return row, summary


def _normalize(s: str) -> str:
    """Collapse an ungrounded proposal's free text to a stable dedup token: drop punctuation,
    squeeze whitespace, casefold — so "OTA-poisoning" and "ota poisoning" fold together."""
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", s)).strip().casefold()


def _dedup_key(info: dict) -> str:
    """Catalogue-level dedup key for one threat, scoped per (session, subsystem) by the caller.
    Prefer the finest real library id; fall back to normalized text for a novel/ungrounded
    proposal. ThreatType is NOT NULL; ThreatName is nullable → treat None as "". Change this and
    you MUST change the IdentityHash fold in _build_scenario_output_row (they must agree, so the
    app-level dedup and the DB unique index block the SAME pair)."""
    catalogue_id = info.get("catalogue_id")
    if catalogue_id is not None:
        return f"cat:{catalogue_id}"
    type_id = info.get("threat_type_id")
    if type_id is not None:
        return f"type:{type_id}"
    return "txt:" + _normalize((info.get("threat_type") or "") + "\x1f" + (info.get("threat_name") or ""))


def find_threats(sess: Session, scenario_session: dict, sub: dict, asset_context: dict, llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, categories: list[str] | None = None,
                actor_examples: list[str] | None = None,
                asset_active_fields: list[str] | None = None,
                sub_active_fields: list[str] | None = None) -> tuple[list[dict], Provenance | None]:
    """Run the THREATS stage for one subsystem: ask the AI for candidate threats, match
    ("ground") each one against the threat library, save them to the database, and report
    the stage as complete. Returns an empty list if another worker already claimed this
    stage or the claim is lost partway through.

    `categories`/`actor_examples` are the live Threat_Category/Threat_Actor names — read live so
    the prompt's vocabulary never drifts from what grounding.py actually matches against (see
    prompts.threats_prompt()'s own fallback note). `asset_active_fields`/`sub_active_fields` are
    the curator-toggled Context_Field_Config field names (dal.active_context_fields), same
    once-per-session reasoning. _process_all_supporting_systems reads all four ONCE per session
    (same reasoning as its own asset_context) and passes them down here, since they're global
    config that can't change mid-run — don't re-query per subsystem. Left optional (None →
    queried here) only so a direct caller without a pre-fetched value still works."""
    sid, ss, tenant = scenario_session["SessionID"], sub["id"], scenario_session["TenantID"]
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
        return [], None
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.THREATS, StageStatus.RUNNING, epoch)
    proposals, prov = _ask_ai(sess, llm, prompts.threats_prompt(
                                scenario_session["AssetName"], asset_context, sub,
                                max_threats=get_settings().max_threats_per_subsystem,
                                categories=categories if categories is not None else dal.active_category_names(sess),
                                actor_examples=actor_examples if actor_examples is not None else dal.active_actor_names(sess),
                                asset_active_fields=asset_active_fields if asset_active_fields is not None
                                    else dal.active_context_fields(sess, "asset"),
                                sub_active_fields=sub_active_fields if sub_active_fields is not None
                                    else dal.active_context_fields(sess, "subsystem")),
                                scenario_session=scenario_session, subsystem_id=ss, stage="threats",
                                level=SubsystemLevel.THREATS, epoch=epoch, task_id=task_id, expected_type=list,
                                # very likely (not guaranteed — see TSG_SDD.md §9.1b) to repeat the
                                # same proposed threats for identical asset/subsystem inputs
                                temperature=get_settings().threat_identification_temperature)
    dal.supersede(sess, m.Identified_Threat, sid, ss)
    threats: list[dict] = []
    rows: list[dict] = []
    sector_ids = json.loads(scenario_session["SectorIDsJSON"]) if scenario_session.get("SectorIDsJSON") else []
    grounding_cache: dict = {}  # scoped to this call — same sector_ids for every proposal below
    # For each threat the AI proposed: pull out its fields, try to match it to a known
    # threat-library entry, then build the row for a new Identified_Threat record.
    for p in proposals:
        # Same renewal _ask_ai does before its own LLM call: this loop can run one grounding
        # match (embedding/rerank) per proposed threat — up to max_threats_per_subsystem — with
        # no LLM call of its own to renew the lease in between, so a long loop could otherwise
        # outlive it under normal per-iteration latency alone.
        if not dal.renew_lease(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
            log.warning("stage.lease_renewal_failed", session_id=sid, subsystem=ss, level=str(SubsystemLevel.THREATS))
        sess.commit()
        ptype = _safe_text(p.get("type"), "")
        pcat = _safe_text(p.get("category"), "")
        pname = _safe_text(p.get("name"), None)  # it's okay for the threat's name to be left blank in the database, so we allow that here
        gr = grounding.find_threat_in_library(sess, llm, p, sector_ids=sector_ids, cache=grounding_cache)
        tid = guid()
        row, summary = _build_threat_records(tid, sid, tenant, ss, ptype, pcat, pname, gr,
                                        scenario_session["EntityID"], scenario_session.get("UserID"))
        rows.append(row)
        threats.append(summary)
    if rows:
        sess.execute(insert(m.Identified_Threat), rows)
    if not dal.finish_stage(sess, sid, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE, epoch, task_id):
        sess.rollback()
        log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="THREATS", epoch=epoch)
        return [], None
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=scenario_session["EntityID"],
                    Stage=WorkflowStage.THREAT_IDENTIFICATION, SubsystemID=ss,
                    EventType=AuditEventType.grounding_summary,
                    DetailJSON=json.dumps({"count": len(threats)}))
    # Commit before announcing: a client reacting to stage_completed by immediately reading
    # results must never race the write it's reading (same discipline as the stage_started
    # commit above — this event just wasn't covered by it, since it fires after more work).
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="THREATS", count=len(threats))
    return threats, prov




def _moderation_report(scenario: dict) -> dict:
    """Optional content-moderation check (llm.moderate — off by default, LLM_MODERATION_ENABLED)
    against this scenario's narrative text fields, joined into one string (one moderation call
    per scenario, same cardinality as the one chat() call that wrote it). Reshaped into a small
    dict so it rides alongside validate_scenario's own report inside the same ValidationJSON
    blob a reviewer already looks at — never a new table/column, and never a reason to reject
    the scenario (moderate() is advisory only — see its own docstring in llm.py)."""
    text = " ".join(str(scenario.get(f) or "") for f in _SCENARIO_TEXT_FIELDS)
    r = moderate(text)
    return {"checked": r.checked, "flagged": r.flagged, "categories": r.categories, "error": r.error}


def _generate_one_scenario(sess: Session, scenario_session: dict, sub: dict, asset_context: dict, sc,
                    enriched: dict, llm: LLMClient, task_id: str, epoch: int,
                    asset_active_fields: list[str] | None,
                    sub_active_fields: list[str] | None) -> tuple[dict, dict, Provenance | None]:
    """Ask the AI to write a scenario for a single scoped threat, then validate the result
    against the threat's expected type/name.

    `asset_active_fields`/`sub_active_fields` come pre-resolved from write_scenarios (its ONE
    real call site, resolved once for the whole batch there — see that function's own comment)
    rather than each threat in a batch re-querying Context_Field_Config for itself."""
    info = enriched.get(sc.threat_id, {})
    threat_type = info.get("library_threat_type") or info.get("threat_type")
    threat_name = info.get("library_threat_name") or info.get("threat_name")
    actors = info.get("actors") or []
    scenario, prov = _ask_ai(sess, llm, prompts.scenario_prompt(
                            scenario_session["AssetName"], asset_context, sub, threat_type, threat_name,
                            actors=actors, asset_active_fields=asset_active_fields,
                            sub_active_fields=sub_active_fields),
                            scenario_session=scenario_session, subsystem_id=sub["id"], stage="scenario",
                            level=SubsystemLevel.SCENARIOS, epoch=epoch, task_id=task_id, expected_type=dict)
    report = validation.validate_scenario(
        scenario, threat_type, threat_name,
        asset_name=scenario_session["AssetName"], critical_service=asset_context.get("critical_service"))
    report["moderation"] = _moderation_report(scenario)
    return scenario, report, prov


def _build_scoped_threat_row(scoped_id: str, sid: str, tenant: str, ss: int, sc: scoping.Scored,
                        entity_id: str | None, user_id: str | None) -> dict:
    """Build the Scoped_Threat DB row for one scored threat. Pure dict-building — no I/O."""
    return {
        "ScopedThreatID": scoped_id, "SessionID": sid, "TenantID": tenant, "EntityID": entity_id,
        "UserID": user_id, "SubsystemID": ss,
        "ThreatID": sc.threat_id, "Score": sc.score, "ScopeRank": sc.rank,
        "Selected": 1 if sc.selected else 0, "Reason": sc.reason,
        "FactorsJSON": json.dumps(sc.factors) if sc.factors else None,  # a record of exactly which scoring rules affected this threat's score, kept for transparency
        "Superseded": 0, "CreatedAt": now(),
    }


def _build_scenario_output_row(scoped_id: str, sid: str, tenant: str, ss: int, scenario: dict, report: dict,
                            epoch: int, entity_id: str | None, user_id: str | None, dedup_key: str) -> dict:
    """Build the Threat_Scenario_Output DB row for one generated scenario. Pure dict-building —
    no I/O."""
    # sha256(SessionID|SubsystemID|dedup_key): folds in the SAME catalogue-level dedup_key the
    # selection pass uses, so the filtered unique index UX_Scenario_ActiveIdentity(SessionID,
    # IdentityHash) WHERE Superseded=0 physically blocks a second active scenario for the same
    # threat even under a crash/retry. SubsystemID MUST be in the hash (the index has no
    # subsystem column) or sibling subsystems sharing a catalogue/type would cross-suppress.
    identity = hashlib.sha256(f"{sid}|{ss}|{dedup_key}".encode()).hexdigest()
    return {
        "OutputID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.complete,
        "ScenarioJSON": json.dumps(scenario),
        "ValidationJSON": json.dumps(report),  # a note recording whether this scenario passed its automatic sanity checks
        "Accepted": 0, "Superseded": 0,
        "IdentityHash": identity, "GenerationEpoch": epoch, "ErrorMessage": None, "CreatedAt": now(),
    }


def _select_unique_top_n(scoped: list[scoping.Scored], enriched: dict, top_n: int | None) -> None:
    """Catalogue-dedupe the already-ranked, threshold-passed threats down to a unique top-N,
    in place (Stage E). Walks in the ranker's own order (Score desc, ThreatID asc). A threat
    keeps its scenario only if its dedup key is unseen AND fewer than top_n uniques are already
    kept — Decision C, "free the slot": the count is over UNIQUE threats, so the reviewer gets N
    DISTINCT scenarios, not N-minus-the-dupes. A later duplicate is demoted (Selected=0, reason)
    but its row is kept for audit/provenance; only the scenario is withheld. Threats already
    excluded in scoring (tech_gate / score threshold) are left as-is — they never consumed a slot.
    Full-run only: a targeted regen is never passed here (a regen target must not be blocked)."""
    seen: set[str] = set()
    kept = 0
    for sc in scoped:
        if not sc.selected:
            continue  # already excluded by tech_gate / score threshold in score_threats
        key = _dedup_key(enriched.get(sc.threat_id, {}))
        if key in seen:
            sc.selected, sc.reason = False, "duplicate of higher-ranked threat"
        elif top_n is not None and kept >= top_n:
            sc.selected, sc.reason = False, f"beyond top-{top_n} cutoff"
        else:
            seen.add(key)
            kept += 1


def write_scenarios(sess: Session, scenario_session: dict, sub: dict, asset_context: dict, threats: list[dict],
                llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, target_threat_ids: set[str] | None = None,
                asset_active_fields: list[str] | None = None,
                sub_active_fields: list[str] | None = None,
                *, require_lock: bool = False) -> list[Provenance | None]:
    """Run the SCENARIOS stage for one subsystem: score/rank the given threats, generate a
    scenario for each selected one, and save everything to the database. If
    `target_threat_ids` is given, only those threats are (re)scored and (re)generated instead
    of the whole set — used when regenerating just a subset. Returns an empty list if another
    worker already claimed this stage or the claim is lost partway through.

    `require_lock=True` (passed by both real callers — tasks.py's own driver and cascade.py's
    regen path, never by a direct unit test) additionally refuses to even attempt the claim
    unless the caller still holds this subsystem's `_LOCK`. Without it: a worker whose prior
    stage stalled past its lease has its THREATS row ERROR'd and its `_LOCK` reclaimed+released
    by the reaper — which also ERROR-marks this SCENARIOS row (still IDLE, never touched) as
    part of finalizing the now-abandoned session (reaper.py's `_close_out_one_abandoned_
    session`). `claim_stage`'s plain IDLE/ERROR branch doesn't know the caller lost the mutex,
    so the same zombie task_id can claim THIS row moments later and silently finish a stage on
    a session the reaper already closed out. `claim_stage` itself intentionally has no `_LOCK`
    check (many tests exercise it standalone) — this is the one call site that actually needs
    the mutex re-verified before resuming multi-step work under a possibly-stale identity."""
    sid, ss, tenant = scenario_session["SessionID"], sub["id"], scenario_session["TenantID"]
    entity_id, user_id = scenario_session["EntityID"], scenario_session.get("UserID")
    if require_lock and not dal.holds_lock(sess, sid, ss, task_id):
        log.warning("subsystem.lock_lost_before_scenarios", session_id=sid, subsystem=ss)
        return []
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id):
        return []
    sess.commit()  # makes the "now RUNNING" flip durable before we announce it below — same reason explained in find_threats above (the pre-AI-call commit is `_ask_ai`'s own job now)
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.SCENARIOS, StageStatus.RUNNING, epoch)

    # Resolve ONCE per call, not once per selected threat below — a caller that doesn't pass
    # these (e.g. cascade.py's regen path) previously left _generate_one_scenario to re-query
    # Context_Field_Config on every single threat in the loop, an N+1 that scaled with batch
    # size (up to _MAX_BATCH targeted threats per regen call). Also makes every threat in THIS
    # call use the exact same field set, instead of each one racing a curator's mid-batch edit.
    if asset_active_fields is None or sub_active_fields is None:
        resolved = dal.active_context_fields_by_group(sess)  # one round-trip for both groups
        if asset_active_fields is None:
            asset_active_fields = resolved["asset"]
        if sub_active_fields is None:
            sub_active_fields = resolved["subsystem"]

    # Only distinct, known threat-type ids are needed to look up the scoring rules that apply.
    type_ids = sorted({t["threat_type_id"] for t in threats if t.get("threat_type_id") is not None})
    settings = get_settings()
    # scoping_top_n is the SCENARIO count. On a full run it is enforced over UNIQUE threats by
    # _select_unique_top_n below (Decision C), so score_threats gets top_n=None and stays the pure
    # deterministic ranker (base + grounding + rules, threshold filtering only — no dedup, no LLM).
    # A targeted regen keeps score_threats' own top_n cutoff and skips dedup entirely. The clamp is
    # belt-and-suspenders to config.py's startup validator, in case top_n is monkeypatched past the
    # candidate ceiling at runtime.
    top_n = settings.scoping_top_n
    if top_n is not None:
        top_n = min(top_n, settings.max_threats_per_subsystem)
    scoped_all = scoping.score_threats(threats, subsystem=sub, rules=dal.active_threat_rules(sess, type_ids),
                                    score_threshold=settings.scoping_score_threshold,
                                    top_n=None if target_threat_ids is None else top_n)
    enriched = {t["threat_id"]: t for t in threats}
    # Dedup to a unique top-N BEFORE any scenario text is generated — full runs only. A targeted
    # regen must never be blocked or demoted by dedup (the reviewer explicitly asked to redo an
    # existing, already-unique scenario), so it is left out of this pass.
    if target_threat_ids is None:
        _select_unique_top_n(scoped_all, enriched, top_n)
    # Full run: score/keep every threat. Targeted regen: only the caller-specified subset.
    scoped = scoped_all if target_threat_ids is None else [sc for sc in scoped_all if sc.threat_id in target_threat_ids]

    pairs = [(sc, guid()) for sc in scoped]  # assign each scoped threat its DB id up front, before generating scenarios


    provs: list[Provenance | None] = []
    scenarios: dict[str, tuple[dict, dict]] = {}  # scoped_id -> (scenario, validation report)
    # Only threats that scoring marked as "selected" get an actual AI-written scenario;
    # the rest are still recorded below as scored-but-not-selected.
    for sc, scoped_id in pairs:
        if not sc.selected:
            continue
        scenario, report, prov = _generate_one_scenario(sess, scenario_session, sub, asset_context, sc, enriched, llm, task_id, epoch,
                                                    asset_active_fields=asset_active_fields, sub_active_fields=sub_active_fields)
        scenarios[scoped_id] = (scenario, report)
        provs.append(prov)

    # [REVIEW-FIX] A targeted regen must never supersede a threat's prior active rows unless a
    # fresh scenario actually replaced them — rescoring can legitimately re-exclude a specific
    # target (a curator's Config_Threat_Rule weight or the scoping_score_threshold/scoping_top_n
    # cutoff changed since the scenario was first written); destroying the old row with nothing
    # to show for it, then reporting a misleading "claim lost" failure, was strictly worse than
    # the pre-existing "just ranked low" behavior these cutoffs were meant to fix.
    generated_ids = {sc.threat_id for sc, scoped_id in pairs if scoped_id in scenarios}
    excluded_ids = (target_threat_ids - generated_ids) if target_threat_ids is not None else set()
    if excluded_ids:
        log.warning("regen.target_no_longer_selected", session_id=sid, subsystem=ss,
                    threat_ids=sorted(excluded_ids))

    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=scenario_session["EntityID"],
                    Stage=WorkflowStage.SCENARIO_GENERATION, SubsystemID=ss,
                    EventType=AuditEventType.scoping_complete,
                    DetailJSON=json.dumps({"scoped": len(scoped), "selected": len(provs)}))

    if target_threat_ids is not None and not generated_ids:
        # Every requested target was excluded by rescoring — nothing to regenerate, and nothing
        # was mutated above. Return the stage to its normal reviewable state (same transition as
        # the success path below) and report this exactly like get_threat_id_to_redo's own
        # pre-lock/post-lock re-check does: a benign conflict (cascade.py's `except
        # RegenerateConflict`), never a pipeline failure.
        if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch, task_id):
            sess.rollback()
            log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
            return []
        sess.commit()
        raise dal.RegenerateConflict(
            f"threat(s) no longer meet the scoping cutoff and cannot be regenerated: {sorted(excluded_ids)}")

    # Mark prior rows as superseded before inserting the new ones: for a targeted regen, only
    # the threats that actually got a fresh scenario this pass; for a full run, everything scored.
    if target_threat_ids is not None:
        old_scoped_ids = dal.active_scoped_threat_ids(sess, sid, ss, generated_ids)
        dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, generated_ids)
        dal.supersede_by_scoped_threats(sess, sid, ss, old_scoped_ids)
    else:
        dal.supersede(sess, m.Scoped_Threat, sid, ss)
        dal.supersede(sess, m.Threat_Scenario_Output, sid, ss)
    scoped_rows = []
    output_rows = []
    for sc, scoped_id in pairs:
        if sc.threat_id in excluded_ids:
            continue  # excluded by rescoring — its prior active rows were left untouched above
        scoped_rows.append(_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id))
        if scoped_id not in scenarios:
            continue
        scenario, report = scenarios[scoped_id]
        output_rows.append(_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                                    entity_id, user_id, _dedup_key(enriched.get(sc.threat_id, {}))))
    if scoped_rows:
        sess.execute(insert(m.Scoped_Threat), scoped_rows)
    if output_rows:
        sess.execute(insert(m.Threat_Scenario_Output), output_rows)
    if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch, task_id):
        sess.rollback()
        log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
        return []
    # Commit before announcing: a client reacting to stage_completed by immediately reading
    # results (GET /sessions/{id}/results) must never race the write it's reading.
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="SCENARIOS", scenarios=len(provs))
    return provs


def _failure_client_message(exc: Exception) -> str:
    """[REVIEW-FIX] a guardrail block (proxy-side, via LLM_GUARDRAILS — llm.py's
    `_chat_kwargs`) previously produced the identical opaque "stage processing failed"
    message as any other random failure, with nothing anywhere (audit record, SSE event, DB
    ErrorMessage) indicating a guardrail specifically fired rather than a network blip, a
    parse error, or a real bug. litellm raises `RejectedRequestError` (a `BadRequestError`
    subclass) specifically for this case — imported locally, not at module top, so this file
    doesn't require `litellm` installed just to define this function (same "optional
    dependency for stub-only test runs" reasoning as every local `import litellm` in llm.py)."""
    if isinstance(exc, validation.LLMResponseParseError):
        return repr(exc)
    try:
        from litellm.exceptions import RejectedRequestError
    except ImportError:
        return "stage processing failed"
    if isinstance(exc, RejectedRequestError):
        return "content blocked by a configured safety guardrail"
    return "stage processing failed"


def _record_failure(sess: Session, scenario_session: dict, subsystem_id: int, exc: Exception, epoch: int = _EPOCH) -> None:
    """Handle a stage that raised an exception: roll back its half-done work, mark the
    subsystem's stages as ERROR, write an audit record, and notify the UI via SSE."""
    sess.rollback()  # undo any half-finished changes from the step that just failed, including its "in progress" marker, so nothing incomplete gets left behind
    sid = scenario_session["SessionID"]
    client_msg = _failure_client_message(exc)
    sess.execute(
        update(m.Subsystem_Stage_State)
        .where(m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level.in_(list(_WORK_LEVELS)),
            m.Subsystem_Stage_State.GenerationEpoch == epoch,  # never condemn a newer generation
            m.Subsystem_Stage_State.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]))
        .values(Status=StageStatus.ERROR, ErrorMessage=client_msg, LeaseExpiresAt=None, UpdatedAt=now())
    )
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"], EntityID=scenario_session["EntityID"],
                    SubsystemID=subsystem_id, EventType=AuditEventType.stage_error,
                    DetailJSON=json.dumps({"error": client_msg, "subsystem_id": subsystem_id}))
    sess.commit()  # commit before announcing — same discipline as every other publish in this file
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid, "subsystem_id": subsystem_id,
                    "message": client_msg, "ts": now().isoformat()})
    log.error("stage.error", session_id=sid, subsystem=subsystem_id, error=repr(exc))  # full detail: server-side only


def decide_session_outcome(sess: Session, scenario_session: dict) -> str | None:
    """Look at every subsystem stage's status and decide what should happen to the whole
    session next: still running (None), move to review, or mark the session cancelled/failed."""
    sid = scenario_session["SessionID"]
    statuses = [str(r["Status"]) for r in dal.stage_rows(sess, sid)]
    if not statuses or any(s in (StageStatus.IDLE, StageStatus.RUNNING) for s in statuses):
        return None  # nothing seeded yet, or work still in flight
    if any(s == StageStatus.AWAITING_DECISION for s in statuses):
        return "review" if _send_to_review(sess, scenario_session) else None
    if any(s == StageStatus.ERROR for s in statuses):
        return "cancelled" if _mark_session_failed(sess, scenario_session) else None
    log.warning("finalize.no_terminal_state", session_id=sid, statuses=statuses)
    return None


def _send_to_review(sess: Session, scenario_session: dict) -> bool:
    """Move the session into the REVIEW stage, but only if it's still active and not already
    there. Returns True if this call was the one that made the change."""
    sid = scenario_session["SessionID"]
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == sid,
            m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW)
        .values(CurrentStage=WorkflowStage.REVIEW, StageStatus=StageStatus.AWAITING_DECISION, UpdatedAt=now())
    )
    if res.rowcount != 1:
        return False  # someone else already moved this session into review a moment ago, or it's no longer active — either way, there's nothing more for this attempt to do
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], Stage=WorkflowStage.REVIEW, EventType=AuditEventType.entered_review)
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.session_entered_review), "session_id": sid,
                    "status": str(StageStatus.AWAITING_DECISION), "ts": now().isoformat()})
    log.info("pipeline.entered_review", session_id=sid)
    return True


def _mark_session_failed(sess: Session, scenario_session: dict) -> bool:
    """Cancel the session because every subsystem errored out, but only if it's still active
    and not already in review. Returns True if this call was the one that made the change."""
    sid = scenario_session["SessionID"]
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == sid,
            m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW)
        .values(SessionStatus=SessionStatus.cancelled, CurrentStage=WorkflowStage.CANCELLED,
                StageStatus=StageStatus.CANCELLED, UpdatedAt=now())
    )
    if res.rowcount != 1:
        return False
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"], EntityID=scenario_session["EntityID"],
                    EventType=AuditEventType.session_cancelled, DetailJSON=json.dumps({"reason": "all subsystems failed"}))
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid,
                    "message": "session failed: all subsystems errored", "ts": now().isoformat()})
    log.warning("pipeline.failed", session_id=sid)
    return True


def _announce_starting_supporting_system(sess: Session, scenario_session: dict, sub: dict, idx: int) -> None:
    """Write an audit entry and send an SSE event announcing that work is starting on this
    subsystem, but only if it actually has pending work to do."""
    if not dal.subsystem_has_pending_work(sess, scenario_session["SessionID"], sub["id"]):
        return
    sid = scenario_session["SessionID"]
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], SubsystemID=sub["id"],
                    EventType=AuditEventType.subsystem_advanced,
                    DetailJSON=json.dumps({"subsystem_index": idx, "subsystem_id": sub["id"]}))
    sess.commit()  # commit before announcing (also makes the caller's CurrentSubsystemIndex update durable)
    bus.publish(sid, {"type": str(SSEEventType.subsystem_started), "session_id": sid,
                    "subsystem_id": sub["id"], "subsystem_index": idx, "ts": now().isoformat()})


def _summarize_generation(sub_id: int, prov_i: Provenance | None, scen_provs: list[Provenance | None]) -> dict:
    """Build the DetailJSON payload for the generation_complete audit entry: a record of
    exactly which AI calls produced this subsystem's results. Pure dict-building — no I/O."""
    return {
        "subsystem_id": sub_id, "identify_provenance": _summarize_ai_call(prov_i),
        "scenario_provenances": [_summarize_ai_call(p) for p in scen_provs],
        "scenario_count": len(scen_provs),
    }


def _process_all_supporting_systems(sess: Session, session_id: str, llm: LLMClient, task_id: str) -> None:
    """Top-level driver for one session: for every subsystem, take its lock, run the THREATS
    and SCENARIOS stages, and record the outcome (success or failure), then decide what
    happens to the session as a whole once all subsystems have been attempted."""
    row = dal.load_session(sess, session_id)
    if row is None:
        return
    scenario_session = dict(row)
    if scenario_session["CurrentStage"] == WorkflowStage.REVIEW:
        # A task message redelivered long after the reaper already drove this session to
        # REVIEW (SessionStatus stays 'active' there — see enums.py — so acquire_lock's
        # session-active gate alone doesn't catch this; Redis's broker visibility_timeout
        # defaults to ~3600s, far longer than this app's own stage_lease_seconds=300, so a
        # worker killed mid-task can have its orphaned message resurface well after a human
        # has started (or finished) reviewing). Regeneration is the only thing allowed to
        # touch a REVIEW session — it goes through cascade.py, never through here.
        log.warning("pipeline.refused_review_session", session_id=session_id, task_id=task_id)
        return
    subsystems = json.loads(scenario_session["SubsystemsJSON"])
    asset_context = json.loads(scenario_session.get("AssetContextJSON") or "{}")  # parsed ONCE per session, not per-subsystem
    # Read ONCE per session, not per-subsystem — global config (Threat_Category/Threat_Actor,
    # Context_Field_Config) that can't change mid-run, same reasoning as asset_context above.
    categories = dal.active_category_names(sess)
    actor_examples = dal.active_actor_names(sess)
    active_fields = dal.active_context_fields_by_group(sess)  # one round-trip for both groups
    asset_active_fields = active_fields["asset"]
    sub_active_fields = active_fields["subsystem"]
    log.info("pipeline.start", session_id=session_id, subsystems=len(subsystems), task_id=task_id)
    for idx, sub in enumerate(subsystems):
        # Skip any subsystem another worker is already processing rather than waiting for it.
        if not dal.acquire_lock(sess, session_id, sub["id"], task_id):
            log.warning("subsystem.locked", session_id=session_id, subsystem=sub["id"])
            continue
        sess.commit()  # make the lock durable BEFORE any other work — same reason find_threats/
                        # write_scenarios commit right after their own claim_stage succeeds: an
                        # exception anywhere below routes through _record_failure's rollback,
                        # which would otherwise undo an uncommitted acquire_lock too, making the
                        # finally block's release_lock spuriously fail ("lock_lost" even though
                        # no other worker ever touched it).
        try:
            sess.execute(update(m.Scenario_Session)
                        .where(m.Scenario_Session.SessionID == session_id)
                        .values(CurrentSubsystemIndex=idx, UpdatedAt=now()))
            _announce_starting_supporting_system(sess, scenario_session, sub, idx)
            threats, prov_i = find_threats(sess, scenario_session, sub, asset_context, llm, task_id,
                                        categories=categories, actor_examples=actor_examples,
                                        asset_active_fields=asset_active_fields, sub_active_fields=sub_active_fields)
            sess.commit()
            if not threats:  # either this step was already done before (idempotent no-op), or there truly are no threats — either way, re-checking the database gives the right answer
                threats = dal.active_threats(sess, session_id, sub["id"])
            scen_provs = write_scenarios(sess, scenario_session, sub, asset_context, threats, llm, task_id,
                                        asset_active_fields=asset_active_fields, sub_active_fields=sub_active_fields,
                                        require_lock=True)
            # Save a record of exactly which AI calls produced this subsystem's results,
            # all together in one entry in the permanent history log.
            dal.append_audit(sess, AuditID=guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
                            EntityID=scenario_session["EntityID"], Stage=WorkflowStage.SCENARIO_GENERATION,
                            SubsystemID=sub["id"], EventType=AuditEventType.generation_complete,
                            DetailJSON=json.dumps(_summarize_generation(sub["id"], prov_i, scen_provs)))
            sess.commit()
        except LLMSlotUnavailable:
            # Temporary "system was busy" condition, not a bug — must NOT be recorded as a
            # permanent per-subsystem ERROR. Re-raise past _record_failure so it reaches
            # Celery's autoretry_for (celery_app.py), which retries the whole task shortly and
            # resumes via the same claim_stage crash-redelivery CAS/resume logic. This defers
            # any remaining subsystems in this round too — acceptable, they're untouched
            # (still IDLE), not corrupted.
            raise
        except Exception as exc:  # noqa: BLE001 — catch any problem here so it gets recorded properly, never let it silently disappear
            _record_failure(sess, scenario_session, sub["id"], exc)
            sess.commit()
        finally:
            if not dal.release_lock(sess, session_id, sub["id"], task_id):
                log.warning("subsystem.lock_lost", session_id=session_id, subsystem=sub["id"], task_id=task_id)
            sess.commit()

    decide_session_outcome(sess, scenario_session)