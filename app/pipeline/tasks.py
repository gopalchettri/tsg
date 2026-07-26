from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.orm import Session

from app.core.enums import (
    AuditEventType, ScenarioStatus, SessionStatus, SSEEventType, StageStatus, SubsystemLevel, WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import execute_dml, guid, now
from app.core.config import get_settings
from app.pipeline import control_mapping, grounding, prompts, scoping, validation
from app.pipeline.llm import LLMClient, LLMSlotUnavailable, Provenance, moderate
from app.sse import bus

log = get_logger(__name__)

_EPOCH = 1
_WORK_LEVELS = (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS)
_SCENARIO_TEXT_FIELDS = ("scenario_title", "scenario_statement", "business_impact",
                        "operational_impact", "risk_statement")

# Asset-centric pipeline: the ASSET is the unit of work, not each supporting system (supporting
# systems are context that explain the asset's attack surface). The session is already 1:1 with
# the asset (UX_Session_ActiveAsset enforces one active session per asset), so we key the single
# THREATS/SCENARIOS/_LOCK triple — and every Identified_Threat/Scoped_Threat/Threat_Scenario_Output
# row, and the identity-hash dedup fold — on this sentinel SubsystemID. Real supporting-system ids
# are DB PKs (>=1), so 0 can never collide with one.
# ponytail: sentinel over a schema migration — the SessionID already IS the asset key; revisit only
# if a session ever needs to span more than one asset (UX_Session_ActiveAsset says it can't).
ASSET_UNIT_ID = 0


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


def set_up_progress_tracking(sess: Session, session_id: str, tenant_id: str, entity_id: str) -> None:
    """Create the initial 'IDLE' progress rows for the asset unit — one THREATS row, one SCENARIOS
    row, and one _LOCK row, all keyed on ASSET_UNIT_ID. The pipeline threat-models the asset as a
    whole (supporting systems are context), so there is exactly one unit of work per session, not
    one per supporting system."""
    rows = [{
        "StateID": guid(), "SessionID": session_id, "TenantID": tenant_id, "EntityID": str(entity_id),
        "SubsystemID": ASSET_UNIT_ID, "Level": level, "Status": StageStatus.IDLE,
        "GenerationEpoch": _EPOCH, "UpdatedAt": now(),
    } for level in (*_WORK_LEVELS, SubsystemLevel.LOCK)]
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
    proposal. ThreatType is NOT NULL; ThreatName is nullable → treat None as "". This is the folding
    rule dal.identity_hash wraps — every IdentityHash producer/consumer routes through that one
    helper, so the app-level dedup and the DB unique index always block the SAME pair."""
    catalogue_id = info.get("catalogue_id")
    if catalogue_id is not None:
        return f"cat:{catalogue_id}"
    type_id = info.get("threat_type_id")
    if type_id is not None:
        return f"type:{type_id}"
    # Normalize each part independently, then join with a delimiter appended AFTER normalization
    # so it survives (_normalize strips `[^\w\s]`, so an in-text separator would be eaten and
    # 'Firmware'+'Tampering' would collide with 'Firmware Tampering'+None). When BOTH parts are
    # empty, fall back to a per-threat-unique token so distinct ungrounded proposals don't all
    # collapse onto a bare 'txt:' — threat_id is present in both the find_threats summary and
    # active_threats, so full-run and regen still agree deterministically.
    key_type = _normalize(info.get("threat_type") or "")
    key_name = _normalize(info.get("threat_name") or "")
    if not key_type and not key_name:
        return "txt:tid:" + str(info.get("threat_id"))
    return "txt:" + key_type + "|" + key_name


def find_threats(sess: Session, scenario_session: dict, subsystems: list[dict], asset_context: dict, llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, categories: list[str] | None = None,
                actor_examples: list[str] | None = None,
                asset_active_fields: list[str] | None = None,
                sub_active_fields: list[str] | None = None,
                supersede: bool = True, exclude: list[str] | None = None) -> tuple[list[dict], Provenance | None]:
    """Run the THREATS stage for the asset: ask the AI for candidate threats (supporting systems as context), match
    ("ground") each one against the threat library, save them to the database, and report
    the stage as complete. Returns an empty list if another worker already claimed this
    stage or the claim is lost partway through.

    `supersede=True` (default, the first-run behaviour) wipes the prior run's active threats
    before inserting this run's. `supersede=False` is the additive "generate next set" mode
    (cascade.run_next_set): earlier threats stay active and returned, and a fresh epoch keeps
    the new batch's stage claim distinct — the accumulation invariant depends on NOT superseding
    here. `exclude` is the coverage list threaded into the prompt (already-proposed threat
    names/types) so an additive round asks the model for threats it hasn't covered yet.

    `categories`/`actor_examples` are the live Threat_Category/Threat_Actor names — read live so
    the prompt's vocabulary never drifts from what grounding.py actually matches against (see
    prompts.threats_prompt()'s own fallback note). `asset_active_fields`/`sub_active_fields` are
    the curator-toggled Context_Field_Config field names (dal.active_context_fields), same
    once-per-session reasoning. _process_all_supporting_systems reads all four ONCE per session
    (same reasoning as its own asset_context) and passes them down here, since they're global
    config that can't change mid-run — don't re-query per subsystem. Left optional (None →
    queried here) only so a direct caller without a pre-fetched value still works."""
    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
        return [], None
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.THREATS, StageStatus.RUNNING, epoch)
    # Resolve both groups in ONE round-trip when a caller (e.g. cascade.run_next_set's additive
    # round) doesn't pass them — same reasoning/pattern write_scenarios already uses below: two
    # independent dal.active_context_fields() calls would be two avoidable SELECTs for the exact
    # same "both groups needed at once" case dal.active_context_fields_by_group() exists for.
    if asset_active_fields is None or sub_active_fields is None:
        resolved = dal.active_context_fields_by_group(sess)  # one round-trip for both groups
        if asset_active_fields is None:
            asset_active_fields = resolved["asset"]
        if sub_active_fields is None:
            sub_active_fields = resolved["subsystem"]
    proposals, prov = _ask_ai(sess, llm, prompts.threats_prompt(
                                scenario_session["AssetName"], asset_context, subsystems,
                                max_threats=get_settings().max_threats_per_asset,
                                categories=categories if categories is not None else dal.active_category_names(sess),
                                actor_examples=actor_examples if actor_examples is not None else dal.active_actor_names(sess),
                                asset_active_fields=asset_active_fields,
                                sub_active_fields=sub_active_fields,
                                exclude=exclude),
                                scenario_session=scenario_session, subsystem_id=ss, stage="threats",
                                level=SubsystemLevel.THREATS, epoch=epoch, task_id=task_id, expected_type=list,
                                # very likely (not guaranteed — see TSG_SDD.md §9.1b) to repeat the
                                # same proposed threats for identical asset/subsystem inputs
                                temperature=get_settings().threat_identification_temperature)
    if supersede:
        dal.supersede(sess, m.Identified_Threat, sid, ss)
    # Additive round (supersede=False): a coverage-aware prompt still occasionally re-proposes a
    # threat already present, which would leak a never-scored dead Identified_Threat row every call.
    # Skip any proposal whose folded catalogue-level identity already matches an active threat (or an
    # earlier proposal in THIS batch). Empty set on a full run → no dedup, unchanged behavior.
    existing_identities = dal.active_identified_threat_identities(sess, sid, ss) if not supersede else set()
    threats: list[dict] = []
    rows: list[dict] = []
    sector_ids = json.loads(scenario_session["SectorIDsJSON"]) if scenario_session.get("SectorIDsJSON") else []
    grounding_cache: dict = {}  # scoped to this call — same sector_ids for every proposal below
    # One batched embed for every proposal's type/name text, instead of one round trip per
    # proposal inside the loop below. All the texts are already known here.
    grounding.prime_query_embeddings(llm, proposals, grounding_cache)
    # For each threat the AI proposed: pull out its fields, try to match it to a known
    # threat-library entry, then build the row for a new Identified_Threat record.
    for p in proposals:
        # Same renewal _ask_ai does before its own LLM call: this loop can run one grounding
        # match (embedding/rerank) per proposed threat — up to max_threats_per_asset — with
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
        if not supersede:
            identity = dal.identity_hash(sid, ss, summary)
            if identity in existing_identities:
                continue  # additive round re-proposed an already-active threat — no dead row
            existing_identities.add(identity)
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
    # controls suggestions (prompt v1.3) are model-generated text shown to reviewers too —
    # same moderation surface as the narrative fields, same single call.
    text = " ".join([text] + [f"{c.get('name') or ''} {c.get('why') or ''}".strip()
                              for c in (scenario.get("controls") or []) if isinstance(c, dict)])
    r = moderate(text)
    return {"checked": r.checked, "flagged": r.flagged, "categories": r.categories, "error": r.error}


#: OT threat types get ICS advisories first; the importer names OT types with these prefixes
#: (scripts/import_threat_libraries.py) — "ICS ATT&CK – ...", "ICS Threat ...", "Embedded Device – ...".
_OT_TYPE_PREFIXES = ("ICS", "Embedded Device")


def _fetch_intel(threat_type: str | None, threat_name: str | None) -> list[dict] | None:
    """Current threat-intel items for one verified threat, or None. Fully fail-open and
    opt-in (TSG_INTEL_ENABLED): any error, disabled flag, or empty result returns None so
    scenario generation is byte-for-byte unchanged from the pre-intel behaviour.

    OT threats prefer live ICS advisories; everything else prefers exploited CVEs."""
    if not get_settings().intel_enabled:
        return None
    try:
        from app.intel.fetchers import query_intel

        is_ot = (threat_type or "").startswith(_OT_TYPE_PREFIXES)
        prefer = ("ics_advisory", "cve") if is_ot else ("cve",)
        # match on the threat wording; query_intel drops terms shorter than 4 chars itself
        terms = [w for w in re.split(r"[^A-Za-z0-9]+", f"{threat_type} {threat_name}") if w]
        return query_intel(terms, prefer_kinds=prefer) or None
    except Exception:  # noqa: BLE001 — enrichment is optional, never breaks generation
        log.warning("scenario.intel_fetch_failed", exc_info=True)
        return None


def _generate_one_scenario(sess: Session, scenario_session: dict, base_ctx: dict, asset_context: dict, sc,
                    enriched: dict, llm: LLMClient, task_id: str, epoch: int) -> tuple[dict, dict, Provenance | None]:
    """Ask the AI to write a scenario for a single scoped threat, then validate the result
    against the threat's expected type/name.

    `base_ctx` is the sanitized asset + supporting-systems prompt context, built ONCE per batch by
    write_scenarios (identical for every threat) and reused here — see prompts.build_base_context.
    `asset_context` is still passed raw (not the redacted base_ctx) because validate_scenario needs
    the un-redacted critical_service for its consistency check."""
    info = enriched.get(sc.threat_id, {})
    threat_type = info.get("library_threat_type") or info.get("threat_type")
    threat_name = info.get("library_threat_name") or info.get("threat_name")
    actors = info.get("actors") or []
    intel_items = _fetch_intel(threat_type, threat_name)
    scenario, prov = _ask_ai(sess, llm,
                            prompts.scenario_prompt(base_ctx, threat_type, threat_name, actors=actors,
                                                    intel_items=intel_items),
                            scenario_session=scenario_session, subsystem_id=ASSET_UNIT_ID, stage="scenario",
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
                            epoch: int, entity_id: str | None, user_id: str | None, info: dict) -> dict:
    """Build the Threat_Scenario_Output DB row for one generated scenario. Pure dict-building —
    no I/O."""
    # dal.identity_hash folds in the SAME catalogue-level identity (_dedup_key(info)) the selection
    # pass uses, so the filtered unique index UX_Scenario_ActiveIdentity(SessionID, IdentityHash)
    # WHERE Superseded=0 physically blocks a second active scenario for the same threat even under a
    # crash/retry. SubsystemID is inside the fold (the index has no subsystem column) or sibling
    # subsystems sharing a catalogue/type would cross-suppress.
    identity = dal.identity_hash(sid, ss, info)
    return {
        "OutputID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.complete,
        "ScenarioJSON": json.dumps(scenario),
        "ValidationJSON": json.dumps(report),  # a note recording whether this scenario passed its automatic sanity checks
        "Accepted": 0, "Superseded": 0,
        "IdentityHash": identity, "GenerationEpoch": epoch, "ErrorMessage": None, "CreatedAt": now(),
    }


def _build_error_output_row(scoped_id: str, sid: str, tenant: str, ss: int, client_msg: str,
                            epoch: int, entity_id: str | None, user_id: str | None, info: dict) -> dict:
    """FAILURE CARD for a full-run threat whose scenario generation failed: same linkage and
    IdentityHash as a real row — so /regenerate/scenarios can target it (THE retry path) and a
    later success supersedes it — but Status=error and a null scenario, which keeps it out of
    accept/salvage/resume (the ScenarioStatus.complete filters in dal.py) and renders through
    the API as the already-documented "scenario: null / generation failed" shape."""
    return {
        "OutputID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.error,
        "ScenarioJSON": None, "ValidationJSON": None,
        "Accepted": 0, "Superseded": 0,
        "IdentityHash": dal.identity_hash(sid, ss, info), "GenerationEpoch": epoch,
        "ErrorMessage": client_msg, "CreatedAt": now(),
    }


def _select_unique_top_n(scoped: list[scoping.Scored], enriched: dict, top_n: int | None) -> int:
    """Catalogue-dedupe the already-ranked, threshold-passed threats down to a unique top-N,
    in place (Stage E). Walks in the ranker's own order (Score desc, ThreatID asc). A threat
    keeps its scenario only if its dedup key is unseen AND fewer than top_n uniques are already
    kept — Decision C, "free the slot": the count is over UNIQUE threats, so the reviewer gets N
    DISTINCT scenarios, not N-minus-the-dupes. A later duplicate is demoted (Selected=0, reason)
    but its row is kept for audit/provenance; only the scenario is withheld. Threats already
    excluded in scoring (tech_gate / score threshold) are left as-is — they never consumed a slot.
    Full-run only: a targeted regen is never passed here (a regen target must not be blocked).

    Returns how many threats were demoted as duplicates (not the top-N cutoff) — surfaced in the
    scoping_complete audit / scenarios.deduped log so dedup activity is observable in aggregate."""
    seen: set[str] = set()
    kept = 0
    deduped = 0
    for sc in scoped:
        if not sc.selected:
            continue  # already excluded by tech_gate / score threshold in score_threats
        key = _dedup_key(enriched.get(sc.threat_id, {}))
        if key in seen:
            sc.selected, sc.reason = False, "duplicate of higher-ranked threat"
            deduped += 1
        elif top_n is not None and kept >= top_n:
            sc.selected, sc.reason = False, f"beyond top-{top_n} cutoff"
        else:
            seen.add(key)
            kept += 1
    return deduped


def _mark_next_set_targets_rescored_out(sess: Session, sid: str, ss: int, pairs: list, excluded_ids: set[str],
                                    tenant: str, entity_id: str | None, user_id: str | None) -> None:
    """Persist a fresh Selected=0 scoped marker for every NEXT-SET target that rescored out with NO
    active scenario, so next_unserved_unique_threats' Selected=1/NULL/top-N filter stops re-serving it.
    Two kinds land here: a fresh threat (no prior scoped row), OR a POOL ZOMBIE (a previously-served
    pool threat whose old Selected=1/'beyond top-%' scoped row rescored out after a mid-session
    tech_gate/threshold tightening).

    Gate on "no active SCENARIO", NOT "no prior active scoped row": a genuine REGEN target keeps its
    active scenario so it stays OUT of this set (regen invariant); a pool zombie has none, so keying on
    the scoped row alone would wrongly spare it and it got re-served on every click. A zombie still
    carries its stale active Scoped_Threat row, so supersede it FIRST, then insert the fresh Selected=0
    marker (its Reason is the current PERMANENT tech_gate/threshold, not 'beyond top-%') — both are
    required: superseding alone leaves no active scoped row and next_unserved re-serves it via its
    `ScopedThreatID IS NULL` branch. A fresh target is unaffected by the supersede and just gets its
    marker; regen targets never reach here (they keep an active scenario)."""
    excluded_needing_marker = (excluded_ids - dal.threats_with_active_scenario(sess, sid, ss, excluded_ids)
                            if excluded_ids else set())
    if not excluded_needing_marker:
        return
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, excluded_needing_marker)
    sess.execute(insert(m.Scoped_Threat), [
        _build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)
        for sc, scoped_id in pairs if sc.threat_id in excluded_needing_marker])


def _begin_full_run_attempt(sess: Session, sid: str, ss: int, tenant: str,
                            entity_id: str | None, user_id: str | None,
                            pairs: list, epoch: int) -> set[str]:
    """A full run persists INCREMENTALLY — each threat's rows are committed the moment its
    scenario is generated, so a mid-batch failure (an LLMSlotUnavailable capacity squeeze that
    Celery retries at the SAME epoch/task_id, or any other exception) never throws away
    scenarios that already succeeded. This helper does the once-per-epoch setup and returns the
    resume-skip set: threat_ids that already own an active scenario from a prior attempt of
    THIS epoch and must not be re-generated.

    The setup must run EXACTLY once per epoch: dal.supersede has no epoch memory, so re-running
    it on a resumed claim would flip this epoch's own just-committed rows back to Superseded=1
    and regenerate them anyway — AttemptCount==1 is the "first successful claim of this epoch"
    signal (dal.stage_attempt_count).

    Full runs only ever execute at the initial epoch (run_pipeline_task hardcodes it; regen/
    next-set always take the targeted branch) — the skipped-supersede-on-resume logic is only
    safe because there is never a PRIOR generation to clear at that first epoch, so the guard
    below turns that load-bearing assumption from accidental into enforced.

    # ponytail: a crash AFTER claim-commit but BEFORE this setup's commit loses the not-selected
    # Scoped_Threat rows for this run (the resume skips the attempt==1 block). Accepted ceiling:
    # the only load-bearing effect is a permanently-gated threat being re-served ONCE by "generate
    # next set", which re-scores and re-marks it Selected=0 — self-healing; the rest is write-only
    # scoring-audit metadata. Make this block idempotent instead if that one wasted slot ever matters.
    """
    if epoch != _EPOCH:
        raise ValueError(
            f"full-run write_scenarios is only valid at the initial epoch {_EPOCH}, got {epoch} — "
            "a regen/next-set hop must pass target_threat_ids and take the targeted branch")
    attempt = dal.stage_attempt_count(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch)
    if attempt == 1:
        dal.supersede(sess, m.Scoped_Threat, sid, ss)
        dal.supersede(sess, m.Threat_Scenario_Output, sid, ss)
        # Not-selected threats' scoring metadata involves no LLM call — persist it up front,
        # once, so a resume never re-inserts it.
        not_selected = [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)
                        for sc, scoped_id in pairs if not sc.selected]
        if not_selected:
            sess.execute(insert(m.Scoped_Threat), not_selected)
        sess.commit()
        # Fresh attempt: the supersede above just cleared every active output for (sid, ss), so
        # the resume-skip set is empty by construction — skip the guaranteed-empty SELECT.
        return set()
    # Resume: a threat already owning an active scenario got it from a prior attempt of THIS
    # epoch (the attempt==1 supersede cleared every older generation first, and the
    # _LOCK/claim_stage CAS means no other epoch can be concurrently active).
    return dal.threats_with_active_scenario(
        sess, sid, ss, {sc.threat_id for sc, _ in pairs if sc.selected})


def _reconcile_targeted_regen(sess: Session, sid: str, ss: int, tenant: str,
                            entity_id: str | None, user_id: str | None,
                            pairs: list, scenarios: dict, enriched: dict,
                            target_threat_ids: set[str], epoch: int, task_id: str) -> bool:
    """The persistence/reconciliation tail of a TARGETED regen/next-set `write_scenarios` call
    (a full run persists incrementally inside write_scenarios' own loop and never comes here):
    compute which targets actually got a fresh scenario, persist rescored-out markers, raise
    `RegenerateConflict` when every target rescored out, supersede exactly the right prior
    rows, and bulk-insert the new ones. Returns False only on the claim-lost path (caller
    returns []); raises `RegenerateConflict` through.

    [REVIEW-FIX] A targeted regen must never supersede a threat's prior active rows unless a
    fresh scenario actually replaced them — rescoring can legitimately re-exclude a specific
    target (a curator's Config_Threat_Rule weight or the scoping_score_threshold/scoping_top_n
    cutoff changed since the scenario was first written); destroying the old row with nothing
    to show for it, then reporting a misleading "claim lost" failure, was strictly worse than
    the pre-existing "just ranked low" behavior these cutoffs were meant to fix."""
    generated_ids = {sc.threat_id for sc, scoped_id in pairs if scoped_id in scenarios}
    excluded_ids = target_threat_ids - generated_ids
    if excluded_ids:
        log.warning("regen.target_no_longer_selected", session_id=sid, subsystem=ss,
                    threat_ids=sorted(excluded_ids))

    # Persist the Selected=0 markers for next-set targets that rescored out — BEFORE the all-excluded
    # RegenerateConflict early-return below, so both that path and the partial-excluded path record
    # them exactly once (they never collide with the supersede/regen handling further down).
    _mark_next_set_targets_rescored_out(sess, sid, ss, pairs, excluded_ids, tenant, entity_id, user_id)

    if not generated_ids:
        # Every requested target was excluded by rescoring — nothing to regenerate, and nothing
        # was mutated above. Return the stage to its normal reviewable state (same transition as
        # the success path below) and report this exactly like get_threat_id_to_redo's own
        # pre-lock/post-lock re-check does: a benign conflict (cascade.py's `except
        # RegenerateConflict`), never a pipeline failure.
        if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch, task_id):
            sess.rollback()
            log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
            return False
        sess.commit()
        raise dal.RegenerateConflict(
            f"threat(s) no longer meet the scoping cutoff and cannot be regenerated: {sorted(excluded_ids)}")

    # Mark prior rows as superseded before inserting the new ones — only the threats that
    # actually got a fresh scenario this pass.
    old_scoped_ids = dal.active_scoped_threat_ids(sess, sid, ss, generated_ids)
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, generated_ids)
    dal.supersede_by_scoped_threats(sess, sid, ss, old_scoped_ids)
    scoped_rows = []
    output_rows = []
    for sc, scoped_id in pairs:
        if sc.threat_id in excluded_ids:
            continue  # excluded by rescoring — its prior active rows were left untouched above
                      # (a fresh no-prior-scoped target already got its Selected=0 marker above)
        scoped_rows.append(_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id))
        if scoped_id not in scenarios:
            continue
        scenario, report = scenarios[scoped_id]
        output_rows.append(_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                                    entity_id, user_id, enriched.get(sc.threat_id, {})))
    if scoped_rows:
        sess.execute(insert(m.Scoped_Threat), scoped_rows)
    if output_rows:
        # Regen skips _select_unique_top_n, so two targets that fold to the SAME dedup_key build the
        # SAME IdentityHash. Two ways that collides on UX_Scenario_ActiveIdentity: both in ONE bulk
        # insert (a legacy pre-dedup session can hold two active same-catalogue outputs), or a later
        # regen whose folded hash matches a prior regen's now-active folded row. Collapse to the
        # first (highest-ranked — output_rows follow ranked order) and supersede any already-active
        # row sharing one of these hashes, so exactly one active scenario per key survives.
        seen_hashes: set[str] = set()
        deduped_output_rows = []
        for r in output_rows:
            if r["IdentityHash"] in seen_hashes:
                continue
            seen_hashes.add(r["IdentityHash"])
            deduped_output_rows.append(r)
        output_rows = deduped_output_rows
        dal.supersede_by_identity_hashes(sess, sid, ss, seen_hashes)
    if output_rows:
        sess.execute(insert(m.Threat_Scenario_Output), output_rows)
    return True


def write_scenarios(sess: Session, scenario_session: dict, subsystems: list[dict], asset_context: dict, threats: list[dict],
                llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, target_threat_ids: set[str] | None = None,
                asset_active_fields: list[str] | None = None,
                sub_active_fields: list[str] | None = None,
                *, require_lock: bool = False,
                on_before_commit: Callable[[list[Provenance | None]], None] | None = None) -> list[Provenance | None]:
    """Run the SCENARIOS stage for the asset: score/rank the given threats, generate a
    scenario for each selected one, and save everything to the database. If
    `target_threat_ids` is given, only those threats are (re)scored and (re)generated instead
    of the whole set — used when regenerating just a subset. Returns an empty list if another
    worker already claimed this stage or the claim is lost partway through.

    `on_before_commit` runs INSIDE this function's final transaction, immediately before the
    commit that makes the batch durable — the hook for a caller that must record something
    atomically with the work itself (cascade.py's regeneration_completed / next-set
    generation_complete audit rows). Writing that audit AFTER write_scenarios returned meant two
    separate transactions: if the second one failed, the work was already committed but the
    caller's generic handler still routed it through _record_failure, stamping a stage_error
    audit row and an error SSE onto a regeneration that had actually succeeded. Sharing one
    transaction removes the window entirely — both land or neither does — and a hook that raises
    now correctly rolls the work back, so the failure the caller then reports is TRUE.

    `require_lock=True` (passed by every real production caller — tasks.py's own driver and both
    of cascade.py's regen/next-set paths, never by a direct unit test) additionally refuses to even attempt the claim
    unless the caller still holds this subsystem's `_LOCK`. Without it: a worker whose prior
    stage stalled past its lease has its THREATS row ERROR'd and its `_LOCK` reclaimed+released
    by the reaper — which also ERROR-marks this SCENARIOS row (still IDLE, never touched) as
    part of finalizing the now-abandoned session (reaper.py's `_close_out_one_abandoned_
    session`). `claim_stage`'s plain IDLE/ERROR branch doesn't know the caller lost the mutex,
    so the same zombie task_id can claim THIS row moments later and silently finish a stage on
    a session the reaper already closed out. `claim_stage` itself intentionally has no `_LOCK`
    check (many tests exercise it standalone) — this is the one call site that actually needs
    the mutex re-verified before resuming multi-step work under a possibly-stale identity."""
    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
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

    # Build the sanitized asset + supporting-systems prompt context ONCE for the whole batch — it's
    # identical for every scenario (only the per-threat fields vary), so re-running the
    # allowlist+redact pass per selected threat below would be pure redundant work.
    base_ctx = prompts.build_base_context(scenario_session["AssetName"], asset_context, subsystems,
                                        asset_active_fields, sub_active_fields)

    # Only distinct, known threat-type ids are needed to look up the scoring rules that apply.
    type_ids = sorted({t["threat_type_id"] for t in threats if t.get("threat_type_id") is not None})
    settings = get_settings()
    # scoping_top_n is the SCENARIO count, enforced over UNIQUE threats by _select_unique_top_n
    # below (Decision C, full run only), so score_threats ALWAYS gets top_n=None and stays the pure
    # deterministic ranker (base + grounding + rules, threshold filtering only — no dedup, no LLM).
    # A targeted regen must rank on the SAME duplicate-inclusive order a full run used: a unique
    # winner a full run kept via free-the-slot can sit beyond raw rank scoping_top_n, and a raw
    # top-N cutoff on regen would wrongly re-exclude it ('beyond top-N') → RegenerateConflict →
    # the Regenerate control silently no-ops. score_threshold/tech_gate still reject a target that
    # genuinely dropped out, and a regen target is always a former unique winner (demoted duplicates
    # never got an active output, so get_threat_id_to_redo can't select them). The clamp is belt-and-
    # suspenders to config.py's startup validator, in case top_n is monkeypatched past the candidate
    # ceiling at runtime — it feeds only the full-run _select_unique_top_n call, never score_threats.
    top_n = settings.scoping_top_n
    if top_n is not None:
        top_n = min(top_n, settings.max_threats_per_asset)
    scoped_all = scoping.score_threats(threats, subsystems=subsystems, rules=dal.active_threat_rules(sess, type_ids),
                                    score_threshold=settings.scoping_score_threshold,
                                    top_n=None)
    enriched = {t["threat_id"]: t for t in threats}
    # Dedup to a unique top-N BEFORE any scenario text is generated — full runs only. A targeted
    # regen must never be blocked or demoted by dedup (the reviewer explicitly asked to redo an
    # existing, already-unique scenario), so it is left out of this pass.
    deduped = _select_unique_top_n(scoped_all, enriched, top_n) if target_threat_ids is None else 0
    # Full run: score/keep every threat. Targeted regen: only the caller-specified subset.
    scoped = scoped_all if target_threat_ids is None else [sc for sc in scoped_all if sc.threat_id in target_threat_ids]

    pairs = [(sc, guid()) for sc in scoped]  # assign each scoped threat its DB id up front, before generating scenarios

    provs: list[Provenance | None] = []
    scenarios: dict[str, tuple[dict, dict]] = {}  # scoped_id -> (scenario, validation report) — regen branch only
    already_done: set[str] = set()
    if target_threat_ids is None:
        already_done = _begin_full_run_attempt(sess, sid, ss, tenant, entity_id, user_id, pairs, epoch)
    # Only threats that scoring marked as "selected" get an actual AI-written scenario; the rest
    # were recorded above (full run) or land via _reconcile_targeted_regen below (targeted regen).
    failures: list[str] = []       # client-safe reasons, for the stage's ErrorMessage
    first_failure: Exception | None = None
    for sc, scoped_id in pairs:
        if not sc.selected or sc.threat_id in already_done:
            continue
        try:
            scenario, report, prov = _generate_one_scenario(sess, scenario_session, base_ctx, asset_context, sc, enriched, llm, task_id, epoch)
        except LLMSlotUnavailable:
            # NOT per-item: a capacity squeeze is transient and applies to the whole hop. Celery's
            # autoretry_for re-runs it shortly; swallowing it here would freeze a temporary
            # shortage into a permanently short batch.
            raise
        except Exception as exc:  # noqa: BLE001 — one threat's failure must not discard its siblings
            # A targeted regen/next-set buffers every scenario until the end (see `scenarios`
            # below), so letting one parse failure propagate threw away every sibling that had
            # already been generated and paid for. Record it, keep going; the survivors are
            # persisted and the stage carries the partial-failure message.
            sess.rollback()  # _ask_ai commits mid-flight; never continue the loop on a dirty session
            first_failure = first_failure or exc
            client_msg = _failure_client_message(exc)
            failures.append(f"{enriched.get(sc.threat_id, {}).get('threat_name') or sc.threat_id}: {client_msg}")
            log.warning("scenario.generation_failed", session_id=sid, subsystem=ss,
                        threat_id=sc.threat_id, error=repr(exc))
            if target_threat_ids is None:
                # Retryability: with no row at all, the failure was invisible to
                # /regenerate/scenarios (which targets OutputIDs) — the only recovery was
                # regenerating threats that already worked. Persist a FAILURE CARD instead:
                # Status=error, null scenario (the shape ScenarioResult.scenario already
                # documents), the client-safe reason, and a real IdentityHash so a later
                # successful regen supersedes it. Status=error keeps it invisible to
                # accept/salvage/resume (see the ScenarioStatus.complete filters in dal.py);
                # get_threat_id_to_redo deliberately does NOT filter it — that IS the retry path.
                # Targeted regen/next-set failures insert nothing: the threat's previous scenario
                # is still active under the same IdentityHash (inserting would collide with
                # UX_Scenario_ActiveIdentity) and is already individually retryable.
                info = enriched.get(sc.threat_id, {})
                # supersede any error card a PRIOR failed attempt left active for this identity —
                # without this, the resumed attempt's fresh card violates UX_Scenario_ActiveIdentity
                dal.supersede_by_identity_hashes(sess, sid, ss, {dal.identity_hash(sid, ss, info)})
                # ...and the prior attempt's Scoped_Threat row for this SAME threat. Superseding
                # only the output left the earlier card's scoped row active, so a resumed attempt
                # accumulated a second active scoped row per retry — duplicating this threat in
                # every "active scoped" read (next-set pool, dedup markers) with no index to stop it.
                dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, {sc.threat_id})
                sess.execute(insert(m.Scoped_Threat),
                            [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
                sess.execute(insert(m.Threat_Scenario_Output),
                            [_build_error_output_row(scoped_id, sid, tenant, ss, client_msg, epoch,
                                                    entity_id, user_id, info)])
                sess.commit()
            continue
        provs.append(prov)
        if target_threat_ids is None:
            # Commit THIS threat's rows before the next threat's LLM call is even attempted —
            # explicitly, not via _ask_ai's own pre-call commit as an incidental side effect
            # (that coupling could silently regress if _ask_ai's commit timing ever changed).
            # First supersede any FAILURE CARD a prior attempt left active for this identity
            # (Status=error rows are excluded from `already_done`, precisely so the retry lands
            # here) — inserting the fresh row over a live card would violate
            # UX_Scenario_ActiveIdentity. No-op when no card exists.
            dal.supersede_by_identity_hashes(
                sess, sid, ss, {dal.identity_hash(sid, ss, enriched.get(sc.threat_id, {}))})
            sess.execute(insert(m.Scoped_Threat),
                        [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
            sess.execute(insert(m.Threat_Scenario_Output),
                        [_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                                    entity_id, user_id, enriched.get(sc.threat_id, {}))])
            sess.commit()
        else:
            scenarios[scoped_id] = (scenario, report)

    if failures and not provs and not already_done and first_failure is not None:
        # EVERY selected threat failed AND nothing survives from an earlier attempt — only then is
        # there nothing to review, so this is a real stage failure. Re-raise the first cause so the
        # caller records THAT message, instead of falling through to _reconcile_targeted_regen's
        # "no longer meet the scoping cutoff" conflict, which would describe a rescoring outcome
        # that never happened.
        #
        # `not already_done` is load-bearing: `provs` holds only THIS attempt's generations (see the
        # ponytail note below), and a resumed attempt deliberately skips threats that already own an
        # active scenario. Without it, a retry whose REMAINING threats all fail would raise despite
        # committed, reviewable output — flipping the stage to ERROR and firing an error SSE for a
        # run that produced scenarios, purely because the failures landed in attempt 2 instead of
        # attempt 1. `already_done` is always empty on the targeted-regen path.
        raise first_failure

    # ponytail: after a resumed attempt, provs holds only THIS attempt's generations, so the
    # audit counts below can under-report the true active total — re-query the DB if that ever matters.
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=scenario_session["EntityID"],
                    Stage=WorkflowStage.SCENARIO_GENERATION, SubsystemID=ss,
                    EventType=AuditEventType.scoping_complete,
                    DetailJSON=json.dumps({"scoped": len(scoped), "selected": len(provs), "deduped": deduped}))
    log.info("scenarios.deduped", session_id=sid, subsystem=ss, deduped=deduped, kept=len(provs))

    if target_threat_ids is not None and not _reconcile_targeted_regen(
            sess, sid, ss, tenant, entity_id, user_id,
            pairs, scenarios, enriched, target_threat_ids, epoch, task_id):
        return []
    # A partial batch still goes to REVIEW (the survivors are worth reviewing) but carries the
    # reason on the stage row. That is exactly what SupportingSystemBoard.error_message is
    # documented for: "Non-null on an awaiting_review board entry means the run failed mid-batch
    # after generating some scenarios — the review set may be PARTIAL, not a complete run."
    partial_error = (f"{len(failures)} of {len(failures) + len(provs)} scenario(s) failed to "
                    f"generate: {'; '.join(failures)}") if failures else None
    # Step 4: map controls for every active output not yet attempted (this run's AND any
    # earlier attempt's). Before finish_stage so the map rows commit atomically with the batch.
    control_mapping.map_controls(sess, scenario_session, asset_context, subsystems, llm,
                                 ASSET_UNIT_ID, task_id, epoch)
    if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION,
                            epoch, task_id, error=partial_error):
        sess.rollback()
        log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
        return []
    # Last thing before the commit, so whatever the caller stages here is part of the SAME
    # transaction as the scenarios above (see on_before_commit in the docstring). Deliberately
    # unguarded: if it raises, the commit never happens and the whole batch rolls back — that is
    # the atomicity this hook exists to provide, not a bug to swallow.
    if on_before_commit is not None:
        on_before_commit(provs)  # provs: what this call actually generated, for the caller's record
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
    # Salvage BEFORE the AWAITING_DECISION branch (not inside a later ERROR branch): in a
    # multi-subsystem session a healthy sibling at AWAITING_DECISION would otherwise short-circuit
    # straight to review while an errored subsystem that STILL owns active, accumulated scenarios
    # stays ERROR — excluded from accept's good_subs (SCENARIOS @ AWAITING_DECISION) and silently
    # dropped (data loss). revive only flips ERROR SCENARIOS rows that still own an active
    # Threat_Scenario_Output, so it is an idempotent no-op when there is nothing to salvage — and
    # leaves an errored subsystem that never committed a scenario untouched, so the pure-ERROR path
    # below still cancels + releases the lock. Re-read the board so the revived rows are seen here.
    if dal.has_active_scenarios(sess, sid):
        dal.revive_errored_scenarios_to_review(sess, sid)
        statuses = [str(r["Status"]) for r in dal.stage_rows(sess, sid)]
    if any(s == StageStatus.AWAITING_DECISION for s in statuses):
        return "review" if _send_to_review(sess, scenario_session) else None
    if any(s == StageStatus.ERROR for s in statuses):
        # Every stage terminal, none reviewable, >=1 ERROR, and the salvage above found nothing
        # active to revive → a genuine total failure (e.g. a first run that errored before
        # committing any scenario). Cancel and release the lock.
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


def _announce_generation_started(sess: Session, scenario_session: dict, subsystem_id: int) -> None:
    """Write an audit entry and send an SSE event announcing that generation is starting for the
    asset unit, but only if it actually has pending work to do."""
    if not dal.subsystem_has_pending_work(sess, scenario_session["SessionID"], subsystem_id):
        return
    sid = scenario_session["SessionID"]
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                    EventType=AuditEventType.subsystem_advanced,
                    DetailJSON=json.dumps({"subsystem_id": subsystem_id}))
    sess.commit()  # commit before announcing
    bus.publish(sid, {"type": str(SSEEventType.subsystem_started), "session_id": sid,
                    "subsystem_id": subsystem_id, "ts": now().isoformat()})


def _summarize_generation(sub_id: int, prov_i: Provenance | None, scen_provs: list[Provenance | None]) -> dict:
    """Build the DetailJSON payload for the generation_complete audit entry: a record of
    exactly which AI calls produced this subsystem's results. Pure dict-building — no I/O."""
    return {
        "subsystem_id": sub_id, "identify_provenance": _summarize_ai_call(prov_i),
        "scenario_provenances": [_summarize_ai_call(p) for p in scen_provs],
        "scenario_count": len(scen_provs),
    }


def _process_all_supporting_systems(sess: Session, session_id: str, llm: LLMClient, task_id: str) -> None:
    """Top-level driver for one session: take the asset unit's lock, run the THREATS and
    SCENARIOS stages once for the whole asset (supporting systems are read-only context, not
    separately processed), record the outcome (success or failure), then decide what happens
    to the session as a whole."""
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
    log.info("pipeline.start", session_id=session_id, subsystems=len(subsystems), task_id=task_id)
    # Asset-centric: the asset is the SINGLE unit of work (supporting systems are context), so there
    # is no per-subsystem loop — one lock, one THREATS pass, one SCENARIOS pass, all keyed on
    # ASSET_UNIT_ID. Another worker already holding the lock means this session is in flight
    # elsewhere; fall straight through to decide_session_outcome.
    if dal.acquire_lock(sess, session_id, ASSET_UNIT_ID, task_id):
        sess.commit()  # make the lock durable BEFORE any other work — an exception below routes
                        # through _record_failure's rollback, which would otherwise undo an
                        # uncommitted acquire_lock and make the finally's release spuriously fail.
        try:
            # Read ONCE per session, not per-subsystem — global config (Threat_Category/Threat_Actor,
            # Context_Field_Config) that can't change mid-run, same reasoning as asset_context above.
            # Deferred until after the lock is won: a call that loses the acquire_lock race (or hits
            # an already-terminal session) below must not pay these 3 avoidable SELECTs for results
            # it would just discard.
            categories = dal.active_category_names(sess)
            actor_examples = dal.active_actor_names(sess)
            active_fields = dal.active_context_fields_by_group(sess)  # one round-trip for both groups
            asset_active_fields = active_fields["asset"]
            sub_active_fields = active_fields["subsystem"]
            _announce_generation_started(sess, scenario_session, ASSET_UNIT_ID)
            threats, prov_i = find_threats(sess, scenario_session, subsystems, asset_context, llm, task_id,
                                        categories=categories, actor_examples=actor_examples,
                                        asset_active_fields=asset_active_fields, sub_active_fields=sub_active_fields)
            sess.commit()
            threats_stage_done = True
            if not threats:  # already done before (idempotent no-op), or truly none — re-read the DB to be sure
                threats = dal.active_threats(sess, session_id, ASSET_UNIT_ID)
                # Still empty is ambiguous: THREATS may have genuinely completed with zero AI-proposed
                # threats, OR find_threats lost its claim to a poison-terminal row (AttemptCount
                # exhausted after repeated LLMSlotUnavailable retries hit the same still-RUNNING row)
                # that never actually finished. Only the former may let SCENARIOS proceed — otherwise
                # SCENARIOS would be marked AWAITING_DECISION with zero scenarios and the session would
                # falsely reach REVIEW instead of being left for the reaper to correctly carry the
                # still-stuck THREATS row to ERROR (and the session on to cancelled).
                threats_stage_done = bool(threats) or dal.stage_completed_at_epoch_or_newer(
                    sess, session_id, ASSET_UNIT_ID, SubsystemLevel.THREATS, _EPOCH)
            if threats_stage_done:
                scen_provs = write_scenarios(sess, scenario_session, subsystems, asset_context, threats, llm, task_id,
                                            asset_active_fields=asset_active_fields, sub_active_fields=sub_active_fields,
                                            require_lock=True)
                # Save a record of exactly which AI calls produced the asset's results, all together
                # in one entry in the permanent history log.
                dal.append_audit(sess, AuditID=guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], Stage=WorkflowStage.SCENARIO_GENERATION,
                                SubsystemID=ASSET_UNIT_ID, EventType=AuditEventType.generation_complete,
                                DetailJSON=json.dumps(_summarize_generation(ASSET_UNIT_ID, prov_i, scen_provs)))
                sess.commit()
            else:
                log.warning("pipeline.threats_not_complete_skipping_scenarios", session_id=session_id, task_id=task_id)
        except LLMSlotUnavailable:
            # Temporary "system was busy" condition, not a bug — must NOT be recorded as a permanent
            # ERROR. Re-raise past _record_failure so it reaches Celery's autoretry_for
            # (celery_app.py), which retries the whole task shortly and resumes via the same
            # claim_stage crash-redelivery CAS/resume logic.
            raise
        except Exception as exc:  # noqa: BLE001 — catch any problem so it gets recorded properly, never let it silently disappear
            _record_failure(sess, scenario_session, ASSET_UNIT_ID, exc)
            sess.commit()
        finally:
            if not dal.release_lock(sess, session_id, ASSET_UNIT_ID, task_id):
                log.warning("asset.lock_lost", session_id=session_id, task_id=task_id)
            sess.commit()
    else:
        # Lock held by another worker (genuine contention), OR the session is no longer
        # SessionStatus.active (already cancelled/completed) — dal.acquire_lock's CAS covers both;
        # the status is included so an operator can tell the two apart in logs instead of both
        # printing an identical "asset.locked" line.
        log.warning("asset.locked", session_id=session_id, session_status=scenario_session["SessionStatus"])

    decide_session_outcome(sess, scenario_session)