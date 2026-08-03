from __future__ import annotations

import difflib
import json
import re
from collections.abc import Callable
from typing import Any, NamedTuple

from sqlalchemy import insert, update
from sqlalchemy.orm import Session

from app.core.enums import (
    AuditEventType, ScenarioStatus, ScopingRejection, SessionStatus, SSEEventType, StageStatus,
    SubsystemLevel, WorkflowStage,
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
_SCENARIO_TEXT_FIELDS = ("scenario_title", "scenario_statement", "risk_statement")

# The ASSET is the unit of work, not each supporting system. Sentinel SubsystemID for the single
# THREATS/SCENARIOS/_LOCK triple and every row keyed on it; real supporting-system ids are DB PKs
# (>=1), so 0 can never collide with one.
# ponytail: sentinel over a schema migration — the SessionID already IS the asset key; revisit only
# if a session ever needs to span more than one asset (UX_Session_ActiveAsset says it can't).
ASSET_UNIT_ID = 0

# difflib ratio at/above which a scenario is flagged "very similar" to a sibling of the SAME
# threat. Advisory only — the scenario is kept, the warning rides the validation report.
# ponytail: difflib is a cheap textual proxy for "meaningfully different", not semantic
# understanding — a false flag costs one ignorable warning; revisit only if it proves noisy.
_SIBLING_SIMILARITY_RATIO = 0.85


class RegenTarget(NamedTuple):
    """ONE regeneration work item — the exact scenario ROW being replaced, never a bare ThreatID.
    With multiple coexisting scenarios per threat (ScenarioNumber), "regenerate this threat" is
    ambiguous by construction: two active rows share the ThreatID."""
    output_id: str
    threat_id: str
    scoped_threat_id: str
    scenario_number: int
    identity_hash: str | None


def _flag_sibling_similarity(report: dict, scenario: dict, sibling_texts: list[tuple[int, str]]) -> None:
    """Warn (into the normal validation report) when the new scenario_statement is very similar to
    an ACTIVE sibling of the same threat. Advisory: the scenario is ALWAYS kept."""
    statement = str(scenario.get("scenario_statement") or "")
    if not statement.strip():
        return
    for number, sibling_statement in sibling_texts:
        if not sibling_statement.strip():
            continue
        if difflib.SequenceMatcher(None, statement, sibling_statement).ratio() >= _SIBLING_SIMILARITY_RATIO:
            report["errors"] = list(report.get("errors") or [])
            report["errors"].append(
                f"scenario is very similar to this threat's other scenario (scenario #{number})")
            report["validation_status"] = "warning"
            return


def _ask_ai(sess: Session, llm: LLMClient, messages: list[dict], *, scenario_session: dict,
            subsystem_id: int, stage: str, level: SubsystemLevel, epoch: int, task_id: str,
            expected_type: type, temperature: float | None = None) -> tuple[Any, Provenance | None]:
    """Send a prompt to the LLM, log the raw request/response to Prompt_Log, and parse the
    reply into the expected type. A failed parse is still logged before the error is re-raised.

    Renews BOTH the stage lease and the subsystem `_LOCK` lease first: claim_stage/acquire_lock
    stamp them once, but a stage makes one of these calls per selected threat, so a still-alive
    worker deep in that loop would otherwise expire its own lease and be reaped. Best-effort —
    an already-lost lease is still caught by the caller's finish_stage fencing. Renewing at this
    one choke point means no caller can reintroduce the gap."""
    sid = scenario_session["SessionID"]
    if not dal.renew_lease(sess, sid, subsystem_id, level, epoch, task_id):
        log.warning("stage.lease_renewal_failed", session_id=sid,
                    subsystem=subsystem_id, level=str(level))
    if not dal.renew_lock_lease(sess, sid, subsystem_id, task_id):
        # Normal on the full-run path, which holds no _LOCK; release_lock's fencing still
        # catches an actual theft on the locked paths.
        log.debug("lock.lease_renewal_skipped", session_id=sid, subsystem=subsystem_id)
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
    """Create the initial 'IDLE' progress rows for the asset unit — one THREATS, one SCENARIOS and
    one _LOCK row, all keyed on ASSET_UNIT_ID (exactly one unit of work per session)."""
    rows = [{
        "StateID": guid(), "SessionID": session_id, "TenantID": tenant_id, "EntityID": str(entity_id),
        "SubsystemID": ASSET_UNIT_ID, "Level": level, "Status": StageStatus.IDLE,
        "GenerationEpoch": _EPOCH, "UpdatedAt": now(), "CreatedAt": now(),
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
        "threat_type_id": gr.type_id,
        "catalogue_id": gr.catalogue_id,  # finer-grained than type_id — the dedup key (_dedup_key)
        "actors": gr.actors,
    }
    return row, summary


def _normalize(s: str) -> str:
    """Collapse an ungrounded proposal's free text to a stable dedup token: drop punctuation,
    squeeze whitespace, casefold — so "OTA-poisoning" and "ota poisoning" fold together."""
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", s)).strip().casefold()


def _dedup_key(info: dict) -> str:
    """Catalogue-level dedup key for one threat, scoped per (session, subsystem) by the caller.
    Prefer the finest real library id; fall back to normalized text for a novel/ungrounded
    proposal. This is the folding rule dal.identity_hash wraps — every IdentityHash producer and
    consumer routes through that helper, so app-level dedup and the DB unique index block the
    SAME pair."""
    catalogue_id = info.get("catalogue_id")
    if catalogue_id is not None:
        return f"cat:{catalogue_id}"
    type_id = info.get("threat_type_id")
    if type_id is not None:
        return f"type:{type_id}"
    # Join the delimiter AFTER normalizing each part: _normalize strips `[^\w\s]`, so an in-text
    # separator would be eaten and 'Firmware'+'Tampering' would collide with 'Firmware Tampering'
    # +None. Both parts empty → a per-threat-unique token, so distinct ungrounded proposals don't
    # all collapse onto a bare 'txt:'.
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
    """Run the THREATS stage for the asset: ask the AI for candidate threats (supporting systems as
    context), ground each against the threat library, save them, and complete the stage. Returns
    an empty list if another worker already claimed this stage or the claim is lost partway.

    `supersede=True` (first-run) wipes the prior run's active threats first. `supersede=False` is
    the additive "generate next set" mode (cascade.run_next_set): earlier threats stay active and
    returned — the accumulation invariant depends on NOT superseding here. `exclude` is the
    already-proposed coverage list threaded into the prompt.

    `categories`/`actor_examples`/`asset_active_fields`/`sub_active_fields` are global config the
    caller reads ONCE per session and passes down (they can't change mid-run); None means "query
    them here", for a direct caller without pre-fetched values."""
    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
        return [], None
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.THREATS, StageStatus.RUNNING, epoch)
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
                                temperature=get_settings().threat_identification_temperature)
    if supersede:
        dal.supersede(sess, m.Identified_Threat, sid, ss)
    # Additive round (supersede=False): a coverage-aware prompt still occasionally re-proposes an
    # already-active threat, leaking a never-scored dead Identified_Threat row. Skip any proposal
    # whose folded identity matches an active threat or an earlier proposal in THIS batch.
    existing_identities = dal.active_identified_threat_identities(sess, sid, ss) if not supersede else set()
    threats: list[dict] = []
    rows: list[dict] = []
    sector_ids = json.loads(scenario_session["SectorIDsJSON"]) if scenario_session.get("SectorIDsJSON") else []
    grounding_cache: dict = {}  # scoped to this call — same sector_ids for every proposal below
    # One batched embed for every proposal's type/name text, instead of one round trip per
    # proposal inside the loop below. All the texts are already known here.
    grounding.prime_query_embeddings(llm, proposals, grounding_cache)
    for p in proposals:
        # This loop runs one grounding match per proposal with no LLM call in between to renew the
        # lease via _ask_ai, so a long loop could otherwise outlive its own lease and be reaped.
        if not dal.renew_lease(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
            log.warning("stage.lease_renewal_failed", session_id=sid, subsystem=ss, level=str(SubsystemLevel.THREATS))
        sess.commit()
        ptype = _safe_text(p.get("type"), "")
        pcat = _safe_text(p.get("category"), "")
        pname = _safe_text(p.get("name"), None)  # ThreatName is nullable
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
    # /results must never race the write it's reading.
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="THREATS", count=len(threats))
    return threats, prov




def _moderation_report(scenario: dict) -> dict:
    """Optional content-moderation check (llm.moderate — off by default, LLM_MODERATION_ENABLED)
    over this scenario's reviewer-visible text, in ONE call. Advisory only: the result rides
    inside ValidationJSON and never rejects the scenario."""
    text = " ".join(str(scenario.get(f) or "") for f in _SCENARIO_TEXT_FIELDS)
    # controls suggestions are model-generated text shown to reviewers too — same surface.
    text = " ".join([text] + [f"{c.get('name') or ''} {c.get('why') or ''}".strip()
                            for c in (scenario.get("controls") or []) if isinstance(c, dict)])
    r = moderate(text)
    return {"checked": r.checked, "flagged": r.flagged, "categories": r.categories, "error": r.error}


#: OT threat types get ICS advisories first; the importer names OT types with these prefixes.
_OT_TYPE_PREFIXES = ("ICS", "Embedded Device")


def _fetch_intel(threat_type: str | None, threat_name: str | None,
                 actors: list[str] | None = None) -> list[dict] | None:
    """Current threat-intel items for one verified threat, or None. Fail-open and opt-in
    (TSG_INTEL_ENABLED): any error, disabled flag, or empty result returns None and generation
    proceeds unchanged. OT threats prefer ICS advisories; everything else prefers exploited CVEs."""
    if not get_settings().intel_enabled:
        return None
    try:
        from app.intel.fetchers import query_intel

        is_ot = (threat_type or "").startswith(_OT_TYPE_PREFIXES)
        prefer = ("ics_advisory", "cve") if is_ot else ("cve",)
        # match on the threat wording; query_intel drops terms shorter than 4 chars itself.
        # Library actors are passed WHOLE (never word-split) — fetch_otx tags pulses with
        # their adversary, so "APT 29" here is what surfaces that actor's current pulses.
        terms = [w for w in re.split(r"[^A-Za-z0-9]+", f"{threat_type} {threat_name}") if w]
        terms += [a for a in (actors or []) if a]
        return query_intel(terms, prefer_kinds=prefer) or None
    except Exception:  # noqa: BLE001 — enrichment is optional, never breaks generation
        log.warning("scenario.intel_fetch_failed", exc_info=True)
        return None


def _generate_one_scenario(sess: Session, scenario_session: dict, base_ctx: dict, asset_context: dict, sc,
                    enriched: dict, llm: LLMClient, task_id: str, epoch: int,
                    sibling_texts: list[tuple[int, str]] | None = None) -> tuple[dict, dict, Provenance | None]:
    """Ask the AI to write a scenario for a single scoped threat, then validate the result
    against the threat's expected type/name.

    `base_ctx` is the sanitized prompt context, built ONCE per batch by the caller. `asset_context`
    is still passed RAW because validate_scenario needs the un-redacted critical_service.

    `sibling_texts` — (ScenarioNumber, scenario_statement) of the threat's OTHER active scenarios,
    batch-fetched by the caller (never a per-scenario SELECT here). Non-empty → the variant prompt
    steers away from each sibling and the result is similarity-flagged (advisory, never a retry).
    Sibling-awareness lives HERE, the one function every scenario write routes through."""
    info = enriched.get(sc.threat_id, {})
    threat_type = info.get("library_threat_type") or info.get("threat_type")
    threat_name = info.get("library_threat_name") or info.get("threat_name")
    actors = info.get("actors") or []
    intel_items = _fetch_intel(threat_type, threat_name, actors)
    if sibling_texts:
        messages = prompts.variant_scenario_prompt(base_ctx, threat_type, threat_name, actors=actors,
                                                intel_items=intel_items, existing=sibling_texts)
    else:
        messages = prompts.scenario_prompt(base_ctx, threat_type, threat_name, actors=actors,
                                        intel_items=intel_items)
    scenario, prov = _ask_ai(sess, llm, messages,
                            scenario_session=scenario_session, subsystem_id=ASSET_UNIT_ID, stage="scenario",
                            level=SubsystemLevel.SCENARIOS, epoch=epoch, task_id=task_id, expected_type=dict)
    report = validation.validate_scenario(
        scenario, threat_type, threat_name,
        asset_name=scenario_session["AssetName"], critical_service=asset_context.get("critical_service"))
    report["moderation"] = _moderation_report(scenario)
    if sibling_texts:
        _flag_sibling_similarity(report, scenario, sibling_texts)
    return scenario, report, prov


def _build_scoped_threat_row(scoped_id: str, sid: str, tenant: str, ss: int, sc: scoping.Scored,
                        entity_id: str | None, user_id: str | None) -> dict:
    """Build the Scoped_Threat DB row for one scored threat. Pure dict-building — no I/O."""
    return {
        "ScopedThreatID": scoped_id, "SessionID": sid, "TenantID": tenant, "EntityID": entity_id,
        "UserID": user_id, "SubsystemID": ss,
        "ThreatID": sc.threat_id, "Score": sc.score, "ScopeRank": sc.rank,
        "Selected": 1 if sc.selected else 0, "Reason": sc.reason, "RejectionKind": sc.rejection,
        "FactorsJSON": json.dumps(sc.factors) if sc.factors else None,
        "Superseded": 0, "CreatedAt": now(),
    }


def _build_scenario_output_row(scoped_id: str, sid: str, tenant: str, ss: int, scenario: dict, report: dict,
                            epoch: int, entity_id: str | None, user_id: str | None, info: dict,
                            scenario_number: int = 1, replaces_output_id: str | None = None) -> dict:
    """Build the Threat_Scenario_Output DB row for one generated scenario. Pure dict-building —
    no I/O."""
    # The filtered unique index UX_Scenario_ActiveIdentity(SessionID, IdentityHash, ScenarioNumber)
    # WHERE Superseded=0 blocks a second active scenario for the same (threat, number) even under a
    # crash/retry. SubsystemID must stay INSIDE the fold (the index has no subsystem column) or
    # sibling subsystems sharing a catalogue/type would cross-suppress.
    identity = dal.identity_hash(sid, ss, info)
    return {
        "OutputID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.complete,
        "ScenarioJSON": json.dumps(scenario),
        "ValidationJSON": json.dumps(report),
        "Accepted": 0, "Superseded": 0,
        "IdentityHash": identity, "ScenarioNumber": scenario_number,
        # Always present (None = replaced nothing) so executemany sees a uniform key set.
        "ReplacesOutputID": replaces_output_id,
        "GenerationEpoch": epoch, "ErrorMessage": None, "CreatedAt": now(),
    }


def _build_error_output_row(scoped_id: str, sid: str, tenant: str, ss: int, client_msg: str,
                            epoch: int, entity_id: str | None, user_id: str | None, info: dict,
                            scenario_number: int = 1, replaces_output_id: str | None = None) -> dict:
    """FAILURE CARD for a full-run threat whose scenario generation failed: same linkage and
    IdentityHash as a real row — so /regenerate/scenarios can target it (THE retry path) and a
    later success supersedes it — but Status=error keeps it out of accept/salvage/resume (the
    ScenarioStatus.complete filters in dal.py)."""
    return {
        "OutputID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.error,
        "ScenarioJSON": None, "ValidationJSON": None,
        "Accepted": 0, "Superseded": 0,
        "IdentityHash": dal.identity_hash(sid, ss, info), "ScenarioNumber": scenario_number,
        # Points at the card it replaced, so the chain survives a failure.
        "ReplacesOutputID": replaces_output_id,
        "GenerationEpoch": epoch,
        "ErrorMessage": client_msg, "CreatedAt": now(),
    }


def _select_unique_top_n(scoped: list[scoping.Scored], enriched: dict, top_n: int | None) -> int:
    """Catalogue-dedupe the already-ranked, threshold-passed threats down to a unique top-N, in
    place, walking the ranker's own order. The count is over UNIQUE threats ("free the slot"), so
    the reviewer gets N DISTINCT scenarios rather than N-minus-the-dupes. A duplicate is demoted
    (Selected=0) but its row survives for audit. FULL RUN ONLY — a regen target must never be
    blocked here. Returns how many were demoted as duplicates (not by the top-N cutoff)."""
    seen: set[str] = set()
    kept = 0
    deduped = 0
    for sc in scoped:
        if not sc.selected:
            continue  # already excluded by tech_gate / score threshold in score_threats
        key = _dedup_key(enriched.get(sc.threat_id, {}))
        if key in seen:
            sc.selected, sc.reason = False, "duplicate of higher-ranked threat"
            sc.rejection = ScopingRejection.duplicate  # permanent: the identity is already served
            deduped += 1
        elif top_n is not None and kept >= top_n:
            sc.selected, sc.reason = False, f"beyond top-{top_n} cutoff"
            sc.rejection = ScopingRejection.top_n_cutoff  # the ONLY kind next-set may re-serve
        else:
            seen.add(key)
            kept += 1
    return deduped


def _mark_next_set_targets_rescored_out(sess: Session, sid: str, ss: int, pairs: list, excluded_ids: set[str],
                                    tenant: str, entity_id: str | None, user_id: str | None) -> None:
    """Persist a fresh Selected=0 scoped marker for every NEXT-SET target that rescored out with NO
    active scenario, so next_unserved_unique_threats stops re-serving it.

    Gate on "no active SCENARIO", NOT "no prior active scoped row": a genuine REGEN target keeps its
    active scenario so it stays out of this set, while a pool zombie (a previously-served threat
    whose Selected=1 row rescored out) has none — keying on the scoped row alone would spare the
    zombie and re-serve it on every click. Supersede FIRST, then insert the marker: superseding
    alone leaves no active scoped row and next_unserved re-serves it via `ScopedThreatID IS NULL`."""
    excluded_needing_marker = (excluded_ids - dal.threats_with_active_scenario(sess, sid, ss, excluded_ids)
                            if excluded_ids else set())
    if not excluded_needing_marker:
        return
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, excluded_needing_marker)
    sess.execute(insert(m.Scoped_Threat), [
        _build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)
        for sc, scoped_id, _t in pairs if sc.threat_id in excluded_needing_marker])


def _begin_full_run_attempt(sess: Session, sid: str, ss: int, tenant: str,
                            entity_id: str | None, user_id: str | None,
                            pairs: list, epoch: int) -> set[str]:
    """Once-per-epoch setup for a full run (which persists INCREMENTALLY, so a mid-batch failure
    never discards scenarios that already succeeded). Returns the resume-skip set: threat_ids that
    already own an active scenario from a prior attempt of THIS epoch.

    The setup must run EXACTLY once per epoch: dal.supersede has no epoch memory, so re-running it
    on a resumed claim would flip this epoch's own just-committed rows back to Superseded=1 and
    regenerate them. AttemptCount==1 is the "first successful claim of this epoch" signal.

    Skipping the supersede on resume is only safe because a full run never runs at anything but
    the initial epoch (there is no PRIOR generation to clear); the guard below enforces that.

    # ponytail: a crash after claim-commit but before this setup's commit loses this run's
    # not-selected Scoped_Threat rows. Ceiling: a gated threat gets re-served ONCE by "generate
    # next set", which re-marks it Selected=0 (self-healing); the rest is write-only audit
    # metadata. Make this block idempotent if that one wasted slot ever matters.
    """
    if epoch != _EPOCH:
        raise ValueError(
            f"full-run write_scenarios is only valid at the initial epoch {_EPOCH}, got {epoch} — "
            "a regen/next-set hop must pass target_threat_ids and take the targeted branch")
    attempt = dal.stage_attempt_count(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch)
    if attempt == 1:
        dal.supersede(sess, m.Scoped_Threat, sid, ss)
        dal.supersede(sess, m.Threat_Scenario_Output, sid, ss)
        # Not-selected threats involve no LLM call — persist their scoring metadata once, up
        # front, so a resume never re-inserts it.
        not_selected = [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)
                        for sc, scoped_id, _t in pairs if not sc.selected]
        if not_selected:
            sess.execute(insert(m.Scoped_Threat), not_selected)
        sess.commit()
        return set()  # the supersede above cleared every active output — skip the empty SELECT
    # Resume: a threat owning an active scenario got it from a prior attempt of THIS epoch (the
    # attempt==1 supersede cleared older generations, and the _LOCK/claim_stage CAS means no
    # other epoch can be concurrently active).
    return dal.threats_with_active_scenario(
        sess, sid, ss, {sc.threat_id for sc, _scoped_id, _t in pairs if sc.selected})


def _reconcile_targeted_regen(sess: Session, sid: str, ss: int, tenant: str,
                            entity_id: str | None, user_id: str | None,
                            pairs: list, scenarios: dict, enriched: dict,
                            epoch: int, task_id: str, *, regen_mode: bool) -> bool:
    """The persistence/reconciliation tail of a TARGETED regen/next-set `write_scenarios` call
    (a full run persists incrementally in write_scenarios' own loop and never comes here):
    compute which targets actually got a fresh scenario, persist rescored-out markers, raise
    `RegenerateConflict` when every target rescored out, supersede exactly the right prior rows,
    and bulk-insert the new ones. Returns False only on the claim-lost path.

    `pairs` are (Scored, new scoped guid, RegenTarget | None) triples. `regen_mode=True` =
    regeneration (every pair carries a RegenTarget — replace exactly that row, at its own
    ScenarioNumber, retiring ONLY its own Scoped_Threat row so a sibling's scoring row survives);
    False = next-set fresh threats (target=None, first scenario, threat-scoped supersede).

    NEVER supersede a threat's prior active rows unless a fresh scenario actually replaced them:
    rescoring can legitimately re-exclude a target (a rule weight or cutoff changed since the
    scenario was written), and destroying the old row with nothing to show for it is data loss."""
    generated_ids = {sc.threat_id for sc, scoped_id, _t in pairs if scoped_id in scenarios}
    all_target_ids = {sc.threat_id for sc, _scoped_id, _t in pairs}
    excluded_ids = all_target_ids - generated_ids
    if excluded_ids:
        log.warning("regen.target_no_longer_selected", session_id=sid, subsystem=ss,
                    threat_ids=sorted(excluded_ids))

    # Before the all-excluded early-return below, so both paths record the markers exactly once.
    # NEXT-SET ONLY: `excluded_ids` also covers "generation raised", and in regen mode the sweep's
    # only real effect would be superseding the Scoped_Threat of an error-card target whose retry
    # failed — reading a transient LLM failure as a permanent scoping decision.
    if not regen_mode:
        _mark_next_set_targets_rescored_out(sess, sid, ss, pairs, excluded_ids, tenant, entity_id, user_id)

    if not generated_ids:
        # Every requested target was excluded by rescoring — nothing regenerated, nothing mutated.
        # Return the stage to its reviewable state and report a benign conflict (cascade.py's
        # `except RegenerateConflict`), never a pipeline failure.
        if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch, task_id):
            sess.rollback()
            log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
            return False
        sess.commit()
        if not pairs:
            # Empty candidate pool from the start — a different cause from a scoping-cutoff
            # exclusion, which the caller-facing reason code must distinguish.
            raise dal.RegenerateConflict(
                "no unserved threats remain for this asset", reason="no_new_threats_found")
        raise dal.RegenerateConflict(
            f"threat(s) no longer meet the scoping cutoff and cannot be regenerated: {sorted(excluded_ids)}",
            reason="new_threat_did_not_qualify")

    # Supersede only what a fresh scenario actually replaces this pass.
    generated_pairs = [(sc, scoped_id, t) for sc, scoped_id, t in pairs if scoped_id in scenarios]
    if regen_mode:
        # Row-scoped, never threat-wide: a sibling scenario (other ScenarioNumber, same ThreatID)
        # keeps its own scoring row.
        dal.supersede_scoped_rows(sess, [t.scoped_threat_id for _sc, _scoped_id, t in generated_pairs])
    else:
        old_scoped_ids = dal.active_scoped_threat_ids(sess, sid, ss, generated_ids)
        dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, generated_ids)
        dal.supersede_by_scoped_threats(sess, sid, ss, old_scoped_ids)
    scoped_rows = []
    output_rows = []
    for sc, scoped_id, target in pairs:
        if sc.threat_id in excluded_ids:
            continue  # excluded by rescoring — its prior active rows were left untouched above
                    # (a fresh no-prior-scoped target already got its Selected=0 marker above)
        if regen_mode and scoped_id not in scenarios:
            # A target whose generation FAILED replaces nothing — its old scenario and scoped row
            # stay active, so don't insert a dangling fresh scoped row for it either.
            continue
        scoped_rows.append(_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id))
        if scoped_id not in scenarios:
            continue
        scenario, report = scenarios[scoped_id]
        number = target.scenario_number if target is not None else 1
        output_rows.append(_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                                    entity_id, user_id, enriched.get(sc.threat_id, {}),
                                                    scenario_number=number))
    if scoped_rows:
        sess.execute(insert(m.Scoped_Threat), scoped_rows)
    if output_rows:
        # Regen skips _select_unique_top_n, so two targets folding to the same dedup_key build the
        # SAME IdentityHash and collide on UX_Scenario_ActiveIdentity — either within this bulk
        # insert or against an already-active row. Collapse to the first (highest-ranked) per
        # (hash, ScenarioNumber) so exactly one active scenario per (identity, number) survives.
        seen_keys: set[tuple[str, int]] = set()
        deduped_output_rows = []
        for r in output_rows:
            key = (r["IdentityHash"], r["ScenarioNumber"])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped_output_rows.append(r)
        output_rows = deduped_output_rows
        by_number: dict[int, set[str]] = {}
        for h, number in seen_keys:
            by_number.setdefault(number, set()).add(h)
        # Stamp from what the supersede ACTUALLY retired, not the requested target: retirement is
        # keyed on (IdentityHash, ScenarioNumber), and the dedup collapse above can retire a row
        # whose target never reaches output_rows.
        retired: dict[tuple[str, int], str] = {}
        for number, hashes in by_number.items():
            for h, old_id in dal.supersede_by_identity_hashes(
                    sess, sid, ss, hashes, scenario_number=number).items():
                retired[(h, number)] = old_id
        for r in output_rows:
            r["ReplacesOutputID"] = retired.get((r["IdentityHash"], r["ScenarioNumber"]))
    if output_rows:
        sess.execute(insert(m.Threat_Scenario_Output), output_rows)
    return True


def _build_work_items(sess: Session, sid: str, ss: int, scoped_all: list[scoping.Scored],
                    target_threat_ids: set[str] | None,
                    regen_targets: dict[str, RegenTarget] | None,
                    ) -> tuple[list[tuple], int, dict[str, list[tuple[str, int, str]]]]:
    """Build one write_scenarios call's batch. Returns:
    - `pairs`: (Scored, new scoped guid, RegenTarget | None) work items. Full run / next-set carry
    target=None (a first scenario, number 1). Regen mode builds one item PER TARGET ROW in rank
    order, each replacement inheriting its own ScenarioNumber.
    - `scoped_threat_count`: distinct THREATS considered, for the caller's audit record —
    deliberately NOT len(pairs), which double-counts a threat whose two scenarios are both
    regenerated in one call.
    - `siblings_by_hash`: IdentityHash -> [(OutputID, ScenarioNumber, statement)] of each regen
    target's OTHER active scenarios, batch-fetched ONCE (anti-N+1). Empty for fresh/full modes.
    """
    pairs: list[tuple[scoping.Scored, str, RegenTarget | None]]  # third slot None outside regen mode
    if regen_targets is not None:
        by_threat_targets: dict[str, list[RegenTarget]] = {}
        for t in regen_targets.values():
            by_threat_targets.setdefault(t.threat_id, []).append(t)
        pairs = [(sc, guid(), t)
                for sc in scoped_all if sc.threat_id in by_threat_targets
                for t in sorted(by_threat_targets[sc.threat_id], key=lambda t: t.scenario_number)]
    elif target_threat_ids is not None:
        pairs = [(sc, guid(), None) for sc in scoped_all if sc.threat_id in target_threat_ids]
    else:
        pairs = [(sc, guid(), None) for sc in scoped_all]
    scoped_threat_count = len({sc.threat_id for sc, _scoped_id, _t in pairs})

    siblings_by_hash: dict[str, list[tuple[str, int, str]]] = {}
    if regen_targets is not None:
        for r in dal.active_scenarios_by_identity(
                sess, sid, ss, {t.identity_hash for t in regen_targets.values() if t.identity_hash}):
            try:
                statement = str((json.loads(r.ScenarioJSON) or {}).get("scenario_statement") or "")
            except (TypeError, ValueError):
                statement = ""
            siblings_by_hash.setdefault(r.IdentityHash, []).append((r.OutputID, r.ScenarioNumber, statement))
    return pairs, scoped_threat_count, siblings_by_hash


class _ScenarioBatch(NamedTuple):
    """Everything resolved ONCE per write_scenarios call, before any scenario text is generated."""
    base_ctx: dict
    enriched: dict
    deduped: int
    pairs: list
    scoped_count: int
    siblings_by_hash: dict


def _prepare_scenario_batch(sess: Session, sid: str, ss: int, scenario_session: dict,
                            subsystems: list[dict], asset_context: dict, threats: list[dict],
                            asset_active_fields: list[str] | None, sub_active_fields: list[str] | None,
                            target_threat_ids: set[str] | None,
                            regen_targets: dict[str, RegenTarget] | None,
                            targeted: bool) -> _ScenarioBatch:
    """Resolve the whole batch's shared inputs in ONE place: active context fields, the base
    prompt context, scoring, dedup, and the work items. Every one of these is per-CALL, not
    per-threat — resolving them inside the generation loop would be the N+1 this codebase has
    already been bitten by, and would also let a curator's mid-batch edit change the field set
    between two threats of the same run."""
    if asset_active_fields is None or sub_active_fields is None:
        resolved = dal.active_context_fields_by_group(sess)  # one round-trip for both groups
        if asset_active_fields is None:
            asset_active_fields = resolved["asset"]
        if sub_active_fields is None:
            sub_active_fields = resolved["subsystem"]
    base_ctx = prompts.build_base_context(scenario_session["AssetName"], asset_context, subsystems,
                                        asset_active_fields, sub_active_fields)

    settings = get_settings()
    type_ids = sorted({t["threat_type_id"] for t in threats if t.get("threat_type_id") is not None})
    # score_threats ALWAYS gets top_n=None: scoping_top_n counts UNIQUE threats and is enforced by
    # _select_unique_top_n (full run only). A raw rank cutoff here would wrongly exclude a regen
    # target a full run kept via free-the-slot from beyond raw rank N → RegenerateConflict → the
    # Regenerate control silently no-ops. score_threshold/tech_gate still reject a genuine dropout.
    # The clamp below feeds only _select_unique_top_n, never score_threats.
    top_n = settings.scoping_top_n
    if top_n is not None:
        top_n = min(top_n, settings.max_threats_per_asset)
    scoped_all = scoping.score_threats(threats, subsystems=subsystems,
                                    rules=dal.active_threat_rules(sess, type_ids),
                                    score_threshold=settings.scoping_score_threshold, top_n=None)
    enriched = {t["threat_id"]: t for t in threats}
    # Dedup BEFORE any scenario text is generated — full runs only; a targeted regen must never be
    # blocked or demoted by dedup (the reviewer asked to redo an already-unique scenario).
    deduped = _select_unique_top_n(scoped_all, enriched, top_n) if not targeted else 0
    pairs, scoped_count, siblings_by_hash = _build_work_items(
        sess, sid, ss, scoped_all, target_threat_ids, regen_targets)
    return _ScenarioBatch(base_ctx, enriched, deduped, pairs, scoped_count, siblings_by_hash)


def _retire_prior_card(sess: Session, sid: str, ss: int, info: dict) -> str | None:
    """Supersede whatever active row this identity already has at ScenarioNumber 1, returning its
    OutputID for the replacement to point at. Both full-run writers need it: error rows are
    excluded from `already_done` precisely so a retry lands here, and inserting over a live card
    would violate UX_Scenario_ActiveIdentity. No-op (returns None) when no card exists."""
    identity = dal.identity_hash(sid, ss, info)
    return dal.supersede_by_identity_hashes(sess, sid, ss, {identity}, scenario_number=1).get(identity)


def _persist_full_run_failure(sess: Session, sid: str, ss: int, tenant: str, entity_id: str | None,
                            user_id: str | None, sc, scoped_id: str, info: dict,
                            client_msg: str, epoch: int) -> None:
    """FULL RUN ONLY: persist a failure card so the failure stays retryable — with no row at all
    it is invisible to /regenerate/scenarios, which targets OutputIDs. Status=error keeps it out
    of accept/salvage/resume, and get_threat_id_to_redo deliberately does NOT filter it: that IS
    the retry path.

    Targeted modes insert nothing instead of calling this — the threat's previous scenario is
    still active under the same IdentityHash (inserting would collide) and is already retryable."""
    retired_card = _retire_prior_card(sess, sid, ss, info)
    # Also retire the prior Scoped_Threat row: superseding only the output leaves the earlier
    # card's scoped row active, so a resumed attempt accumulates a second active scoped row per
    # retry, duplicating the threat in every "active scoped" read.
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, {sc.threat_id})
    sess.execute(insert(m.Scoped_Threat),
                [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
    sess.execute(insert(m.Threat_Scenario_Output),
                [_build_error_output_row(scoped_id, sid, tenant, ss, client_msg, epoch,
                                        entity_id, user_id, info, replaces_output_id=retired_card)])
    sess.commit()


def _persist_full_run_scenario(sess: Session, sid: str, ss: int, tenant: str, entity_id: str | None,
                            user_id: str | None, sc, scoped_id: str, info: dict,
                            scenario: dict, report: dict, epoch: int) -> None:
    """FULL RUN ONLY: commit THIS threat's rows before the next threat's LLM call — explicitly,
    not as an incidental side effect of _ask_ai's own pre-call commit, which could regress if that
    timing ever changed. The targeted paths buffer instead and write once in
    _reconcile_targeted_regen."""
    retired_card = _retire_prior_card(sess, sid, ss, info)
    sess.execute(insert(m.Scoped_Threat),
                [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
    sess.execute(insert(m.Threat_Scenario_Output),
                [_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                            entity_id, user_id, info, replaces_output_id=retired_card)])
    sess.commit()


def write_scenarios(sess: Session, scenario_session: dict, subsystems: list[dict], asset_context: dict, threats: list[dict],
                llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, target_threat_ids: set[str] | None = None,
                asset_active_fields: list[str] | None = None,
                sub_active_fields: list[str] | None = None,
                *, require_lock: bool = False,
                regen_targets: dict[str, RegenTarget] | None = None,
                on_before_commit: Callable[[list[Provenance | None]], None] | None = None) -> list[Provenance | None]:
    """Run the SCENARIOS stage for the asset: score/rank the given threats, generate a
    scenario for each selected one, and save everything to the database. Two targeted modes:
    `regen_targets` (regeneration — one work item PER EXISTING ROW, each replacement inheriting
    its target's ScenarioNumber; the only way to express "redo a scenario") or
    `target_threat_ids` (next-set — threats getting their FIRST scenario, always number 1).
    Mutually exclusive; both None = the initial full run. Returns an empty list if another
    worker already claimed this stage or the claim is lost partway through.

    `on_before_commit` runs INSIDE this function's final transaction, immediately before the
    commit that makes the batch durable, for a caller that must record something atomically with
    the work (cascade.py's regeneration_completed / generation_complete audit rows). Both land or
    neither does, and a hook that raises correctly rolls the work back.

    `require_lock=True` (every production caller; never a direct unit test) refuses to even
    attempt the claim unless the caller still holds this subsystem's `_LOCK`. Without it, a
    worker whose prior stage stalled past its lease — reaped, `_LOCK` reclaimed, this still-IDLE
    SCENARIOS row ERROR-marked as part of closing out the session — could re-claim THIS row under
    the same zombie task_id and silently finish a stage on a session the reaper already closed
    out. `claim_stage` deliberately has no `_LOCK` check of its own (tests exercise it
    standalone); this is the one call site that needs the mutex re-verified."""
    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
    entity_id, user_id = scenario_session["EntityID"], scenario_session.get("UserID")
    if require_lock and not dal.holds_lock(sess, sid, ss, task_id):
        log.warning("subsystem.lock_lost_before_scenarios", session_id=sid, subsystem=ss)
        return []
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id):
        return []
    sess.commit()  # make the "now RUNNING" flip durable before announcing it
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.SCENARIOS, StageStatus.RUNNING, epoch)

    targeted = target_threat_ids is not None or regen_targets is not None
    batch = _prepare_scenario_batch(sess, sid, ss, scenario_session, subsystems, asset_context, threats,
                                    asset_active_fields, sub_active_fields,
                                    target_threat_ids, regen_targets, targeted)
    base_ctx, enriched, deduped = batch.base_ctx, batch.enriched, batch.deduped
    pairs, scoped_threat_count, siblings_by_hash = batch.pairs, batch.scoped_count, batch.siblings_by_hash

    provs: list[Provenance | None] = []
    scenarios: dict[str, tuple[dict, dict]] = {}  # scoped_id -> (scenario, validation report) — regen branch only
    already_done: set[str] = set()
    if not targeted:
        already_done = _begin_full_run_attempt(sess, sid, ss, tenant, entity_id, user_id, pairs, epoch)
    failures: list[str] = []       # client-safe reasons, for the stage's ErrorMessage
    first_failure: Exception | None = None
    for sc, scoped_id, target in pairs:
        if not sc.selected or sc.threat_id in already_done:
            continue
        # Siblings = the same identity's other active scenarios, excluding the row being replaced.
        sibling_texts = None
        if target is not None and target.identity_hash:
            sibling_texts = [(number, statement)
                            for output_id, number, statement in siblings_by_hash.get(target.identity_hash, [])
                            if output_id != target.output_id] or None
        try:
            scenario, report, prov = _generate_one_scenario(sess, scenario_session, base_ctx, asset_context, sc,
                                                            enriched, llm, task_id, epoch,
                                                            sibling_texts=sibling_texts)
        except LLMSlotUnavailable:
            # NOT per-item: a capacity squeeze is transient and applies to the whole hop. Celery's
            # autoretry_for re-runs it shortly; swallowing it here would freeze a temporary
            # shortage into a permanently short batch.
            raise
        except Exception as exc:  # noqa: BLE001 — one threat's failure must not discard its siblings
            # Targeted modes buffer every scenario until the end, so propagating here would throw
            # away siblings already generated and paid for. Record and keep going.
            sess.rollback()  # _ask_ai commits mid-flight; never continue the loop on a dirty session
            first_failure = first_failure or exc
            client_msg = _failure_client_message(exc)
            failures.append(f"{enriched.get(sc.threat_id, {}).get('threat_name') or sc.threat_id}: {client_msg}")
            log.warning("scenario.generation_failed", session_id=sid, subsystem=ss,
                        threat_id=sc.threat_id, error=repr(exc))
            if not targeted:
                _persist_full_run_failure(sess, sid, ss, tenant, entity_id, user_id, sc, scoped_id,
                                        enriched.get(sc.threat_id, {}), client_msg, epoch)
            continue
        provs.append(prov)
        if not targeted:
            # Re-verify the claim BEFORE committing. finish_stage's fencing at the end is enough
            # for the targeted paths (buffered, rolled back there), but this branch commits each
            # threat as it goes, so by then the rollback has nothing left to undo — a reaped worker
            # would keep committing fresh scenarios into a session a human is already reviewing.
            if not dal.renew_lease(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id):
                sess.rollback()
                log.warning("stage.claim_lost_midbatch", session_id=sid, subsystem=ss,
                            stage="SCENARIOS", epoch=epoch, committed=len(provs) - 1)
                break
            _persist_full_run_scenario(sess, sid, ss, tenant, entity_id, user_id, sc, scoped_id,
                                    enriched.get(sc.threat_id, {}), scenario, report, epoch)
        else:
            scenarios[scoped_id] = (scenario, report)

    if failures and not provs and not already_done and first_failure is not None:
        # EVERY selected threat failed AND nothing survives from an earlier attempt — only then is
        # there nothing to review. Re-raise the first cause so the caller records THAT message,
        # not _reconcile_targeted_regen's "no longer meet the scoping cutoff" conflict, which would
        # describe a rescoring outcome that never happened.
        #
        # `not already_done` is load-bearing: `provs` holds only THIS attempt's generations, so
        # without it a resumed attempt whose remaining threats all fail would flip the stage to
        # ERROR despite committed, reviewable output. Always empty on the targeted path.
        raise first_failure

    # ponytail: after a resumed attempt, provs holds only THIS attempt's generations, so the
    # audit counts below can under-report the true active total — re-query the DB if that ever matters.
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=scenario_session["EntityID"],
                    Stage=WorkflowStage.SCENARIO_GENERATION, SubsystemID=ss,
                    EventType=AuditEventType.scoping_complete,
                    DetailJSON=json.dumps({"scoped": scoped_threat_count, "selected": len(provs), "deduped": deduped}))
    log.info("scenarios.deduped", session_id=sid, subsystem=ss, deduped=deduped, kept=len(provs))

    if targeted and not _reconcile_targeted_regen(
            sess, sid, ss, tenant, entity_id, user_id,
            pairs, scenarios, enriched, epoch, task_id,
            regen_mode=regen_targets is not None):
        return []
    # A partial batch still goes to REVIEW (the survivors are worth reviewing) but carries the
    # reason on the stage row — that is what SessionProgress.error_message means on an
    # awaiting_review board: the review set may be PARTIAL.
    partial_error = (f"{len(failures)} of {len(failures) + len(provs)} scenario(s) failed to "
                    f"generate: {'; '.join(failures)}") if failures else None
    # Before finish_stage, so the control-map rows commit atomically with the batch.
    _finalize_scenario_batch(sess, scenario_session, asset_context, subsystems, llm, task_id, epoch)
    if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION,
                            epoch, task_id, error=partial_error):
        sess.rollback()
        log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
        return []
    # Deliberately unguarded: if it raises, the commit never happens and the whole batch rolls
    # back — that is the atomicity this hook exists to provide, not a bug to swallow.
    if on_before_commit is not None:
        on_before_commit(provs)
    sess.commit()  # commit before announcing
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="SCENARIOS", scenarios=len(provs))
    return provs


def _finalize_scenario_batch(sess: Session, scenario_session: dict, asset_context: dict,
                            subsystems: list[dict], llm: LLMClient, task_id: str, epoch: int) -> None:
    """The mandatory tail of EVERY scenario-writing path — Step-4 control mapping for every active
    output not yet attempted (map_controls is data-driven off ControlsMappedAt, so one call covers
    whatever the caller just inserted). A data-state test ("no active scenario permanently without
    a controls attempt") catches any future writer that skips this."""
    control_mapping.map_controls(sess, scenario_session, asset_context, subsystems, llm,
                                ASSET_UNIT_ID, task_id, epoch)


def write_variant_scenarios(sess: Session, scenario_session: dict, subsystem_id: int,
                            subsystems: list[dict], asset_context: dict, llm: LLMClient,
                            task_id: str, epoch: int, max_variants: int,
                            exclude_threat_ids: set[str] | None = None) -> int:
    """"Generate next set"'s variant fallback: when no genuinely NEW threat exists, write one
    ADDITIONAL, deliberately-different scenario for up to `max_variants` already-covered threats
    (best score first), each at the identity's next free ScenarioNumber. Returns how many were
    actually created. Exactly one chat call per variant.

    `exclude_threat_ids` is for a caller topping up a PARTIAL batch: the primaries it just
    committed are active, complete and highest-scored, so without it they would sort to the front
    of the eligibility list and get a scenario #2 for the #1 that click just wrote.

    Deliberately NOT a pipeline stage: the SCENARIOS stage is already terminal by the time this
    runs, so there is no claim/epoch dance — a plain side write under the caller's subsystem lock.

    Failure semantics (each deliberate):
    - insert+commit PER VARIANT, so a mid-batch crash keeps the variants already paid for;
    - a failed generation is skip-and-log: NO error card (it would squat on the scenario number
    and block the retry forever) and no _record_failure (erroring an already-terminal stage
    misreports a finished stage). The threat stays eligible; the next click is the retry;
    - LLMSlotUnavailable STOPS the batch and returns the honest count — it never raises;
    - a concurrent double-click racing to the same (identity, number) loses on
    UX_Scenario_ActiveIdentity and is skipped as the benign race it is."""
    from sqlalchemy.exc import IntegrityError

    sid, ss, tenant = scenario_session["SessionID"], subsystem_id, scenario_session["TenantID"]
    entity_id, user_id = scenario_session["EntityID"], scenario_session.get("UserID")
    eligible = dal.variant_eligible_primaries(
        sess, sid, ss, max_variants, get_settings().max_scenarios_per_threat,
        exclude_threat_ids=exclude_threat_ids)
    if not eligible:
        return 0
    threats = dal.active_threats(sess, sid, ss)
    enriched = {t["threat_id"]: t for t in threats}
    resolved = dal.active_context_fields_by_group(sess)
    base_ctx = prompts.build_base_context(scenario_session["AssetName"], asset_context, subsystems,
                                        resolved["asset"], resolved["subsystem"])
    # Batched sibling fetch — one SELECT for the whole batch, never per variant (anti-N+1).
    siblings_by_hash: dict[str, list[tuple[int, str]]] = {}
    for r in dal.active_scenarios_by_identity(sess, sid, ss, {e["identity_hash"] for e in eligible}):
        try:
            statement = str((json.loads(r.ScenarioJSON) or {}).get("scenario_statement") or "")
        except (TypeError, ValueError):
            statement = ""
        siblings_by_hash.setdefault(r.IdentityHash, []).append((r.ScenarioNumber, statement))

    created = 0
    for item in eligible:
        info = enriched.get(item["threat_id"])
        if not info:
            continue  # threat superseded between the eligibility read and now — benign, skip
        try:
            factors = json.loads(item["factors_json"]) if item["factors_json"] else []
        except (TypeError, ValueError):
            factors = []
        sc = scoping.Scored(threat_id=item["threat_id"], score=item["score"] or 0.0,
                            rank=item["scope_rank"] or 0, selected=True,
                            reason=item["reason"] or "", factors=factors)
        try:
            scenario, report, prov = _generate_one_scenario(
                sess, scenario_session, base_ctx, asset_context, sc, enriched, llm, task_id, epoch,
                sibling_texts=siblings_by_hash.get(item["identity_hash"]) or None)
        except LLMSlotUnavailable:
            # STOP the batch, don't raise: the sole caller (cascade._top_up_with_variants) must
            # never raise, so nothing here can trigger a Celery retry — raising would only destroy
            # `created`, the count of variants already committed above. Remaining threats stay
            # eligible and the user's next click is the retry.
            sess.rollback()
            log.warning("variant.slots_exhausted", session_id=sid, subsystem=ss,
                        created=created, remaining=len(eligible) - created)
            break
        except Exception as exc:  # noqa: BLE001 — one variant's failure must not discard its siblings
            sess.rollback()
            log.warning("variant.generation_failed", session_id=sid, subsystem=ss,
                        threat_id=item["threat_id"], error=repr(exc))
            continue
        scoped_id = guid()
        try:
            sess.execute(insert(m.Scoped_Threat),
                        [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
            sess.execute(insert(m.Threat_Scenario_Output),
                        [_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                                    entity_id, user_id, info,
                                                    scenario_number=item["next_number"])])
            sess.commit()  # per-variant durability — a later failure never rolls this one back
        except IntegrityError:
            sess.rollback()  # a concurrent click already filled this (identity, number) — benign race
            log.info("variant.race_lost", session_id=sid, subsystem=ss, threat_id=item["threat_id"],
                    scenario_number=item["next_number"])
            continue
        created += 1
    if created:
        # Step-4 mapping can fail AFTER the variants are durable. Losing it costs unmapped controls
        # (map_controls re-picks them up); letting it escape would report 0 for work on disk.
        try:
            _finalize_scenario_batch(sess, scenario_session, asset_context, subsystems, llm, task_id, epoch)
            sess.commit()
        except Exception as exc:  # noqa: BLE001 — see above; the variants are already committed
            sess.rollback()
            log.warning("variant.finalize_failed", session_id=sid, subsystem=ss,
                        created=created, error=repr(exc))
    return created


def _failure_client_message(exc: Exception) -> str:
    """Client-safe reason for a stage failure. A proxy-side guardrail block gets its own message
    (litellm raises `RejectedRequestError` for exactly that) so it isn't indistinguishable from a
    network blip or a real bug. litellm is imported locally, not at module top, so this module
    stays importable without it — same reasoning as every local `import litellm` in llm.py."""
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
    sess.rollback()  # undo the failed step's half-finished work, including its "in progress" marker
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
    sess.commit()  # commit before announcing
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
    # Salvage BEFORE the AWAITING_DECISION branch: a healthy sibling at AWAITING_DECISION would
    # otherwise short-circuit to review while an errored subsystem that STILL owns active
    # scenarios stays ERROR — excluded from accept's good_subs and silently dropped (data loss).
    # revive only flips ERROR SCENARIOS rows that still own an active output, so it no-ops when
    # there is nothing to salvage and the pure-ERROR path below still cancels. Re-read the board.
    if dal.has_active_scenarios(sess, sid):
        dal.revive_errored_scenarios_to_review(sess, sid)
        statuses = [str(r["Status"]) for r in dal.stage_rows(sess, sid)]
    if any(s == StageStatus.AWAITING_DECISION for s in statuses):
        return "review" if _send_to_review(sess, scenario_session) else None
    if any(s == StageStatus.ERROR for s in statuses):
        # Every stage terminal, none reviewable, and the salvage above found nothing to revive →
        # a genuine total failure. Cancel and release the lock.
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
        return False  # already moved into review, or no longer active — nothing left to do
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
    """Top-level driver for one session: take the asset unit's lock, run THREATS then SCENARIOS
    once for the whole asset (supporting systems are read-only context), record the outcome, then
    decide what happens to the session as a whole."""
    row = dal.load_session(sess, session_id)
    if row is None:
        return
    scenario_session = dict(row)
    if scenario_session["CurrentStage"] == WorkflowStage.REVIEW:
        # A task message redelivered after the session already reached REVIEW. SessionStatus stays
        # 'active' there, so acquire_lock's session-active gate alone doesn't catch it, and the
        # broker's visibility_timeout (~3600s) far outlives stage_lease_seconds. Regeneration is
        # the only thing allowed to touch a REVIEW session, and it goes through cascade.py.
        log.warning("pipeline.refused_review_session", session_id=session_id, task_id=task_id)
        return
    subsystems = json.loads(scenario_session["SubsystemsJSON"])
    asset_context = json.loads(scenario_session.get("AssetContextJSON") or "{}")
    log.info("pipeline.start", session_id=session_id, subsystems=len(subsystems), task_id=task_id)
    # One lock, one THREATS pass, one SCENARIOS pass, all keyed on ASSET_UNIT_ID. Another worker
    # holding the lock means this session is in flight elsewhere; fall through to
    # decide_session_outcome.
    if dal.acquire_lock(sess, session_id, ASSET_UNIT_ID, task_id):
        sess.commit()  # make the lock durable BEFORE any other work — an exception below routes
                        # through _record_failure's rollback, which would otherwise undo an
                        # uncommitted acquire_lock and make the finally's release spuriously fail.
        try:
            # Global config that can't change mid-run — read ONCE per session, and only after the
            # lock is won so a lost race doesn't pay for results it would discard.
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
            if not threats:  # already done before (idempotent no-op), or truly none — re-read to be sure
                threats = dal.active_threats(sess, session_id, ASSET_UNIT_ID)
                # Still empty is ambiguous: THREATS genuinely completed with zero proposals, OR
                # find_threats lost its claim to a still-RUNNING row that never finished. Only the
                # former may let SCENARIOS proceed — otherwise the session falsely reaches REVIEW
                # with zero scenarios instead of being left for the reaper to carry to ERROR.
                threats_stage_done = bool(threats) or dal.stage_completed_at_epoch_or_newer(
                    sess, session_id, ASSET_UNIT_ID, SubsystemLevel.THREATS, _EPOCH)
            if threats_stage_done:
                scen_provs = write_scenarios(sess, scenario_session, subsystems, asset_context, threats, llm, task_id,
                                            asset_active_fields=asset_active_fields, sub_active_fields=sub_active_fields,
                                            require_lock=True)
                dal.append_audit(sess, AuditID=guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], Stage=WorkflowStage.SCENARIO_GENERATION,
                                SubsystemID=ASSET_UNIT_ID, EventType=AuditEventType.generation_complete,
                                DetailJSON=json.dumps(_summarize_generation(ASSET_UNIT_ID, prov_i, scen_provs)))
                sess.commit()
            else:
                log.warning("pipeline.threats_not_complete_skipping_scenarios", session_id=session_id, task_id=task_id)
        except LLMSlotUnavailable:
            # Transient "system was busy", not a bug — must NOT be recorded as a permanent ERROR.
            # Re-raise past _record_failure so Celery's autoretry_for retries the whole task and
            # resumes via claim_stage's crash-redelivery CAS.
            raise
        except Exception as exc:  # noqa: BLE001 — every failure must be recorded, never lost
            _record_failure(sess, scenario_session, ASSET_UNIT_ID, exc)
            sess.commit()
        finally:
            if not dal.release_lock(sess, session_id, ASSET_UNIT_ID, task_id):
                log.warning("asset.lock_lost", session_id=session_id, task_id=task_id)
            sess.commit()
    else:
        # acquire_lock's CAS covers two cases: genuine contention, or a session that is no longer
        # active. The logged status is what tells an operator which one happened.
        log.warning("asset.locked", session_id=session_id, session_status=scenario_session["SessionStatus"])

    decide_session_outcome(sess, scenario_session)