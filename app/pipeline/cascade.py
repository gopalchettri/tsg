""" handles "regenerate" requests — redoing just one part of a
session (a scenario, a threat, a whole threat type, or the whole profile)
instead of starting the entire subsystem over from scratch.

Regeneration cascade (SDD [R9], reusing [R1]/[R3]/[R5]) — redo a subsystem's
profile/threat/threat-type/scenario without re-running the whole pipeline.

Row-scoped for `scenario`/`threat` granularities so redoing one bad item doesn't
discard its siblings (the actual point of the feature — `RegenGranularity`
already distinguishes `threat` (one specific threat) from `threat_type` (all
threats of a type), so the implementation honors that instead of collapsing both
into "redo everything"). `threat_type`/`profile` are correctly subsystem-wide.

Reuses the exact CAS/lock/epoch machinery `tasks.py` uses for the initial run:
`dal.acquire_lock` for the `_LOCK` mutex ([R5], mutual exclusion with accept),
`dal.claim_stage`'s existing `epoch` parameter, and the unmodified
`decide_session_outcome` to re-enter REVIEW once the board shows `AWAITING_DECISION`
again.

The epoch is reserved by the CALLER (the API endpoint's session-level CAS, exactly
once per logical request) and passed in — NOT computed here. A Celery task can be
redelivered (acks_late) and re-execute this whole function with the SAME epoch; at
that fixed epoch, `claim_stage`'s CAS correctly no-ops once a level is already
COMPLETE/AWAITING_DECISION, exactly like the initial pipeline's fixed `_EPOCH`. If
epoch were minted fresh on every call (as an earlier version of this module did),
a redelivery would compute a NEW epoch and destructively re-run the whole hop.

Crash-resume (`threat` granularity, [MEDIUM-1]): write_scenarios commits its SCENARIOS
stage-claim BEFORE the LLM call (gevent deadlock avoidance, tasks.py), and that commit also
flushes recheck_threat_in_library's already-pending supersede+insert — so the THREATS step is
durable before the scenario step finishes. If the worker then dies during the scenario LLM
call, the OLD target is already superseded and a redelivery would conflict at `get_threat_id_to_redo`
with no lineage column to find the replacement. `recheck_threat_in_library` therefore mints the
replacement id DETERMINISTICALLY from (session, subsystem, old threat, epoch) via
`_new_threat_id`; on redelivery `find_threat_to_resume_after_crash` recomputes that same id, finds
it still active, and resumes just the scenario step (`claim_stage`'s epoch CAS makes an
already-finished scenario a safe no-op). A genuine cross-request conflict (different epoch,
or replacement itself superseded) still no-ops as before.
"""
from __future__ import annotations

import json
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import AuditEventType, RegenGranularity, StageStatus, SubsystemLevel, WorkflowStage
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import RegenerateConflict, guid, now
from app.pipeline import grounding, tasks
from app.pipeline.llm import LLMClient

log = get_logger(__name__)

# The endpoint (sessions.py::post_regenerate) resets exactly these levels to IDLE before
# dispatching the task; run_regeneration's if/elif branches below MUST regenerate the same
# set. These two are the sole sources of truth for "what a granularity touches" — add a
# level here and you must add it to the matching branch, or the endpoint resets a stage
# nothing regenerates (stuck IDLE → reaper).
LEVELS_BY_GRANULARITY = {
    RegenGranularity.scenario: (SubsystemLevel.SCENARIOS,),
    RegenGranularity.threat: (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS),
    RegenGranularity.threat_type: (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS),
    RegenGranularity.threat_category: (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS),
    RegenGranularity.profile: (SubsystemLevel.PROFILE, SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS),
}


def _new_threat_id(sid: str, subsystem_id: int, old_threat_id: str, epoch: int) -> str:
    """ always produces the same replacement ID for the same
    regenerate request, so if it runs twice by accident it doesn't create two
    different replacements.

    Deterministic replacement ThreatID for a `threat`-granularity regen. Derived from
    (session, subsystem, old threat, epoch) — not random — so a redelivery of the SAME task
    (same epoch) recomputes the SAME id, letting the scenario step resume after a crash even
    though the old target is already superseded (there is no old->new lineage column). [MEDIUM-1]"""
    return str(uuid.uuid5(uuid.NAMESPACE_OID, f"regen-threat:{sid}:{subsystem_id}:{old_threat_id}:{epoch}"))


def get_threat_id_to_redo(sess: Session, session_id: str, subsystem_id: int,
                   granularity: RegenGranularity, target_ids: list[str] | list[int] | None) -> set[str] | None:
    """ checks the thing(s) the user wants to regenerate actually
    exist(s) and is/are still active.

    Validate every id in `target_ids` exists and is in-scope for the granularity — read-only,
    no side effects, so it's safe to call from BOTH the API endpoint (fast 404/409 instead of
    a silent task failure) and the cascade task itself (re-validated under the subsystem's
    `_LOCK`, closing the gap between those two calls). ONE batched query per granularity (plan
    item 2) — never N+1. The whole request fails atomically on ANY missing/invalid id (nothing
    is processed for a partially-valid batch). The input list is deduped first so a repeated id
    is never double-processed. Returns the resolved, deduped id set for `scenario`/`threat`/
    `threat_type`/`threat_category`, else None for `profile` (doesn't target rows at all)."""
    if granularity == RegenGranularity.profile:
        return None  # profile doesn't target one or more specific rows
    ids = list(dict.fromkeys(target_ids or []))  # dedupe, preserve order
    if not ids:
        raise RegenerateConflict(f"{granularity} regeneration requires at least one target id")
    if granularity == RegenGranularity.scenario:
        rows = sess.execute(
            select(m.Threat_Scenario_Output.c.OutputID, m.Scoped_Threat.c.ThreatID)
            .select_from(m.Threat_Scenario_Output.join(
                m.Scoped_Threat, m.Threat_Scenario_Output.c.ScopedThreatID == m.Scoped_Threat.c.ScopedThreatID))
            .where(m.Threat_Scenario_Output.c.OutputID.in_(ids),
                  m.Threat_Scenario_Output.c.SessionID == session_id,
                  m.Threat_Scenario_Output.c.SubsystemID == subsystem_id,
                  m.Threat_Scenario_Output.c.Superseded == 0)
        ).all()
        found = {r.OutputID: r.ThreatID for r in rows}
        missing = set(ids) - found.keys()
        if missing:
            raise RegenerateConflict(f"scenario output(s) not found or not active: {sorted(missing)}")
        return set(found.values())
    if granularity == RegenGranularity.threat:
        found = set(sess.execute(
            select(m.Identified_Threat.c.ThreatID).where(
                m.Identified_Threat.c.ThreatID.in_(ids),
                m.Identified_Threat.c.SessionID == session_id,
                m.Identified_Threat.c.SubsystemID == subsystem_id,
                m.Identified_Threat.c.Superseded == 0)
        ).scalars().all())
        missing = set(ids) - found
        if missing:
            raise RegenerateConflict(f"threat(s) not found or not active: {sorted(missing)}")
        return found
    if granularity == RegenGranularity.threat_type:
        found = {r["ThreatTypeID"] for r in dal.active_threat_types(sess, ids)}
        missing = set(ids) - found
        if missing:
            raise RegenerateConflict(f"threat type(s) not found or not active: {sorted(missing)}")
        return {str(i) for i in found}
    if granularity == RegenGranularity.threat_category:
        found = {r["ThreatCategoryID"] for r in dal.active_threat_categories(sess, ids)}
        missing = set(ids) - found
        if missing:
            raise RegenerateConflict(f"threat categor(y/ies) not found or not active: {sorted(missing)}")
        return {str(i) for i in found}
    return None


def _reground_one_threat(sess: Session, session: dict, sub: dict, threat_id: str,
                        llm: LLMClient, epoch: int) -> str | None:
    """The actual per-threat regrounding work, WITHOUT claiming/completing the shared
    THREATS stage cell — split out of `recheck_threat_in_library` (plan item 12) so a
    multi-threat_ids batch can claim THREATS exactly ONCE, reground every id in the loop,
    then complete the stage once — claiming per-item would fail on the 2nd+ item since
    `claim_stage` is a per-(subsystem, level) cell, not per-threat. Returns the new
    threat_id, or None if the row wasn't found (see recheck_threat_in_library's docstring
    for why that's structurally unreachable but still handled)."""
    sid, ss, tenant = session["SessionID"], sub["id"], session["TenantID"]
    row = sess.execute(
        select(m.Identified_Threat).where(
            m.Identified_Threat.c.ThreatID == threat_id,
            m.Identified_Threat.c.SessionID == sid,
            m.Identified_Threat.c.Superseded == 0,
        )
    ).mappings().first()
    if row is None:
        return None
    proposal = {
        "category": row["ThreatCategory"], "type": row["ThreatType"], "name": row["ThreatName"],
        "actors": json.loads(row["ThreatActorsJSON"] or "{}").get("actors", []),
    }
    sector_ids = json.loads(session["SectorIDsJSON"]) if session.get("SectorIDsJSON") else []
    gr = grounding.find_threat_in_library(sess, llm, proposal, sector_ids=sector_ids)
    # The OLD threat's full lineage — Identified_Threat AND its Scoped_Threat/
    # Threat_Scenario_Output rows — must be superseded HERE, keyed by the OLD
    # threat_id. The replacement gets a brand-new ThreatID with no prior Scoped_Threat
    # lineage of its own, so write_scenarios's later target_threat_id=new_tid lookup
    # correctly finds nothing to supersede (there's nothing OLD under the new id) —
    # if superseding were left to that call, the real old rows (keyed by the OLD id)
    # would never be touched and a stale duplicate scenario would linger forever.
    old_scoped_id = dal.active_scoped_threat_id(sess, sid, ss, threat_id)
    dal.supersede_by_threat(sess, m.Identified_Threat, sid, ss, threat_id)
    dal.supersede_by_threat(sess, m.Scoped_Threat, sid, ss, threat_id)
    if old_scoped_id is not None:
        dal.supersede_by_scoped_threat(sess, sid, ss, old_scoped_id)
    new_tid = _new_threat_id(sid, ss, threat_id, epoch)  # deterministic → crash-resumable ([MEDIUM-1])
    dal.insert_row(sess, m.Identified_Threat, {
        "ThreatID": new_tid, "SessionID": sid, "TenantID": tenant, "SubsystemID": ss,
        "ThreatCategory": row["ThreatCategory"], "ThreatType": row["ThreatType"], "ThreatName": row["ThreatName"],
        "ThreatActorsJSON": json.dumps({"actors": gr.actors, "validated": gr.actors_validated}),
        "LibraryThreatType": gr.library_type, "LibraryThreatName": gr.library_name,
        "ThreatTypeID": gr.type_id, "ThreatCatalogueID": gr.catalogue_id,
        "GroundingStatus": gr.status, "GroundingScore": gr.score,
        "Superseded": 0, "CreatedAt": now(),
    })
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=session["EntityID"],
                     Stage=WorkflowStage.THREAT_IDENTIFICATION, SubsystemID=ss,
                     EventType=AuditEventType.threat_regrounded,
                     DetailJSON=json.dumps({"granularity": "threat", "old_threat_id": threat_id, "new_threat_id": new_tid}))
    log.info("regen.threat_regrounded", session_id=sid, subsystem=ss, old=threat_id, new=new_tid)
    return new_tid


def recheck_threat_in_library(sess: Session, session: dict, sub: dict, threat_id: str,
                           llm: LLMClient, task_id: str, epoch: int) -> tuple[str, str] | None:
    """ re-checks one existing threat against the threat
    library again (without asking the AI for a new idea) — useful when the
    library itself has changed since the original run.

    `threat` granularity's SINGLE-item row-scoped step: claims THREATS, regrounds ONE
    existing threat proposal (via `_reground_one_threat`) — no new LLM proposal call,
    just a fresh library match (useful when masters changed since the original run) —
    then completes THREATS. Returns (new_threat_id, grounding_status), or None if the
    stage couldn't be claimed (idempotent no-op, mirrors find_threats's own claim-miss
    behavior). Still used directly by the single-target crash-resume test/callers;
    the LIST case (plan item 12) uses `_reground_one_threat` directly in a loop instead,
    claiming/completing the shared stage cell once around the whole batch."""
    sid, ss = session["SessionID"], sub["id"]
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
        return None
    new_tid = _reground_one_threat(sess, session, sub, threat_id, llm, epoch)
    if new_tid is None:
        # Validated pre-lock by get_threat_id_to_redo under this same _LOCK, so structurally unreachable
        # — but if it ever happens, don't leave the THREATS stage we just claimed stuck RUNNING
        # (LOW-3): flip it ERROR so finalize/the reaper see a terminal board, not a wedged row.
        dal.set_stage(sess, sid, ss, SubsystemLevel.THREATS, StageStatus.ERROR)
        return None
    dal.set_stage(sess, sid, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE)
    gr_status = sess.execute(
        select(m.Identified_Threat.c.GroundingStatus).where(m.Identified_Threat.c.ThreatID == new_tid)
    ).scalar()
    return new_tid, str(gr_status)


def redo_the_requested_parts(sess: Session, session: dict, sub: dict, granularity: RegenGranularity,
                     threat_ids: set[str] | None, epoch: int, llm: LLMClient, task_id: str) -> None:
    """ runs the right combination of steps depending on what's
    being regenerated (one or more scenarios, threats, a whole threat type/category, or
    the profile).

    Run the stage function(s) for one granularity at the caller-reserved `epoch`, under the
    already-held `_LOCK`. Split out of run_regeneration for length; each stage function
    (`write_profile`/`find_threats`/`write_scenarios`) claims its own
    level via `claim_stage`'s epoch CAS, so a redelivery at the same epoch no-ops any level
    already terminal ([R3]).

    `threat_ids` for `threat_type`/`threat_category` carries the RESOLVED numeric ids (as
    strings, from get_threat_id_to_redo) — converted back to int here for the DAL/prompt-scope
    calls, which need real ids, not their string form."""
    sid, subsystem_id = session["SessionID"], sub["id"]
    if granularity == RegenGranularity.scenario:
        threats = dal.active_threats(sess, sid, subsystem_id)
        tasks.write_scenarios(sess, session, sub, threats, llm, task_id, epoch=epoch, target_threat_ids=threat_ids)
    elif granularity == RegenGranularity.threat:
        new_tids: set[str] = set()
        # THREATS is claimed ONCE for the whole batch (a per-(subsystem,level) cell, not
        # per-threat) — _reground_one_threat does the per-item work without claiming/
        # completing the stage itself, so a redelivery mid-batch still CAS-no-ops correctly
        # via THIS single claim (plan item 12: per-item crash-resume is find_threat_to_resume_
        # after_crash recomputing each id's deterministic replacement, not a per-item claim).
        if threat_ids and dal.claim_stage(sess, sid, subsystem_id, SubsystemLevel.THREATS, epoch, task_id):
            for old_tid in threat_ids:
                new_tid = _reground_one_threat(sess, session, sub, old_tid, llm, epoch)
                if new_tid is not None:
                    new_tids.add(new_tid)
            dal.set_stage(sess, sid, subsystem_id, SubsystemLevel.THREATS, StageStatus.COMPLETE)
        if new_tids:
            # Full current sibling set (recheck_threat_in_library already superseded the old
            # threats and inserted their replacements) so scoping ranks each new_tid among its
            # real peers — a synthetic singleton list would rank it #1 regardless of standing.
            threats = dal.active_threats(sess, sid, subsystem_id)
            tasks.write_scenarios(sess, session, sub, threats, llm, task_id, epoch=epoch, target_threat_ids=new_tids)
    elif granularity == RegenGranularity.threat_type:
        type_ids = [int(t) for t in (threat_ids or set())]
        profile = dal.get_active_profile(sess, sid, subsystem_id) or {}
        threats, _ = tasks.find_threats(sess, session, sub, profile, llm, task_id, epoch=epoch, only_type_ids=type_ids)
        tasks.write_scenarios(sess, session, sub, threats, llm, task_id, epoch=epoch,
                              target_threat_ids={t["threat_id"] for t in threats})
    elif granularity == RegenGranularity.threat_category:
        category_ids = [int(c) for c in (threat_ids or set())]
        profile = dal.get_active_profile(sess, sid, subsystem_id) or {}
        threats, _ = tasks.find_threats(sess, session, sub, profile, llm, task_id, epoch=epoch, only_category_ids=category_ids)
        tasks.write_scenarios(sess, session, sub, threats, llm, task_id, epoch=epoch,
                              target_threat_ids={t["threat_id"] for t in threats})
    elif granularity == RegenGranularity.profile:
        profile, _ = tasks.write_profile(sess, session, sub, llm, task_id, epoch=epoch)
        threats, _ = tasks.find_threats(sess, session, sub, profile or {}, llm, task_id, epoch=epoch)
        tasks.write_scenarios(sess, session, sub, threats, llm, task_id, epoch=epoch)


def find_threat_to_resume_after_crash(sess: Session, sid: str, subsystem_id: int,
                               granularity: RegenGranularity, target_ids: list[str] | list[int] | None,
                               epoch: int) -> set[str]:
    """ figures out if a crashed regenerate job can pick up
    where it left off instead of starting over.

    Distinguish a resumable crash from a benign redelivery when get_threat_id_to_redo conflicts on a
    superseded target. For `threat` granularity a worker can crash after the threat step commits
    (old target superseded) but before the scenario step finishes; THIS epoch's deterministic
    replacement is then still active, so return it to resume the scenario step. Per-item (plan
    item 12): each target_id in the list independently computes its own deterministic replacement
    and is checked for resumability — a partial crash (some threats' scenario steps finished,
    others didn't) resumes exactly the ones still pending. Returns an empty set for every genuine
    no-op: wrong granularity, no target ids, or none of the replacements are active (a
    different-epoch regen superseded the targets, or the replacements were themselves later
    superseded). A replacement that IS active — even for an already-finished regen — is always
    safe to include: re-running its scenario step is a safe `claim_stage` no-op. [MEDIUM-1]"""
    if granularity != RegenGranularity.threat or not target_ids:
        return set()
    active = {t["threat_id"] for t in dal.active_threats(sess, sid, subsystem_id)}  # dal shape: lowercase key
    resumable = set()
    for target_id in target_ids:
        cand = _new_threat_id(sid, subsystem_id, target_id, epoch)
        if cand in active:
            resumable.add(cand)
    return resumable


def run_regeneration(sess: Session, session: dict, subsystem_id: int, granularity: RegenGranularity,
                     target_ids: list[str] | list[int] | None, epoch: int, llm: LLMClient, task_id: str,
                     user_note: str | None = None) -> str | None:
    """ the main entry point for a regenerate request — locks
    the subsystem, does the actual work, and always leaves the session in a
    clean state afterward, even if something goes wrong.

    Dispatcher: acquires the subsystem's `_LOCK` for the whole regen, runs
    the right stage function(s) at the CALLER-reserved `epoch`, and always finishes
    via `decide_session_outcome`. Returns "review" | "cancelled" | None.

    Every rejection path (bad subsystem, stale/invalid target, lock already held) is
    handled here — never raised uncaught out of a Celery task. These are NOT routed
    through `tasks._record_failure` (that call marks work rows ERROR, which would
    be wrong here: we don't yet — or never — hold the subsystem's `_LOCK`, so another
    actor may legitimately own those rows). `_record_failure` is reserved for
    genuine stage-execution failures AFTER the lock is confirmed ours."""
    sid = session["SessionID"]
    subsystems = json.loads(session["SubsystemsJSON"])
    sub = next((s for s in subsystems if s["id"] == subsystem_id), None)
    if sub is None:
        log.warning("regen.no_such_subsystem", session_id=sid, subsystem=subsystem_id)
        return tasks.decide_session_outcome(sess, session)

    resume_tids: set[str] = set()
    try:
        # Read-only, no side effects — also the scenario/threat redelivery guard: once a hop
        # succeeds its target is superseded, so a redelivered retry conflicts here.
        threat_ids = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
    except RegenerateConflict as exc:
        # Normally a benign no-op. EXCEPTION: a `threat` regen whose threat step committed but
        # whose scenario step didn't finish (crash mid-scenario) — the deterministic replacement
        # is still live, so resume ITS scenario step rather than drop the scenario ([MEDIUM-1],
        # see module docstring). Any other conflict stays the benign no-op it was.
        resume_tids = find_threat_to_resume_after_crash(sess, sid, subsystem_id, granularity, target_ids, epoch)
        if not resume_tids:
            log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
            return tasks.decide_session_outcome(sess, session)
        threat_ids = None
        log.info("regen.resume_scenario", session_id=sid, subsystem=subsystem_id, threats=sorted(resume_tids))
    except Exception as exc:  # noqa: BLE001 — a transient DB/driver error here must not escape
        # uncaught (the lock isn't held yet, so _record_failure would be wrong regardless of
        # the exception's type — same reasoning as the conflict case, for the unexpected case).
        log.error("regen.pre_lock_error", session_id=sid, subsystem=subsystem_id, error=repr(exc))
        return tasks.decide_session_outcome(sess, session)

    if not dal.acquire_lock(sess, sid, subsystem_id, task_id):
        log.warning("regen.locked", session_id=sid, subsystem=subsystem_id)
        return tasks.decide_session_outcome(sess, session)
    try:
        if resume_tids:
            # Re-derive under the just-acquired _LOCK — the pre-lock computation above only
            # guards the redelivery/crash-resume DECISION; a concurrent request (different
            # epoch) could have superseded our replacement(s) between that check and acquiring
            # the lock. Recomputing here (same function, fresh `active_threats` read) is what
            # actually closes the TOCTOU gap for this branch too — without it, a stale
            # resume_tids sails into write_scenarios and `scoped_all` filtering silently
            # produces an empty scenario set instead of a detectable no-op.
            resume_tids = find_threat_to_resume_after_crash(sess, sid, subsystem_id, granularity, target_ids, epoch)
            if not resume_tids:
                log.info("regen.resume_target_conflict", session_id=sid, subsystem=subsystem_id)
            else:
                threats = dal.active_threats(sess, sid, subsystem_id)
                tasks.write_scenarios(sess, session, sub, threats, llm, task_id, epoch=epoch, target_threat_ids=resume_tids)
        else:
            # Re-validate under the just-acquired _LOCK — the pre-lock call above only guards
            # the redelivery/crash-resume decision; a concurrent request could have superseded
            # our target(s) between that check and acquiring the lock. Re-checking here is what
            # actually closes the TOCTOU gap the module docstring (line 92) claims is closed:
            # without it, a stale threat_ids sails into redo_the_requested_parts and the row-miss
            # at _reground_one_threat (line 161) silently no-ops instead of raising/failing.
            threat_ids = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
            redo_the_requested_parts(sess, session, sub, granularity, threat_ids, epoch, llm, task_id)
        # Full audit trail (plan item 11): the actual resolved id/name list that was
        # regenerated, not just a count — a reviewer needs to see exactly what was in scope.
        # threat_type/threat_category resolve to their canonical library NAMES here (not just
        # the raw ids) since that's what a reviewer actually wants to read later.
        resolved_names = None
        # Flagged (ThreatTypeID NULL) threats are structurally unreachable by
        # supersede_by_categories' Threat_Type join (see its docstring) — a threat_category
        # regen silently leaves them untouched. Surface that gap explicitly in the audit
        # instead of reporting a clean success that omits it.
        skipped_flagged_count = None
        if granularity == RegenGranularity.threat_type and threat_ids:
            resolved_names = sorted(r["ThreatTypeName"] for r in dal.active_threat_types(sess, [int(t) for t in threat_ids]))
        elif granularity == RegenGranularity.threat_category and threat_ids:
            resolved_names = sorted(r["ThreatCategoryName"] for r in dal.active_threat_categories(sess, [int(c) for c in threat_ids]))
            skipped_flagged_count = dal.count_active_flagged_threats(sess, sid, subsystem_id)
        dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=session["TenantID"],
                         EntityID=session["EntityID"], SubsystemID=subsystem_id,
                         EventType=AuditEventType.regeneration_completed, Granularity=str(granularity),
                         DetailJSON=json.dumps({
                             "target_ids": sorted(threat_ids) if threat_ids else (sorted(resume_tids) if resume_tids else None),
                             "resolved_names": resolved_names,
                             "requested_ids": list(target_ids) if target_ids else None,
                             "skipped_flagged_count": skipped_flagged_count,
                             "epoch": epoch, "user_note": user_note}))
        sess.commit()
    except Exception as exc:  # noqa: BLE001 — capture, don't swallow ([R8], same discipline as _process_all_supporting_systems)
        tasks._record_failure(sess, session, subsystem_id, exc)
        sess.commit()
    finally:
        dal.release_lock(sess, sid, subsystem_id)
        sess.commit()

    return tasks.decide_session_outcome(sess, session)
