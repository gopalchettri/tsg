""" This file runs the AI process for every supporting system in a session.
For each supporting system, three things happen in order: the AI first writes
a short profile describing the supporting system, then it suggests possible security
threats for it, and finally it writes a full, detailed scenario for each
threat that's worth pursuing. Doing this exact same three-part process once
per supporting system, instead of once for the whole session, is what
"fan-out" means in the technical note below — the same work is repeated
("fanned out") once for every item in a list, rather than run a single time.

Pipeline orchestration — AUTO fan-out over supporting systems, Stages 1→3,
stopping at the single REVIEW.

In even simpler terms: this file is written so it can be safely tested without a real
AI hookup or a live database — you can hand it a fake AI and a temporary practice
database and everything still works the same way. It's also built so that if the same
piece of work accidentally gets attempted twice (which can genuinely happen when work
is handed off across a network), doing it twice causes no harm — the second attempt
simply notices the work is already done and skips it. Only one worker is ever allowed
to touch one supporting system at a time, so two workers can never step on each
other's work at once. If a step fails, that failure is always written down — never
silently dropped — in two places: a permanent history log, and a live "something went
wrong" message sent to anyone watching the session. And the app only ever decides a
session is "ready for human review" by directly checking its own official status
board, never by simply assuming a loop of work has finished.

Plain functions (directly unit-testable with a stub LLM + DB session); the Celery
wrapper lives in `celery_app.py`, the prompts in `prompts.py`. Idempotency under
at-least-once delivery is the Compare-And-Swap (CAS) + GenerationEpoch stage claim; each
subsystem is serialised by `_LOCK`; a stage error is captured as `ERROR` +
audit + Server-Sent Events (SSE); the REVIEW barrier is gated on the authoritative stage board
(never on loop-exit).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.enums import (
    AuditEventType, ScenarioStatus, SessionStatus, SSEEventType, StageStatus, SubsystemLevel, WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import guid, now
from app.core.config import get_settings
from app.pipeline import grounding, prompts, scoping, validation
from app.pipeline.llm import LLMClient, Provenance
from app.sse import bus

log = get_logger(__name__)

# A "generation number" used to tell different requests for the same work apart. The
# very first run of a session always uses generation number 1 (below). When someone
# later asks to regenerate something, a fresh, unique generation number is picked for
# that specific request — so if that same regenerate request accidentally gets handled
# twice, the second attempt recognizes "this exact generation is already done" and
# safely does nothing instead of duplicating the work.
_EPOCH = 1
_WORK_LEVELS = (SubsystemLevel.PROFILE, SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS)


def _ask_ai(sess: Session, llm: LLMClient, messages: list[dict], *, session: dict,
              subsystem_id: int, stage: str, expected_type: type) -> tuple[Any, Provenance | None]:
    """Sends a prompt to the AI, saves a record of exactly
    what was asked and answered, and fails loudly if the AI's reply can't be understood.

    Call the LLM, parse its reply, and log the prompt+response pair to Prompt_Log.
    Raw model output goes ONLY here, never into the client-visible
    ErrorMessage/audit/SSE channels. A parse failure raises so the stage fails
    through the existing `_record_failure` path; before raising, the
    stage's doomed uncommitted work is rolled back (exactly what the error handler
    would do next) so the failure's Prompt_Log row can commit on its own and
    survive. Success rows ride the stage's normal commit — no extra round trip."""
    text, prov = llm.chat(messages)
    if prov is not None:
        prov.prompt_version = prompts.PROMPT_VERSION
    row = {
        "LogID": guid(), "SessionID": session["SessionID"], "TenantID": session["TenantID"],
        "EntityID": session["EntityID"], "UserID": session.get("UserID"),
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
        log.warning("llm_response.parse_failed", session_id=session["SessionID"],
                    subsystem=subsystem_id, stage=stage)
        raise
    dal.insert_row(sess, m.Prompt_Log, {**row, "ParseSucceeded": True})
    return parsed, prov


def _summarize_ai_call(p: Provenance | None) -> dict | None:
    """Converts the AI-call record into a simple format for
    saving in the permanent record of what happened (the "audit trail").

    Provenance → plain-dict for audit DetailJSON; passes through None so a
    no-op stage (idempotent skip) doesn't fabricate a fake provenance record."""
    return None if p is None else {"model": p.model, "version": p.model_version,
                                   "params": p.params, "prompt_version": p.prompt_version}


def _send_live_update(session_id: str, sse_type: SSEEventType, subsystem_id: int,
          level: SubsystemLevel, status: StageStatus, epoch: int = _EPOCH) -> None:
    """Sends one live update to anyone watching this
    session's progress.

    Shared Server-Side Event (SSE) envelope for stage-started/stage-completed events, so every
    stage function publishes the same shape (session/subsystem/stage/status/epoch)."""
    bus.publish(session_id, {
        "type": str(sse_type), "session_id": session_id, "subsystem_id": subsystem_id,
        "stage": str(level), "status": str(status), "generation_epoch": epoch,
        "ts": now().isoformat(),
    })


def set_up_progress_tracking(sess: Session, session_id: str, tenant_id: str, entity_id: str, subsystems: list[dict]) -> None:
    """Creates a tracking record for every supporting system
    before any work starts, so that when a worker is ready to pick up a piece of
    work, there's already a marker there waiting for it.

    Seed per-(subsystem, level) rows so workers can Compare-And-Swap (CAS) claim them."""
    for sub in subsystems:
        for level in (*_WORK_LEVELS, SubsystemLevel.LOCK):
            dal.insert_row(sess, m.Subsystem_Stage_State, {
                "StateID": guid(), "SessionID": session_id, "TenantID": tenant_id, "EntityID": str(entity_id),
                "SubsystemID": sub["id"], "Level": level, "Status": StageStatus.IDLE,
                "GenerationEpoch": _EPOCH, "UpdatedAt": now(),
            })


def write_profile(sess: Session, session: dict, sub: dict, llm: LLMClient, task_id: str,
                epoch: int = _EPOCH) -> tuple[dict | None, Provenance | None]:
    """This is the first of the three steps described in the
    module notes above — it asks the AI to write a short description of one
    supporting system, and saves that description.

    Stage 1: Compare-And-Swap (CAS) claim PROFILE for this subsystem, generate the profile via
    LLM, and persist it. Returns (None, None) if the claim fails (already COMPLETE or
    owned by another worker) — callers must treat that as an idempotent no-op, not
    an error."""
    sid, ss, tenant, entity_id = session["SessionID"], sub["id"], session["TenantID"], session["EntityID"]
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.PROFILE, epoch, task_id):
        return None, None  # nothing to do — this step is already finished, or another worker is already handling it
    #  talking to the AI takes a while. This app handles many sessions
    # at once by having lots of small tasks quickly take turns — but the way this app
    # talks to its database can't take a "break" mid-task: once it starts waiting on
    # something, everything else sharing that same database connection has to wait
    # for it too. So right here, BEFORE we start the slow wait for the AI's reply, we
    # save ("commit") the "this stage is now RUNNING" update to the database
    # immediately. That closes out the database transaction cleanly so nothing is left
    # half-finished while we wait — so nobody else (including the cleanup job that
    # watches for crashed sessions) can get stuck waiting on us. If the app happens to
    # crash while it's still waiting on the AI, that's already handled safely
    # elsewhere — a separate safety check knows how to pick that unfinished work back
    # up later, so committing early here creates no new risk.
    #
    # Technical version: Commit the RUNNING flip NOW, before the blocking LLM call — pyodbc
    # can't yield the gevent hub, so leaving this row's lock open across the call lets any
    # other pyodbc query that touches it (e.g. the reaper, if a stage ever runs past its
    # lease) block-wait on a lock only THIS greenlet could release, freezing the whole
    # worker. Committing here makes the RUNNING flip durable and releases the lock
    # immediately; a crash before the stage finishes is exactly the "mid-flight retry
    # resumes it" case claim_stage's own CAS (same task_id) already handles.
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.PROFILE, StageStatus.RUNNING, epoch)
    profile, prov = _ask_ai(sess, llm, prompts.profile_prompt(session["AssetName"], sub),
                              session=session, subsystem_id=ss, stage="profile", expected_type=dict)
    val = validation.validate_profile(profile, sub["name"])  # checks the profile for obvious problems and notes them for a human reviewer — it never stops the pipeline, just leaves a note
    dal.supersede(sess, m.Subsystem_Profile, sid, ss)
    dal.insert_row(sess, m.Subsystem_Profile, {
        "ProfileID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "SubsystemID": ss,
        "ProfileJSON": json.dumps(profile), "ValidationJSON": json.dumps(val),
        "Accepted": 0, "Superseded": 0, "CreatedAt": now(),
    })
    dal.set_stage(sess, sid, ss, SubsystemLevel.PROFILE, StageStatus.COMPLETE)
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.PROFILE, StageStatus.COMPLETE, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="PROFILE")
    return profile, prov


def _safe_text(v: Any, default: str | None) -> str | None:
    """Safely turns an AI-provided value into text, or a
    safe default if it's not text.

    Coerce an untrusted model field to `str`, or `default` for null / non-string, before it
    reaches a DB string column; a `None` default lets the nullable `ThreatName` column stay
    NULL. Now DELEGATES to `grounding.ensure_text` rather than mirroring it, so the two can never
    drift apart."""
    return grounding.ensure_text(v, default)


def find_threats(sess: Session, session: dict, sub: dict, profile: dict, llm: LLMClient, task_id: str,
                 epoch: int = _EPOCH) -> tuple[list[dict], Provenance | None]:
    """This is the second of the three steps — it asks the
    AI to suggest possible security threats for the supporting system, then
    checks each suggested threat against the organization's real, approved
    threat library.

    Stage 2: CAS-claim THREATS, ask the LLM for threat proposals, then
    ground each one before persisting. Returns ([], None) on a
    failed claim — same idempotent-no-op contract as write_profile."""
    sid, ss, tenant = session["SessionID"], sub["id"], session["TenantID"]
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
        return [], None
    sess.commit()  # saves progress to the database before waiting on the AI's reply — same reason explained in write_profile above
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.THREATS, StageStatus.RUNNING, epoch)
    proposals, prov = _ask_ai(sess, llm, prompts.threats_prompt(session["AssetName"], sub, profile),
                                session=session, subsystem_id=ss, stage="threats", expected_type=list)
    dal.supersede(sess, m.Identified_Threat, sid, ss)
    threats: list[dict] = []
    sector_ids = json.loads(session["SectorIDsJSON"]) if session.get("SectorIDsJSON") else []
    for p in proposals:
        # The AI's raw reply can't be fully trusted to have the right shape — it might send a
        # number, or nothing at all, where we expect text. This next part makes sure we only
        # ever try to save real text into the database, so a surprising reply from the AI can
        # never cause a database error.
        ptype = _safe_text(p.get("type"), "")
        pcat = _safe_text(p.get("category"), "")
        pname = _safe_text(p.get("name"), None)  # it's okay for the threat's name to be left blank in the database, so we allow that here
        gr = grounding.find_threat_in_library(sess, llm, p, sector_ids=sector_ids)
        tid = guid()
        dal.insert_row(sess, m.Identified_Threat, {
            "ThreatID": tid, "SessionID": sid, "TenantID": tenant, "SubsystemID": ss,
            "ThreatCategory": pcat, "ThreatType": ptype,
            "ThreatName": pname,
            # Save whether these attacker types were actually double-checked against the real
            # library, alongside the list itself — so later, when deciding whether a newly
            # found threat is safe to add to the shared library, the app can tell the
            # difference between a checked list and an unchecked one.
            "ThreatActorsJSON": json.dumps({"actors": gr.actors, "validated": gr.actors_validated}),
            "LibraryThreatType": gr.library_type, "LibraryThreatName": gr.library_name,
            "ThreatTypeID": gr.type_id, "ThreatCatalogueID": gr.catalogue_id,
            "GroundingStatus": gr.status, "GroundingScore": gr.score,
            "Superseded": 0, "CreatedAt": now(),
        })
        threats.append({
            "threat_id": tid, "grounding_status": str(gr.status),
            "threat_type": ptype, "threat_name": pname,
            "library_threat_type": gr.library_type, "library_threat_name": gr.library_name,
            "threat_type_id": gr.type_id,  # the real threat type this was matched to, needed later so the scoring step knows what kind of threat this is
        })
    dal.set_stage(sess, sid, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE)
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=session["EntityID"],
                     Stage=WorkflowStage.THREAT_IDENTIFICATION, SubsystemID=ss,
                     EventType=AuditEventType.grounding_summary,
                     DetailJSON=json.dumps({"count": len(threats)}))
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="THREATS", count=len(threats))
    return threats, prov


def _write_one_scenario(sess: Session, session: dict, sub: dict, sc, scoped_id: str,
                       enriched: dict, llm: LLMClient, epoch: int) -> Provenance | None:
    """Writes and saves one full scenario for one threat
    that's been selected.

    Generate + persist ONE scenario for a selected scoped threat; returns its provenance.
    Library-grounded type/name win (canonical catalogue terminology), falling back to the AI's
    raw Stage-1 proposal for flagged/no-match threats so even an ungrounded threat still gets
    *something*, never silently reverting to blind."""
    sid, ss, tenant = session["SessionID"], sub["id"], session["TenantID"]
    info = enriched.get(sc.threat_id, {})
    threat_type = info.get("library_threat_type") or info.get("threat_type")
    threat_name = info.get("library_threat_name") or info.get("threat_name")
    scenario, prov = _ask_ai(sess, llm, prompts.scenario_prompt(session["AssetName"], sub, threat_type, threat_name),
                               session=session, subsystem_id=ss, stage="scenario", expected_type=dict)
    identity = hashlib.sha256(f"{sid}|{scoped_id}".encode()).hexdigest()  # a unique fingerprint for this exact scenario, used to detect if it's ever accidentally generated twice
    dal.insert_row(sess, m.Threat_Scenario_Output, {
        "OutputID": guid(), "SessionID": sid, "TenantID": tenant, "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.complete,
        "ScenarioJSON": json.dumps(scenario),
        "ValidationJSON": json.dumps(validation.validate_scenario(scenario, threat_type, threat_name)),  # a note recording whether this scenario passed its automatic sanity checks
        "AcceptedSubsetJSON": None, "Accepted": 0, "Superseded": 0,
        "IdentityHash": identity, "GenerationEpoch": epoch, "ErrorMessage": None, "CreatedAt": now(),
    })
    return prov


def write_scenarios(sess: Session, session: dict, sub: dict, threats: list[dict], llm: LLMClient, task_id: str,
                  epoch: int = _EPOCH, target_threat_ids: set[str] | None = None) -> list[Provenance]:
    """This is the third and final step — it scores and
    ranks all the threats found in the previous step, then writes a full,
    detailed scenario for each threat that's worth pursuing.

    `target_threat_ids` (M2 row-scoped regen, [R9], plan item 3): when set, only the
    scoped-threat/scenario pairs matching ids IN THIS SET are superseded+rebuilt — siblings
    are left untouched. A `set` (not a list) for O(1) membership checks. `threats` still
    needs every active threat for the subsystem so `scoping.score_threats` ranks the
    target(s) against their real siblings; only the supersede+insert is narrowed. The
    existing per-id supersede calls still run once per id in the set — one UPDATE per row,
    not a new N+1 (each row's audit-relevant state is superseded individually by design)."""
    sid, ss, tenant = session["SessionID"], sub["id"], session["TenantID"]
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id):
        return []
    sess.commit()  # saves progress to the database before making the (possibly many) AI calls below — same reason explained in write_profile above
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.SCENARIOS, StageStatus.RUNNING, epoch)
    # Look up any scoring rules that apply to these threats' matched types, and read the
    # score/count limits from the app's settings — these decide which threats are worth
    # writing a full scenario for.
    type_ids = sorted({t["threat_type_id"] for t in threats if t.get("threat_type_id") is not None})
    settings = get_settings()
    scoped_all = scoping.score_threats(threats, subsystem=sub, rules=dal.active_threat_rules(sess, type_ids),
                                       score_threshold=settings.scoping_score_threshold, top_n=settings.scoping_top_n)
    enriched = {t["threat_id"]: t for t in threats}
    if target_threat_ids is not None:
        scoped = [sc for sc in scoped_all if sc.threat_id in target_threat_ids]
        # The saved scenario is linked to a specific scoring record, not directly to the
        # threat itself — so before we retire the old scoring records, we need to note which
        # ones they are, so the scenarios tied to them can be retired too. Batched (one SELECT
        # + 2 UPDATEs total for the whole target set), not a per-id loop — up to
        # _MAX_BATCH=50 targets no longer costs up to 150 sequential DB round-trips.
        old_scoped_ids = dal.active_scoped_threat_ids(sess, sid, ss, target_threat_ids)
        dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, target_threat_ids)
        dal.supersede_by_scoped_threats(sess, sid, ss, old_scoped_ids)
    else:
        scoped = scoped_all
        dal.supersede(sess, m.Scoped_Threat, sid, ss)
        dal.supersede(sess, m.Threat_Scenario_Output, sid, ss)
    provs: list[Provenance] = []
    for sc in scoped:
        scoped_id = guid()
        dal.insert_row(sess, m.Scoped_Threat, {
            "ScopedThreatID": scoped_id, "SessionID": sid, "TenantID": tenant, "SubsystemID": ss,
            "ThreatID": sc.threat_id, "Score": sc.score, "ScopeRank": sc.rank,
            "Selected": 1 if sc.selected else 0, "Reason": sc.reason,
            "FactorsJSON": json.dumps(sc.factors) if sc.factors else None,  # a record of exactly which scoring rules affected this threat's score, kept for transparency
            "Superseded": 0, "CreatedAt": now(),
        })
        if sc.selected:
            provs.append(_write_one_scenario(sess, session, sub, sc, scoped_id, enriched, llm, epoch))
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=session["EntityID"],
                     Stage=WorkflowStage.SCENARIO_GENERATION, SubsystemID=ss,
                     EventType=AuditEventType.scoping_complete,
                     DetailJSON=json.dumps({"scoped": len(scoped), "selected": len(provs)}))
    # This step always ends by marking the subsystem as ready for a human to review —
    # that's the one and only point where the app pauses and waits for a person.
    dal.set_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION)
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="SCENARIOS", scenarios=len(provs))
    return provs


def _record_failure(sess: Session, session: dict, subsystem_id: int, exc: Exception) -> None:
    """When something goes wrong in a step, this records
    the failure clearly so it's never silently lost.

    Capture a stage failure durably: mark the failed/unrun work levels ERROR,
    audit it, and emit an error SSE event so it can never vanish silently."""
    sess.rollback()  # undo any half-finished changes from the step that just failed, including its "in progress" marker, so nothing incomplete gets left behind
    sid = session["SessionID"]
    # Most raw error messages might accidentally contain sensitive internal details (like
    # database or AI-service addresses), so we don't show the raw error to the end user —
    # instead they get a generic "something went wrong" message, and the FULL detail is
    # only written to the server's own private log below. The one exception is a specific,
    # already-safe error about the AI's reply being unreadable, which is fine to show as-is.
    client_msg = repr(exc) if isinstance(exc, validation.LLMResponseParseError) else "stage processing failed"
    sess.execute(
        update(m.Subsystem_Stage_State)
        .where(m.Subsystem_Stage_State.c.SessionID == sid,
               m.Subsystem_Stage_State.c.SubsystemID == subsystem_id,
               m.Subsystem_Stage_State.c.Level.in_(list(_WORK_LEVELS)),
               m.Subsystem_Stage_State.c.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]))
        .values(Status=StageStatus.ERROR, ErrorMessage=client_msg, LeaseExpiresAt=None, UpdatedAt=now())
    )
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=session["TenantID"], EntityID=session["EntityID"],
                     SubsystemID=subsystem_id, EventType=AuditEventType.stage_error,
                     DetailJSON=json.dumps({"error": client_msg, "subsystem_id": subsystem_id}))
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid, "subsystem_id": subsystem_id,
                      "message": client_msg, "ts": now().isoformat()})
    log.error("stage.error", session_id=sid, subsystem=subsystem_id, error=repr(exc))  # full detail: server-side only


def decide_session_outcome(sess: Session, session: dict) -> str | None:
    """Looks at the status of every supporting system in the session and decides what
    happens next, once nothing is still actively being worked on. If at least one
    supporting system finished successfully, the whole session is handed over for a
    human to review and approve — even if some other supporting systems failed along
    the way, since the good ones aren't held back by the bad ones. If EVERY supporting
    system failed, the whole session is marked as failed instead. This function is
    carefully written so it's safe to call more than once by accident — for example if
    the normal pipeline and a separate background cleanup job both try to finish the
    same session at nearly the same moment — only one of those attempts actually takes
    effect, and neither can undo a decision the other already made.

    TOTAL terminal transition once no work is in flight — the single place a
    session leaves the running state. Returns "review", "cancelled", or None (no change).
    Called after the pipeline loop AND by the reaper (the safety net for a worker that
    died before it could finalize).

    Decision from the authoritative stage board (never loop-exit):
      - a work row still IDLE/RUNNING  → still in flight (this or another worker) → wait;
      - at least one subsystem reached the review barrier (AWAITING_DECISION)
                                       → REVIEW: partial *or* full success. The human
                                         accepts the good subsystems; errored ones are
                                         flagged. The M4 lock is held for the review (a
                                         legitimate wait, not a leak — the reaper exempts REVIEW);
      - every subsystem errored        → terminal `cancelled` (reason=all failed), which
                                         releases the coarse M4 per-asset lock so the asset
                                         is immediately retryable.

    Idempotent: both transitions are CAS updates guarded on `active AND stage != REVIEW`,
    so REVIEW and the failure-cancel are mutually exclusive and overlapping callers
    (pipeline + reaper, or a redelivered task) can't double-fire or cancel a REVIEW session.
    """
    sid = session["SessionID"]
    statuses = [str(r["Status"]) for r in dal.stage_rows(sess, sid)]
    if not statuses or any(s in (StageStatus.IDLE, StageStatus.RUNNING) for s in statuses):
        return None  # nothing seeded yet, or work still in flight
    if any(s == StageStatus.AWAITING_DECISION for s in statuses):
        return "review" if _send_to_review(sess, session) else None
    if any(s == StageStatus.ERROR for s in statuses):
        return "cancelled" if _mark_session_failed(sess, session) else None
    # This situation should never actually happen in normal use (the last step always
    # leaves something waiting for review) — but if it somehow does, we don't guess what
    # to do next. We just write a warning to the log so a human notices and investigates,
    # instead of silently leaving a session stuck in a confusing in-between state.
    log.warning("finalize.no_terminal_state", session_id=sid, statuses=statuses)
    return None


def _send_to_review(sess: Session, session: dict) -> bool:
    """Flips the session into "waiting for human review" mode — but only if nobody
    else has already done so at the exact same moment; if someone else already moved
    it into review a split second earlier, this quietly backs off instead of doing it
    twice.

    CAS-flip the session into the REVIEW barrier (§6.1). Returns False if another
    concurrent decide_session_outcome caller (pipeline vs. reaper, or a redelivered task)
    already won the race, so the caller knows not to double-report "review"."""
    sid = session["SessionID"]
    res = sess.execute(
        update(m.Scenario_Session)
        .where(m.Scenario_Session.c.SessionID == sid,
               m.Scenario_Session.c.SessionStatus == SessionStatus.active,
               m.Scenario_Session.c.CurrentStage != WorkflowStage.REVIEW)
        .values(CurrentStage=WorkflowStage.REVIEW, StageStatus=StageStatus.AWAITING_DECISION, UpdatedAt=now())
    )
    if res.rowcount != 1:
        return False  # someone else already moved this session into review a moment ago, or it's no longer active — either way, there's nothing more for this attempt to do
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=session["TenantID"],
                     EntityID=session["EntityID"], Stage=WorkflowStage.REVIEW, EventType=AuditEventType.entered_review)
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.session_entered_review), "session_id": sid,
                      "status": str(StageStatus.AWAITING_DECISION), "ts": now().isoformat()})
    log.info("pipeline.entered_review", session_id=sid)
    return True


def _mark_session_failed(sess: Session, session: dict) -> bool:
    """Marks the whole session as failed. This only happens when EVERY supporting
    system ran into an error — if even one supporting system got as far as being
    ready for review, the session goes to review instead, never to failed.

    Every subsystem errored → terminal cancel, releasing the M4 lock. CAS-guarded on
    `active AND stage != REVIEW` so it can never cancel a session that concurrently
    reached REVIEW (REVIEW dominates). Sets CurrentStage/StageStatus to CANCELLED too
    (mirrors dal.cancel_session) so the board doesn't keep showing stale progress for
    a session that's actually dead."""
    sid = session["SessionID"]
    res = sess.execute(
        update(m.Scenario_Session)
        .where(m.Scenario_Session.c.SessionID == sid,
               m.Scenario_Session.c.SessionStatus == SessionStatus.active,
               m.Scenario_Session.c.CurrentStage != WorkflowStage.REVIEW)
        .values(SessionStatus=SessionStatus.cancelled, CurrentStage=WorkflowStage.CANCELLED,
                StageStatus=StageStatus.CANCELLED, UpdatedAt=now())
    )
    if res.rowcount != 1:
        return False
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=session["TenantID"], EntityID=session["EntityID"],
                     EventType=AuditEventType.session_cancelled, DetailJSON=json.dumps({"reason": "all subsystems failed"}))
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid,
                      "message": "session failed: all subsystems errored", "ts": now().isoformat()})
    log.warning("pipeline.failed", session_id=sid)
    return True


def _announce_starting_supporting_system(sess: Session, session: dict, sub: dict, idx: int) -> None:
    """Tells anyone watching that the pipeline has started
    working on a new supporting system. This message is only ever sent once per
    supporting system, even if the background job restarts and re-checks work it's
    already finished — it won't repeat the announcement for something already done.

    One-time 'subsystem advanced' audit + SSE signal, emitted ONLY when the subsystem has
    genuinely pending work. A Celery redelivery restarts the loop from index 0 and walks back
    through already-COMPLETE subsystems; without this gate each redelivery would re-announce
    (duplicate audit row + SSE) work nothing is about to happen to — claim_stage guards the real
    stage work, but this one-time signal has no CAS of its own, so it needs this gate instead."""
    if not dal.subsystem_has_pending_work(sess, session["SessionID"], sub["id"]):
        return
    sid = session["SessionID"]
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=session["TenantID"],
                     EntityID=session["EntityID"], SubsystemID=sub["id"],
                     EventType=AuditEventType.subsystem_advanced,
                     DetailJSON=json.dumps({"subsystem_index": idx, "subsystem_id": sub["id"]}))
    bus.publish(sid, {"type": str(SSEEventType.subsystem_started), "session_id": sid,
                      "subsystem_id": sub["id"], "subsystem_index": idx, "ts": now().isoformat()})


def _process_all_supporting_systems(sess: Session, session_id: str, llm: LLMClient, task_id: str) -> None:
    """The main loop — goes through every supporting system
    in the session, one at a time, running all three steps (profile, then
    threats, then scenarios) for each one. If one supporting system runs into a
    problem, that failure is recorded and the loop simply moves on to the next
    supporting system — one bad supporting system never stops the others from
    being processed.

    Top-level orchestration for one session: per-subsystem M4 lock,
    then Stages 1→3 in order, committing after each stage so a crash mid-subsystem
    resumes cleanly rather than replaying from an in-memory checkpoint. A stage
    exception is caught here (not left to escape to the Celery wrapper) so one
    subsystem's failure doesn't abort the others still queued in this loop. The
    Celery task wrapper in celery_app.py calls this directly."""
    session = dal.load_session(sess, session_id)
    if session is None:
        return
    session = dict(session)
    subsystems = json.loads(session["SubsystemsJSON"])
    log.info("pipeline.start", session_id=session_id, subsystems=len(subsystems), task_id=task_id)
    for idx, sub in enumerate(subsystems):
        if not dal.acquire_lock(sess, session_id, sub["id"], task_id):
            log.warning("subsystem.locked", session_id=session_id, subsystem=sub["id"])
            continue
        try:
            sess.execute(update(m.Scenario_Session)
                         .where(m.Scenario_Session.c.SessionID == session_id)
                         .values(CurrentSubsystemIndex=idx, UpdatedAt=now()))
            _announce_starting_supporting_system(sess, session, sub, idx)
            profile, prov_p = write_profile(sess, session, sub, llm, task_id)
            sess.commit()
            # If this exact step was already finished in an earlier attempt (for example,
            # the worker crashed and this whole function is now running again), the
            # function above won't redo the work — it just comes back with nothing new. So
            # here we check: if we got nothing back, go fetch the ALREADY-SAVED result from
            # the database instead, so the next step always has real information to work
            # with, rather than accidentally working from an empty blank.
            if profile is None:
                profile = dal.get_active_profile(sess, session_id, sub["id"])
            threats, prov_i = find_threats(sess, session, sub, profile or {}, llm, task_id)
            sess.commit()
            if not threats:  # same idea as above: either this step was already done before, or there truly are no threats — either way, re-checking the database gives the right answer
                threats = dal.active_threats(sess, session_id, sub["id"])
            scen_provs = write_scenarios(sess, session, sub, threats, llm, task_id)
            # Save a record of exactly which AI calls produced this subsystem's results,
            # all together in one entry in the permanent history log.
            dal.append_audit(sess, AuditID=guid(), SessionID=session_id, TenantID=session["TenantID"],
                             EntityID=session["EntityID"], Stage=WorkflowStage.SCENARIO_GENERATION,
                             SubsystemID=sub["id"], EventType=AuditEventType.generation_complete,
                             DetailJSON=json.dumps({
                                 "subsystem_id": sub["id"], "profile_provenance": _summarize_ai_call(prov_p),
                                 "identify_provenance": _summarize_ai_call(prov_i),
                                 "scenario_provenances": [_summarize_ai_call(p) for p in scen_provs],
                                 "scenario_count": len(scen_provs)}))
            sess.commit()
        except Exception as exc:  # noqa: BLE001 — catch any problem here so it gets recorded properly, never let it silently disappear
            _record_failure(sess, session, sub["id"], exc)
            sess.commit()
        finally:
            dal.release_lock(sess, session_id, sub["id"])
            sess.commit()

    decide_session_outcome(sess, session)
