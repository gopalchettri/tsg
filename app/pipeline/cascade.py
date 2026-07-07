""" handles "regenerate" requests — redoing just one or more scenarios
of a session instead of starting the entire subsystem over from scratch.

Regeneration cascade (SDD [R9], reusing [R1]/[R3]/[R5]) — redo a subsystem's
scenario(s) without re-running the whole pipeline.

Row-scoped so redoing one bad item doesn't discard its siblings (the actual
point of the feature).

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
"""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import AuditEventType, RegenGranularity, SubsystemLevel
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import RegenerateConflict, guid
from app.pipeline import tasks
from app.pipeline.llm import LLMClient

log = get_logger(__name__)

# The endpoint (sessions.py::post_regenerate) resets exactly these levels to IDLE before
# dispatching the task; run_regeneration below MUST regenerate the same set. These two are
# the sole sources of truth for "what a granularity touches" — add a level here and you
# must add it to run_regeneration too, or the endpoint resets a stage nothing regenerates
# (stuck IDLE → reaper).
LEVELS_BY_GRANULARITY = {
    RegenGranularity.scenario: (SubsystemLevel.SCENARIOS,),
}


def get_threat_id_to_redo(sess: Session, session_id: str, subsystem_id: int,
                   granularity: RegenGranularity, target_ids: list[str] | list[int] | None) -> set[str] | None:
    """ checks the thing(s) the user wants to regenerate actually
    exist(s) and is/are still active.

    Validate every id in `target_ids` exists and is in-scope for the granularity — read-only,
    no side effects, so it's safe to call from BOTH the API endpoint (fast 404/409 instead of
    a silent task failure) and the cascade task itself (re-validated under the subsystem's
    `_LOCK`, closing the gap between those two calls). ONE batched query (plan item 2) —
    never N+1. The whole request fails atomically on ANY missing/invalid id (nothing is
    processed for a partially-valid batch). The input list is deduped first so a repeated id
    is never double-processed. Returns the resolved, deduped ThreatID set."""
    ids = list(dict.fromkeys(target_ids or []))  # dedupe, preserve order
    if not ids:
        raise RegenerateConflict(f"{granularity} regeneration requires at least one target id")
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


def run_regeneration(sess: Session, session: dict, subsystem_id: int, granularity: RegenGranularity,
                     target_ids: list[str] | list[int] | None, epoch: int, llm: LLMClient, task_id: str,
                     user_note: str | None = None) -> str | None:
    """ the main entry point for a regenerate request — locks
    the subsystem, does the actual work, and always leaves the session in a
    clean state afterward, even if something goes wrong.

    Dispatcher: acquires the subsystem's `_LOCK` for the whole regen, rebuilds the
    target scenario(s) at the CALLER-reserved `epoch`, and always finishes via
    `decide_session_outcome`. Returns "review" | "cancelled" | None.

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

    try:
        # Read-only, no side effects — also the redelivery guard: once a hop succeeds its
        # target is superseded, so a redelivered retry conflicts here.
        threat_ids = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
    except RegenerateConflict as exc:
        # Benign no-op — the target was already superseded by an earlier attempt/redelivery.
        log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
        return tasks.decide_session_outcome(sess, session)
    except Exception as exc:  # noqa: BLE001 — a transient DB/driver error here must not escape
        # uncaught (the lock isn't held yet, so _record_failure would be wrong regardless of
        # the exception's type).
        log.error("regen.pre_lock_error", session_id=sid, subsystem=subsystem_id, error=repr(exc))
        return tasks.decide_session_outcome(sess, session)

    if not dal.acquire_lock(sess, sid, subsystem_id, task_id):
        log.warning("regen.locked", session_id=sid, subsystem=subsystem_id)
        return tasks.decide_session_outcome(sess, session)
    try:
        # Re-validate under the just-acquired _LOCK — the pre-lock call above only guards
        # the redelivery decision; a concurrent request could have superseded our target(s)
        # between that check and acquiring the lock. Re-checking here is what actually
        # closes the TOCTOU gap the module docstring claims is closed: without it, a stale
        # threat_ids would sail into write_scenarios and silently no-op instead of
        # raising/failing.
        threat_ids = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
        threats = dal.active_threats(sess, sid, subsystem_id)
        tasks.write_scenarios(sess, session, sub, threats, llm, task_id, epoch=epoch, target_threat_ids=threat_ids)
        # Full audit trail (plan item 11): the actual resolved id list that was
        # regenerated, not just a count — a reviewer needs to see exactly what was in scope.
        dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=session["TenantID"],
                         EntityID=session["EntityID"], SubsystemID=subsystem_id,
                         EventType=AuditEventType.regeneration_completed, Granularity=str(granularity),
                         DetailJSON=json.dumps({
                             "target_ids": sorted(threat_ids) if threat_ids else None,
                             "requested_ids": list(target_ids) if target_ids else None,
                             "epoch": epoch, "user_note": user_note}))
        sess.commit()
    except Exception as exc:  # noqa: BLE001 — capture, don't swallow ([R8], same discipline as _process_all_supporting_systems)
        tasks._record_failure(sess, session, subsystem_id, exc)
        sess.commit()
    finally:
        dal.release_lock(sess, sid, subsystem_id)
        sess.commit()

    return tasks.decide_session_outcome(sess, session)
