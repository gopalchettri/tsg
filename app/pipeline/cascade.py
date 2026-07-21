""" handles "regenerate" requests — redoing just one or more scenarios
of a session instead of starting the entire subsystem over from scratch.

Regeneration cascade  — redo a subsystem's
scenario(s) without re-running the whole pipeline.

Row-scoped so redoing one bad item doesn't discard its siblings (the actual
point of the feature).

Reuses the exact CAS/lock/epoch machinery `tasks.py` uses for the initial run:
`dal.acquire_lock` for the `_LOCK` mutex, mutual exclusion with accept),
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
from app.core.security import redact
from app.db import dal
from app.db import models as m
from app.db.dal import RegenerateConflict, guid
from app.pipeline import tasks
from app.pipeline.llm import LLMClient, LLMSlotUnavailable

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
    """Turn the caller's requested target ids into the set of ThreatIDs to redo.

    Checks that every requested id still points to an active (non-superseded)
    scenario output for this session/subsystem, and raises RegenerateConflict if
    none were given or if any id doesn't resolve to a real, active row.
    """
    ids = list(dict.fromkeys(target_ids or []))  # dedupe, preserve order
    if not ids:
        raise RegenerateConflict(f"{granularity} regeneration requires at least one target id")
    rows = sess.execute(
        select(m.Threat_Scenario_Output.OutputID, m.Scoped_Threat.ThreatID)
        .select_from(m.Threat_Scenario_Output.__table__.join(
            m.Scoped_Threat, m.Threat_Scenario_Output.ScopedThreatID == m.Scoped_Threat.ScopedThreatID))
        .where(m.Threat_Scenario_Output.OutputID.in_(ids),
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.SubsystemID == subsystem_id,
            m.Threat_Scenario_Output.Superseded == 0)
    ).all()
    found = {r.OutputID: r.ThreatID for r in rows}
    # any requested id that the query above didn't return is stale, superseded, or doesn't belong here
    missing = set(ids) - found.keys()
    if missing:
        # key=str: target_ids/ids are str|int depending on caller, so there's no single type
        # mypy can prove orderable across the union — sort by string form instead.
        raise RegenerateConflict(f"scenario output(s) not found or not active: {sorted(missing, key=str)}")
    return set(found.values())


def _resolve_regen_subsystem(scenario_session: dict, subsystem_id: int) -> tuple[list[dict], dict, dict | None]:
    """Parse the session's subsystem/asset-context JSON and look up the requested subsystem's config."""
    subsystems = json.loads(scenario_session["SubsystemsJSON"])
    asset_context = json.loads(scenario_session.get("AssetContextJSON") or "{}")
    # find the requested subsystem's config among the session's subsystems
    sub = next((s for s in subsystems if s["id"] == subsystem_id), None)
    return subsystems, asset_context, sub


def _build_regen_audit_detail(threat_ids: set[str] | None, target_ids: list[str] | list[int] | None,
                            epoch: int, user_note: str | None) -> str:
    """Build the DetailJSON payload for the regeneration-completed audit record.

    [REVIEW-FIX] user_note is raw, unvalidated client free text (never reaches an LLM prompt —
    confirmed, this isn't a prompt-injection path) but was previously written to the persistent
    audit trail verbatim. redact() here matches the treatment every other free-text value in this
    codebase gets before being persisted or logged."""
    return json.dumps({
        "target_ids": sorted(threat_ids) if threat_ids else None,
        "requested_ids": list(target_ids) if target_ids else None,
        "epoch": epoch, "user_note": redact(user_note)})


def run_regeneration(sess: Session, scenario_session: dict, subsystem_id: int, granularity: RegenGranularity,
                    target_ids: list[str] | list[int] | None, epoch: int, llm: LLMClient, task_id: str,
                    user_note: str | None = None) -> str | None:
    """Redo scenario generation for one subsystem's targeted threat(s) instead of the whole pipeline.

    Validates the request, takes the per-subsystem lock, re-runs scenario generation
    for just the requested threats, writes an audit record, and always releases the
    lock afterwards. Any failure along the way is recorded rather than raised, and
    the function falls back to the normal session-outcome decision either way.
    """
    sid = scenario_session["SessionID"]
    subsystems, asset_context, sub = _resolve_regen_subsystem(scenario_session, subsystem_id)
    if sub is None:
        log.warning("regen.no_such_subsystem", session_id=sid, subsystem=subsystem_id)
        return tasks.decide_session_outcome(sess, scenario_session)

    try:
        # fail fast, before taking the lock, if the requested target ids don't resolve to real threats
        threat_ids = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
    except RegenerateConflict as exc:
        log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
        return tasks.decide_session_outcome(sess, scenario_session)
    except Exception as exc:  # noqa: BLE001 — a transient DB/driver error here must not escape
        log.error("regen.pre_lock_error", session_id=sid, subsystem=subsystem_id, error=repr(exc))
        return tasks.decide_session_outcome(sess, scenario_session)

    if not dal.acquire_lock(sess, sid, subsystem_id, task_id):
        # someone else holds the lock (another regen/pipeline run in flight) — bail out without changing anything
        log.warning("regen.locked", session_id=sid, subsystem=subsystem_id)
        return tasks.decide_session_outcome(sess, scenario_session)
    # Make the lock durable BEFORE any other work: an exception below routes through
    # tasks._record_failure's unconditional rollback, which would otherwise undo this
    # still-uncommitted acquire_lock too (same invariant as tasks.py's find_threats /
    # write_scenarios / _process_all_supporting_systems committing right after their own
    # claim_stage/acquire_lock succeeds).
    sess.commit()
    try:
        # re-check target ids now that we hold the lock, in case state changed between the pre-check above and here
        threat_ids = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
        threats = dal.active_threats(sess, sid, subsystem_id)
        # asset_active_fields/sub_active_fields deliberately NOT passed — a regeneration
        # intentionally reflects the CURRENT Context_Field_Config policy, not whatever was active
        # when the session originally ran. If a curator has since turned a field off (e.g. for a
        # compliance reason), a freshly regenerated scenario should honor that, not keep sending
        # a field the curator explicitly disabled. write_scenarios resolves this once for the
        # whole call (not once per threat) when left unset — see its own comment.
        scen_provs = tasks.write_scenarios(sess, scenario_session, sub, asset_context, threats, llm, task_id,
                                        epoch=epoch, target_threat_ids=threat_ids, require_lock=True)
        if not scen_provs:
            raise RuntimeError("regeneration claim lost mid-flight (stage reaped or superseded)")
        dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                        EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                        EventType=AuditEventType.regeneration_completed, Granularity=str(granularity),
                        DetailJSON=_build_regen_audit_detail(threat_ids, target_ids, epoch, user_note))
        sess.commit()
    except RegenerateConflict as exc:
        # same benign race as the pre-lock check above (the target became stale between
        # acquiring the lock and re-checking it — a concurrent regen/accept superseded it
        # in the gap). Not a real pipeline failure: no ERROR state, no audit row, no SSE
        # error event — just report the outcome as-is, same as the pre-lock check does.
        log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
    except LLMSlotUnavailable:
        # Same treatment as _process_all_supporting_systems: a temporary "system was busy"
        # condition, not a bug — re-raise past _record_failure so Celery's autoretry_for
        # (celery_app.py) retries this regeneration shortly instead of recording a permanent
        # ERROR.
        raise
    except Exception as exc:  # noqa: BLE001 — capture, don't swallow ([R8], same discipline as _process_all_supporting_systems)
        tasks._record_failure(sess, scenario_session, subsystem_id, exc, epoch)
        sess.commit()
    finally:
        # Always release the lock, even if the try block above failed, so the subsystem doesn't
        # stay stuck locked. A release failure (or the commit that makes it durable) is only
        # logged, not re-raised, so it can't break this function's contract of always falling
        # through to decide_session_outcome below (same discipline as accept.py's accept_session
        # lock-release cleanup).
        try:
            if not dal.release_lock(sess, sid, subsystem_id, task_id):
                log.warning("regen.lock_lost", session_id=sid, subsystem=subsystem_id, task_id=task_id)
            sess.commit()
        except Exception:
            log.warning("regen.lock_release_failed", session_id=sid, subsystem=subsystem_id)

    return tasks.decide_session_outcome(sess, scenario_session)
