from __future__ import annotations

import json

from sqlalchemy import RowMapping, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    AuditDecision,
    AuditEventType,
    ReviewGateReason,
    ScenarioDecisionReason,
    SessionStatus,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import EntityForbidden, NotFoundError, guid, now
from app.sse import bus

log = get_logger(__name__)


_REASON_TEXT = {
    ScenarioDecisionReason.failure_card: "failed to generate, so it has no content to accept",
    ScenarioDecisionReason.subsystem_not_awaiting_decision: "is not ready for review yet",
    ScenarioDecisionReason.unknown: "is not a scenario in this session",
    ScenarioDecisionReason.duplicate_identity: ("names the same scenario as another selected id — "
                                            "accept only one version of each scenario"),
    ScenarioDecisionReason.already_accepted: "is already accepted — that decision stands",
    ScenarioDecisionReason.already_rejected: "is already rejected — that decision stands",
}


class AcceptConflict(Exception):
    def __init__(self, message: str, reason: str | None = None):
        super().__init__(message)
        self.reason = reason

def _undecidable_subset(sess: Session, session_id: str, subset: list[str], good_subs: list[int],
                        *, requested: int, matched: int, decision: AuditDecision) -> NotFoundError:
    """The 404 for a subset the write would not fully touch — shared by accept and reject.

    One builder, because the two differ only in a verb: the envelope (`requested`/`matched`/
    `unacceptable`), the id-naming cap and the "go re-read /results" advice are identical, and a
    second copy would be the thing that drifts."""
    verb = "accepted" if decision is AuditDecision.accept else "rejected"
    reasons = dal.undecidable_subset_reasons(sess, session_id, subset, good_subs, decision=decision)
    named = list(reasons)[:get_settings().accept_named_in_message]
    shown = "; ".join(f"{oid} {_REASON_TEXT.get(reasons[oid], reasons[oid])}" for oid in named)
    more = f"; and {len(reasons) - len(named)} more" if len(reasons) > len(named) else ""
    return NotFoundError(
        f"Nothing was {verb}. {requested - matched} of the {requested} scenarios you selected "
        f"cannot be {verb}: {shown}{more}. Get the current scenario ids from "
        f"GET /v1/sessions/{session_id}/results and try again.",
        details={"requested": requested, "matched": matched,
                "unacceptable": [{"scenario_id": oid, "reason": r} for oid, r in reasons.items()]},
    )


class MasterInactive(Exception):
    pass


def _assert_one_version_per_scenario(sess: Session, session_id: str, subset: list[str] | None,
                                    subsystem_ids: list[int]) -> None:
    """Refuse an accept that would leave TWO versions of one scenario accepted, before any write.

    `subset=None` means accept-all, which is checked too: accepting version A, regenerating to
    version B, then clicking accept-all flips B while A is still Accepted=1 — two accepted
    versions of one identity, which UX_Scenario_ActiveAccepted rejects at statement time.

    UX_Scenario_ActiveAccepted permits one accepted version per (IdentityHash, ScenarioNumber);
    without this pre-flight the second one violates it at statement time and surfaces as an
    untyped 500. `subsystem_ids` scopes the lookup to the same rows decide_scenarios would flip,
    so an id it will not touch cannot manufacture a false conflict here.

    Checked against the identities this session ALREADY accepted, because accept is now
    repeatable: the session completes when generation ends, so a reviewer can accept scenario 1
    today and scenario 2 next week. The collision that matters is therefore across CALLS, not only
    within one subset. (While accept also completed the session that check was unreachable and was
    deliberately left out; that is no longer true, and the index would raise instead.)

    `already` maps pair -> the ScenarioID holding it, and comparing that id is the point: naming the
    SAME version again is idempotent, exactly as re-rejecting is, and only a DIFFERENT version of
    an already-accepted scenario is a conflict. Keeping the pairs but discarding the ids made an
    id collide with itself, turning a harmless double-click into a 409."""
    if subset is not None and not subset:
        return  # decide-none writes nothing; nothing can collide
    already = dal.accepted_identity_pairs(sess, session_id)
    pairs = (dal.scenario_identity_pairs(sess, session_id, subset, subsystem_ids) if subset is not None
            else dal.active_accept_candidates(sess, session_id, subsystem_ids))
    seen_identity: dict[tuple, str] = {}
    for oid in (dict.fromkeys(subset) if subset is not None else pairs):
        pair = pairs.get(oid)
        # NULL IdentityHash = a legacy pre-IdentityHash row, which the filtered index exempts
        # (SQL Server compares NULLs equal) — skip it here for the same reason.
        if pair is None or pair[0] is None:
            continue
        prior = already.get(pair)
        if prior is not None and prior != oid:
            raise AcceptConflict(
                f"Nothing was accepted. {oid} "
                f"{_REASON_TEXT[ScenarioDecisionReason.duplicate_identity]} "
                f"(version {prior} of that scenario was already accepted on this session — "
                f"accept only one version of each scenario).",
                reason=ScenarioDecisionReason.duplicate_identity)
        if pair in seen_identity:
            raise AcceptConflict(
                f"Nothing was accepted. {oid} "
                f"{_REASON_TEXT[ScenarioDecisionReason.duplicate_identity]} "
                f"(the other selected version: {seen_identity[pair]}).",
                reason=ScenarioDecisionReason.duplicate_identity)
        seen_identity[pair] = oid


def accept_session(sess: Session, session_id: str, entity_id: str, user_id: str | None,
                subset: list[str] | None = None) -> int:
    scenario_session = dal.get_session(sess, session_id, entity_id)
    if scenario_session is None:
        raise EntityForbidden(f"session {session_id} not in entity {entity_id}")

    scenario_session = _ensure_session_ready_to_accept(sess, scenario_session)

    subsystem_ids = dal.subsystem_ids_at_level(sess, session_id, SubsystemLevel.LOCK)
    good_subs = dal.subsystem_ids_at_level(
        sess, session_id, SubsystemLevel.SCENARIOS, status=StageStatus.AWAITING_DECISION)

    # Acquire all locks before validating or writing.
    acquired: list[int] = []
    try:
        for ss in subsystem_ids:
            if not dal.acquire_execution_lock(sess, session_id, ss, task_id=session_id):
                raise AcceptConflict(f"subsystem {ss} lock held (regeneration in progress)")
            acquired.append(ss)
            # Make the lock visible to concurrent regeneration.
            sess.commit()

        _ensure_threat_data_still_active(sess, session_id, good_subs)

        if subset is not None:
            # Use canonical ids for checks, writes, and audit data.
            subset = [dal.canonical_guid(s) for s in subset]
        _assert_one_version_per_scenario(sess, session_id, subset, good_subs)
        try:
            # decide_scenarios writes the per-scenario ledger rows in the SAME call — accept has
            # no separate audit step that could fall out of step with the decision.
            matched = dal.decide_scenarios(
                sess, session_id, good_subs, decision=AuditDecision.accept, subset=subset,
                tenant_id=scenario_session["TenantID"], entity_id=str(entity_id), user_id=user_id)
        except IntegrityError as exc:
            # The pre-flight above reads, then this writes — two concurrent accepts naming
            # different versions of one scenario both pass the read and collide here.
            # UX_Scenario_ActiveAccepted is the real arbiter; without this the loser of that race
            # is an untyped 500. Caught at sess.execute, NOT at commit: these are Core UPDATEs
            # with no ORM objects pending, so the flush at commit time is a no-op and the
            # violation surfaces at statement time (same rule as treatment.py's own catch).
            raise AcceptConflict(
                "Nothing was accepted. Another decision on this session accepted a different "
                "version of one of these scenarios first — refresh and try again.",
                reason=ScenarioDecisionReason.duplicate_identity) from exc
        if subset is not None:
            # Repeated ids count once; every selected id must match.
            requested = len(set(subset))
            if matched != requested:
                raise _undecidable_subset(sess, session_id, subset, good_subs,
                                        requested=requested, matched=matched,
                                        decision=AuditDecision.accept)
        else:
            # Accept-all must cover every active subsystem.
            uncovered = dal.subsystems_with_active_scenarios(sess, session_id) - set(good_subs)
            if uncovered:
                raise AcceptConflict(
                    f"accept-all leaves active scenarios in subsystem(s) {sorted(uncovered)} whose "
                    f"SCENARIOS stage is not AWAITING_DECISION (subsystem stage state out of sync)")
            if matched == 0:
                raise AcceptConflict(
                    "accept-all found no completed scenarios to accept — regenerate or request a "
                    "next set first",
                    reason="nothing_to_accept")

        # ponytail: no complete_session here. Generation already completed the session at its
        # review barrier (tasks._send_to_review), which is what frees the asset. Completing it
        # again would be wrong twice over: the CAS is fenced on SessionStatus == active and would
        # fail on every call, and "the session is over" is no longer what an accept means — each
        # scenario carries its own decision, and undecided ones stay pending for the next visit.

        if subset is None:
            decision = AuditDecision.accept
        elif subset:
            decision = AuditDecision.partial
        else:
            decision = AuditDecision.reject
        # Session-scoped rows: "a review action happened on this session", one pair per CALL.
        # The per-scenario scenario_accepted rows written inside decide_scenarios answer the
        # different question ("which scenario, by whom, when"). Both are kept — this is an
        # append-only ledger, and dropping entries rewrites history.
        events = ((AuditEventType.review_decision,) if decision == AuditDecision.reject
                else (AuditEventType.scenarios_accepted, AuditEventType.review_decision))
        for event in events:
            dal.append_audit(sess, AuditID=guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
                            EntityID=str(entity_id), EventType=event, Decision=decision, ActorUserID=user_id,
                            DetailJSON=json.dumps({"subset": subset}) if subset is not None else None)
        sess.commit()
        log.info("session.accepted", session_id=session_id, decision=str(decision),
                accepted_count=matched, user=user_id)
        # SSE is a hint; stream status is authoritative.
        bus.publish(session_id, {"type": "session_accepted", "session_id": session_id,
                                "status": str(SessionStatus.completed), "ts": now().isoformat()})
        return matched
    except Exception:
        # Keep committed locks durable; discard pending decision work.
        sess.rollback()
        raise
    finally:
        # Release locks without masking the original error.
        try:
            for ss in acquired:
                dal.release_lock(sess, session_id, ss, task_id=session_id)
            sess.commit()
        except Exception:  # noqa: BLE001 — best-effort lock release; must not mask the original error
            log.warning("accept.lock_release_failed", session_id=session_id)


def reject_scenarios(sess: Session, session_id: str, entity_id: str, user_id: str | None,
                    scenario_ids: list[str]) -> int:
    """Explicitly decline scenarios. The mirror of accept_session, and deliberately its shape.

    Rejecting is a DECISION, not a deletion: the scenario keeps its content and its history, and
    `RejectedAt`/`RejectedBy` record who declined it and when. A rejected scenario leaves the
    reviewer's queue but stays in the evidence trail — which is the whole reason a GRC platform
    needs an explicit "no" rather than scenarios sitting pending forever.

    Same review gate, same per-subsystem execution lock and same 404 envelope as accept, because a
    reject races exactly what an accept races. There is no reject-all: declining everything is a
    click no reviewer should be one mis-tap away from, and leaving scenarios pending is already a
    valid resting state."""
    scenario_session = dal.get_session(sess, session_id, entity_id)
    if scenario_session is None:
        raise EntityForbidden(f"session {session_id} not in entity {entity_id}")

    scenario_session = _ensure_session_ready_to_accept(sess, scenario_session)

    subsystem_ids = dal.subsystem_ids_at_level(sess, session_id, SubsystemLevel.LOCK)
    good_subs = dal.subsystem_ids_at_level(
        sess, session_id, SubsystemLevel.SCENARIOS, status=StageStatus.AWAITING_DECISION)

    acquired: list[int] = []
    try:
        for ss in subsystem_ids:
            if not dal.acquire_execution_lock(sess, session_id, ss, task_id=session_id):
                raise AcceptConflict(f"subsystem {ss} lock held (regeneration in progress)")
            acquired.append(ss)
            sess.commit()  # make the lock visible to a concurrent accept/regeneration

        subset = [dal.canonical_guid(s) for s in scenario_ids]
        # decide_scenarios writes the scenario_rejected ledger rows in the same call. No
        # session-level audit row: the session is not what is being decided here.
        matched = dal.decide_scenarios(
            sess, session_id, good_subs, decision=AuditDecision.reject, subset=subset,
            tenant_id=scenario_session["TenantID"], entity_id=str(entity_id), user_id=user_id)
        requested = len(set(subset))
        if matched != requested:
            raise _undecidable_subset(sess, session_id, subset, good_subs,
                                    requested=requested, matched=matched,
                                    decision=AuditDecision.reject)
        sess.commit()
        log.info("scenarios.rejected", session_id=session_id, rejected_count=matched, user=user_id)
        # SSE is a hint; stream status is authoritative.
        bus.publish(session_id, {"type": "scenarios_rejected", "session_id": session_id,
                                "rejected_count": matched, "ts": now().isoformat()})
        return matched
    except Exception:
        sess.rollback()  # keep committed locks durable; discard pending decision work
        raise
    finally:
        try:
            for ss in acquired:
                dal.release_lock(sess, session_id, ss, task_id=session_id)
            sess.commit()
        except Exception:  # noqa: BLE001 — a lost lock must not mask the caller's error
            log.warning("reject.lock_release_failed", session_id=session_id)


def review_gate_reason(scenario_session: RowMapping | dict) -> tuple[str, str] | None:
    if (scenario_session["CurrentStage"] == WorkflowStage.REVIEW
            and scenario_session["StageStatus"] == StageStatus.AWAITING_DECISION):
        return None
    status = scenario_session["SessionStatus"]
    if status == SessionStatus.completed:
        return ("session_completed",
                (f"session already completed at {scenario_session['CompletedAt']} — the review "
                f"decision is final; accepted scenarios are available via "
                f"GET /v1/sessions/{scenario_session['SessionID']}/accepted-scenarios, "
                f"and a new session for this asset can run a fresh review"))
    if status == SessionStatus.cancelled:
        return ("session_cancelled",
                f"session was cancelled — start a new session for asset {scenario_session['AssetID']}")
    return ("generation_in_progress",
            (f"session not at REVIEW yet (stage={scenario_session['CurrentStage']}, "
            f"status={scenario_session['StageStatus']}) — generation still in progress"))


def ensure_review_gate(sess: Session, scenario_session: RowMapping | dict) -> RowMapping | dict:
    """`review_gate_reason`, but reconciled against whether a worker is ACTUALLY alive.

    Returns the session row to keep working with — the reloaded one if recovery ran — and raises
    AcceptConflict otherwise. Shared by the accept/reject gate and sessions.py's regenerate/next-set
    gate, so every decision route reconciles identically.

    WHY THIS EXISTS. `CurrentStage`/`StageStatus` on Scenario_Session are a denormalised CACHE of
    pipeline progress; `Subsystem_Stage_State` is the authority. When a worker dies or hangs
    mid-run, nothing writes the cache back, and the reaper — the only reconciler — cannot act until
    the lease expires, and only while worker AND beat are running. Every route that trusted the
    cache alone therefore answered "generation still in progress" for runs that had stopped hours
    earlier, leaving the session acceptable by nobody and advanceable by nothing. Observed live:
    a next-set task hung after committing its work but before releasing the `_LOCK`, and accept +
    regenerate both 409'd on a session whose scenarios were finished and sitting in the DB.

    So: a live lease is required to CLAIM something is running (dal.live_lease_exists explains why
    that signal is exact rather than heuristic). Without one, the run is abandoned, and this
    finalises it on the spot through the very same `recover_abandoned_session` the reaper uses —
    same `_LOCK` mutex, same decide_session_outcome — so an in-flight worker can never be raced.
    Recovery is idempotent and returns None untouched if any lock is genuinely held."""
    gate = review_gate_reason(scenario_session)
    if gate is None:
        return scenario_session
    reason, message = gate
    # session_completed / session_cancelled are terminal facts, not stale cache — nothing to
    # reconcile, and recovery could not change them.
    if reason != ReviewGateReason.generation_in_progress:
        raise AcceptConflict(message, reason=reason)

    sid = scenario_session["SessionID"]
    if dal.session_has_live_lease(sess, sid):
        raise AcceptConflict(message, reason=reason)   # a worker really is running: the message is true

    log.warning("review_gate.recovering_abandoned_run", session_id=sid,
                stage=str(scenario_session["CurrentStage"]),
                stage_status=str(scenario_session["StageStatus"]),
                note="no live lease — previous run died or hung; finalising it now")
    # recover_session_now, NOT recover_abandoned_session: the latter is only the sweep's step 3 and
    # bails out on a held `_LOCK` — which is exactly the state an abandoned run leaves behind.
    from app.pipeline.reaper import recover_session_now  # local: reaper -> tasks -> accept
    try:
        recover_session_now(sess, dict(scenario_session))
    except Exception:  # a failed recovery must still produce an honest 409, not a 500
        sess.rollback()
        log.warning("review_gate.recovery_failed", session_id=sid, exc_info=True)

    fresh = dal.get_session(sess, sid, str(scenario_session["EntityID"]))
    if fresh is None:  # deleted underneath us — treat as the caller's original refusal
        raise AcceptConflict(message, reason=reason)
    gate = review_gate_reason(fresh)
    if gate is None:
        log.info("review_gate.recovered", session_id=sid, stage=str(fresh["CurrentStage"]))
        return fresh
    reason, message = gate
    # Recovery resolved it to a terminal state (e.g. every stage errored -> cancelled). Report THAT
    # — it is accurate and tells the caller what to do next; generation_abandoned would lose it.
    if reason != ReviewGateReason.generation_in_progress:
        raise AcceptConflict(message, reason=reason)
    raise AcceptConflict(
        f"the previous generation run was abandoned — no worker has held a lease on session {sid} "
        f"since it stopped — and automatic recovery could not park it at REVIEW "
        f"(stage={fresh['CurrentStage']}, status={fresh['StageStatus']}). Waiting will not help; "
        f"cancel the session and start a new one for asset {fresh['AssetID']}",
        reason=ReviewGateReason.generation_abandoned)


def _ensure_session_ready_to_accept(sess: Session, scenario_session: RowMapping) -> RowMapping | dict:
    """The review gate every decision route must pass: is this session AT a review barrier?

    Returns the session row to use from here on — recovery may have reloaded it, and the caller
    must not keep reading the pre-recovery snapshot.

    Deliberately NOT an ownership check. Any authenticated colleague in the entity may decide this
    assessment; who actually did is recorded per scenario by dal.decide_scenarios. An owner check
    lived here briefly and was removed on purpose — see get_authorized_session.

    A guard in scripts/test_pipeline_guards.py fails the build if a function that decides
    scenarios does not call this first, so a new decision route cannot skip the barrier."""
    return ensure_review_gate(sess, scenario_session)


def _ensure_threat_data_still_active(sess: Session, session_id: str, good_subs: list[int]) -> None:
    rows = sess.execute(
        select(m.Identified_Threat.ThreatTypeID, m.Identified_Threat.ThreatCatalogueID)
        .where(
            m.Identified_Threat.SessionID == session_id,
            dal.active(m.Identified_Threat.Superseded),
            m.Identified_Threat.SubsystemID.in_(good_subs),
        )
    ).all()
    type_ids = {t for t, _ in rows if t is not None}
    cat_ids = {c for _, c in rows if c is not None}

    if type_ids:
        active = {r[0] for r in sess.execute(
            select(m.Threat_Type.ThreatTypeID).where(
                m.Threat_Type.ThreatTypeID.in_(type_ids),
                m.Threat_Type.IsActive == True, m.Threat_Type.IsDeleted == False))}
        if type_ids - active:
            raise MasterInactive(f"Threat_Type inactive: {sorted(type_ids - active)}")
    if cat_ids:
        live = dal.catalogue_rows_active(sess, sorted(cat_ids))
        if cat_ids - live:
            raise MasterInactive(f"Threat_Catalogue inactive: {sorted(cat_ids - live)}")


