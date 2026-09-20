from __future__ import annotations

import json
from typing import NamedTuple

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
    UnacceptGateReason,
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


class Replacement(NamedTuple):
    """One acceptance moved between two versions of the same scenario. BOTH ids, because a caller
    needs to know what gained the decision and what lost it — the loser is the id whose cached
    plan, board row and register entry just stopped being the answer for that risk."""
    scenario_id: str            # now the accepted version
    replaced_scenario_id: str   # accepted until this call, now history


class Accepted(NamedTuple):
    """What an accept call did: rows accepted, and the replacements it really made (empty on
    every ordinary accept). The pair the API and the log both report from."""
    count: int
    replaced: list[Replacement]


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
                                    subsystem_ids: list[int],
                                    *, replace_accepted: bool = False) -> dict[str, str]:
    """Refuse an accept that would leave TWO versions of one scenario accepted, before any write.

    Returns {already-accepted ScenarioID: the version replacing it} — empty unless the reviewer
    asked to replace. `replace_accepted` is that ask (AcceptBody.replace_accepted): the collision
    below stops being a refusal and becomes the replacement decide_scenarios writes. It is
    deliberately NOT the default — retiring a decision the register already carries, and with it
    the remediation plan hanging off that version, is not something a stray double-click may do.
    Accept-ALL never replaces: `subset is None` keeps the refusal whatever the flag says, so one
    click can never rewrite every decision in a session.

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
        return {}  # decide-none writes nothing; nothing can collide
    already = dal.accepted_identity_pairs(sess, session_id)
    pairs = (dal.scenario_identity_pairs(sess, session_id, subset, subsystem_ids) if subset is not None
            else dal.active_accept_candidates(sess, session_id, subsystem_ids))
    seen_identity: dict[tuple, str] = {}
    displace: dict[str, str] = {}
    for oid in (dict.fromkeys(subset) if subset is not None else pairs):
        pair = pairs.get(oid)
        # NULL IdentityHash = a legacy pre-IdentityHash row, which the filtered index exempts
        # (SQL Server compares NULLs equal) — skip it here for the same reason.
        if pair is None or pair[0] is None:
            continue
        prior = already.get(pair)
        if prior is not None and prior != oid:
            if not replace_accepted or subset is None:
                # Two refusals, because the two callers have different ways out. Accept-ALL
                # cannot carry replace_accepted at all (AcceptBody rejects the pair with a 422),
                # so telling an accept-all caller to "repeat this call with the flag" sent them
                # to a dead end — a message must only name an action the API will accept.
                how = (
                    f'accept {oid} on its own — mode "subset", naming it, with '
                    f'"replace_accepted": true' if subset is None else
                    'repeat this call with "replace_accepted": true')
                raise AcceptConflict(
                    f"Nothing was accepted. {oid} "
                    f"{_REASON_TEXT[ScenarioDecisionReason.duplicate_identity]} "
                    f"(version {prior} of that scenario was already accepted on this session). "
                    f"To make {oid} the accepted version instead, {how} — {prior} then moves to "
                    f"history, keeping its audit trail, and its remediation plan stays with it "
                    f"and leaves the plan board. To keep {prior}, reject {oid} instead.",
                    reason=ScenarioDecisionReason.duplicate_identity)
            displace[prior] = oid
        if pair in seen_identity:
            raise AcceptConflict(
                f"Nothing was accepted. {oid} "
                f"{_REASON_TEXT[ScenarioDecisionReason.duplicate_identity]} "
                f"(the other selected version: {seen_identity[pair]}).",
                reason=ScenarioDecisionReason.duplicate_identity)
        seen_identity[pair] = oid
    return displace


def accept_session(sess: Session, session_id: str, entity_id: str, user_id: str | None,
                subset: list[str] | None = None, *,
                replace_accepted: bool = False) -> Accepted:
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
        displace = _assert_one_version_per_scenario(sess, session_id, subset, good_subs,
                                                replace_accepted=replace_accepted)
        try:
            # A REPLACEMENT is two decisions, written in this order and in this transaction.
            # Un-accept first because UX_Scenario_ActiveAccepted permits one accepted version per
            # identity — the other order violates it at statement time. Both calls go through the
            # single writer, so neither decision can exist without its ledger row, and the
            # rollback below covers the pair.
            #
            # `replaced` reports what the un-accept ACTUALLY flipped, never what the pre-flight
            # asked for: a version some other decision moved first matches nothing, and a client
            # told otherwise would invalidate a plan that never moved.
            replaced: list[Replacement] = []
            if displace:
                undone = dal.decide_scenarios(
                    sess, session_id, good_subs, decision=AuditDecision.unaccept,
                    subset=list(displace), tenant_id=scenario_session["TenantID"],
                    entity_id=str(entity_id), user_id=user_id,
                    details={old: {"replaced_by": new} for old, new in displace.items()})
                replaced = [Replacement(displace[old], old) for old in undone.changed]
            decided = dal.decide_scenarios(
                sess, session_id, good_subs, decision=AuditDecision.accept, subset=subset,
                tenant_id=scenario_session["TenantID"], entity_id=str(entity_id), user_id=user_id,
                # The other half of the link: from the version that GAINED the decision, name the
                # one it displaced. Without it the trail walked old → new only, and after a switch
                # back the scenario rows cannot answer it either.
                details={r.scenario_id: {"replaces": r.replaced_scenario_id} for r in replaced})
            matched = decided.count
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

        # no complete_session here. Generation already completed the session at its
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
        # replaced_count is what the write ACTUALLY flipped, not what the pre-flight asked for:
        # a prior another decision moved first matches nothing, and a log that still claimed a
        # replacement would be the only out-of-band record of it — and wrong.
        log.info("session.accepted", session_id=session_id, decision=str(decision),
                accepted_count=matched, replaced_count=len(replaced), user=user_id)
        # SSE is a hint; stream status is authoritative.
        bus.publish(session_id, {"type": "session_accepted", "session_id": session_id,
                                "status": str(SessionStatus.completed), "ts": now().isoformat()})
        return Accepted(matched, replaced)
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


def unaccept_scenario(sess: Session, session_id: str, entity_id: str, user_id: str | None,
                    scenario_id: str) -> None:
    """Take one acceptance back, without adopting anything in its place.

    The third decision, and the one the reviewer had no way to make: reject is refused on an
    accepted scenario (the two are mutually exclusive), and replacing needs another version to
    adopt. "I accepted that by mistake, and I do not want a rewrite either" had no answer at all.

    The scenario returns to UNDECIDED, so the review queue reopens for it and it can later be
    rejected, or accepted again. Nothing is deleted: the original scenario_accepted row stays in
    the ledger with the scenario_unaccepted row appended beside it.

    Its remediation plan is deliberately NOT touched. It stays attached to this version, drops
    off the plan board and the entity register while the version is not accepted, cannot be
    approved there, and comes back if the version is accepted again — the same behaviour a
    replacement already has. That is why there is no treatment_plan_exists refusal: the orphan it
    guarded against cannot happen.

    Same gate, same per-subsystem lock and the same single writer as accept and reject, because
    an unaccept races exactly what they race.
    """
    scenario_session = dal.get_session(sess, session_id, entity_id)
    if scenario_session is None:
        raise EntityForbidden(f"session {session_id} not in entity {entity_id}")
    # Called here, not inside a helper: scripts/test_pipeline_guards.py walks each function's own
    # AST and fails the build if a decision writer skips the gate.
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

        oid = dal.canonical_guid(scenario_id)
        if dal.decide_scenarios(
                sess, session_id, good_subs, decision=AuditDecision.unaccept, subset=[oid],
                tenant_id=scenario_session["TenantID"], entity_id=str(entity_id),
                user_id=user_id).count != 1:
            # Nothing to undo. Reported as the SAME 409 envelope accept uses, with its own reason:
            # an unaccept is a decision on a scenario, and a second error code would only make a
            # client branch twice for one class of answer.
            raise AcceptConflict(
                f"Nothing was un-accepted. {oid} is not an accepted scenario of this session — "
                f"only an acceptance can be taken back. Check GET /v1/sessions/{session_id}"
                f"/results, where the accepted version reads accepted: true.",
                reason=UnacceptGateReason.not_accepted)
        sess.commit()
        log.info("scenario.unaccepted", session_id=session_id, scenario_id=oid, user=user_id)
        # SSE is a hint; stream status is authoritative. Same shape as its two siblings.
        bus.publish(session_id, {"type": "scenario_unaccepted", "session_id": session_id,
                                "scenario_id": oid, "ts": now().isoformat()})
    except Exception:
        sess.rollback()  # keep committed locks durable; discard pending decision work
        raise
    finally:
        try:
            for ss in acquired:
                dal.release_lock(sess, session_id, ss, task_id=session_id)
            sess.commit()
        except Exception:  # noqa: BLE001 — a lost lock must not mask the caller's error
            log.warning("unaccept.lock_release_failed", session_id=session_id)


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
        # .count: reject never displaces (a rejection replaces no decision), so the other half of
        # Decided is always empty here and naming it would only invite someone to read it.
        matched = dal.decide_scenarios(
            sess, session_id, good_subs, decision=AuditDecision.reject, subset=subset,
            tenant_id=scenario_session["TenantID"], entity_id=str(entity_id), user_id=user_id).count
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

    So: when the reaper's OWN rule (reaper.session_is_abandoned — no live lease AND proven dead or
    stale) says the run is abandoned, this finalises it on the spot through the very same recovery
    the reaper uses — same `_LOCK` mutex, same decide_session_outcome — so an in-flight worker can
    never be raced. Otherwise the refusal stands: the run is working, queued, or between claims.
    "No live lease" alone is not enough — a still-QUEUED session holds none either, and treating
    that as dead once cancelled a healthy run whose accept arrived 0.1 s after its create.
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
    # Local import: reaper -> tasks -> accept.
    from app.pipeline.reaper import recover_session_now, session_is_abandoned
    if not session_is_abandoned(sess, sid):
        raise AcceptConflict(message, reason=reason)   # working, queued or between claims: true

    log.warning("review_gate.recovering_abandoned_run", session_id=sid,
                stage=str(scenario_session["CurrentStage"]),
                stage_status=str(scenario_session["StageStatus"]),
                note="abandoned by the reaper's rule — previous run died or never started; "
                     "finalising it now")
    # recover_session_now, NOT recover_abandoned_session: the latter is only the sweep's step 3 and
    # bails out on a held `_LOCK` — which is exactly the state an abandoned run leaves behind.
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
        # IsDeleted-only, not IsActive-gated: a type promote-to-library just minted starts
        # IsActive=False (pending curator review, see dal.upsert_threat_type) and must still
        # count as existing here, or accepting a session containing an already-promoted threat
        # would wrongly 409 as MasterInactive. Only a hard-deleted type should trip this gate.
        active = {r[0] for r in sess.execute(
            select(m.Threat_Type.ThreatTypeID).where(
                m.Threat_Type.ThreatTypeID.in_(type_ids), m.Threat_Type.IsDeleted == False))}
        if type_ids - active:
            raise MasterInactive(f"Threat_Type inactive: {sorted(type_ids - active)}")
    if cat_ids:
        live = dal.catalogue_rows_active(sess, sorted(cat_ids))
        if cat_ids - live:
            raise MasterInactive(f"Threat_Catalogue inactive: {sorted(cat_ids - live)}")


