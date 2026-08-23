from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, NamedTuple, cast

from sqlalchemy import RowMapping, Table, bindparam, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import tuning
from app.core.config import get_settings
from app.core.enums import (
    ActorType,
    AuditDecision,
    AuditEventType,
    CandidateKind,
    CandidateStatus,
    ScenarioDecisionReason,
    SessionStatus,
    StageStatus,
    SubsystemLevel,
    TriageVerdict,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import EntityForbidden, NotFoundError, guid, now
from app.pipeline import embeddings, grounding
from app.pipeline.accept_actors import (
    _clean_actor_name,
    pending_card_identities,
    resolve_actor_id_by_identity,
)
from app.pipeline.llm import get_llm
from app.pipeline.tasks import asset_agnostic_name, clean_library_name
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
                "unacceptable": [{"output_id": oid, "reason": r} for oid, r in reasons.items()]},
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

    `already` maps pair -> the OutputID holding it, and comparing that id is the point: naming the
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

    _ensure_session_ready_to_accept(scenario_session)

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

        run_promotion_phase(sess, scenario_session, good_subs, user_id, acquired)
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


def run_promotion_phase(sess: Session, scenario_session: RowMapping, good_subs: list[int],
                        user_id: str | None, lock_subsystem_ids: list[int]) -> bool:
    """Promote this session's novel threats into the library. Returns success; NEVER raises.

    Phase 2 of accept, and the accept in phase 1 is already durably committed by the time this
    runs — so any exception escaping here would fail a request whose real work succeeded, and the
    caller has no way to undo it. Every step therefore lives inside the try, including the lease
    renewal and its commit: those touch the database too, and a deadlock victim or a dropped
    connection there is exactly the kind of failure this contract exists to absorb. A failure is
    stamped for the reaper's retry sweep instead of propagating.
    """
    session_id = scenario_session["SessionID"]
    try:
        for subsystem_id in lock_subsystem_ids:
            if not dal.renew_lock_lease(sess, session_id, subsystem_id, task_id=session_id):
                log.debug("promotion.lock_lease_renewal_skipped", session_id=session_id, subsystem_id=subsystem_id)
        sess.commit()
        promoted_names = _add_unverified_threats_to_library(sess, scenario_session, good_subs, user_id)
        dal.clear_promotion_failure(sess, session_id)
        sess.commit()
        # Commit SQL before updating the embedding store.
        eager_embed_promoted(sess, get_llm(), promoted_names)
        return True
    except Exception as exc:
        # Roll back all promotion writes together.
        sess.rollback()
        try:
            dal.stamp_promotion_failure(sess, session_id, error_message=str(exc), user_id=user_id)
            sess.commit()
        except Exception:
            sess.rollback()
            log.warning("session.promotion_failure_stamp_failed", session_id=session_id, exc_info=True)
        log.warning("session.promotion_failed", session_id=session_id, user_id=user_id, exc_info=True)
        return False


class CandidateResolution(NamedTuple):
    won: bool
    type_id: int | None
    catalogue_id: int | None
    promoted_names: list[tuple[str, str]]


def resolve_candidate(sess: Session, candidate: RowMapping, reviewer_user_id: str | None,
                    *, approve: bool) -> CandidateResolution:
    kind = candidate.get("CandidateKind")
    original_proposer = candidate.get("CreatedBy") or reviewer_user_id

    if not approve:
        won = dal.close_candidate_review(sess, candidate["CandidateID"],
                                        status=CandidateStatus.rejected, reviewer_user_id=reviewer_user_id)
        if won:
            dal.append_audit(sess, AuditID=guid(), SessionID=candidate["SessionID"],
                            TenantID=candidate["TenantID"], EntityID=candidate["EntityID"],
                            EventType=AuditEventType.candidate_reconciled, ActorUserID=reviewer_user_id,
                            DetailJSON=json.dumps({"candidate_id": candidate["CandidateID"],
                                                    "kind": str(kind or CandidateKind.threat),
                                                    "decision": str(CandidateStatus.rejected)}))
        return CandidateResolution(won, None, None, [])

    grounded_type_id = candidate["ThreatTypeID"]
    if grounded_type_id is not None and not dal.threat_type_active(sess, grounded_type_id):
        grounded_type_id = None

    if kind == CandidateKind.actor:
        link_type_id = grounded_type_id
        if link_type_id is None:
            link_type_id = dal.find_active_type_id_by_name(sess, candidate["ProposedType"])
        won = dal.close_candidate_review(sess, candidate["CandidateID"],
                                        status=CandidateStatus.accepted,
                                        reviewer_user_id=reviewer_user_id,
                                        type_id=link_type_id,
                                        clear_type_id=True)
        if not won:
            return CandidateResolution(False, None, None, [])
        display = _clean_actor_name(candidate["ProposedName"]) or candidate["ProposedName"]
        actor_master_id = resolve_actor_id_by_identity(sess, display)
        if actor_master_id is None:
            actor_master_id = dal.upsert_threat_actor(sess, display,
                                                    created_by=original_proposer)
        if link_type_id is not None:
            dal.link_type_actor(sess, link_type_id, actor_master_id)
        else:
            log.warning("accept.actor_link_skipped", candidate_id=candidate["CandidateID"],
                        actor=candidate["ProposedName"], proposed_type=candidate["ProposedType"],
                        note="no unambiguous active Threat_Type for the card's type text — "
                            "actor created unlinked; link via PATCH /threat-types/{id} if real")
        dal.append_audit(sess, AuditID=guid(), SessionID=candidate["SessionID"],
                        TenantID=candidate["TenantID"], EntityID=candidate["EntityID"],
                        EventType=AuditEventType.candidate_reconciled, ActorUserID=reviewer_user_id,
                        ThreatTypeRefID=link_type_id,
                        DetailJSON=json.dumps({"candidate_id": candidate["CandidateID"],
                                                "kind": str(CandidateKind.actor),
                                                "actor_id": actor_master_id,
                                                "linked_type_id": link_type_id,
                                                "decision": str(CandidateStatus.accepted)}))
        # Through promoted_names so the caller's existing eager_embed_promoted call vectors the
        # new actor for the nearest-match fallback. Best-effort there (create_items skips cached
        # names; an identity-matched EXISTING actor whose spelling differs just logs and no-ops).
        return CandidateResolution(True, link_type_id, None, [("threat_actor", display)])

    category_id = grounding.find_category(sess, candidate["ProposedCategory"])
    type_id = grounded_type_id
    if type_id is None:
        type_id, _created = dal.upsert_threat_type(sess, candidate["ProposedType"], category_id,
                                                    sector_id=None, created_by=original_proposer)
    generic = candidate["ProposedGenericName"] or candidate["ProposedName"]
    catalogue_id = dal.upsert_threat_catalogue(sess, generic, type_id, sector_id=None,
                                                created_by=original_proposer)
    if category_id is not None:
        dal.link_catalogue_category(sess, catalogue_id, category_id)
    else:
        # No master category matched ProposedCategory. Linking would write NULL into a
        # composite PK and raise; the catalogue row itself is still valid, so record the
        # gap and continue rather than failing the whole approval.
        log.warning("candidate.category_unresolved", candidate_id=candidate["CandidateID"],
                    proposed_category=candidate["ProposedCategory"], catalogue_id=catalogue_id)
    won = dal.close_candidate_review(sess, candidate["CandidateID"], status=CandidateStatus.accepted,
                                    reviewer_user_id=reviewer_user_id, type_id=type_id,
                                    catalogue_id=catalogue_id)
    if not won:
        return CandidateResolution(False, None, None, [])
    dal.append_audit(sess, AuditID=guid(), SessionID=candidate["SessionID"], TenantID=candidate["TenantID"],
                    EntityID=candidate["EntityID"], EventType=AuditEventType.candidate_reconciled,
                    ActorUserID=reviewer_user_id, ThreatTypeRefID=type_id,
                    DetailJSON=json.dumps({"candidate_id": candidate["CandidateID"],
                                            "kind": str(kind or CandidateKind.threat),
                                            "decision": str(CandidateStatus.accepted),
                                            "catalogue_id": catalogue_id}))
    return CandidateResolution(True, type_id, catalogue_id,
                                [("threat_type", candidate["ProposedType"]), ("threat_catalogue", generic)])


def reject_scenarios(sess: Session, session_id: str, entity_id: str, user_id: str | None,
                    output_ids: list[str]) -> int:
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

    _ensure_session_ready_to_accept(scenario_session)

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

        subset = [dal.canonical_guid(s) for s in output_ids]
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


def _ensure_session_ready_to_accept(scenario_session: RowMapping) -> None:
    """The review gate every decision route must pass: is this session AT a review barrier?

    Deliberately NOT an ownership check. Any authenticated colleague in the entity may decide this
    assessment; who actually did is recorded per scenario by dal.decide_scenarios. An owner check
    lived here briefly and was removed on purpose — see get_authorized_session.

    A guard in scripts/test_pipeline_guards.py fails the build if a function that decides
    scenarios does not call this first, so a new decision route cannot skip the barrier."""
    gate = review_gate_reason(scenario_session)
    if gate is not None:
        reason, message = gate
        raise AcceptConflict(message, reason=reason)


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
        active = {r[0] for r in sess.execute(
            select(m.Threat_Catalogue.ThreatCatalogueID).where(
                m.Threat_Catalogue.ThreatCatalogueID.in_(cat_ids),
                m.Threat_Catalogue.IsActive == True, m.Threat_Catalogue.IsDeleted == False))}
        if cat_ids - active:
            raise MasterInactive(f"Threat_Catalogue inactive: {sorted(cat_ids - active)}")


def _pick_sector_for_promotion(scenario_session: RowMapping) -> int | None:
    raw = scenario_session.get("SectorIDsJSON")
    ids = json.loads(raw) if raw else []
    if len(ids) >= 2:
        return ids[1]
    if len(ids) == 1:
        return ids[0]
    return None




def _find_or_create_type_and_catalogue(
    sess: Session, row: RowMapping, sector_id: int | None, resolved: dict,
    created_by: str | None = None, allow_mint: bool = True,
) -> tuple[int | None, int | None]:
    def _category_id() -> int | None:
        cat_key = ("category", row["ThreatCategory"])
        if cat_key not in resolved:
            resolved[cat_key] = grounding.find_category(sess, row["ThreatCategory"])
        return resolved[cat_key]

    type_id = row["ThreatTypeID"]
    if type_id is None:
        key = ("type", row["ThreatCategory"], row["ThreatType"])
        type_id = resolved.get(key)
        if type_id is None and not allow_mint:
            return None, row["ThreatCatalogueID"]
        if type_id is None:
            type_id, created = dal.upsert_threat_type(sess, row["ThreatType"], _category_id(),
                                                    sector_id, created_by=created_by)
            resolved[key] = type_id
            if created:
                resolved[("minted_type", type_id)] = True

    return type_id, row["ThreatCatalogueID"]


def _active_catalogue_with_categories(sess: Session) -> list[dict]:
    tc, tt, mp = m.Threat_Catalogue, m.Threat_Type, m.Threat_Catalogue_Category_Map
    rows = sess.execute(
        select(tc.ThreatCatalogueID, tc.ThreatName, tc.ThreatTypeID, tc.SectorID,
            tt.ThreatCategoryID)
        .select_from(tc.__table__.outerjoin(tt, tc.ThreatTypeID == tt.ThreatTypeID))
        .where(tc.IsActive == True, tc.IsDeleted == False)
    ).all()
    mapped: dict[int, set[int]] = {}
    for cat_id, category_id in sess.execute(select(mp.ThreatCatalogueID, mp.ThreatCategoryID)):
        mapped.setdefault(cat_id, set()).add(category_id)
    return [{"id": r.ThreatCatalogueID, "name": r.ThreatName,
            "type_id": r.ThreatTypeID, "sector_id": r.SectorID,
            "cats": frozenset(mapped.get(r.ThreatCatalogueID)
                            or ([r.ThreatCategoryID] if r.ThreatCategoryID is not None else []))}
            for r in rows if r.ThreatName]


def _triage_generic_name(qv: Sequence[float], cand_cat_id: int | None, sector_ids: list[int],
                        entries: list[dict], name_vecs: dict[str, Sequence[float]],
                        tn: tuning.ResolvedTuning) -> tuple[TriageVerdict, int | None, float | None]:
    best_any: tuple[float, int] | None = None
    best_reject: tuple[float, int] | None = None
    for e in entries:
        vec = name_vecs.get(e["name"])
        if vec is None:
            continue
        cos = grounding.how_similar(qv, vec)
        if best_any is None or cos > best_any[0]:
            best_any = (cos, e["id"])
        if (cand_cat_id is not None and cand_cat_id in e["cats"]
                and (e["sector_id"] is None or e["sector_id"] in sector_ids)
                and (best_reject is None or cos > best_reject[0])):
            best_reject = (cos, e["id"])
    if best_any is None:
        return TriageVerdict.auto_approve, None, None
    if best_reject is not None and best_reject[0] >= tn.triage_auto_reject_cosine:
        return TriageVerdict.auto_reject, best_reject[1], best_reject[0]
    if best_any[0] < tn.triage_auto_approve_cosine:
        return TriageVerdict.auto_approve, best_any[1], best_any[0]
    return TriageVerdict.review, best_any[1], best_any[0]


def _promotion_candidates(sess: Session, sid: str, good_subs: list[int]) -> list[RowMapping]:
    st, out = m.Scoped_Threat, m.Threat_Scenario_Output
    scenario_accepted = (
        select(1)
        .where(st.SessionID == sid, st.ThreatID == m.Identified_Threat.ThreatID,
            out.SessionID == sid, out.ScopedThreatID == st.ScopedThreatID,
            dal.accepted(out.Accepted))
        .exists()
    )
    return list(sess.execute(
        select(m.Identified_Threat.ThreatID, m.Identified_Threat.ThreatCategory,
            m.Identified_Threat.ThreatType, m.Identified_Threat.ThreatName,
            m.Identified_Threat.GenericName, m.Identified_Threat.GroundingScore,
            m.Identified_Threat.ThreatActorsJSON, m.Identified_Threat.ThreatTypeID,
            m.Identified_Threat.ThreatCatalogueID)
        .where(m.Identified_Threat.SessionID == sid,
            dal.active(m.Identified_Threat.Superseded),
            m.Identified_Threat.SubsystemID.in_(good_subs),
            scenario_accepted)
    ).mappings().all())




class _TriageInputs(NamedTuple):
    entries: list[dict]
    catalogue_vecs: dict
    query_vecs: dict
    generic_by_tid: dict
    sector_ids: list[int]


def _prepare_triage(sess: Session, llm, scenario_session: RowMapping,
                    rows: Sequence[RowMapping]) -> _TriageInputs:
    asset_name = scenario_session["AssetName"]
    sector_ids = (json.loads(scenario_session["SectorIDsJSON"])
                if scenario_session.get("SectorIDsJSON") else [])
    generic_by_tid = {row["ThreatID"]: (row["GenericName"]
                                        or asset_agnostic_name(row["ThreatName"], asset_name))
                    for row in rows}
    if not rows:
        return _TriageInputs([], {}, {}, generic_by_tid, sector_ids)
    try:
        entries = _active_catalogue_with_categories(sess)
        if not entries:
            return _TriageInputs([], {}, {}, generic_by_tid, sector_ids)
        catalogue_vecs = embeddings.get_vectors(
            llm, [e["name"] for e in entries], model_id=get_settings().embedding_model,
            group="threat_catalogue", kind="passage")
        to_embed = sorted({g for row in rows if row["ThreatCatalogueID"] is None
                        for g in [generic_by_tid[row["ThreatID"]]] if g})
        query_vecs: dict = {}
        if to_embed:
            vecs = llm.embed(to_embed, kind="query")
            if len(vecs) != len(to_embed):
                raise RuntimeError(f"embed returned {len(vecs)} vectors for {len(to_embed)} queries")
            query_vecs = dict(zip(to_embed, vecs))
        return _TriageInputs(entries, catalogue_vecs, query_vecs, generic_by_tid, sector_ids)
    except Exception:
        log.warning("accept.triage_unavailable",
                    session_id=scenario_session["SessionID"], exc_info=True)
        return _TriageInputs([], {}, {}, generic_by_tid, sector_ids)


class _CandidateFate(NamedTuple):
    verdict: str
    type_id: int | None
    catalogue_id: int | None
    matched_id: int | None
    cosine: float | None
    minted: list[tuple[str, str]]


def _decide_candidate_fate(sess: Session, row: RowMapping, generic: str | None, sector_id: int | None,
                        resolved: dict, triage: _TriageInputs, tn: tuning.ResolvedTuning,
                        *, created_by: str | None, auto_mode: bool,
                        pending_cards: set) -> _CandidateFate:
    cat_key = ("category", row["ThreatCategory"])
    if cat_key not in resolved:
        resolved[cat_key] = grounding.find_category(sess, row["ThreatCategory"])
    cand_cat = resolved[cat_key]
    verdict, matched_id, cosine = TriageVerdict.review, None, None
    qv = triage.query_vecs.get(generic) if generic else None
    if row["ThreatCatalogueID"] is None and generic and triage.entries and qv is not None:
        try:
            verdict, matched_id, cosine = _triage_generic_name(
                qv, cand_cat, triage.sector_ids, triage.entries, triage.catalogue_vecs, tn)
        except Exception:
            verdict, matched_id, cosine = TriageVerdict.review, None, None
            log.warning("accept.triage_failed", threat_id=row["ThreatID"], exc_info=True)
    if verdict is TriageVerdict.auto_approve and cand_cat is None:
        verdict = TriageVerdict.review
    if verdict is TriageVerdict.auto_approve and clean_library_name(generic) is None:
        verdict = TriageVerdict.review
    if verdict is TriageVerdict.auto_approve and not auto_mode:
        verdict = TriageVerdict.review
    if verdict is TriageVerdict.auto_approve:
        ident = ((generic or row["ThreatName"]) or "").strip().casefold()
        if ident and (CandidateKind.threat, ident) in pending_cards:
            verdict = TriageVerdict.review
    matched_entry = (next((e for e in triage.entries if e["id"] == matched_id), None)
                    if verdict is TriageVerdict.auto_reject else None)
    if verdict is TriageVerdict.auto_reject and matched_entry is None:
        verdict = TriageVerdict.review
    if (matched_entry is not None and row["ThreatTypeID"] is not None
            and matched_entry["type_id"] != row["ThreatTypeID"]):
        verdict, matched_entry = TriageVerdict.review, None

    if matched_entry is not None:
        type_id = matched_entry["type_id"]
        minted: list[tuple[str, str]] = []
        if type_id is None:
            type_id, _ = _find_or_create_type_and_catalogue(sess, row, sector_id, resolved,
                                                            created_by=created_by,
                                                            allow_mint=auto_mode)
            if type_id is None:
                return _CandidateFate(TriageVerdict.review, None, row["ThreatCatalogueID"],
                                    matched_id, cosine, [])
            if resolved.get(("minted_type", type_id)):
                minted.append(("threat_type", row["ThreatType"]))
        return _CandidateFate(verdict, type_id, matched_id, matched_id, cosine, minted)

    type_id, catalogue_id = _find_or_create_type_and_catalogue(sess, row, sector_id, resolved,
                                                            created_by=created_by,
                                                            allow_mint=auto_mode)
    minted = [("threat_type", row["ThreatType"])] if resolved.get(("minted_type", type_id)) else []
    if verdict is TriageVerdict.auto_approve and generic and type_id is not None:
        catalogue_id = dal.upsert_threat_catalogue(sess, generic, type_id, sector_id,
                                                created_by=created_by)
        dal.link_catalogue_category(sess, catalogue_id, cand_cat)
        minted.append(("threat_catalogue", generic))
        triage.entries.append({"id": catalogue_id, "name": generic, "type_id": type_id,
                            "sector_id": sector_id, "cats": frozenset({cand_cat})})
        triage.catalogue_vecs.setdefault(generic, qv)
    return _CandidateFate(verdict, type_id, catalogue_id, matched_id, cosine, minted)


def _add_unverified_threats_to_library(sess: Session, scenario_session: RowMapping, good_subs: list[int],
                                        user_id: str | None) -> list[tuple[str, str]]:
    sector_id = _pick_sector_for_promotion(scenario_session)
    sid = scenario_session["SessionID"]
    tenant, entity = scenario_session["TenantID"], scenario_session["EntityID"]
    all_rows = _promotion_candidates(sess, sid, good_subs)
    threshold = get_settings().library_promotion_threshold
    rows: list[RowMapping] = []
    scored_rows: list[RowMapping] = []
    for r in all_rows:
        # GAP-7 guard: a threat ALREADY linked to a catalogue row must never enter the
        # promotion lane, whatever its score. Library-first retrieval writes continuous
        # scores (not just the synthetic band the old split assumed), so a low-scoring
        # library match could otherwise run _find_or_create_type_and_catalogue and mint a
        # near-duplicate catalogue row for something already present — and near-duplicate
        # entries permanently break _auto_calibrate for every future worker boot.
        if r["ThreatCatalogueID"] is not None:
            scored_rows.append(r)
        elif r["GroundingScore"] is None or r["GroundingScore"] < threshold:
            rows.append(r)
        else:
            scored_rows.append(r)

    resolved: dict[tuple, Any] = {}

    stamp = now()
    actor_id = user_id or scenario_session["UserID"]
    actor_type = ActorType.user if user_id else ActorType.system
    llm = get_llm()
    tn = tuning.from_session(dict(scenario_session))
    auto_mode = get_settings().promotion_auto_approve_enabled
    triage = _prepare_triage(sess, llm, scenario_session, rows)
    pending_cards = pending_card_identities(sess) if all_rows else set()
    update_rows: list[dict] = []
    audit_rows: list[dict] = []
    candidate_rows: list[dict] = []
    triage_details: list[dict] = []
    promoted_names: list[tuple[str, str]] = []
    for row in rows:
        generic = triage.generic_by_tid[row["ThreatID"]]
        fate = _decide_candidate_fate(sess, row, generic, sector_id, resolved, triage, tn,
                                    created_by=actor_id, auto_mode=auto_mode,
                                    pending_cards=pending_cards)
        verdict, type_id, catalogue_id_new, matched_id, cosine, minted = fate

        # NO actor minting or linking. Actors are library-only (grounding): a threat carries
        # either its type's curator-maintained links or a nearest-match fallback. Writing a
        # fallback back as a curated link would corrupt the library one accept at a time —
        # the next session would read that guess as a curator's decision.
        triage_details.append({"threat_id": row["ThreatID"], "generic_name": generic,
                            "verdict": verdict, "cosine": cosine,
                            "matched_catalogue_id": matched_id})

        promoted = (type_id != row["ThreatTypeID"]
                    or catalogue_id_new != row["ThreatCatalogueID"])
        if promoted:
            update_rows.append({"b_tid": row["ThreatID"], "ThreatTypeID": type_id,
                                "ThreatCatalogueID": catalogue_id_new})
            audit_rows.append(dal.audit_row(
                sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=entity,
                EventType=AuditEventType.library_promoted, ActorUserID=actor_id, ActorType=actor_type,
                ThreatTypeRefID=type_id, CreatedAt=stamp,
                DetailJSON=json.dumps({"threat_id": row["ThreatID"], "catalogue_id": catalogue_id_new,
                                        "sector_id": sector_id,
                                        "triage_verdict": verdict})))
            log.info("threat.promoted", session_id=sid, threat_id=row["ThreatID"],
                    type_id=type_id, catalogue_id=catalogue_id_new, sector_id=sector_id)
            promoted_names.extend(minted)

        ident = ((generic or row["ThreatName"]) or "").strip().casefold()
        ckey = ("candidate", ident)
        # ThreatCatalogueID is None: a threat ALREADY linked to a library entry must never queue a
        # curation card. _decide_candidate_fate skips triage for exactly those rows (its
        # `row["ThreatCatalogueID"] is None` gate), so `verdict` keeps its default `review` — and
        # without this conjunct any RE-RUN of promotion (the retry sweep today; per-accept
        # promotion once scenarios decide independently) queues a fresh pending card for a threat
        # already in the library. auto_reject stamps ThreatCatalogueID itself, so those are covered.
        if (verdict is TriageVerdict.review and row["ThreatCatalogueID"] is None
                and row["ThreatName"] and ident
                and ckey not in resolved
                and (CandidateKind.threat, ident) not in pending_cards):
            resolved[ckey] = True
            candidate_rows.append({
                "CandidateID": guid(), "TenantID": tenant, "EntityID": entity,
                "SessionID": sid, "ProposedCategory": row["ThreatCategory"],
                "ProposedType": row["ThreatType"], "ProposedName": row["ThreatName"],
                "ProposedGenericName": generic,
                "Status": CandidateStatus.pending, "ThreatTypeID": type_id,
                "ThreatCatalogueID": catalogue_id_new,
                "ReviewedBy": None, "ReviewedAt": None, "CreatedAt": stamp,
                "CandidateKind": CandidateKind.threat, "CreatedBy": actor_id,
            })
        elif (verdict is TriageVerdict.review and ident
                and (CandidateKind.threat, ident) in pending_cards):
            log.info("accept.threat_card_suppressed", threat_id=row["ThreatID"], ident=ident,
                    note="identity already queued for review or previously rejected — no re-queue")

    # The scored_rows loop that lived here existed ONLY to mint actors from well-matched
    # threats. Actors are library-only now, so it is gone; scored_rows still names the rows
    # deliberately EXCLUDED from threat promotion by the split above.

    if triage_details:
        audit_rows.append(dal.audit_row(
            sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=entity,
            EventType=AuditEventType.promotion_triage, ActorUserID=actor_id, ActorType=actor_type,
            CreatedAt=stamp,
            DetailJSON=json.dumps({
                "bands": {"auto_reject": tn.triage_auto_reject_cosine,
                        "auto_approve": tn.triage_auto_approve_cosine},
                "candidates": triage_details})))
    if update_rows:
        it = cast(Table, m.Identified_Threat.__table__)
        sess.execute(update(it).where(it.c.ThreatID == bindparam("b_tid")), update_rows)
    if candidate_rows:
        sess.execute(insert(m.Threat_Candidate_Review), candidate_rows)
        n_actor = sum(1 for c in candidate_rows if c["CandidateKind"] == CandidateKind.actor)
        log.info("accept.candidates_queued", session_id=sid,
                threat_cards=len(candidate_rows) - n_actor, actor_cards=n_actor,
                auto_mode=auto_mode)
    if audit_rows:
        sess.execute(insert(m.Scenario_Audit), audit_rows)
    return promoted_names


def eager_embed_promoted(sess: Session, llm, promoted_names: list[tuple[str, str]]) -> None:
    if not promoted_names:
        return
    names_by_group: dict[str, list[str]] = {}
    for group, name in promoted_names:
        names_by_group.setdefault(group, []).append(name)
    for group, names in names_by_group.items():
        try:
            embeddings.create_items(sess, llm, group, names)
        except Exception:
            log.warning("session.eager_embed_failed", embedding_group=group, names=names, exc_info=True)
