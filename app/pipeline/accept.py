""" this is what runs when a human clicks "Accept" — it locks
everything down, marks the chosen items as approved, and (if new threats were
found) adds them to the shared threat library.

Single final review & accept (SDD §5.7, [A1]).

One transaction (Unit of Work). Mutual exclusion with an in-flight regeneration is
enforced two ways ([R5]): a **positive state gate** (accept only when the session
is actually at the REVIEW barrier — which the pipeline reaches only after every
subsystem finishes) and by **honoring the `_LOCK` CAS** (a held lock aborts the
accept). It re-validates grounded master ids are still active ([R6]), then sets
`Accepted=1` and flips the session to `completed`, releasing the M4 lock ([R1]).
"""
from __future__ import annotations

import json

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.enums import (
    AuditDecision, AuditEventType, CandidateStatus, GroundingStatus, StageStatus, SubsystemLevel, WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import EntityForbidden, guid, now
from app.pipeline import grounding

log = get_logger(__name__)


class AcceptConflict(Exception):
    """Accept attempted off the REVIEW barrier or against a held lock → 409 ([R5])."""


class MasterInactive(Exception):
    """A grounded master id was deactivated since Stage 2 → block accept ([R6])."""


def accept_session(sess: Session, session_id: str, entity_id: str, user_id: str | None,
                   subset: list[str] | None = None) -> None:
    """ the main accept function — checks the session is
    really ready for review, locks it, marks the approved profile/scenarios,
    grows the library if needed, and finishes the session.

    Final review & accept (SDD §5.7, [A1]): gate on the REVIEW barrier, take every
    subsystem `_LOCK` to shut out a concurrent regeneration, re-check grounded masters
    are still active ([R6]), then mark the accepted profile/scenarios and complete the
    session in one transaction. `subset`, if given, restricts which scenario OutputIDs
    get `Accepted=1` (partial accept, [R8]); omit it to accept everything at REVIEW."""
    session = dal.get_session(sess, session_id, entity_id)  # entity guard (INV-1)
    if session is None:
        raise EntityForbidden(f"session {session_id} not in entity {entity_id}")

    # Positive state gate — the session is only at REVIEW after the LAST subsystem
    # finishes (tasks._maybe_enter_review), so this closes the entire mid-pipeline window.
    if session["CurrentStage"] != WorkflowStage.REVIEW or session["StageStatus"] != StageStatus.AWAITING_DECISION:
        raise AcceptConflict(
            f"session not at REVIEW (stage={session['CurrentStage']}, status={session['StageStatus']})")

    subsystem_ids = dal.subsystem_ids_at_level(sess, session_id, SubsystemLevel.LOCK)

    # [R8] Partial-REVIEW: accept touches ONLY subsystems that actually reached the review
    # barrier (SCENARIOS AWAITING_DECISION). An errored subsystem's committed profile/threats
    # must not be marked Accepted, nor may its stale grounded masters gate the whole accept.
    good_subs = dal.subsystem_ids_at_level(
        sess, session_id, SubsystemLevel.SCENARIOS, status=StageStatus.AWAITING_DECISION)

    # Acquire every _LOCK; a held lock (regeneration running) aborts deterministically.
    acquired: list[int] = []
    try:
        for ss in subsystem_ids:
            # Lock holder id must fit the GUID ActiveTaskID column (like every Celery task id);
            # session_id is itself a UUID and identifies the accept holder — no prefix (would overflow).
            if not dal.acquire_lock(sess, session_id, ss, task_id=session_id):
                raise AcceptConflict(f"subsystem {ss} lock held (regeneration in progress)")
            acquired.append(ss)

        _assert_masters_active(sess, session_id, good_subs)  # [R6], scoped to reviewed subsystems

        dal.mark_profiles_accepted(sess, session_id, good_subs)
        # [R8] same scope as the profile update; subset=None means "accept all"
        dal.mark_scenarios_accepted(sess, session_id, good_subs, subset=subset)

        # AFTER the Accepted=1 update so promotion can gate on the scenarios the
        # reviewer actually accepted — a partial accept's excluded scenarios (and
        # scoping's Selected=0 threats, which have no scenario at all) never promote.
        _promote_flagged_threats(sess, session, good_subs, user_id)

        dal.complete_session(sess, session_id)  # [R1] releases the M4 lock

        decision = AuditDecision.partial if subset is not None else AuditDecision.accept
        for event in (AuditEventType.profiles_accepted, AuditEventType.scenarios_accepted, AuditEventType.review_decision):
            dal.append_audit(sess, AuditID=guid(), SessionID=session_id, TenantID=session["TenantID"],
                             EntityID=str(entity_id), EventType=event, Decision=decision, ActorUserID=user_id,
                             DetailJSON=json.dumps({"subset": subset}) if subset is not None else None)
        log.info("session.accepted", session_id=session_id, decision=str(decision), user=user_id)
    finally:
        try:
            for ss in acquired:
                dal.release_lock(sess, session_id, ss)
        except Exception:
            # A failed accept is mid-rollback: releasing would raise PendingRollbackError
            # and MASK the real error. The rollback itself frees the uncommitted lock
            # rows, so swallowing here never leaks a lock.
            log.warning("accept.lock_release_failed", session_id=session_id)


def _assert_masters_active(sess: Session, session_id: str, good_subs: list[int]) -> None:
    """ makes sure the threat-library entries this session
    matched against haven't been turned off since the matching happened.

    Every stored Type/Catalogue master reference must still be active — ANY band,
    not just grounded/confirm: a flagged row's stored ThreatTypeID (type matched at
    >=confirm, only the catalogue fell below) is reused by promotion ([R10]), so a
    deactivated parent must block accept before a new active catalogue gets created
    under it. Batched: two set-membership queries, not one probe per id. [R8] Scoped to
    the subsystems being accepted (`good_subs`) so an errored subsystem's stale
    grounding can't block accept."""
    rows = sess.execute(
        select(m.Identified_Threat.c.ThreatTypeID, m.Identified_Threat.c.ThreatCatalogueID,
              m.Identified_Threat.c.GroundingStatus)
        .where(
            m.Identified_Threat.c.SessionID == session_id,
            m.Identified_Threat.c.Superseded == 0,
            m.Identified_Threat.c.SubsystemID.in_(good_subs),
        )
    ).all()
    # Type ids are load-bearing on EVERY band (promotion reuses a flagged row's type id);
    # a flagged row's catalogue id is a below-threshold match promotion IGNORES — checking
    # it would let an irrelevant stale match block the whole accept.
    type_ids = {t for t, _, _ in rows if t is not None}
    cat_ids = {c for _, c, s in rows if c is not None and s != GroundingStatus.flagged}

    if type_ids:
        active = {r[0] for r in sess.execute(
            select(m.Threat_Type.c.ThreatTypeID).where(
                m.Threat_Type.c.ThreatTypeID.in_(type_ids), m.Threat_Type.c.IsActive == True))}
        if type_ids - active:
            raise MasterInactive(f"Threat_Type inactive: {sorted(type_ids - active)}")
    if cat_ids:
        active = {r[0] for r in sess.execute(
            select(m.Threat_Catalogue.c.ThreatCatalogueID).where(
                m.Threat_Catalogue.c.ThreatCatalogueID.in_(cat_ids), m.Threat_Catalogue.c.IsActive == True))}
        if cat_ids - active:
            raise MasterInactive(f"Threat_Catalogue inactive: {sorted(cat_ids - active)}")


def _default_sector_id(session: dict) -> int | None:
    """ works out which sector a newly-added library entry
    should belong to, since there's no screen yet for a human to choose.

    [R10] Default sector scope for a newly-promoted master (SDD §5.7 step 2 — the
    reviewer's-choice UI doesn't exist yet, so this implements the SDD's stated
    DEFAULT only: parent sector when the session has one). `SectorIDsJSON` is
    `[sector_id, parent_sector_id]` (R6, migration 0013) — the same shape
    `gather_asset_details`/`grounding` already use; NULL/empty means no sector context
    → global (SectorID=NULL), matching what `sector_ids=[]` always meant elsewhere."""
    raw = session.get("SectorIDsJSON")
    ids = json.loads(raw) if raw else []
    if len(ids) >= 2:
        return ids[1]   # parent
    if len(ids) == 1:
        return ids[0]    # no parent above it — closest available to "parent" here
    return None           # no sector context at all → global


def _promote_actors(sess: Session, type_id: int, actors: list[str], resolved: dict) -> list[str]:
    """ adds any new attacker types to the library and links
    them to the right threat type.

    Upsert each validated actor and link it to `type_id`; return the names whose type→actor
    link was NEWLY created this accept — so the caller audits real library growth, not a re-affirmed
    pre-existing link. `resolved` memoizes actor ids / links across rows within the one accept."""
    newly_linked: list[str] = []
    for actor_name in actors:
        actor_key = ("actor", actor_name)
        actor_id = resolved.get(actor_key)
        if actor_id is None:
            actor_id = dal.upsert_threat_actor(sess, actor_name)
            resolved[actor_key] = actor_id
        link_key = ("link", type_id, actor_id)
        if link_key not in resolved:
            if dal.link_type_actor(sess, type_id, actor_id):  # True only when a NEW link row was inserted
                newly_linked.append(actor_name)
            resolved[link_key] = True
    return newly_linked


def _promote_flagged_threats(sess: Session, session: dict, good_subs: list[int], user_id: str | None) -> None:
    """ for every threat the AI found that WASN'T already in
    the library, and that got accepted — this adds it to the shared library so
    future sessions can match against it too.

    [R10] SDD §5.7 steps 1, 3, 4 — library growth on accept, strictly for flagged
    threats whose ACTIVE SCENARIO WAS JUST ACCEPTED (runs after the Accepted=1 update:
    a partial accept's excluded scenarios — and scoping's Selected=0 threats, which
    have no scenario row at all — never promote; §5.7 "for each accepted scenario").
    Grounded/confirm threats already point at a real master — skipped. A flagged row's
    stored ThreatTypeID is trusted (grounding only stores one matched at >=confirm
    band) and is reused; a stored ThreatCatalogueID is BY CONSTRUCTION a below-
    threshold match, so the reviewer-approved PROPOSED name is upserted instead and
    the row re-pointed to the result (the upsert returns the existing entry when that
    exact name already lives under the type/sector). Upserts are race-safe
    (M2-index-backed, dal.upsert_*); identical proposals within one accept are deduped
    in-memory. Actor names are promoted only from VALIDATED actor sets ([R6] §8.4
    step 5: never silently trust actors for an ungrounded type — raw unvalidated LLM
    actors wait for the curator gate, R11). Rows where promotion changes nothing emit
    no audit/candidate row (no false library_promoted trail)."""
    sector_id = _default_sector_id(session)
    sid = session["SessionID"]
    st, out = m.Scoped_Threat, m.Threat_Scenario_Output
    scenario_accepted = (
        select(1)
        .where(st.c.SessionID == sid, st.c.ThreatID == m.Identified_Threat.c.ThreatID,
               st.c.Superseded == 0,
               out.c.SessionID == sid, out.c.ScopedThreatID == st.c.ScopedThreatID,
               out.c.Superseded == 0, out.c.Accepted == 1)
        .exists()
    )
    rows = sess.execute(
        select(m.Identified_Threat.c.ThreatID, m.Identified_Threat.c.ThreatCategory,
              m.Identified_Threat.c.ThreatType, m.Identified_Threat.c.ThreatName,
              m.Identified_Threat.c.ThreatActorsJSON, m.Identified_Threat.c.ThreatTypeID,
              m.Identified_Threat.c.ThreatCatalogueID)
        .where(m.Identified_Threat.c.SessionID == sid,
               m.Identified_Threat.c.Superseded == 0,
               m.Identified_Threat.c.SubsystemID.in_(good_subs),
               m.Identified_Threat.c.GroundingStatus == GroundingStatus.flagged,
               scenario_accepted)
    ).mappings().all()

    resolved = {}  # in-accept memo: ("category"|"type"|"cat"|"actor"|"link", ...) -> id/True
    for row in rows:
        type_id = row["ThreatTypeID"]  # >=confirm-band match when set — trusted ([R6])
        if type_id is None:
            key = ("type", row["ThreatCategory"], row["ThreatType"])
            type_id = resolved.get(key)
            if type_id is None:
                cat_key = ("category", row["ThreatCategory"])
                if cat_key not in resolved:
                    resolved[cat_key] = grounding.find_category(sess, row["ThreatCategory"])
                type_id = dal.upsert_threat_type(sess, row["ThreatType"], resolved[cat_key], sector_id)
                resolved[key] = type_id

        catalogue_id = row["ThreatCatalogueID"]
        if row["ThreatName"]:  # the accepted PROPOSED name wins over any low-confidence stored id
            ckey = ("cat", type_id, row["ThreatName"])
            catalogue_id = resolved.get(ckey)
            if catalogue_id is None:
                catalogue_id = dal.upsert_threat_catalogue(sess, row["ThreatName"], type_id, sector_id)
                resolved[ckey] = catalogue_id

        actors_meta = json.loads(row["ThreatActorsJSON"] or "{}")
        raw_actors = actors_meta.get("actors", []) if actors_meta.get("validated") else []
        # Only validated string actors promote ([R6] §8.4 step 5); shape-hardened by the same
        # function grounding.find_threat_in_library() itself uses, so the two can never drift apart again.
        actors = grounding.ensure_actor_list(raw_actors)
        linked_actors = _promote_actors(sess, type_id, actors, resolved)  # names NEWLY linked this accept

        if (type_id == row["ThreatTypeID"] and catalogue_id == row["ThreatCatalogueID"]
                and not linked_actors):
            continue  # nothing promoted, re-pointed, or newly actor-linked — no false audit trail

        sess.execute(
            update(m.Identified_Threat).where(m.Identified_Threat.c.ThreatID == row["ThreatID"])
            .values(ThreatTypeID=type_id, ThreatCatalogueID=catalogue_id)
        )
        dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=session["TenantID"],
                         EntityID=session["EntityID"], EventType=AuditEventType.library_promoted,
                         ActorUserID=user_id, ThreatTypeRefID=type_id,
                         DetailJSON=json.dumps({"threat_id": row["ThreatID"], "catalogue_id": catalogue_id,
                                                "sector_id": sector_id, "actors": linked_actors}))

        candidate_id = guid()
        dal.insert_row(sess, m.Threat_Candidate_Review, {
            "CandidateID": candidate_id, "TenantID": session["TenantID"], "EntityID": session["EntityID"],
            "SessionID": sid, "ProposedCategory": row["ThreatCategory"],
            "ProposedType": row["ThreatType"], "ProposedName": row["ThreatName"] or "",
            "Status": CandidateStatus.accepted, "ThreatTypeID": type_id, "ThreatCatalogueID": catalogue_id,
            "ReviewedBy": user_id, "ReviewedAt": now(), "CreatedAt": now(),
        })
        dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=session["TenantID"],
                         EntityID=session["EntityID"], EventType=AuditEventType.candidate_reconciled,
                         ActorUserID=user_id,
                         DetailJSON=json.dumps({"candidate_id": candidate_id, "threat_id": row["ThreatID"]}))
        log.info("threat.promoted", session_id=sid, threat_id=row["ThreatID"],
                 type_id=type_id, catalogue_id=catalogue_id, sector_id=sector_id)
