""" this is what runs when a human clicks "Accept" — it locks
everything down, marks the chosen items as approved, and (if new threats were
found) adds them to the shared threat library.

Single final review & accept.

One transaction (Unit of Work) for the accept decision itself — each `_LOCK`
acquisition commits immediately (same discipline as tasks.py/cascade.py) so its
row-level lock isn't held for the rest of the request, but validation, marking
scenarios accepted, promotion, `complete_session`, and audit writes all commit
or roll back together. Mutual exclusion with an in-flight regeneration is
enforced two ways: a **positive state gate** (accept only when the session
is actually at the REVIEW barrier — which the pipeline reaches only after every
subsystem finishes) and by **honoring the `_LOCK` CAS** (a held lock aborts the
accept). It re-validates grounded master ids are still active, then sets
`Accepted=1` and flips the session to `completed`, releasing the lock.
"""
from __future__ import annotations

import json
from typing import Any, Sequence, cast

from sqlalchemy import RowMapping, Table, bindparam, insert, select, update
from sqlalchemy.orm import Session

from app.core.enums import (
    ActorType, AuditDecision, AuditEventType, CandidateStatus, GroundingStatus, SessionStatus, StageStatus,
    SubsystemLevel, WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import EntityForbidden, NotFoundError, guid, now
from app.pipeline import grounding

log = get_logger(__name__)


class AcceptConflict(Exception):
    """Accept attempted off the REVIEW barrier or against a held lock → 409 ([R5]).

    `reason` is an optional machine-readable code (e.g. "session_completed") surfaced by the
    HTTP handler as `details.reason` — same pattern as dal.SessionConflict's
    `active_session_id`. Raise sites without a stable cause just omit it."""

    def __init__(self, message: str, reason: str | None = None):
        super().__init__(message)
        self.reason = reason


class MasterInactive(Exception):
    """A grounded master id was deactivated since Stage 2 → block accept ([R6])."""


def accept_session(sess: Session, session_id: str, entity_id: str, user_id: str | None,
                subset: list[str] | None = None) -> int:
    """Run the "Accept" action for a session in one transaction: lock the session's
    subsystems, re-check the master data is still valid, mark the chosen scenarios
    accepted, promote any newly-approved threats into the shared library, and mark
    the session complete. Locks are always released in the `finally` block.
    """
    # Look up the session scoped to this entity; a miss means the caller doesn't
    # own this session (wrong tenant/entity), so treat it as forbidden.
    scenario_session = dal.get_session(sess, session_id, entity_id)
    if scenario_session is None:
        raise EntityForbidden(f"session {session_id} not in entity {entity_id}")

    _ensure_session_ready_to_accept(scenario_session)

    # Subsystems whose regeneration lock we must hold for the duration of accept.
    subsystem_ids = dal.subsystem_ids_at_level(sess, session_id, SubsystemLevel.LOCK)


    # Subsystems that actually finished scenario generation and are awaiting this decision —
    # these are the ones whose scenarios/threats we'll act on below.
    good_subs = dal.subsystem_ids_at_level(
        sess, session_id, SubsystemLevel.SCENARIOS, status=StageStatus.AWAITING_DECISION)

    # Acquire every _LOCK; a held lock (regeneration running) aborts deterministically.
    acquired: list[int] = []
    try:
        for ss in subsystem_ids:
            if not dal.acquire_lock(sess, session_id, ss, task_id=session_id):
                raise AcceptConflict(f"subsystem {ss} lock held (regeneration in progress)")
            acquired.append(ss)
            # Make the lock durable BEFORE any other work — same reason tasks.py's
            # find_threats/write_scenarios and cascade.py's run_regeneration commit right
            # after their own acquire_lock succeeds: leaving it uncommitted would hold a
            # real SQL Server X-lock on the _LOCK row for the rest of accept (validation,
            # promotion loop, complete_session, audit writes), forcing a concurrent
            # regenerate_task's acquire_lock to block on that row instead of failing fast.
            sess.commit()

        _ensure_threat_data_still_active(sess, session_id, good_subs)

        if subset is not None:
            # One canonical (lowercase, stripped) form BEFORE both uses below: Python's set()
            # counts case-sensitively but MSSQL's default CI collation matches OutputID
            # case-insensitively (and ignores trailing spaces), so without normalization the
            # same GUID sent in two casings counts as 2 requested yet matches only 1 row — a
            # spurious 404 on a legitimate request. dal.guid() stores lowercase, so lowercase
            # is the canonical form; this also canonicalizes what AcceptedSubsetJSON and the
            # audit DetailJSON record.
            # dal.canonical_guid, not .strip().lower(): case+whitespace folding alone leaves the
            # dashless (Guid.ToString("N")), braced and urn:uuid: spellings distinct, so the SAME
            # id sent twice in two forms inflated `requested` past the row count `matched` below
            # → spurious 404 and a full rollback of a legitimate accept. It also canonicalizes
            # what AcceptedSubsetJSON / the audit DetailJSON persist, so those stay joinable to
            # the OutputIDs the API actually returns.
            subset = [dal.canonical_guid(s) for s in subset]
        # subset=None means "accept all"
        matched = dal.mark_scenarios_accepted(sess, session_id, good_subs, subset=subset)
        if subset is not None:
            # [REVIEW-FIX] a subset id that doesn't match any row here (wrong session/
            # subsystem, already superseded, or never existed) previously no-op'd
            # silently — the session still completed as if the accept fully succeeded.
            # set() first: output_ids permits duplicate ids at the schema layer (as does its
            # sibling RegenerateScenariosBody.output_ids, whose duplicates are deduped
            # downstream in cascade.get_threat_id_to_redo), and a repeated id can only ever
            # match its row once, so counting raw len(subset) would false-flag a
            # legitimate duplicate-id request as a mismatch.
            requested = len(set(subset))
            if matched != requested:
                raise NotFoundError(
                    f"{requested - matched} of {requested} requested OutputID(s) in `subset` did "
                    f"not match an active, awaiting-decision scenario in session {session_id}")
        else:
            # [FIX L1 class-killer] accept-all must cover EVERY subsystem that still owns active,
            # reviewable scenarios — not just the ones good_subs (SCENARIOS @ AWAITING_DECISION)
            # happens to name. If a subsystem has active Threat_Scenario_Output rows but its stage
            # row is out of sync (e.g. a next-set/regen failure left it ERROR), its accumulated
            # scenarios would be silently dropped while the session completes. decide_session_outcome
            # runs dal.revive_errored_scenarios_to_review before REVIEW to prevent exactly this, so
            # this only fires on a genuinely inconsistent board — and raising is the safe direction:
            # never silently drop a batch, never silently accept off a stale board. Subsumes the old
            # matched==0 guard (zero matches with active scenarios ⇒ those subsystems are uncovered).
            uncovered = dal.subsystems_with_active_scenarios(sess, session_id) - set(good_subs)
            if uncovered:
                raise AcceptConflict(
                    f"accept-all leaves active scenarios in subsystem(s) {sorted(uncovered)} whose "
                    f"SCENARIOS stage is not AWAITING_DECISION (subsystem stage state out of sync)")

        _add_flagged_threats_to_library(sess, scenario_session, good_subs, user_id)

        # CAS-fenced: False means a concurrent writer (e.g. a cancel) already moved
        # the session off 'active' between our REVIEW-barrier check above and here —
        # surface that as a conflict rather than silently completing over it.
        if not dal.complete_session(sess, session_id):
            raise AcceptConflict(f"session {session_id} is no longer active")

        # Three-way decision, mirroring the wire-level all/none/subset choice: no subset ->
        # full accept; an explicit empty subset -> reject (accept nothing, but the session
        # still completes — [R8]); a populated subset -> partial.
        if subset is None:
            decision = AuditDecision.accept
        elif subset:
            decision = AuditDecision.partial
        else:
            decision = AuditDecision.reject
        # review_decision always; scenarios_accepted ONLY when something actually flipped —
        # its documented meaning (enums.py: Threat_Scenario_Output flipped Accepted=1) must
        # stay queryable at face value, and a reject (mode="none") flips nothing, so writing
        # it there would make audit queries for accepted-content over-report.
        events = ((AuditEventType.review_decision,) if decision == AuditDecision.reject
                else (AuditEventType.scenarios_accepted, AuditEventType.review_decision))
        for event in events:
            dal.append_audit(sess, AuditID=guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
                            EntityID=str(entity_id), EventType=event, Decision=decision, ActorUserID=user_id,
                            DetailJSON=json.dumps({"subset": subset}) if subset is not None else None)
        log.info("session.accepted", session_id=session_id, decision=str(decision),
                accepted_count=matched, user=user_id)
        return matched
    except Exception:
        # The lock acquisitions above are already committed (see comment there); everything
        # after them — validation, mark_scenarios_accepted, the promotion loop, complete_session,
        # audit rows — is still one uncommitted unit of work. Roll THAT back explicitly (same
        # discipline as tasks.py's _record_failure) so a failure here can never leave a partial
        # accept committed once the `finally` block below commits the lock release.
        sess.rollback()
        raise
    finally:
        # Always release whatever locks we managed to acquire, even if something above
        # failed partway through. A release failure is only logged, not re-raised, so it
        # doesn't mask the original error (if any) from the try block.
        try:
            for ss in acquired:
                dal.release_lock(sess, session_id, ss, task_id=session_id)
            sess.commit()
        except Exception:
            log.warning("accept.lock_release_failed", session_id=session_id)


def review_gate_reason(scenario_session: RowMapping | dict) -> tuple[str, str] | None:
    """Why this session cannot take a review action (accept/regenerate) right now, as a
    (machine_reason, human_message) pair — or None if it is at the REVIEW barrier.

    Branches on SessionStatus FIRST — the authoritative liveness signal — because
    CurrentStage/StageStatus are progress history: complete_session deliberately never
    rewrites StageStatus, so a completed session still reads AWAITING_DECISION, and echoing
    that verbatim produced a self-contradictory message ("not at REVIEW ...
    status=AWAITING_DECISION") that misled callers into retrying a final decision. Shared by
    the accept gate (below) and sessions.py's regenerate/next-set gate so the two can never
    drift apart again."""
    if (scenario_session["CurrentStage"] == WorkflowStage.REVIEW
            and scenario_session["StageStatus"] == StageStatus.AWAITING_DECISION):
        return None
    status = scenario_session["SessionStatus"]
    if status == SessionStatus.completed:
        return ("session_completed",
                f"session already completed at {scenario_session['CompletedAt']} — the review "
                f"decision is final; accepted scenarios are available via "
                f"GET /v1/assets/{scenario_session['AssetID']}/accepted-scenarios, and a new "
                f"session for this asset can run a fresh review")
    if status == SessionStatus.cancelled:
        return ("session_cancelled",
                f"session was cancelled — start a new session for asset {scenario_session['AssetID']}")
    return ("generation_in_progress",
            f"session not at REVIEW yet (stage={scenario_session['CurrentStage']}, "
            f"status={scenario_session['StageStatus']}) — generation still in progress")


def _ensure_session_ready_to_accept(scenario_session: RowMapping) -> None:
    """Accept is only allowed while the session is sitting at the REVIEW step
    waiting on a human decision; anything else means it's not ready (or already handled).
    """
    gate = review_gate_reason(scenario_session)
    if gate is not None:
        reason, message = gate
        raise AcceptConflict(message, reason=reason)


def _ensure_threat_data_still_active(sess: Session, session_id: str, good_subs: list[int]) -> None:
    """Re-check that every Threat_Type / Threat_Catalogue id referenced by this session's
    threats is still active. Someone could have deactivated one after Stage 2 ran, so we
    block the accept (raise MasterInactive) rather than accept against stale master data.
    """
    rows = sess.execute(
        select(m.Identified_Threat.ThreatTypeID, m.Identified_Threat.ThreatCatalogueID)
        .where(
            m.Identified_Threat.SessionID == session_id,
            m.Identified_Threat.Superseded == 0,
            m.Identified_Threat.SubsystemID.in_(good_subs),
        )
    ).all()
    # Collect every referenced type id and catalogue id. A non-null ThreatCatalogueID always
    # means grounding matched a real, pre-existing Threat_Catalogue row (find_threat_in_library
    # only ever sets it from an actual candidate row) — that holds regardless of the threat's
    # overall GroundingStatus, since a confidently-typed threat can still end up "flagged"
    # purely because its NAME match scored below grounding_confirm_threshold while a real
    # catalogue candidate existed. So every non-null id genuinely needs re-validating, the same
    # way type_ids already is below — gating this on GroundingStatus != flagged let a since-
    # deactivated/deleted catalogue row slip past the check for exactly that sub-case.
    type_ids = {t for t, _ in rows if t is not None}
    cat_ids = {c for _, c in rows if c is not None}

    # Check Threat_Type ids are still active; any that dropped out of the "active" set
    # since Stage 2 blocks the whole accept.
    if type_ids:
        active = {r[0] for r in sess.execute(
            select(m.Threat_Type.ThreatTypeID).where(
                m.Threat_Type.ThreatTypeID.in_(type_ids),
                m.Threat_Type.IsActive == True, m.Threat_Type.IsDeleted == False))}
        if type_ids - active:
            raise MasterInactive(f"Threat_Type inactive: {sorted(type_ids - active)}")
    # Same check, mirrored for Threat_Catalogue ids.
    if cat_ids:
        active = {r[0] for r in sess.execute(
            select(m.Threat_Catalogue.ThreatCatalogueID).where(
                m.Threat_Catalogue.ThreatCatalogueID.in_(cat_ids),
                m.Threat_Catalogue.IsActive == True, m.Threat_Catalogue.IsDeleted == False))}
        if cat_ids - active:
            raise MasterInactive(f"Threat_Catalogue inactive: {sorted(cat_ids - active)}")


def _pick_sector_for_promotion(scenario_session: RowMapping) -> int | None:
    """Pick which sector a newly-promoted threat type/catalogue entry should be scoped to,
    based on the session's sector hierarchy JSON. Prefers the parent sector; falls back to
    the only sector if there's no parent, or None (global) if there's no sector at all.
    """
    raw = scenario_session.get("SectorIDsJSON")
    ids = json.loads(raw) if raw else []
    if len(ids) >= 2:
        return ids[1]   # parent
    if len(ids) == 1:
        return ids[0]    # no parent above it — closest available to "parent" here
    return None           # no sector context at all → global


def _link_actors_to_threat_type(sess: Session, type_id: int, actors: list[str], resolved: dict) -> list[str]:
    """Make sure each actor name is a real Threat_Actor row and is linked to this threat
    type, creating whichever rows/links don't exist yet. Returns the actor names that
    got a brand-new link (used for audit logging), not ones that were already linked.
    """
    newly_linked: list[str] = []
    # `resolved` is a shared memo (actor name -> id, and (type,actor) -> "already linked")
    # so repeated actor names across many threats in this accept don't hit the DB twice.
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


def _extract_actor_names_per_threat(rows: Sequence[RowMapping]) -> tuple[dict[int, list[str]], set[str]]:
    """Parse each row's stored actor JSON up front, but only trust the actor list if it was
    marked "validated" — otherwise treat the threat as having no actors. Returns the
    per-threat actor lists plus the union of every actor name seen (for the bulk id lookup).
    """
    parsed_actors: dict[int, list[str]] = {}
    all_actor_names: set[str] = set()
    for row in rows:
        actors_meta = json.loads(row["ThreatActorsJSON"] or "{}")
        raw_actors = actors_meta.get("actors", []) if actors_meta.get("validated") else []
        actors = grounding.ensure_actor_list(raw_actors)
        parsed_actors[row["ThreatID"]] = actors
        all_actor_names.update(actors)
    return parsed_actors, all_actor_names


def _find_or_create_type_and_catalogue(
    sess: Session, row: RowMapping, sector_id: int | None, resolved: dict
) -> tuple[int, int | None]:
    """Work out (or create) the Threat_Type and Threat_Catalogue ids this flagged threat
    should end up pointing at: reuse the high-confidence type match recorded at Stage 2
    when present, otherwise resolve/create via category+type name; an accepted
    PROPOSED catalogue name always wins over any low-confidence stored catalogue id.

    A newly-created Threat_Catalogue row also gets linked into Threat_Catalogue_Category_Map
    under the same resolved category — [A2]'s "authoritative per-threat category source"
    otherwise only ever gets populated by the curated Excel seed, never by AI promotion, so
    every threat promoted through this path would be permanently stuck relying on its Type's
    single rough default instead. One category today (the AI proposes exactly one); the map
    table is already multi-valued, so a future threat gaining a second category is just
    another link_catalogue_category call, not a schema change.
    """
    def _category_id() -> int | None:
        cat_key = ("category", row["ThreatCategory"])
        if cat_key not in resolved:
            resolved[cat_key] = grounding.find_category(sess, row["ThreatCategory"])
        return resolved[cat_key]

    type_id = row["ThreatTypeID"]  # >=confirm-band match when set — trusted
    if type_id is None:
        # No high-confidence type match was recorded earlier, so find/create one now,
        # under the resolved category.
        key = ("type", row["ThreatCategory"], row["ThreatType"])
        type_id = resolved.get(key)
        if type_id is None:
            type_id = dal.upsert_threat_type(sess, row["ThreatType"], _category_id(), sector_id)
            resolved[key] = type_id

    catalogue_id = row["ThreatCatalogueID"]
    if row["ThreatName"]:  # the accepted PROPOSED name wins over any low-confidence stored id
        ckey = ("cat", type_id, row["ThreatName"])
        catalogue_id = resolved.get(ckey)
        if catalogue_id is None:
            catalogue_id = dal.upsert_threat_catalogue(sess, row["ThreatName"], type_id, sector_id)
            resolved[ckey] = catalogue_id
            category_id = _category_id()
            if category_id is not None:  # [R6] None means "couldn't resolve" — nothing to link
                dal.link_catalogue_category(sess, catalogue_id, category_id)

    return type_id, catalogue_id


def _add_flagged_threats_to_library(sess: Session, scenario_session: RowMapping, good_subs: list[int], user_id: str | None) -> None:
    """For every threat that was flagged as "new to the library" and whose scenario got
    accepted, create/reuse the matching Threat_Type, Threat_Catalogue, and Threat_Actor
    rows so it becomes part of the shared library, then write audit + candidate-review
    records for each promotion.
    """
    sector_id = _pick_sector_for_promotion(scenario_session)
    sid = scenario_session["SessionID"]
    tenant, entity = scenario_session["TenantID"], scenario_session["EntityID"]
    st, out = m.Scoped_Threat, m.Threat_Scenario_Output
    # A flagged threat only gets promoted if at least one of its scenario outputs was
    # actually accepted — being in a "good" subsystem isn't enough on its own.
    scenario_accepted = (
        select(1)
        .where(st.SessionID == sid, st.ThreatID == m.Identified_Threat.ThreatID,
            st.Superseded == 0,
            out.SessionID == sid, out.ScopedThreatID == st.ScopedThreatID,
            out.Superseded == 0, out.Accepted == 1)
        .exists()
    )
    # Pull every still-flagged threat, in an accepted subsystem, with at least one
    # accepted scenario — these are the candidates to promote into the shared library.
    rows = sess.execute(
        select(m.Identified_Threat.ThreatID, m.Identified_Threat.ThreatCategory,
            m.Identified_Threat.ThreatType, m.Identified_Threat.ThreatName,
            m.Identified_Threat.ThreatActorsJSON, m.Identified_Threat.ThreatTypeID,
            m.Identified_Threat.ThreatCatalogueID)
        .where(m.Identified_Threat.SessionID == sid,
            m.Identified_Threat.Superseded == 0,
            m.Identified_Threat.SubsystemID.in_(good_subs),
            m.Identified_Threat.GroundingStatus == GroundingStatus.flagged,
            scenario_accepted)
    ).mappings().all()

    resolved: dict[tuple, Any] = {}  # in-accept memo: ("category"|"type"|"cat"|"actor"|"link", ...) -> id/True

    parsed_actors, all_actor_names = _extract_actor_names_per_threat(rows)

    # Bulk-load ids for actor names that already exist, so the per-row loop below doesn't
    # issue a separate query per actor.
    if all_actor_names:
        for actor_id, name in sess.execute(
            select(m.Threat_Actor.ThreatActorID, m.Threat_Actor.ThreatActorName).where(
                m.Threat_Actor.ThreatActorName.in_(all_actor_names),
                m.Threat_Actor.IsActive == True, m.Threat_Actor.IsDeleted == False)
        ):
            resolved[("actor", name)] = actor_id

    # Same idea for type-actor links: pre-load the ones that already exist so the main
    # loop below only has to insert genuinely new links.
    known_type_ids = {r["ThreatTypeID"] for r in rows if r["ThreatTypeID"] is not None}
    actor_ids = {v for k, v in resolved.items() if k[0] == "actor"}
    if known_type_ids and actor_ids:
        for type_id, actor_id in sess.execute(
            select(m.ThreatType_ThreatActor_Map.ThreatTypeID, m.ThreatType_ThreatActor_Map.ThreatActorID)
            .where(m.ThreatType_ThreatActor_Map.ThreatTypeID.in_(known_type_ids),
                m.ThreatType_ThreatActor_Map.ThreatActorID.in_(actor_ids))
        ):
            resolved[("link", type_id, actor_id)] = True  # pre-existing link, not newly created

    # Main promotion loop: for each candidate threat, work out (or create) the Threat_Type,
    # Threat_Catalogue, and actor links it should end up pointing at, then ACCUMULATE the
    # resulting writes — batched below into one UPDATE + 2 INSERTs total instead of one
    # UPDATE + 3 INSERTs per row, so an accept promoting many newly-flagged threats issues
    # a small fixed number of round trips instead of 4N (same accumulate-then-bulk-insert
    # pattern tasks.py already uses for Identified_Threat), keeping this still-open
    # transaction's lock hold time from scaling with the number of promotions.
    stamp = now()  # one instant for every row in this batch, not one now() call per row
    # Resolved ONCE, not per row: dal.audit_row falls back to a PK lookup for the accountable
    # user when the caller names nobody, which inside this loop would be one query per promoted
    # threat. The session row is already in hand, so answer both questions here instead.
    actor_id = user_id or scenario_session["UserID"]
    actor_type = ActorType.user if user_id else ActorType.system
    update_rows: list[dict] = []
    audit_rows: list[dict] = []
    candidate_rows: list[dict] = []
    for row in rows:
        type_id, catalogue_id = _find_or_create_type_and_catalogue(sess, row, sector_id, resolved)

        actors = parsed_actors[row["ThreatID"]]
        linked_actors = _link_actors_to_threat_type(sess, type_id, actors, resolved)  # names NEWLY linked this accept

        if (type_id == row["ThreatTypeID"] and catalogue_id == row["ThreatCatalogueID"]
                and not linked_actors):
            continue  # nothing promoted, re-pointed, or newly actor-linked — no false audit trail

        update_rows.append({"b_tid": row["ThreatID"], "ThreatTypeID": type_id, "ThreatCatalogueID": catalogue_id})
        audit_rows.append(dal.audit_row(
            sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=entity,
            EventType=AuditEventType.library_promoted, ActorUserID=actor_id, ActorType=actor_type,
            ThreatTypeRefID=type_id, CreatedAt=stamp,
            DetailJSON=json.dumps({"threat_id": row["ThreatID"], "catalogue_id": catalogue_id,
                                    "sector_id": sector_id, "actors": linked_actors})))

        # Also record a Threat_Candidate_Review row so this promotion shows up in the
        # normal candidate-review history/audit trail, already marked as accepted.
        candidate_id = guid()
        candidate_rows.append({
            "CandidateID": candidate_id, "TenantID": tenant, "EntityID": entity,
            "SessionID": sid, "ProposedCategory": row["ThreatCategory"],
            "ProposedType": row["ThreatType"], "ProposedName": row["ThreatName"] or "",
            "Status": CandidateStatus.accepted, "ThreatTypeID": type_id, "ThreatCatalogueID": catalogue_id,
            "ReviewedBy": user_id, "ReviewedAt": stamp, "CreatedAt": stamp,
        })
        audit_rows.append(dal.audit_row(
            sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=entity,
            EventType=AuditEventType.candidate_reconciled, ActorUserID=actor_id, ActorType=actor_type,
            CreatedAt=stamp,
            DetailJSON=json.dumps({"candidate_id": candidate_id, "threat_id": row["ThreatID"]})))
        log.info("threat.promoted", session_id=sid, threat_id=row["ThreatID"],
                type_id=type_id, catalogue_id=catalogue_id, sector_id=sector_id)

    if update_rows:
        # Table (Core), not the mapped class: a plain executemany UPDATE, not an ORM bulk-update-
        # by-PK (which requires the dict key to be the PK attribute name, not a bindparam name,
        # and otherwise needs synchronize_session=None to allow this extra WHERE at all).
        it = cast(Table, m.Identified_Threat.__table__)
        sess.execute(update(it).where(it.c.ThreatID == bindparam("b_tid")), update_rows)
    if candidate_rows:
        sess.execute(insert(m.Threat_Candidate_Review), candidate_rows)
    if audit_rows:
        sess.execute(insert(m.Scenario_Audit), audit_rows)
