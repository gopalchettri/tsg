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
from typing import Any, NamedTuple, Sequence, cast

from sqlalchemy import RowMapping, Table, bindparam, insert, or_, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    TriageVerdict,
    ActorType,
    AuditDecision,
    AuditEventType,
    CandidateStatus,
    SessionStatus,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core import tuning
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import EntityForbidden, NotFoundError, guid, now
from app.pipeline import embeddings, grounding
from app.pipeline.llm import get_llm
# THE one asset-name strip (legacy-row fallback only; new rows carry the AI's GenericName)
# and THE one junk-name gate — both defined beside their Stage-1 writers so the vocabulary
# of what may enter the shared library lives in exactly one module.
from app.pipeline.tasks import asset_agnostic_name, clean_library_name

log = get_logger(__name__)


class AcceptConflict(Exception):
    """Accept attempted off the REVIEW barrier or against a held lock → 409 ([R5]).

    `reason` is an optional machine-readable code (e.g. "session_completed") surfaced by the
    HTTP handler as `details.reason` — same pattern as dal.SessionConflict's
    `active_session_id`. Raise sites without a stable cause just omit it."""

    def __init__(self, message: str, reason: str | None = None):
        super().__init__(message)
        self.reason = reason


#: How many offending ids to name in the human-readable message. `details.unacceptable` always
#: carries every one — this only stops a 50-id request producing an unreadable sentence.
_NAMED_IN_MESSAGE = 3

#: Sentence fragments, so "<id> <text>" reads as plain English. No internal vocabulary:
#: "OutputID", "subset" and "superseded" mean nothing to whoever is reading the response.
_REASON_TEXT = {
    "superseded": "is an older version that a regeneration replaced",
    "failure_card": "failed to generate, so it has no content to accept",
    "subsystem_not_awaiting_decision": "is not ready for review yet",
    "unknown": "is not a scenario in this session",
}


def _unacceptable_subset(sess: Session, session_id: str, subset: list[str],
                        good_subs: list[int], *, requested: int, matched: int) -> NotFoundError:
    """Build the partial-accept 404, naming each id that cannot be accepted and why.

    Returns rather than raises so the call site still reads as `raise ...` — the diagnosis is a
    one-off read on a request that is already failing, not control flow."""
    reasons = dal.unacceptable_subset_reasons(sess, session_id, subset, good_subs)
    named = list(reasons)[:_NAMED_IN_MESSAGE]
    # Outcome FIRST — "nothing was accepted" is the fact the reader acts on, and burying it
    # mid-sentence invited "so did the other two go through?". Then what is wrong, then the one
    # thing to do. No `subset`/OutputID jargon, and no second aside competing with the action.
    shown = "; ".join(f"{oid} {_REASON_TEXT.get(reasons[oid], reasons[oid])}" for oid in named)
    more = f"; and {len(reasons) - len(named)} more" if len(reasons) > len(named) else ""
    return NotFoundError(
        f"Nothing was accepted. {requested - matched} of the {requested} scenarios you selected "
        f"cannot be accepted: {shown}{more}. Get the current scenario ids from "
        f"GET /v1/sessions/{session_id}/results and try again.",
        details={"requested": requested, "matched": matched,
                "unacceptable": [{"output_id": oid, "reason": r} for oid, r in reasons.items()]},
    )


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
                raise _unacceptable_subset(sess, session_id, subset, good_subs,
                                        requested=requested, matched=matched)
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
            if matched == 0:
                # Zero completed scenarios anywhere (e.g. every generation failed and only error
                # cards remain). Completing here would stamp the session a success with
                # accepted_count=0 — confusing at best. The uncovered guard above cannot catch
                # this: with NO active complete scenarios at all, `uncovered` is empty by
                # construction. Reject-all (an explicit empty accepted_scenario_ids) remains the
                # deliberate way to close a session as reviewed-with-nothing.
                raise AcceptConflict(
                    "accept-all found no completed scenarios to accept — regenerate or request a "
                    "next set first, or submit an explicit empty accepted_scenario_ids to close "
                    "the session as reviewed-with-none",
                    reason="nothing_to_accept")

        _add_unverified_threats_to_library(sess, scenario_session, good_subs, user_id)

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

    Branches on SessionStatus FIRST — the authoritative liveness signal — rather than
    inferring completed/cancelled from CurrentStage/StageStatus, which are progress history.
    complete_session and cancel_session both stamp a terminal StageStatus (COMPLETE /
    CANCELLED respectively), so the two stay in sync today, but SessionStatus remains the
    single source of truth here: it is what previously caught the case where a completed
    session still read AWAITING_DECISION and echoing that verbatim produced a
    self-contradictory message ("not at REVIEW ... status=AWAITING_DECISION") that misled
    callers into retrying a final decision. Shared by the accept gate (below) and
    sessions.py's regenerate/next-set gate so the two can never drift apart again."""
    if (scenario_session["CurrentStage"] == WorkflowStage.REVIEW
            and scenario_session["StageStatus"] == StageStatus.AWAITING_DECISION):
        return None
    status = scenario_session["SessionStatus"]
    if status == SessionStatus.completed:
        return ("session_completed",
                f"session already completed at {scenario_session['CompletedAt']} — the review "
                f"decision is final; accepted scenarios are available via "
                f"GET /v1/sessions/{scenario_session['SessionID']}/accepted-scenarios, "
                f"and a new session for this asset can run a fresh review")
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
    # only ever sets it from an actual candidate row) — and, since grounding now withholds the id
    # unless the NAME match itself verified, a non-null id also means that match was confident.
    # Every non-null id still needs re-validating, the same way type_ids does below: the master
    # could have been deactivated between Stage 2 and accept. This check is now load-bearing in a
    # way it was not before — accept no longer re-points a threat onto a freshly-minted catalogue
    # row, so the id validated here is the one that persists.
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


def _link_actors_to_threat_type(sess: Session, type_id: int, actors: list[str], resolved: dict,
                                created_by: str | None = None,
                                resolve_only: bool = False) -> list[str]:
    """Make sure each actor name is a real Threat_Actor row and is linked to this threat
    type. Returns the actor names that got a brand-new link (used for audit logging), not
    ones that were already linked.

    `resolve_only=True` — the AI-promotion posture — links EXISTING active actors but NEVER
    creates one. The closed actor vocabulary is enforced only in the Stage-1 prompt; on the
    unverified grounding branch (the only branch that mints new types) actors pass RAW with no
    server-side membership check, so an upsert here would turn any hallucinated string into a
    permanent global Threat_Actor row — which immediately enters dal.active_actor_names and
    therefore every future session's Stage-1 closed list: a self-reinforcing vocabulary-growth
    loop with no review step. Unresolved names are skipped and logged; POST /threat-actors
    stays the one deliberate creation path.

    `created_by` is the accountable user for this accept — the same value the audit rows
    carry, so a row promoted into the shared library names whoever caused it to exist.
    """
    newly_linked: list[str] = []
    # `resolved` is a shared memo (actor name -> id, and (type,actor) -> "already linked")
    # so repeated actor names across many threats in this accept don't hit the DB twice.
    for actor_name in actors:
        actor_key = ("actor", actor_name)
        # exact first, then case-insensitive — MSSQL's collation resolves 'nation state' to
        # 'Nation State', so the memo must too or a case-variant would mint a duplicate row.
        actor_id = resolved.get(actor_key)
        if actor_id is None:
            actor_id = resolved.get(("actor_cf", actor_name.casefold()))
        if actor_id is None:
            if resolve_only:
                log.warning("accept.actor_not_in_vocabulary", actor=actor_name, type_id=type_id,
                            note="AI-proposed actor has no active Threat_Actor row — skipped, "
                                "never auto-created; add it via POST /threat-actors if real")
                continue
            actor_id = dal.upsert_threat_actor(sess, actor_name, created_by=created_by)
        resolved[actor_key] = actor_id
        resolved[("actor_cf", actor_name.casefold())] = actor_id
        link_key = ("link", type_id, actor_id)
        if link_key not in resolved:
            if dal.link_type_actor(sess, type_id, actor_id):  # True only when a NEW link row was inserted
                newly_linked.append(actor_name)
            resolved[link_key] = True
    return newly_linked


def _extract_actor_names_per_threat(rows: Sequence[RowMapping]) -> tuple[dict[int, list[str]], set[str]]:
    """Parse each row's stored actor JSON up front — the RAW list, deliberately. Promotion
    candidates are exactly the UNVERIFIED threats, whose stored blob is always
    validated=false, so the old validated_actors gate returned [] for every one of them and
    made the whole actor-linking pass a silent no-op. Trust is enforced downstream instead:
    _link_actors_to_threat_type(resolve_only=True) links raw names only when they already
    exist as active Threat_Actor rows and never creates one. Returns the per-threat actor
    lists plus the union of every actor name seen (for the bulk id lookup)."""
    parsed_actors: dict[int, list[str]] = {}
    all_actor_names: set[str] = set()
    for row in rows:
        # The one shared reader for the ThreatActorsJSON shape — a corrupt blob degrades to
        # no-actors instead of raising.
        actors = grounding.stored_actors(row["ThreatActorsJSON"])
        parsed_actors[row["ThreatID"]] = actors
        all_actor_names.update(actors)
    return parsed_actors, all_actor_names


def _find_or_create_type_and_catalogue(
    sess: Session, row: RowMapping, sector_id: int | None, resolved: dict,
    created_by: str | None = None,
) -> tuple[int, int | None]:
    """Resolve the Threat_Type id this unverified threat should point at — reusing the verified
    type match recorded at Stage 2 when present, otherwise creating one under the resolved
    category — and pass the stored catalogue id straight through.

    ONLY the TYPE is auto-promoted. The catalogue name is not, and deliberately: prompts.py
    REQUIRES `name` to embed the asset's own name ('<impact> of <asset name>'), while it FORBIDS
    asset/product names in `type`. So `ThreatType` is library-shaped by construction and
    `ThreatName` never is — auto-minting a Threat_Catalogue row from it could only ever park an
    asset-named sibling next to the generic entry it belongs under ('Unauthorized disclosure of
    Citizen Personal Information' beside 'Sensitive data exposure'). Every one of the 75 curated
    catalogue rows is generic idiom; none is asset-named. The proposal instead goes to
    Threat_Candidate_Review as `pending`, which is where prompts.py always said it belonged
    ("carries that asset-named name through the existing curator review, where it can be
    generalized") — that review just never had a writer until now.

    Consequence for the caller: `catalogue_id` is now always exactly `row["ThreatCatalogueID"]`,
    so the no-op check in _add_unverified_threats_to_library can no longer use it to detect that
    something happened. See the `promoted` split there.
    """
    def _category_id() -> int | None:
        cat_key = ("category", row["ThreatCategory"])
        if cat_key not in resolved:
            resolved[cat_key] = grounding.find_category(sess, row["ThreatCategory"])
        return resolved[cat_key]

    type_id = row["ThreatTypeID"]  # a `verified` type match when set — trusted
    if type_id is None:
        # No high-confidence type match was recorded earlier, so find/create one now,
        # under the resolved category.
        key = ("type", row["ThreatCategory"], row["ThreatType"])
        type_id = resolved.get(key)
        if type_id is None:
            type_id, created = dal.upsert_threat_type(sess, row["ThreatType"], _category_id(),
                                                    sector_id, created_by=created_by)
            resolved[key] = type_id
            if created:
                # Minted THIS accept — the one case actor linking may seed. A type that already
                # existed (curated, or minted by an earlier accept) keeps its curator-owned actor
                # set; see the linking gate in _add_unverified_threats_to_library.
                resolved[("minted_type", type_id)] = True

    # Passthrough, never overwritten. grounding sets this only on a VERIFIED name match, so when
    # it is set it already names the right library row and there is nothing to promote.
    return type_id, row["ThreatCatalogueID"]


def _active_catalogue_with_categories(sess: Session) -> list[dict]:
    """Every active Threat_Catalogue entry with its resolved STRIDE category ids —
    `Threat_Catalogue_Category_Map` rows (multi-category, ANY-overlap semantics), falling back
    to the owning `Threat_Type.ThreatCategoryID`: the same resolution `get_possible_types`
    implements. An entry with NO resolvable category gets an empty set — the triage never
    auto-rejects against it (it still counts for the novelty check).

    `type_id`/`sector_id` ride along because an auto-REJECT stores the matched entry onto the
    threat row: the stored (ThreatTypeID, ThreatCatalogueID) pair must keep the invariant that
    the catalogue entry's OWNER defines the type, and the entry must be sector-visible — the
    same two rules grounding.get_possible_names enforces everywhere else a match is stored."""
    tc, tt, mp = m.Threat_Catalogue, m.Threat_Type, m.Threat_Catalogue_Category_Map
    rows = sess.execute(
        select(tc.ThreatCatalogueID, tc.ThreatName, tc.ThreatTypeID, tc.SectorID,
            tt.ThreatCategoryID)
        .select_from(tc.__table__.outerjoin(tt, tc.ThreatTypeID == tt.ThreatTypeID))
        .where(tc.IsActive == True, tc.IsDeleted == False)  # noqa: E712
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
                        tn: tuning.ResolvedTuning) -> tuple[str, int | None, float | None]:
    """Banded triage of one candidate generic name against the active catalogue →
    (verdict: auto_reject | auto_approve | review, matched catalogue id, cosine).

    `qv` is the candidate's PRE-COMPUTED query vector — the caller batch-embeds every
    candidate in ONE llm.embed call (kind='query', never get_vectors: a one-off text must not
    enter the shared library cache), so lock-hold time inside the open accept transaction no
    longer scales with candidate count. The CATALOGUE side arrives pre-embedded via
    get_vectors(group='threat_catalogue') — the library embeds once ever.

    Auto-REJECT eligibility = shared resolved STRIDE category AND sector visibility
    (SectorID NULL or in the session's sector_ids — grounding.visible_to_this_sector's rule):
    a reject stores the matched entry onto the threat row, and no other writer can store a
    sector-invisible or wrong-category match. Measured basis for the category gate:
    'Unauthorized disclosure of X' vs '…modification of X' scores 0.969, above every true
    paraphrase — ungated high cosine reads 'same words', not 'same idea'.

    Auto-APPROVE requires the candidate to be far from EVERY entry (category- and sector-free
    novelty check — safe by construction, and it correctly leaves a cross-category near-twin
    in the review band). The CALLER additionally demotes a category-unresolvable auto_approve
    to review: inserting an entry whose category cannot be linked would breed exactly the
    NULL-category rows that force everything back to human review."""
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
                and (e["sector_id"] is None or e["sector_id"] in sector_ids)):
            if best_reject is None or cos > best_reject[0]:
                best_reject = (cos, e["id"])
    if best_any is None:  # empty/unembeddable library — a first entry is novel by definition
        return TriageVerdict.auto_approve, None, None
    if best_reject is not None and best_reject[0] >= tn.triage_auto_reject_cosine:
        return TriageVerdict.auto_reject, best_reject[1], best_reject[0]
    if best_any[0] < tn.triage_auto_approve_cosine:
        return TriageVerdict.auto_approve, best_any[1], best_any[0]
    return TriageVerdict.review, best_any[1], best_any[0]


def _promotion_candidates(sess: Session, sid: str, good_subs: list[int]) -> list[RowMapping]:
    """Every below-threshold threat, in an accepted subsystem, with at least one ACCEPTED
    scenario — the candidate set for library promotion.

    Selects on SCORE, not on GroundingStatus, and that distinction is the point. "Do we trust
    this match enough to use the library's wording?" and "should this go INTO the library?" are
    different questions; piggybacking curation on the grounding band meant every retune of the
    matching cutoff silently moved promotion volume too.

    NULL-safe by design: `GroundingScore < th` alone is UNKNOWN for a NULL score, which would
    silently EXCLUDE such a row. A row with no recorded score is by definition not a confident
    match, so it belongs in the candidate set — the column is nullable and legacy rows carry NULL.
    """
    st, out = m.Scoped_Threat, m.Threat_Scenario_Output
    # An unverified threat only gets promoted if at least one of its scenario outputs was
    # actually accepted — being in a "good" subsystem isn't enough on its own.
    scenario_accepted = (
        select(1)
        .where(st.SessionID == sid, st.ThreatID == m.Identified_Threat.ThreatID,
            st.Superseded == 0,
            out.SessionID == sid, out.ScopedThreatID == st.ScopedThreatID,
            out.Superseded == 0, out.Accepted == 1)
        .exists()
    )
    return sess.execute(
        select(m.Identified_Threat.ThreatID, m.Identified_Threat.ThreatCategory,
            m.Identified_Threat.ThreatType, m.Identified_Threat.ThreatName,
            m.Identified_Threat.GenericName,
            m.Identified_Threat.ThreatActorsJSON, m.Identified_Threat.ThreatTypeID,
            m.Identified_Threat.ThreatCatalogueID)
        .where(m.Identified_Threat.SessionID == sid,
            m.Identified_Threat.Superseded == 0,
            m.Identified_Threat.SubsystemID.in_(good_subs),
            or_(m.Identified_Threat.GroundingScore.is_(None),
                m.Identified_Threat.GroundingScore < get_settings().library_promotion_threshold),
            scenario_accepted)
    ).mappings().all()


def _preload_actor_memo(sess: Session, rows: Sequence[RowMapping], all_actor_names: set[str],
                        resolved: dict) -> None:
    """Bulk-load existing actor ids and type-actor links into the in-accept memo, so the
    promotion loop issues no per-actor query. Two queries, both skipped when there is nothing
    to look up."""
    if all_actor_names:
        for actor_id, name in sess.execute(
            select(m.Threat_Actor.ThreatActorID, m.Threat_Actor.ThreatActorName).where(
                m.Threat_Actor.ThreatActorName.in_(all_actor_names),
                m.Threat_Actor.IsActive == True, m.Threat_Actor.IsDeleted == False)  # noqa: E712
        ):
            resolved[("actor", name)] = actor_id
            # casefold alias so a case-variant proposal resolves to the canonical row instead
            # of reading as unknown (MSSQL's IN() above matches case-insensitively already)
            resolved[("actor_cf", name.casefold())] = actor_id
    known_type_ids = {r["ThreatTypeID"] for r in rows if r["ThreatTypeID"] is not None}
    actor_ids = {v for k, v in resolved.items() if k[0] == "actor"}
    if known_type_ids and actor_ids:
        for type_id, actor_id in sess.execute(
            select(m.ThreatType_ThreatActor_Map.ThreatTypeID, m.ThreatType_ThreatActor_Map.ThreatActorID)
            .where(m.ThreatType_ThreatActor_Map.ThreatTypeID.in_(known_type_ids),
                m.ThreatType_ThreatActor_Map.ThreatActorID.in_(actor_ids))
        ):
            resolved[("link", type_id, actor_id)] = True  # pre-existing link, not newly created


class _TriageInputs(NamedTuple):
    """Everything the banded triage needs, resolved ONCE per accept."""
    entries: list[dict]          # active catalogue: id, name, owner type, sector, categories
    catalogue_vecs: dict         # entry name -> cached passage vector
    query_vecs: dict             # candidate generic name -> query vector (ONE batched embed)
    generic_by_tid: dict         # threat id -> library-shaped name
    sector_ids: list[int]        # the session's sector visibility list


def _prepare_triage(sess: Session, llm, scenario_session: RowMapping,
                    rows: Sequence[RowMapping]) -> _TriageInputs:
    """Resolve the triage inputs in a fixed number of round trips: the active catalogue with
    its resolved categories/owner/sector, that catalogue's CACHED passage vectors (embedded
    once ever, per find_closest_match's contract), and ONE batched query-embed of every
    candidate generic name — per-row embeds made lock-hold time inside the still-open accept
    transaction scale with candidate count.

    Any failure degrades to entries=[] — every candidate then falls to the review queue.
    Automation fails TOWARD the human, never silently approves or rejects."""
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
    """One candidate's resolved library outcome."""
    verdict: str                   # auto_reject | auto_approve | review
    type_id: int                   # the Threat_Type the threat ends up pointing at
    catalogue_id: int | None       # its Threat_Catalogue id after triage (None = none matched)
    matched_id: int | None         # the entry the cosine was measured against (audit/calibration)
    cosine: float | None


def _decide_candidate_fate(sess: Session, row: RowMapping, generic: str | None, sector_id: int | None,
                        resolved: dict, triage: _TriageInputs, tn: tuning.ResolvedTuning,
                        *, created_by: str | None) -> _CandidateFate:
    """Banded triage of the LIBRARY-SHAPED name (never the asset-embedded one), then the type
    and catalogue ids that follow from it. Runs triage BEFORE type resolution so an auto-reject
    adopts the matched entry's owning type instead of minting a fresh Threat_Type it is about
    to abandon:

      >= reject band (shared category + sector-visible): same idea reworded → link this threat
         to the entry it duplicates, under THAT entry's owning type;
      <  approve band vs EVERYTHING: genuinely novel → insert active, with its category linked
         (upsert_threat_catalogue deliberately doesn't link — without it the automation would
         breed the NULL-category entries that force everything back to review);
      between, or category unresolvable, or the embedder failed → the curator queue.

    Auto-MERGE stays forbidden: automation never rewrites or retires an existing entry.
    An auto-approve also appends itself to the in-accept snapshot, so two paraphrases in ONE
    accept cannot both read "novel" and both insert."""
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
        # a category-less insert would breed exactly the NULL-category entries the gate
        # exists to prevent — the curator decides instead
        verdict = TriageVerdict.review
    if verdict is TriageVerdict.auto_approve and clean_library_name(generic) is None:
        # junk/degenerate text ('N/A', one-word fragments from the legacy strip fallback)
        # embeds far from everything, so it lands EXACTLY in the auto-approve band — the one
        # band no curator sees. Nothing enters the shared library without passing the gate.
        verdict = TriageVerdict.review
    matched_entry = (next((e for e in triage.entries if e["id"] == matched_id), None)
                    if verdict is TriageVerdict.auto_reject else None)
    if verdict is TriageVerdict.auto_reject and matched_entry is None:
        verdict = TriageVerdict.review  # unreachable today; keeps the audit record truthful if it ever is
    if (matched_entry is not None and row["ThreatTypeID"] is not None
            and matched_entry["type_id"] != row["ThreatTypeID"]):
        # A reranked, thresholded Stage-2 TYPE match must not be outranked by a raw-cosine
        # NAME hit: verified-type/unverified-name is the DOMINANT candidate shape here, and
        # adopting the entry's owner would rewrite the verified ThreatTypeID and link actors
        # under the wrong type in the shared map. The two verdicts disagree — the curator
        # decides, same fail-toward-the-human rule as the category-unresolvable demotion.
        verdict, matched_entry = TriageVerdict.review, None

    if matched_entry is not None:
        # the catalogue entry's OWNER defines the type — the invariant every other writer of a
        # stored (ThreatTypeID, ThreatCatalogueID) pair keeps (grounding's model)
        type_id = matched_entry["type_id"]
        if type_id is None:  # ownerless legacy entry — resolve/mint as usual
            type_id, _ = _find_or_create_type_and_catalogue(sess, row, sector_id, resolved,
                                                            created_by=created_by)
        return _CandidateFate(verdict, type_id, matched_id, matched_id, cosine)

    type_id, catalogue_id = _find_or_create_type_and_catalogue(sess, row, sector_id, resolved,
                                                            created_by=created_by)
    if verdict is TriageVerdict.auto_approve:
        catalogue_id = dal.upsert_threat_catalogue(sess, generic, type_id, sector_id,
                                                created_by=created_by)
        dal.link_catalogue_category(sess, catalogue_id, cand_cat)
        # Visible to the LATER candidates by construction: _pick_sector_for_promotion draws
        # sector_id from the session's own SectorIDsJSON — the same list _prepare_triage puts
        # in triage.sector_ids — so this entry passes _triage_generic_name's visibility test.
        # Break that and the in-accept dedup silently stops working (duplicates return).
        triage.entries.append({"id": catalogue_id, "name": generic, "type_id": type_id,
                            "sector_id": sector_id, "cats": frozenset({cand_cat})})
        triage.catalogue_vecs.setdefault(generic, qv)
    return _CandidateFate(verdict, type_id, catalogue_id, matched_id, cosine)


def _add_unverified_threats_to_library(sess: Session, scenario_session: RowMapping, good_subs: list[int], user_id: str | None) -> None:
    """Promote this accept's novel threats into the shared library: for each candidate, decide
    its catalogue fate by banded triage, create/reuse the matching Threat_Type and actor links,
    and accumulate the audit + candidate-review records. Reads are pre-resolved by
    `_promotion_candidates` / `_preload_actor_memo` / `_prepare_triage`; writes are batched at
    the bottom.
    """
    sector_id = _pick_sector_for_promotion(scenario_session)
    sid = scenario_session["SessionID"]
    tenant, entity = scenario_session["TenantID"], scenario_session["EntityID"]
    rows = _promotion_candidates(sess, sid, good_subs)

    resolved: dict[tuple, Any] = {}  # in-accept memo: ("category"|"type"|"cat"|"actor"|"link", ...) -> id/True
    parsed_actors, all_actor_names = _extract_actor_names_per_threat(rows)
    _preload_actor_memo(sess, rows, all_actor_names, resolved)

    # Main promotion loop: for each candidate threat, work out (or create) the Threat_Type,
    # Threat_Catalogue, and actor links it should end up pointing at, then ACCUMULATE the
    # resulting writes — batched below into one UPDATE + 2 INSERTs total instead of one
    # UPDATE + 3 INSERTs per row, so an accept promoting many newly-unverified threats issues
    # a small fixed number of round trips instead of 4N (same accumulate-then-bulk-insert
    # pattern tasks.py already uses for Identified_Threat), keeping this still-open
    # transaction's lock hold time from scaling with the number of promotions.
    stamp = now()  # one instant for every row in this batch, not one now() call per row
    # Resolved ONCE, not per row: dal.audit_row falls back to a PK lookup for the accountable
    # user when the caller names nobody, which inside this loop would be one query per promoted
    # threat. The session row is already in hand, so answer both questions here instead.
    actor_id = user_id or scenario_session["UserID"]
    actor_type = ActorType.user if user_id else ActorType.system
    llm = get_llm()
    tn = tuning.from_session(scenario_session)
    triage = _prepare_triage(sess, llm, scenario_session, rows)
    update_rows: list[dict] = []
    audit_rows: list[dict] = []
    candidate_rows: list[dict] = []
    triage_details: list[dict] = []
    for row in rows:
        # Banded triage of the LIBRARY-SHAPED name FIRST (never the asset-embedded one) —
        # before any type resolution, so an auto-reject adopts the matched entry's owning type
        # instead of minting a fresh Threat_Type it is about to abandon:
        # >= reject band (shared category + sector-visible): same idea reworded → link this
        #    threat to the entry it duplicates;
        # <  approve band vs EVERYTHING: genuinely novel → insert active, with its category
        #    linked (upsert_threat_catalogue deliberately doesn't link — without it the
        #    automation would breed the NULL-category entries that force everything to review);
        # between, or category unresolvable, or the embedder failed → the curator queue.
        # Auto-MERGE stays forbidden: automation never rewrites or retires an existing entry.
        generic = triage.generic_by_tid[row["ThreatID"]]
        fate = _decide_candidate_fate(sess, row, generic, sector_id, resolved, triage, tn,
                                    created_by=actor_id)
        verdict, type_id, catalogue_id_new, matched_id, cosine = fate

        actors = parsed_actors[row["ThreatID"]]
        # TWO gates, closing two different loops:
        # * resolve_only — AI-proposed names may LINK existing actors, never CREATE one (the
        #   vocabulary-growth loop, _link_actors_to_threat_type's docstring);
        # * minted-only — links may SEED a type minted in this very accept, never extend a
        #   pre-existing type's actor set. Without this, an unvalidated AI assertion ("Hacktivist
        #   does type 210") written today becomes the very set get_allowed_actor_names validates
        #   future sessions against tomorrow — attribution laundering one level up from the
        #   vocabulary loop. A curated type's actor set changes only via
        #   PATCH /threat-types/{id} (actor_names), the deliberate, audited path.
        if resolved.get(("minted_type", type_id)):
            linked_actors = _link_actors_to_threat_type(sess, type_id, actors, resolved,
                                                        created_by=actor_id,
                                                        resolve_only=True)  # names NEWLY linked this accept
        else:
            linked_actors = []
            if actors:
                log.info("accept.actor_links_withheld", type_id=type_id, actors=actors,
                        threat_id=row["ThreatID"],
                        note="type pre-exists this accept; curator owns its actor set — add via "
                            "PATCH /v1/tsg/threat-library/threat-types/{id} if the attribution is real")
        triage_details.append({"threat_id": row["ThreatID"], "generic_name": generic,
                            "verdict": verdict, "cosine": cosine,
                            "matched_catalogue_id": matched_id})

        # Three INDEPENDENT outcomes per row, deliberately not one `continue` — a type mint, a
        # new actor link and a triage decision are separate facts, any of which warrants the
        # UPDATE + audit.
        promoted = (type_id != row["ThreatTypeID"] or bool(linked_actors)
                    or catalogue_id_new != row["ThreatCatalogueID"])
        if promoted:
            update_rows.append({"b_tid": row["ThreatID"], "ThreatTypeID": type_id,
                                "ThreatCatalogueID": catalogue_id_new})
            audit_rows.append(dal.audit_row(
                sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=entity,
                EventType=AuditEventType.library_promoted, ActorUserID=actor_id, ActorType=actor_type,
                ThreatTypeRefID=type_id, CreatedAt=stamp,
                DetailJSON=json.dumps({"threat_id": row["ThreatID"], "catalogue_id": catalogue_id_new,
                                        "sector_id": sector_id, "actors": linked_actors,
                                        # keeps the record truthful: an auto_reject LINKED the
                                        # threat to an existing entry, it created nothing
                                        "triage_verdict": verdict})))
            log.info("threat.promoted", session_id=sid, threat_id=row["ThreatID"],
                    type_id=type_id, catalogue_id=catalogue_id_new, sector_id=sector_id)

        # ONLY the middle band reaches a human. `pending` is the honest status — nothing has
        # been reviewed, hence no ReviewedBy/ReviewedAt and no `candidate_reconciled` audit.
        # Deduped per (type, name) within one accept — the table has no unique index, so two
        # identical proposals would otherwise queue the same curation task twice.
        ckey = ("candidate", row["ThreatType"], row["ThreatName"])
        if verdict is TriageVerdict.review and row["ThreatName"] and ckey not in resolved:
            resolved[ckey] = True
            candidate_rows.append({
                "CandidateID": guid(), "TenantID": tenant, "EntityID": entity,
                "SessionID": sid, "ProposedCategory": row["ThreatCategory"],
                "ProposedType": row["ThreatType"], "ProposedName": row["ThreatName"],
                "ProposedGenericName": generic,
                "Status": CandidateStatus.pending, "ThreatTypeID": type_id,
                "ThreatCatalogueID": catalogue_id_new,
                "ReviewedBy": None, "ReviewedAt": None, "CreatedAt": stamp,
            })

    if triage_details:
        # ONE calibration record per accept (AuditEventType.promotion_triage): every candidate's
        # cosine, matched entry and band verdict, plus the bands in force — 6d tightens the
        # bands by comparing these against what curators actually chose in the middle band.
        audit_rows.append(dal.audit_row(
            sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=entity,
            EventType=AuditEventType.promotion_triage, ActorUserID=actor_id, ActorType=actor_type,
            CreatedAt=stamp,
            DetailJSON=json.dumps({
                "bands": {"auto_reject": tn.triage_auto_reject_cosine,
                        "auto_approve": tn.triage_auto_approve_cosine},
                "candidates": triage_details})))
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
