"""The single final review & accept: mark chosen scenarios approved and promote novel threats
into the shared library.

One transaction for the decision — validation, marking accepted, promotion, `complete_session`
and audit commit or roll back together; each `_LOCK` acquisition commits immediately so its row
lock isn't held for the rest of the request. Mutual exclusion with an in-flight regeneration is
enforced two ways: a positive state gate (accept only at the REVIEW barrier) and honouring the
`_LOCK` CAS (a held lock aborts the accept).
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, NamedTuple, cast

from sqlalchemy import RowMapping, Table, bindparam, insert, select, update
from sqlalchemy.orm import Session

from app.core import tuning
from app.core.config import get_settings
from app.core.enums import (
    AcceptSubsetReason,
    ActorType,
    AuditDecision,
    AuditEventType,
    CandidateKind,
    CandidateStatus,
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

# The whole actor-candidacy subsystem lives in its own module (accept_actors) — accept.py
# stays the orchestration layer. Underscored names are shared package-internals, not API.
from app.pipeline.accept_actors import (
    _ActorPromoCtx,
    _clean_actor_name,
    _extract_actor_names_per_threat,
    _link_actors_to_threat_type,
    _preload_actor_memo,
    _queue_or_mint_row_actors,
    log_withheld_links,
    pending_card_identities,
    resolve_actor_id_by_identity,
)
from app.pipeline.llm import get_llm
from app.sse import bus

# THE one asset-name strip (legacy-row fallback only; new rows carry the AI's GenericName)
# and THE one junk-name gate — both defined beside their Stage-1 writers so the vocabulary
# of what may enter the shared library lives in exactly one module.
from app.pipeline.tasks import asset_agnostic_name, clean_library_name

log = get_logger(__name__)


class AcceptConflict(Exception):
    """Accept attempted off the REVIEW barrier or against a held lock → 409. `reason` is an
    optional machine-readable code surfaced as `details.reason`; raise sites without one omit it."""

    def __init__(self, message: str, reason: str | None = None):
        super().__init__(message)
        self.reason = reason


#: How many offending ids to name in the human-readable message lives in
#: Settings.accept_named_in_message now (default unchanged: 3). `details.unacceptable` always
#: carries every one — this only stops a 50-id request producing an unreadable sentence.

#: Sentence fragments, so "<id> <text>" reads as plain English. No internal vocabulary:
#: "OutputID" and "subset" mean nothing to whoever is reading the response. Keyed on
#: AcceptSubsetReason (the one typed vocabulary for these codes) — a test pins every member
#: to an entry here. No `superseded` entry: naming an older version is a legitimate accept now.
_REASON_TEXT = {
    AcceptSubsetReason.failure_card: "failed to generate, so it has no content to accept",
    AcceptSubsetReason.subsystem_not_awaiting_decision: "is not ready for review yet",
    AcceptSubsetReason.unknown: "is not a scenario in this session",
    AcceptSubsetReason.duplicate_identity: ("names the same scenario as another selected id — "
                                            "accept only one version of each scenario"),
}


def _unacceptable_subset(sess: Session, session_id: str, subset: list[str],
                        good_subs: list[int], *, requested: int, matched: int) -> NotFoundError:
    """Build the partial-accept 404, naming each unacceptable id and why. Returns rather than
    raises so the call site still reads as `raise ...`."""
    reasons = dal.unacceptable_subset_reasons(sess, session_id, subset, good_subs)
    named = list(reasons)[:get_settings().accept_named_in_message]
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


def _assert_one_version_per_scenario(sess: Session, session_id: str, subset: list[str]) -> None:
    """Pre-flight duplicate-identity guard, BEFORE any write: with Accepted decoupled from
    Superseded, a subset naming two versions of ONE scenario has no natural collision left to
    stop it — both rows would flip Accepted=1 and only the UX_Scenario_ActiveAccepted unique
    index would object, as a raw IntegrityError mid-transaction. Reject it here, cleanly, with
    a typed reason instead. `subset` must already be canonicalized (the caller's own rule)."""
    pairs = dal.scenario_identity_pairs(sess, session_id, subset)
    seen_identity: dict[tuple, str] = {}
    for oid in dict.fromkeys(subset):  # preserve order, collapse repeats of the SAME id
        pair = pairs.get(oid)
        if pair is None or pair[0] is None:
            continue  # unknown ids get their 404 later; a NULL-hash row has no version twin
        if pair in seen_identity:
            # Message body comes from _REASON_TEXT so this reason has ONE wording source,
            # same "<id> <text>" shape as the 404's per-id fragments.
            raise AcceptConflict(
                f"Nothing was accepted. {oid} "
                f"{_REASON_TEXT[AcceptSubsetReason.duplicate_identity]} "
                f"(the other selected version: {seen_identity[pair]}).",
                reason=AcceptSubsetReason.duplicate_identity)
        seen_identity[pair] = oid


def accept_session(sess: Session, session_id: str, entity_id: str, user_id: str | None,
                subset: list[str] | None = None) -> int:
    """Accept in one transaction: lock the subsystems, re-check master data is still valid, mark
    the chosen scenarios accepted, promote novel threats, complete the session. Locks are always
    released in the `finally`."""
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
            _assert_one_version_per_scenario(sess, session_id, subset)
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

        # ---- PHASE 1: CORE ACCEPT — the caller's actual request; must survive no matter what
        # happens in Phase 2 below. Library promotion used to run BEFORE complete_session/audit,
        # sharing this same uncommitted transaction — so ANY promotion failure (a bug, a transient
        # LLM/network error, anything) rolled this back too, leaving the session exactly as if
        # accept had never been called. Moving promotion to its own phase AFTER this commit fixes
        # that: the accept a caller asked for is now durable independent of the side-effect that
        # follows it.
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
        sess.commit()  # Phase 1 durable: mark_scenarios_accepted + complete_session + audit rows
        log.info("session.accepted", session_id=session_id, decision=str(decision),
                accepted_count=matched, user=user_id)
        # Fast path only (item 1/item 30's sentinel-tick status check in stream_events() is the
        # actual close guarantee, and closes with or without this): an already-subscribed client
        # hears about the accept near-instantly instead of waiting up to sse_ping_seconds for the
        # next tick. `type` is deliberately NOT an SSEEventType member — accept/cancel have no
        # typed contract in this plan (Section E enumerates only the 9 worker-driven kinds); this
        # is an informal nudge, not a documented event.
        bus.publish(session_id, {"type": "session_accepted", "session_id": session_id,
                                "status": str(SessionStatus.completed), "ts": now().isoformat()})

        # ---- PHASE 2: LIBRARY PROMOTION — isolated; its own failures never reach the outer
        # except below, so they can never undo Phase 1 (see run_promotion_phase's own docstring).
        run_promotion_phase(sess, scenario_session, good_subs, user_id, acquired)
        return matched
    except Exception:
        # The lock acquisitions above are already committed (see comment there); everything
        # after them up to Phase 1's own commit above — validation, mark_scenarios_accepted,
        # complete_session, audit rows — is still one uncommitted unit of work whenever this
        # fires BEFORE that commit. Roll THAT back explicitly (same discipline as tasks.py's
        # _record_failure) so a failure here can never leave a partial accept committed once the
        # `finally` block below commits the lock release. Phase 2 never reaches here — see above.
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
        except Exception:  # noqa: BLE001 — logged, not re-raised, so it doesn't mask the original error
            log.warning("accept.lock_release_failed", session_id=session_id)


def run_promotion_phase(sess: Session, scenario_session: RowMapping, good_subs: list[int],
                        user_id: str | None, lock_subsystem_ids: list[int]) -> bool:
    """Attempt library promotion exactly once, then record the outcome on `scenario_session`'s
    4 promotion-tracking columns — clear on success, stamp on failure. NEVER raises: a promotion
    failure must never propagate to a caller that has already durably committed the real accept.

    Caller must already hold the session's `_LOCK` subsystem locks (accept_session holds them for
    its whole duration; retry_one_promotion/dismiss_promotion acquire them before calling this) —
    `lock_subsystem_ids` names exactly which ones, so this function can refresh their lease
    before the potentially slow embedding work below. Same renew_lock_lease mechanism _ask_ai
    already uses before every chat call elsewhere in the pipeline: without it, a promotion attempt
    slow enough to outlast stage_lease_seconds could have its lock reclaimed by the reaper
    mid-flight, letting a second concurrent attempt start on the same session. Shared by all
    callers so there is exactly one place that decides what "promotion succeeded" or "promotion
    failed" means for these columns, not two copies that could drift apart.

    Returns True on success, False on failure — reaper.retry_one_promotion uses this to build its
    own richer outcome; accept_session ignores it (a promotion failure never changes what accept
    itself returns to its caller)."""
    session_id = scenario_session["SessionID"]
    for subsystem_id in lock_subsystem_ids:
        if not dal.renew_lock_lease(sess, session_id, subsystem_id, task_id=session_id):
            log.debug("promotion.lock_lease_renewal_skipped", session_id=session_id, subsystem_id=subsystem_id)
    sess.commit()
    try:
        promoted_names = _add_unverified_threats_to_library(sess, scenario_session, good_subs, user_id)
        dal.clear_promotion_failure(sess, session_id)
        sess.commit()
        # Eager-embed AFTER the commit above, never before: embedding writes go to Mongo, a
        # separate system with no shared transaction, so embedding a name before its SQL row is
        # durably committed could leave an orphan vector if this attempt later rolled back.
        eager_embed_promoted(sess, get_llm(), promoted_names)
        return True
    except Exception as exc:
        # Undoes the WHOLE attempt, not a partial one: _add_unverified_threats_to_library commits
        # nothing internally, so everything it did this call is still uncommitted here.
        sess.rollback()
        try:
            dal.stamp_promotion_failure(sess, session_id, error_message=str(exc), user_id=user_id)
            sess.commit()
        except Exception:  # noqa: BLE001 — logged, not re-raised, so it doesn't mask the real failure
            sess.rollback()
            log.warning("session.promotion_failure_stamp_failed", session_id=session_id, exc_info=True)
        log.warning("session.promotion_failed", session_id=session_id, user_id=user_id, exc_info=True)
        return False


class CandidateResolution(NamedTuple):
    """Outcome of one resolve_candidate() call — a small named result instead of a growing
    positional tuple, so a call site reads `resolution.type_id` instead of counting positions."""
    won: bool                          # False = lost the CAS race; caller should report 409
    type_id: int | None                # library id this candidate resolved to; None on reject/
                                       # loss AND on a won actor approval whose link was skipped
    catalogue_id: int | None           # library id this candidate resolved to; None on reject/
                                       # loss AND on every actor approval (actors have no entry)
    promoted_names: list[tuple[str, str]]  # for the caller to eager-embed after its own commit


def resolve_candidate(sess: Session, candidate: RowMapping, reviewer_user_id: str | None,
                    *, approve: bool) -> CandidateResolution:
    """Curator resolution of one Threat_Candidate_Review row — THE writer `CandidateStatus`'s
    accepted/rejected comments name (via dal.close_candidate_review). Reject just closes the
    row; approve additionally mints/reuses its Threat_Type and Threat_Catalogue entry, reusing
    the SAME race-safe upsert primitives auto-promotion uses.

    No Identified_Threat row is touched: Threat_Candidate_Review carries no ThreatID (a proposal
    can be deduplicated across many threats, even across sessions, so there is no single
    "originating" row). Actor cards DO link on approval — to the type the card itself names
    (the grounded ThreatTypeID when queue time recorded one that is still live, else a
    find-only lookup of the stored ProposedType text) — the admin saw that association on the
    card and approved it.

    `won` is False when a concurrent request already resolved this candidate first (CAS loss —
    caller should report 409, never re-run this). Returns the resolved type/catalogue ids
    directly (not just a bool) so the caller never needs a second round trip to learn what this
    call already computed. `promoted_names` is the SAME (embedding_group, name) contract
    `_add_unverified_threats_to_library` returns, for the caller to eager-embed after its own
    commit; empty on reject or on a lost CAS."""
    # KIND BRANCH FIRST — mandatory, not defensive: an actor row (NULL ProposedCategory;
    # ProposedType holds the proposing threat's TYPE TEXT, not a threat proposal — NULL only
    # on legacy actor rows) must never reach the threat path below, which would mint a bogus
    # type/catalogue pair from it. NULL CandidateKind = legacy 'threat' row.
    kind = candidate.get("CandidateKind")
    # CreatedBy = the ORIGINAL proposer (the accepting user who raised the card) — master-row
    # credit goes to the discoverer, never the admin; the admin lands on ReviewedBy + audit.
    # Legacy rows (CreatedBy NULL, predates the column) fall back to the reviewer.
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

    # APPROVE paths only from here (reject above never consumes the grounded id, so it never
    # pays this SELECT). Queue-time grounding can go stale: a curator may have soft-deleted
    # (or deactivated) the type between queue time and this approval, and nothing revalidates
    # the card meanwhile. ONE liveness check at this shared point covers BOTH branches: a dead
    # id is treated as ungrounded — the actor branch re-resolves by name (else links nothing),
    # the threat branch mints/find-or-creates fresh under the resolved category (the soft
    # delete freed the natural key, so this is name resurrection, not a duplicate).
    grounded_type_id = candidate["ThreatTypeID"]
    if grounded_type_id is not None and not dal.threat_type_active(sess, grounded_type_id):
        grounded_type_id = None

    if kind == CandidateKind.actor:
        # Approve a proposed ACTOR: link it to the type the CARD NAMES — the admin saw
        # ProposedType and approved the association, not just a bare name. The target resolves
        # LIVE: the (liveness-checked) grounded id when queue time recorded one, else a
        # find-only lookup of the stored type text — so approving the sibling threat card first
        # makes the link land, and an unapproved type just means no link yet, never a guessed
        # one. ORDER MATTERS: reads first, then the CAS, and only a WINNER writes — a losing
        # request must not mint, link, or log anything (its transaction is rolled back by the
        # caller, but a log line would survive the rollback and mislead an operator).
        # No embedding — actors have no embedding group.
        link_type_id = grounded_type_id
        if link_type_id is None:
            link_type_id = dal.find_active_type_id_by_name(sess, candidate["ProposedType"])
        won = dal.close_candidate_review(sess, candidate["CandidateID"],
                                        status=CandidateStatus.accepted,
                                        reviewer_user_id=reviewer_user_id,
                                        type_id=link_type_id,
                                        # link skipped -> the card must read NULL, not keep the
                                        # stale (possibly dead) queue-time grounding
                                        clear_type_id=True)
        if not won:
            return CandidateResolution(False, None, None, [])  # lost the CAS — nothing written
        # Strip wrapping junk before the mint — a card queued as '"APT-Nova"' must not become
        # the literal stored spelling (the same rule the auto-mint path applies). Pure junk
        # falls back to the raw text: the admin SAW it and explicitly approved it — the gate's
        # job is review, not overruling the reviewer. IDENTITY-GUARDED: 'APT Nova' approved
        # against an existing 'APT-Nova' reuses that row — exact-name upserts alone would mint
        # a normalized twin the read layer then resolves ambiguously.
        display = _clean_actor_name(candidate["ProposedName"]) or candidate["ProposedName"]
        actor_master_id = resolve_actor_id_by_identity(sess, display)
        if actor_master_id is None:
            actor_master_id = dal.upsert_threat_actor(sess, display,
                                                    created_by=original_proposer)
        if link_type_id is not None:
            dal.link_type_actor(sess, link_type_id, actor_master_id)
        else:
            # No live type matches the card (type never approved / soft-deleted since queue
            # time / legacy card with no stored text), or SEVERAL match (ambiguous name) —
            # save the actor, skip the link; never guess master data. The log + audit answer
            # "why isn't APT-X linked?".
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
        return CandidateResolution(True, link_type_id, None, [])

    # Sector-agnostic (sector_id=None): a candidate carries no sector scoping of its own, unlike
    # a live accept's scenario_session (which _pick_sector_for_promotion draws from).
    category_id = grounding.find_category(sess, candidate["ProposedCategory"])
    type_id = grounded_type_id  # liveness-checked above — a dead grounded id re-mints fresh
    if type_id is None:
        type_id, _created = dal.upsert_threat_type(sess, candidate["ProposedType"], category_id,
                                                    sector_id=None, created_by=original_proposer)
    generic = candidate["ProposedGenericName"] or candidate["ProposedName"]
    catalogue_id = dal.upsert_threat_catalogue(sess, generic, type_id, sector_id=None,
                                                created_by=original_proposer)
    dal.link_catalogue_category(sess, catalogue_id, category_id)
    won = dal.close_candidate_review(sess, candidate["CandidateID"], status=CandidateStatus.accepted,
                                    reviewer_user_id=reviewer_user_id, type_id=type_id,
                                    catalogue_id=catalogue_id)
    if not won:
        # Lost the CAS: another request resolved this candidate first. The caller checks `won`
        # INSIDE its transaction and rolls back (admin.py::_resolve_and_respond), so the mint
        # above is erased, not committed alongside a "rejected" verdict — report the conflict,
        # don't audit twice. (The upserts are also race-safe against a concurrent WINNING
        # approve of another card with the same name — see the design's gap #14/#15.)
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


def review_gate_reason(scenario_session: RowMapping | dict) -> tuple[str, str] | None:
    """Why this session cannot take a review action right now, as (machine_reason, human_message),
    or None if it is at the REVIEW barrier.

    Branches on SessionStatus FIRST — the authoritative liveness signal — never inferring
    completed/cancelled from CurrentStage/StageStatus, which are progress history. Echoing those
    verbatim yields self-contradictory messages ("not at REVIEW ... status=AWAITING_DECISION") that
    send callers back to retry a final decision. Shared by the accept gate and sessions.py's
    regenerate/next-set gate so the two cannot drift."""
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
    """Accept is only allowed while the session is sitting at the REVIEW step
    waiting on a human decision; anything else means it's not ready (or already handled).
    """
    gate = review_gate_reason(scenario_session)
    if gate is not None:
        reason, message = gate
        raise AcceptConflict(message, reason=reason)


def _ensure_threat_data_still_active(sess: Session, session_id: str, good_subs: list[int]) -> None:
    """Raise MasterInactive if any Threat_Type / Threat_Catalogue id this session references was
    deactivated after Stage 2 — better to block than accept against stale master data."""
    rows = sess.execute(
        select(m.Identified_Threat.ThreatTypeID, m.Identified_Threat.ThreatCatalogueID)
        .where(
            m.Identified_Threat.SessionID == session_id,
            dal.active(m.Identified_Threat.Superseded),
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
    """Sector for a newly-promoted entry, from the session's sector hierarchy: prefers the parent,
    falls back to the only sector, else None (global)."""
    raw = scenario_session.get("SectorIDsJSON")
    ids = json.loads(raw) if raw else []
    if len(ids) >= 2:
        return ids[1]   # parent
    if len(ids) == 1:
        return ids[0]    # no parent above it — closest available to "parent" here
    return None           # no sector context at all → global




def _find_or_create_type_and_catalogue(
    sess: Session, row: RowMapping, sector_id: int | None, resolved: dict,
    created_by: str | None = None, allow_mint: bool = True,
) -> tuple[int | None, int | None]:
    """Resolve the Threat_Type id this unverified threat points at — reusing Stage 2's verified type
    match when present, else creating one under the resolved category — and pass the stored
    catalogue id straight through.

    TYPE minting is governed by `allow_mint` (the promotion_auto_approve_enabled master switch):
    True (switch ON) find-or-creates under the resolved category; False (switch OFF) returns
    `(None, catalogue_id)` for a novel type — nothing is minted, the candidate card keeps
    ThreatTypeID NULL, and resolve_candidate mints only when the admin approves. Matched types
    (a verified Stage-2 id, or the in-accept memo) flow under either posture.

    The NAME is never auto-minted HERE under any posture: prompts.py REQUIRES `name` to embed
    the asset's own name and FORBIDS asset names in `type`, so `ThreatType` is library-shaped by
    construction and `ThreatName` never is — minting a catalogue row from it could only park an
    asset-named sibling beside the generic entry it belongs under. The proposal goes to
    Threat_Candidate_Review as `pending` instead.

    So `catalogue_id` is always exactly `row["ThreatCatalogueID"]` — the caller cannot use it to
    detect that something happened; see the `promoted` split in
    _add_unverified_threats_to_library."""
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
        if type_id is None and not allow_mint:
            # Admin-gated mode (master switch OFF): a novel type is NEVER minted at accept —
            # the candidate row keeps ThreatTypeID NULL and resolve_candidate mints it only
            # when the admin approves. Matched types (the branch above) still flow.
            return None, row["ThreatCatalogueID"]
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
                and (e["sector_id"] is None or e["sector_id"] in sector_ids)
                and (best_reject is None or cos > best_reject[0])):
            best_reject = (cos, e["id"])
    if best_any is None:  # empty/unembeddable library — a first entry is novel by definition
        return TriageVerdict.auto_approve, None, None
    if best_reject is not None and best_reject[0] >= tn.triage_auto_reject_cosine:
        return TriageVerdict.auto_reject, best_reject[1], best_reject[0]
    if best_any[0] < tn.triage_auto_approve_cosine:
        return TriageVerdict.auto_approve, best_any[1], best_any[0]
    return TriageVerdict.review, best_any[1], best_any[0]


def _promotion_candidates(sess: Session, sid: str, good_subs: list[int]) -> list[RowMapping]:
    """Every threat in an accepted subsystem with at least one ACCEPTED scenario — with its
    GroundingScore, so the CALLER splits candidacy: THREAT promotion keeps the
    library_promotion_threshold filter (in Python now, not SQL), while ACTOR candidacy runs
    over every row — how novel an actor name is has nothing to do with how well its threat
    matched, so filtering here silently excluded every actor riding a well-matched threat.

    Threat candidacy still selects on SCORE, not on GroundingStatus, and that distinction is
    the point. "Do we trust this match enough to use the library's wording?" and "should this
    go INTO the library?" are different questions; piggybacking curation on the grounding band
    meant every retune of the matching cutoff silently moved promotion volume too.
    """
    st, out = m.Scoped_Threat, m.Threat_Scenario_Output
    # An unverified threat only gets promoted if at least one of its scenario outputs was
    # actually accepted — being in a "good" subsystem isn't enough on its own.
    scenario_accepted = (
        select(1)
        .where(st.SessionID == sid, st.ThreatID == m.Identified_Threat.ThreatID,
            out.SessionID == sid, out.ScopedThreatID == st.ScopedThreatID,
            # Accepted alone, and NO Superseded filter on EITHER hop: an accepted older
            # version's ScopedThreatID always points at a SUPERSEDED scoped row (regen
            # supersedes the scoped row and mints a new ScopedThreatID for the replacement,
            # tasks.py), so requiring st or out active here silently starves promotion of
            # that threat. The outer query still requires the Identified_Threat itself active.
            dal.accepted(out.Accepted))
        .exists()
    )
    return sess.execute(
        select(m.Identified_Threat.ThreatID, m.Identified_Threat.ThreatCategory,
            m.Identified_Threat.ThreatType, m.Identified_Threat.ThreatName,
            m.Identified_Threat.GenericName, m.Identified_Threat.GroundingScore,
            m.Identified_Threat.ThreatActorsJSON, m.Identified_Threat.ThreatTypeID,
            m.Identified_Threat.ThreatCatalogueID)
        .where(m.Identified_Threat.SessionID == sid,
            dal.active(m.Identified_Threat.Superseded),
            m.Identified_Threat.SubsystemID.in_(good_subs),
            scenario_accepted)
    ).mappings().all()




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
    type_id: int | None            # the Threat_Type the threat ends up pointing at; None =
                                   # novel type under admin-gated mode (queued, not minted)
    catalogue_id: int | None       # its Threat_Catalogue id after triage (None = none matched)
    matched_id: int | None         # the entry the cosine was measured against (audit/calibration)
    cosine: float | None
    # (embedding_group, name) pairs THIS call genuinely inserted — never a name that merely got
    # LINKED to an already-existing entry. An auto_reject match reuses an existing row under
    # whatever name IT was originally stored as, which is not necessarily `row["ThreatType"]`/
    # `generic` (those are this candidate's own proposed spelling, matched by cosine similarity,
    # not exact identity) — eager-embedding those would either silently do nothing useful (best
    # case) or spend a call resolving a name that matches no active master row (worst case, an
    # avoidable warning on the single most common promotion outcome).
    minted: list[tuple[str, str]]


def _decide_candidate_fate(sess: Session, row: RowMapping, generic: str | None, sector_id: int | None,
                        resolved: dict, triage: _TriageInputs, tn: tuning.ResolvedTuning,
                        *, created_by: str | None, auto_mode: bool,
                        pending_cards: set) -> _CandidateFate:
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
    if verdict is TriageVerdict.auto_approve and not auto_mode:
        # Master-table writes are manual-by-default: a genuinely novel candidate is routed
        # into the SAME curator queue as the ambiguous "review" band below, instead of minting
        # an entry no human has seen. `auto_mode` is the caller's one LIVE get_settings() read
        # (never `tn`, the per-session frozen tuning snapshot) deliberately: an admin flipping
        # the master switch is operational policy that applies to every promotion attempt from
        # that moment on, including a retry of a session created before the flip.
        verdict = TriageVerdict.review
    if verdict is TriageVerdict.auto_approve:
        # An admin's earlier verdict on this identity OWNS it: a card already queued (pending)
        # or already REJECTED must never be auto-minted past — the switch being ON does not
        # outrank a recorded human decision. Demoted to review; the card block below then
        # dedupes against the same set, so a rejected identity mints nothing and re-queues
        # nothing. Same fold as the card block's `ident` — the two must never diverge.
        ident = ((generic or row["ThreatName"]) or "").strip().casefold()
        if ident and (CandidateKind.threat, ident) in pending_cards:
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
        minted: list[tuple[str, str]] = []
        if type_id is None:  # ownerless legacy entry — resolve/mint as usual (gated by the
            # switch). Under OFF a novel type text deliberately gets NO card here either: the
            # matched entry already covers this threat ("already present, do nothing") — its
            # type vocabulary is the curator's call via the library CRUD, not a queue item.
            type_id, _ = _find_or_create_type_and_catalogue(sess, row, sector_id, resolved,
                                                            created_by=created_by,
                                                            allow_mint=auto_mode)
            if type_id is None:
                # Switch OFF + ownerless entry: adopting the entry WITHOUT its owner would
                # store the one (ThreatTypeID NULL, ThreatCatalogueID real) pair every other
                # writer's invariant forbids. Fail toward the human instead: review card,
                # row left exactly as it was.
                return _CandidateFate(TriageVerdict.review, None, row["ThreatCatalogueID"],
                                    matched_id, cosine, [])
            if resolved.get(("minted_type", type_id)):
                minted.append(("threat_type", row["ThreatType"]))
        return _CandidateFate(verdict, type_id, matched_id, matched_id, cosine, minted)

    type_id, catalogue_id = _find_or_create_type_and_catalogue(sess, row, sector_id, resolved,
                                                            created_by=created_by,
                                                            allow_mint=auto_mode)
    minted = [("threat_type", row["ThreatType"])] if resolved.get(("minted_type", type_id)) else []
    if verdict is TriageVerdict.auto_approve:
        catalogue_id = dal.upsert_threat_catalogue(sess, generic, type_id, sector_id,
                                                created_by=created_by)
        dal.link_catalogue_category(sess, catalogue_id, cand_cat)
        minted.append(("threat_catalogue", generic))
        # Visible to the LATER candidates by construction: _pick_sector_for_promotion draws
        # sector_id from the session's own SectorIDsJSON — the same list _prepare_triage puts
        # in triage.sector_ids — so this entry passes _triage_generic_name's visibility test.
        # Break that and the in-accept dedup silently stops working (duplicates return).
        triage.entries.append({"id": catalogue_id, "name": generic, "type_id": type_id,
                            "sector_id": sector_id, "cats": frozenset({cand_cat})})
        triage.catalogue_vecs.setdefault(generic, qv)
    return _CandidateFate(verdict, type_id, catalogue_id, matched_id, cosine, minted)


def _add_unverified_threats_to_library(sess: Session, scenario_session: RowMapping, good_subs: list[int],
                                        user_id: str | None) -> list[tuple[str, str]]:
    """Promote this accept's novel threats into the shared library: for each candidate, decide
    its catalogue fate by banded triage, create/reuse the matching Threat_Type and actor links,
    and accumulate the audit + candidate-review records. Reads are pre-resolved by
    `_promotion_candidates` / `_preload_actor_memo` / `_prepare_triage`; writes are batched at
    the bottom.

    Returns every `(embedding_group, name)` pair actually promoted this call, for the caller to
    eager-embed AFTER its own commit (see run_promotion_phase) — never computed here, since this
    function's writes are not yet durable when it returns.
    """
    sector_id = _pick_sector_for_promotion(scenario_session)
    sid = scenario_session["SessionID"]
    tenant, entity = scenario_session["TenantID"], scenario_session["EntityID"]
    all_rows = _promotion_candidates(sess, sid, good_subs)
    # THREAT candidacy keeps the threshold ("should this go INTO the library?"); ACTOR
    # candidacy deliberately does not — a novel actor name on a 92-scoring threat still
    # reaches the curator queue (the scored_rows pass below). NULL-safe: a row with no
    # recorded score is by definition not a confident match, so it stays a threat candidate.
    threshold = get_settings().library_promotion_threshold
    rows, scored_rows = [], []
    for r in all_rows:
        (rows if r["GroundingScore"] is None or r["GroundingScore"] < threshold
        else scored_rows).append(r)

    resolved: dict[tuple, Any] = {}  # in-accept memo: ("category"|"type"|"cat"|"actor"|"link", ...) -> id/True
    parsed_actors, all_actor_names = _extract_actor_names_per_threat(all_rows)
    actor_table, actor_trigram_index, actor_token_index = _preload_actor_memo(
        sess, all_rows, all_actor_names, resolved)

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
    # THE master switch, read LIVE once per promotion attempt (config.py docstring): OFF =
    # admin-gated (no mints, no links, novel actors queue); ON = full auto at accept.
    auto_mode = get_settings().promotion_auto_approve_enabled
    triage = _prepare_triage(sess, llm, scenario_session, rows)
    # Cross-session dedup, preloaded in ONE query (same batched-IO rule as the actor memo):
    # (kind, folded identity) of every PENDING or REJECTED curation card, checked at the
    # queue/mint sites instead of a per-row probe. Loaded AFTER _prepare_triage on purpose:
    # that call spans an external embedding round-trip, and reading the card set before it
    # would stretch the (accepted, documented) preload-then-insert dedup window across a
    # network call for no reason. Skipped when there is nothing to file.
    pending_cards = pending_card_identities(sess) if all_rows else set()
    update_rows: list[dict] = []
    audit_rows: list[dict] = []
    candidate_rows: list[dict] = []
    triage_details: list[dict] = []
    actor_triage: list[dict] = []
    promoted_names: list[tuple[str, str]] = []  # (embedding_group, name) — see return docstring
    actx = _ActorPromoCtx(sess, resolved, pending_cards, actor_table, actor_trigram_index,
                        actor_token_index, tn, auto_mode, candidate_rows, actor_triage, sid,
                        tenant, entity, stamp, actor_id)
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
                                    created_by=actor_id, auto_mode=auto_mode,
                                    pending_cards=pending_cards)
        verdict, type_id, catalogue_id_new, matched_id, cosine, minted = fate

        actors = parsed_actors[row["ThreatID"]]
        # Actor candidacy FIRST — the same order the type/catalogue path uses (triage before
        # any write): duplicates resolve into the memo, novel names mint (switch ON, junk-
        # gated) or queue as cards, the review band queues under either switch. Only names
        # this call resolved or minted can then LINK below.
        _queue_or_mint_row_actors(actx, row, type_id, actors)
        # The remaining gate, closing the laundering loop: links may SEED a type minted in
        # this very accept, never extend a pre-existing type's actor set. Without this, an
        # unvalidated AI assertion ("Hacktivist does type 210") written today becomes the very
        # set get_allowed_actor_names canonicalizes future sessions against tomorrow. A curated
        # type's actor set changes only via PATCH /threat-types/{id} (actor_names) or an
        # admin-approved actor card — the deliberate, audited paths.
        if resolved.get(("minted_type", type_id)):
            linked_actors = _link_actors_to_threat_type(sess, type_id, actors, resolved)
        else:
            linked_actors = []
            if actors and type_id is not None:
                # PATCH hint, filtered inside the helper to the names it is actionable for
                # (known-but-unlinked) — carded and unknown names have their own traces.
                log_withheld_links(resolved, type_id, actors, row["ThreatID"])
            elif actors:
                # OFF + novel type: no id to PATCH yet — the type is itself pending as a card.
                # The names above were still triaged/queued; links become possible only after
                # the admin approves the type (and actor) cards. Distinct line because the
                # withheld-log's "type pre-exists" wording would be wrong here.
                log.info("accept.actor_links_deferred_novel_type", actors=actors,
                        threat_id=row["ThreatID"])
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
            # `minted` (not row["ThreatType"]/generic unconditionally): an auto_reject LINKS to
            # an EXISTING entry under whatever name it was actually stored as, which is not
            # necessarily this candidate's own proposed spelling — eager-embedding the wrong
            # name would either no-op uselessly or fail name resolution on the most common
            # promotion outcome. _decide_candidate_fate already tracked exactly what it minted.
            promoted_names.extend(minted)

        # ONLY the middle band reaches a human. `pending` is the honest status — nothing has
        # been reviewed, hence no ReviewedBy/ReviewedAt and no `candidate_reconciled` audit.
        # TWO dedup layers (the table has no unique index): the in-accept memo, then the
        # preloaded cross-session set of already-PENDING rows — without that layer, every
        # session that proposes the same threat queues the same curation card again (the
        # pile-up the curator queue existed to avoid). BOTH layers key on the SAME folded
        # identity (generic-or-name), so two paraphrases in one accept can't double-queue
        # what one session would have deduped against another.
        ident = ((generic or row["ThreatName"]) or "").strip().casefold()
        ckey = ("candidate", ident)
        # `ident` (not just ThreatName) must be non-empty: the preload drops empty folds, so a
        # blank-identity card could never be remembered and would re-queue every accept.
        if (verdict is TriageVerdict.review and row["ThreatName"] and ident
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
            # Cross-session suppression must not be silent (the actor path already logs its
            # twin): the identity is queued or was rejected — an operator can answer "why does
            # this threat never reach the library?" from this line alone.
            log.info("accept.threat_card_suppressed", threat_id=row["ThreatID"], ident=ident,
                    note="identity already queued for review or previously rejected — no re-queue")

    # GAP B pass: rows whose THREAT matched well (score >= threshold) carry no threat
    # candidacy — their type/catalogue ids are already the library's — but their ACTOR names
    # still get the full gate: triage, cards, junk-gated mints under the switch. Links stay
    # curator-owned (the anti-laundering rule above): a pre-existing type's actor set never
    # grows at accept, so a known-but-unlinked name only logs the PATCH hint.
    for row in scored_rows:
        actors = parsed_actors[row["ThreatID"]]
        if not actors:
            continue
        vtype_id = row["ThreatTypeID"]
        _queue_or_mint_row_actors(actx, row, vtype_id, actors)
        if vtype_id is not None:
            log_withheld_links(resolved, vtype_id, actors, row["ThreatID"])

    if triage_details or actor_triage:
        # ONE calibration record per accept (AuditEventType.promotion_triage): every candidate's
        # cosine, matched entry and band verdict, plus the bands in force — 6d tightens the
        # bands by comparing these against what curators actually chose in the middle band.
        # "candidates" = threat/catalogue decisions (embedding cosine); "actors" = actor-name
        # decisions (string ratio, same band knobs) — the kind discriminator IS the array.
        audit_rows.append(dal.audit_row(
            sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=entity,
            EventType=AuditEventType.promotion_triage, ActorUserID=actor_id, ActorType=actor_type,
            CreatedAt=stamp,
            DetailJSON=json.dumps({
                "bands": {"auto_reject": tn.triage_auto_reject_cosine,
                        "auto_approve": tn.triage_auto_approve_cosine},
                "candidates": triage_details,
                "actors": actor_triage})))
    if update_rows:
        # Table (Core), not the mapped class: a plain executemany UPDATE, not an ORM bulk-update-
        # by-PK (which requires the dict key to be the PK attribute name, not a bindparam name,
        # and otherwise needs synchronize_session=None to allow this extra WHERE at all).
        it = cast(Table, m.Identified_Threat.__table__)
        sess.execute(update(it).where(it.c.ThreatID == bindparam("b_tid")), update_rows)
    if candidate_rows:
        sess.execute(insert(m.Threat_Candidate_Review), candidate_rows)
        n_actor = sum(1 for c in candidate_rows if c["CandidateKind"] == CandidateKind.actor)
        # The one operator-visible trace that the admin-gated path did its job this accept.
        log.info("accept.candidates_queued", session_id=sid,
                threat_cards=len(candidate_rows) - n_actor, actor_cards=n_actor,
                auto_mode=auto_mode)
    if audit_rows:
        sess.execute(insert(m.Scenario_Audit), audit_rows)
    return promoted_names


def eager_embed_promoted(sess: Session, llm, promoted_names: list[tuple[str, str]]) -> None:
    """Fingerprint every (embedding_group, name) pair promoted this call, right now, instead of
    waiting for some later accept's triage to lazily compute it. Best-effort: a slow or
    unreachable embedding/Mongo service must never fail an accept or a retry that already
    succeeded on the DB side, so every failure here is only logged, never raised. The existing
    lazy fallback in embeddings.get_vectors still covers this name if this call is skipped or
    fails — no separate retry mechanism is needed for eager embedding itself."""
    if not promoted_names:
        return
    names_by_group: dict[str, list[str]] = {}
    for group, name in promoted_names:
        names_by_group.setdefault(group, []).append(name)
    for group, names in names_by_group.items():
        try:
            embeddings.create_items(sess, llm, group, names)
        except Exception:  # noqa: BLE001 — best-effort; the lazy fallback self-heals this later
            log.warning("session.eager_embed_failed", embedding_group=group, names=names, exc_info=True)
