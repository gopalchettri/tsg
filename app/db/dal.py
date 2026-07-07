"""Data-access layer — the ONE place isolation and concurrency guards live
Every entity-scoped read/write goes through here so
the `EntityID` predicate and active-row rule (`Superseded=0`) can
never be forgotten, and the CAS primitives (stage claim, `_LOCK`) are written
once, correctly.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import and_, func, insert, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import SessionStatus, StageStatus, SubsystemLevel
from app.db import models as m


def now() -> datetime:
    """Current UTC timestamp — the single definition every writer imports, so every
    CreatedAt/UpdatedAt/LeaseExpiresAt column shares one clock/timezone convention."""
    return datetime.now(timezone.utc)


def guid() -> str:
    """Row-key primitive (GUID as nvarchar(36)); the single definition every writer imports."""
    return str(uuid.uuid4())


# --- exceptions mapped to HTTP by the API layer ---
class SessionConflict(Exception):
    """An active session already exists for this (entity, asset) → 409."""

    def __init__(self, active_session_id: str | None):
        """Carries the conflicting session's id (may be None if the M4 winner
        couldn't be re-resolved) so the API layer can surface it in the 409 body."""
        self.active_session_id = active_session_id
        super().__init__(active_session_id)


class EntityForbidden(Exception):
    """Requested object is outside the caller's entity scope → 403."""


class NotFoundError(Exception):
    """Requested entity does not exist → 404."""


def active(table) -> Any:
    """Active-row predicate: only `Superseded = 0` rows are valid (§5.8)."""
    return table.c.Superseded == 0


# ---------------------------------------------------------------------------
# Sessions (carry EntityID directly — filtered by it, INV-1)
# ---------------------------------------------------------------------------
def create_session(sess: Session, values: Mapping[str, Any]) -> str:
    """Insert a session. Two independent unique indexes can reject the insert: M4
    (EntityID, AssetExternalID) WHERE active, and M8 (EntityID, IdempotencyKey) WHERE
    IdempotencyKey IS NOT NULL — a concurrent request racing the SAME idempotency key
    past `reserve_idempotency_key_or_get_existing`'s pre-check TOCTOU window can violate
    EITHER. Check the idempotency-key index first when a key was supplied: it's the
    more specific match, and re-scoping by (EntityID, AssetExternalID) alone would
    silently miss a same-key/different-asset winner (that row need not share our
    AssetExternalID), returning the wrong conflict type with no session id.
    """
    try:
        with sess.begin_nested():  # savepoint so a violation doesn't kill the txn
            sess.execute(insert(m.Scenario_Session).values(**values))
    except IntegrityError:
        idem_key = values.get("IdempotencyKey")
        if idem_key:
            winner = sess.execute(
                select(m.Scenario_Session.c.SessionID).where(
                    m.Scenario_Session.c.EntityID == values["EntityID"],
                    m.Scenario_Session.c.IdempotencyKey == idem_key,
                )
            ).scalar()
            if winner is not None:
                raise IdempotencyKeyConflict(winner)
        existing = sess.execute(
            select(m.Scenario_Session.c.SessionID).where(
                m.Scenario_Session.c.EntityID == values["EntityID"],
                m.Scenario_Session.c.AssetExternalID == values["AssetExternalID"],
                m.Scenario_Session.c.SessionStatus == SessionStatus.active,
            )
        ).scalar()
        raise SessionConflict(existing)
    return values["SessionID"]


def load_session(sess: Session, session_id: str) -> Mapping[str, Any] | None:
    """Load a session by id WITHOUT an entity filter — the API then checks the
    row's EntityID is in the caller's authorized set ([R2] object-level authz).
    """
    return sess.execute(
        select(m.Scenario_Session).where(m.Scenario_Session.c.SessionID == session_id)
    ).mappings().first()


def get_session(sess: Session, session_id: str, entity_id: str) -> Mapping[str, Any] | None:
    """Fetch a session **only within the caller's entity** — the data-layer IDOR
    guard (INV-1): another entity's session is invisible even with a valid token.
    """
    return sess.execute(
        select(m.Scenario_Session).where(
            m.Scenario_Session.c.SessionID == session_id,
            m.Scenario_Session.c.EntityID == str(entity_id),
        )
    ).mappings().first()


def complete_session(sess: Session, session_id: str) -> None:
    """Accept path: flip to completed/APPROVED — this releases the M4 lock."""
    from app.core.enums import WorkflowStage

    sess.execute(
        update(m.Scenario_Session)
        .where(m.Scenario_Session.c.SessionID == session_id)
        .values(
            SessionStatus=SessionStatus.completed,
            CurrentStage=WorkflowStage.APPROVED,
            CompletedAt=now(),
            UpdatedAt=now(),
        )
    )


def cancel_session(sess: Session, session_id: str) -> None:
    """Cancel/reaper path → cancelled (also releases the M4 lock). Mirrors
    `complete_session`'s pattern: CurrentStage/StageStatus move to a real terminal
    value too, not just SessionStatus — otherwise the board keeps showing the stale
    pre-cancel stage forever (e.g. AWAITING_DECISION on a session that's actually dead)."""
    from app.core.enums import WorkflowStage

    sess.execute(
        update(m.Scenario_Session)
        .where(m.Scenario_Session.c.SessionID == session_id)
        .values(SessionStatus=SessionStatus.cancelled, CurrentStage=WorkflowStage.CANCELLED,
                StageStatus=StageStatus.CANCELLED, UpdatedAt=now())
    )


# ---------------------------------------------------------------------------
# Admission control — backpressure + idempotent create
# ---------------------------------------------------------------------------
class CapacityExceeded(Exception):
    """Active-session ceiling reached → 503 (soft, deliberately racy — see
    `count_active_sessions`)."""


class IdempotencyKeyConflict(Exception):
    """Idempotency-Key reused against a different (entity, asset) → 409."""

    def __init__(self, existing_session_id: str):
        """Carries the session id the reused key was already bound to, so the API
        layer's 409 body can point the caller at the (entity, asset) that actually
        owns this Idempotency-Key."""
        self.existing_session_id = existing_session_id
        super().__init__(existing_session_id)


def count_active_sessions(sess: Session) -> int:
    """Index-only-scan COUNT against the filtered `IX_Session_Active` index — never
    touches the base table. Deliberately racy under concurrency: a soft backpressure
    ceiling only needs to protect an already-saturated system, not be exact — unlike
    the M4 per-asset lock, which IS a correctness invariant and must never be racy.
    """
    return sess.execute(
        select(func.count()).select_from(m.Scenario_Session)
        .where(m.Scenario_Session.c.SessionStatus == SessionStatus.active)
    ).scalar()


def assert_capacity_available(sess: Session) -> None:
    """Raise CapacityExceeded if the active-session ceiling is at/over
    `max_active_sessions`. Checked before the more expensive `gather_asset_details`."""
    if count_active_sessions(sess) >= get_settings().max_active_sessions:
        raise CapacityExceeded()


def reserve_idempotency_key_or_get_existing(
    sess: Session, entity_id: str, idempotency_key: str, asset_external_id: str,
) -> tuple[str | None, bool]:
    """One indexed SELECT against `UX_Session_IdempotencyKey`. Returns:
      - (None, False)        — key unused, caller proceeds to create.
      - (session_id, False)  — same key + same asset → return the existing session.
      - (session_id, True)   — same key + a DIFFERENT asset → caller raises 409
        (silently ignoring a reused key against a different payload would be a worse
        trap than a loud conflict).
    The actual create-time race (two concurrent requests racing this same read) is
    caught by `create_session`'s IntegrityError handler, which checks the
    IdempotencyKey index FIRST (before falling back to the M4 asset index) — the two
    racing requests need NOT share (EntityID, AssetExternalID).
    """
    row = sess.execute(
        select(m.Scenario_Session.c.SessionID, m.Scenario_Session.c.AssetExternalID)
        .where(m.Scenario_Session.c.EntityID == entity_id,
               m.Scenario_Session.c.IdempotencyKey == idempotency_key)
    ).mappings().first()
    if row is None:
        return None, False
    return row["SessionID"], row["AssetExternalID"] != asset_external_id


# ---------------------------------------------------------------------------
# Stage state — CAS primitives
# ---------------------------------------------------------------------------
def claim_stage(
    sess: Session, session_id: str, subsystem_id: int, level: SubsystemLevel,
    epoch: int, task_id: str,
) -> bool:
    """Atomically claim a work stage for one attempt. Returns True iff this
    call won the claim (`@@ROWCOUNT == 1`). Claimable states: `IDLE`/`ERROR` (fresh
    or failed), or a row THIS task left `RUNNING` (a mid-flight retry resumes it) —
    AND `AttemptCount` under the poison-terminal cap. A stage already
    `COMPLETE`/`AWAITING_DECISION` is **not** re-claimable — so a Celery redelivery
    of a finished stage is a true no-op, never a destructive re-run. [R8] Once
    `AttemptCount` reaches `stage_max_attempts` the row stops being re-claimable
    (and so stops refreshing its lease); the existing reaper sweep + `decide_session_outcome`
    then carry it to a terminal state with no new plumbing.
    """
    s = get_settings()
    res = sess.execute(
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.c.SessionID == session_id,
            m.Subsystem_Stage_State.c.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.c.Level == level,
            m.Subsystem_Stage_State.c.GenerationEpoch == epoch,
            m.Subsystem_Stage_State.c.AttemptCount < s.stage_max_attempts,
            or_(
                m.Subsystem_Stage_State.c.Status.in_([StageStatus.IDLE, StageStatus.ERROR]),
                and_(m.Subsystem_Stage_State.c.ActiveTaskID == task_id,
                     m.Subsystem_Stage_State.c.Status == StageStatus.RUNNING),
            ),
        )
        .values(
            Status=StageStatus.RUNNING,
            ActiveTaskID=task_id,
            LeaseExpiresAt=now() + timedelta(seconds=s.stage_lease_seconds),
            HeartbeatAt=now(),
            AttemptCount=m.Subsystem_Stage_State.c.AttemptCount + 1,
            UpdatedAt=now(),
        )
    )
    return res.rowcount == 1


def acquire_lock(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """[R5] Compare-and-set on the `_LOCK` row — serialises work on one subsystem.
    Only one caller can flip IDLE→RUNNING; returns True iff we hold it. A lease is
    set so the reaper can reclaim it if the holder dies ([R1]).
    """
    s = get_settings()
    # A lock may only be taken while the owning session is still 'active'. This closes the
    # race where a redelivered task (or the reaper) resumes/mutates a session that was
    # concurrently cancelled/completed — the _LOCK row is the mutex, this is its session gate.
    session_active = (
        select(1)
        .where(m.Scenario_Session.c.SessionID == session_id,
               m.Scenario_Session.c.SessionStatus == SessionStatus.active)
        .exists()
    )
    res = sess.execute(
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.c.SessionID == session_id,
            m.Subsystem_Stage_State.c.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.c.Level == SubsystemLevel.LOCK,
            m.Subsystem_Stage_State.c.Status == StageStatus.IDLE,
            session_active,
        )
        .values(
            Status=StageStatus.RUNNING, ActiveTaskID=task_id,
            LeaseExpiresAt=now() + timedelta(seconds=s.stage_lease_seconds), UpdatedAt=now(),
        )
    )
    return res.rowcount == 1


def release_lock(sess: Session, session_id: str, subsystem_id: int) -> None:
    """Unconditionally flip the `_LOCK` row back to IDLE, freeing it for the next
    `acquire_lock` caller. No CAS guard here — the holder proved ownership when it
    won `acquire_lock`, so release is a plain write, not another compare-and-set."""
    sess.execute(
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.c.SessionID == session_id,
            m.Subsystem_Stage_State.c.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.c.Level == SubsystemLevel.LOCK,
        )
        # Clear the lease too: a released lock holds no lease, so the reaper's "any live
        # lease?" liveness check never mistakes a freed lock for a running worker.
        .values(Status=StageStatus.IDLE, ActiveTaskID=None, LeaseExpiresAt=None, UpdatedAt=now())
    )


def set_stage(
    sess: Session, session_id: str, subsystem_id: int, level: SubsystemLevel,
    status: StageStatus, error: str | None = None,
) -> None:
    """A row's `LeaseExpiresAt` means "someone is actively RUNNING this right now" —
    every transition AWAY from RUNNING (COMPLETE/AWAITING_DECISION/ERROR) must clear
    it. Otherwise a long-finished row keeps carrying its original (now long-expired)
    lease forever, and the reaper's `dead_lease` check — meant to catch a genuinely
    abandoned mid-flight attempt — fires on a session that simply left REVIEW minutes
    ago for a routine regeneration, bypassing the grace-period fallback entirely."""
    sess.execute(
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.c.SessionID == session_id,
            m.Subsystem_Stage_State.c.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.c.Level == level,
        )
        .values(Status=status, ErrorMessage=error, LeaseExpiresAt=None, UpdatedAt=now())
    )


def stage_rows(sess: Session, session_id: str) -> list[Mapping[str, Any]]:
    """Per-subsystem stage rows for the status board (§6.1), excluding `_LOCK`."""
    return list(
        sess.execute(
            select(
                m.Subsystem_Stage_State.c.SubsystemID,
                m.Subsystem_Stage_State.c.Level,
                m.Subsystem_Stage_State.c.Status,
            ).where(
                m.Subsystem_Stage_State.c.SessionID == session_id,
                m.Subsystem_Stage_State.c.Level != SubsystemLevel.LOCK,
            )
        ).mappings()
    )


def subsystem_ids_at_level(
    sess: Session, session_id: str, level: SubsystemLevel, status: StageStatus | None = None,
) -> list[int]:
    """Every SubsystemID for this session at a given Subsystem_Stage_State Level,
    optionally narrowed to a specific Status (e.g. accept's REVIEW-barrier check:
    which subsystems are `_LOCK`ed, or which reached `SCENARIOS`/`AWAITING_DECISION`)."""
    where = [m.Subsystem_Stage_State.c.SessionID == session_id, m.Subsystem_Stage_State.c.Level == level]
    if status is not None:
        where.append(m.Subsystem_Stage_State.c.Status == status)
    return [r[0] for r in sess.execute(select(m.Subsystem_Stage_State.c.SubsystemID).where(*where)).all()]


def subsystem_has_pending_work(sess: Session, session_id: str, subsystem_id: int) -> bool:
    """True iff any non-_LOCK stage for this subsystem is IDLE or RUNNING — i.e.
    genuinely unstarted or resumable. False means every stage already reached a
    terminal state (COMPLETE/AWAITING_DECISION/ERROR): a loop pass over this
    subsystem is just walking past already-finished work (e.g. a Celery redelivery
    resuming a LATER subsystem restarts `_process_all_supporting_systems`'s loop from index 0, passing
    back through earlier subsystems that already completed in a prior, committed
    attempt) — used to gate the one-time `subsystem_advanced` signal so a redelivery
    doesn't re-announce a subsystem nothing is actually about to happen to."""
    return sess.execute(
        select(1).where(
            m.Subsystem_Stage_State.c.SessionID == session_id,
            m.Subsystem_Stage_State.c.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.c.Level != SubsystemLevel.LOCK,
            m.Subsystem_Stage_State.c.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]),
        )
    ).first() is not None


# ---------------------------------------------------------------------------
# Regeneration (M2, [R9]) — per-(subsystem, level) generation epoch bump
# ---------------------------------------------------------------------------
class RegenerateConflict(Exception):
    """Regenerate rejected: not at REVIEW, target lock held, or a concurrent
    regen/accept won the race → 409. Distinct from AcceptConflict — a different
    action, so it needs its own error_code."""


def next_epoch(sess: Session, session_id: str, subsystem_id: int, levels: tuple) -> int:
    """max(GenerationEpoch) scoped to ONLY the levels touched in this regen hop, +1.
    Deliberately narrower than a subsystem-wide max: an untouched level's epoch
    lineage is never disturbed by an unrelated regen (e.g. regenerating SCENARIOS
    doesn't bump PROFILE's epoch number)."""
    current = sess.execute(
        select(func.max(m.Subsystem_Stage_State.c.GenerationEpoch)).where(
            m.Subsystem_Stage_State.c.SessionID == session_id,
            m.Subsystem_Stage_State.c.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.c.Level.in_(levels),
        )
    ).scalar()
    return (current or 0) + 1


def reset_stage_for_regen(sess: Session, session_id: str, subsystem_id: int, levels: tuple, new_epoch: int) -> None:
    """Reset the target level(s) to a fresh, claimable IDLE row at `new_epoch` so
    `claim_stage`'s `GenerationEpoch == epoch` CAS matches. Also zeroes `AttemptCount`
    and clears `ErrorMessage`: without this, a subsystem that exhausted its
    poison-terminal attempt budget under the OLD epoch would stay permanently
    unclaimable under the new one too — a regenerated subsystem born poisoned."""
    sess.execute(
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.c.SessionID == session_id,
            m.Subsystem_Stage_State.c.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.c.Level.in_(levels),
        )
        .values(GenerationEpoch=new_epoch, Status=StageStatus.IDLE, AttemptCount=0,
               ErrorMessage=None, UpdatedAt=now())
    )


def active_threats(sess: Session, session_id: str, subsystem_id: int) -> list[dict]:
    """Active threats for a subsystem, shaped for `scoping.score_threats` AND
    `write_scenarios`'s per-threat prompt enrichment (the `scenario` granularity's
    regen needs the full sibling list to rank the target threat correctly, even
    though only ONE row ends up rewritten). Matches `find_threats`'s own returned
    dict shape exactly so `write_scenarios` consumes both sources identically."""
    return [
        {
            "threat_id": r["ThreatID"], "grounding_status": r["GroundingStatus"],
            "threat_type": r["ThreatType"], "threat_name": r["ThreatName"],
            "library_threat_type": r["LibraryThreatType"], "library_threat_name": r["LibraryThreatName"],
            "threat_type_id": r["ThreatTypeID"],  # [R12] scoping rules key on the grounded type
        }
        for r in sess.execute(
            select(m.Identified_Threat.c.ThreatID, m.Identified_Threat.c.GroundingStatus,
                  m.Identified_Threat.c.ThreatType, m.Identified_Threat.c.ThreatName,
                  m.Identified_Threat.c.LibraryThreatType, m.Identified_Threat.c.LibraryThreatName,
                  m.Identified_Threat.c.ThreatTypeID).where(
                m.Identified_Threat.c.SessionID == session_id,
                m.Identified_Threat.c.SubsystemID == subsystem_id,
                m.Identified_Threat.c.Superseded == 0,
            )
        ).mappings()
    ]


def active_threat_rules(sess: Session, threat_type_ids: list[int]) -> list[dict]:
    """Active scoping rules for the given grounded master types ([R12], SDD §5.4) — one
    query for the whole subsystem, ordered by ThreatRuleID so rule evaluation (and the
    FactorsJSON it records) is deterministic. Empty input → no query, no rules."""
    if not threat_type_ids:
        return []
    ct = m.Config_Threat_Rule
    return [dict(r) for r in sess.execute(
        select(ct.c.RuleType, ct.c.ThreatTypeID, ct.c.RuleKey, ct.c.RuleValue, ct.c.Metadata)
        .where(ct.c.ThreatTypeID.in_(threat_type_ids),
               ct.c.IsActive == True, ct.c.IsDeleted == False)  # noqa: E712 — SQLAlchemy binary expr
        .order_by(ct.c.ThreatRuleID)
    ).mappings()]


def latest_completed_session(sess: Session, entity_id: str, asset_external_id: str) -> Mapping[str, Any] | None:
    """The asset's most recent COMPLETED session — the downstream contract's "current
    accepted truth" ([R13]): older completed sessions' rows are never cross-session
    superseded, so without this scope a consumer would ingest stale generations
    alongside current ones. Entity filter lives here in the DAL (INV-1)."""
    return sess.execute(
        select(m.Scenario_Session)
        .where(m.Scenario_Session.c.EntityID == str(entity_id),
               m.Scenario_Session.c.AssetExternalID == str(asset_external_id),
               m.Scenario_Session.c.SessionStatus == SessionStatus.completed)
        # SessionID tie-break: two sessions completing in the same clock tick must
        # still yield ONE deterministic "current" pick (same convention as scoping's
        # score-desc/id-asc ordering) — never a query-plan-dependent answer.
        .order_by(m.Scenario_Session.c.CompletedAt.desc(), m.Scenario_Session.c.SessionID)
        .limit(1)
    ).mappings().first()


def accepted_scenarios(sess: Session, session_id: str) -> list[dict]:
    """Accepted, non-superseded scenario rows for one (completed) session, joined to
    their grounded threat so every row carries the [R13] contract's join ids
    (ThreatTypeID/ThreatCatalogueID/SubsystemID). One query; ordered for stable output.
    The joins are by globally-unique GUID keys, so no extra Superseded filter is needed
    on the joined tables — a completed session's rows are immutable."""
    out, st, it = m.Threat_Scenario_Output, m.Scoped_Threat, m.Identified_Threat
    return [dict(r) for r in sess.execute(
        select(out.c.OutputID, out.c.SubsystemID, out.c.ScopedThreatID, out.c.ScenarioJSON,
               it.c.ThreatTypeID, it.c.ThreatCatalogueID, it.c.ThreatType, it.c.ThreatName,
               it.c.LibraryThreatType, it.c.LibraryThreatName)
        .select_from(out.join(st, out.c.ScopedThreatID == st.c.ScopedThreatID)
                     .join(it, st.c.ThreatID == it.c.ThreatID))
        .where(out.c.SessionID == session_id, out.c.Accepted == 1, out.c.Superseded == 0)
        .order_by(out.c.SubsystemID, out.c.OutputID)
    ).mappings()]


def get_active_profile(sess: Session, session_id: str, subsystem_id: int) -> dict | None:
    """The current active profile dict, for granularities that don't regenerate
    PROFILE itself but still need it to build the threats prompt (`threat_type`)."""
    row = sess.execute(
        select(m.Subsystem_Profile.c.ProfileJSON).where(
            m.Subsystem_Profile.c.SessionID == session_id,
            m.Subsystem_Profile.c.SubsystemID == subsystem_id,
            m.Subsystem_Profile.c.Superseded == 0,
        )
    ).scalar()
    return json.loads(row) if row else None


def mark_profiles_accepted(sess: Session, session_id: str, subsystem_ids: list[int]) -> None:
    """Sets Accepted=1 on every non-superseded profile for these subsystems (accept, §5.7)."""
    sess.execute(
        update(m.Subsystem_Profile)
        .where(
            m.Subsystem_Profile.c.SessionID == session_id, m.Subsystem_Profile.c.Superseded == 0,
            m.Subsystem_Profile.c.SubsystemID.in_(subsystem_ids),
        )
        .values(Accepted=1)
    )


def mark_scenarios_accepted(
    sess: Session, session_id: str, subsystem_ids: list[int], subset: list[str] | None = None,
) -> None:
    """Sets Accepted=1 on every non-superseded scenario for these subsystems (accept, §5.7),
    optionally narrowed to `subset` OutputIDs ([R8] partial accept — `subset=[]` means
    "accept none", distinct from `subset=None` meaning "accept all")."""
    where = [m.Threat_Scenario_Output.c.SessionID == session_id, m.Threat_Scenario_Output.c.Superseded == 0,
             m.Threat_Scenario_Output.c.SubsystemID.in_(subsystem_ids)]
    if subset is not None:
        where.append(m.Threat_Scenario_Output.c.OutputID.in_(subset))
    sess.execute(update(m.Threat_Scenario_Output).where(*where).values(Accepted=1))


# ---------------------------------------------------------------------------
# Generic write helpers
# ---------------------------------------------------------------------------
def supersede(sess: Session, table, session_id: str, subsystem_id: int) -> None:
    """Mark the active rows of a (session, subsystem) as superseded (§5.8)."""
    sess.execute(
        update(table)
        .where(
            table.c.SessionID == session_id,
            table.c.SubsystemID == subsystem_id,
            table.c.Superseded == 0,
        )
        .values(Superseded=1)
    )


def active_scoped_threat_ids(sess: Session, session_id: str, subsystem_id: int, threat_ids) -> list[str]:
    """Every current active ScopedThreatID for a SET of ThreatIDs in ONE query — used by
    `write_scenarios`'s multi-target regen path so an up-to-`_MAX_BATCH` target list
    doesn't do one SELECT per id."""
    if not threat_ids:
        return []
    return list(sess.execute(
        select(m.Scoped_Threat.c.ScopedThreatID).where(
            m.Scoped_Threat.c.SessionID == session_id,
            m.Scoped_Threat.c.SubsystemID == subsystem_id,
            m.Scoped_Threat.c.ThreatID.in_(threat_ids),
            m.Scoped_Threat.c.Superseded == 0,
        )
    ).scalars().all())


def supersede_by_threats(sess: Session, table, session_id: str, subsystem_id: int, threat_ids) -> None:
    """Every active row (Identified_Threat/Scoped_Threat) whose ThreatID is in the
    requested set — one UPDATE, not a loop."""
    if not threat_ids:
        return
    sess.execute(
        update(table)
        .where(
            table.c.SessionID == session_id,
            table.c.SubsystemID == subsystem_id,
            table.c.ThreatID.in_(threat_ids),
            table.c.Superseded == 0,
        )
        .values(Superseded=1)
    )


def supersede_by_scoped_threats(sess: Session, session_id: str, subsystem_id: int, scoped_threat_ids) -> None:
    """Every active Threat_Scenario_Output row whose ScopedThreatID is in the requested
    set — one UPDATE, not a loop."""
    if not scoped_threat_ids:
        return
    sess.execute(
        update(m.Threat_Scenario_Output)
        .where(
            m.Threat_Scenario_Output.c.SessionID == session_id,
            m.Threat_Scenario_Output.c.SubsystemID == subsystem_id,
            m.Threat_Scenario_Output.c.ScopedThreatID.in_(scoped_threat_ids),
            m.Threat_Scenario_Output.c.Superseded == 0,
        )
        .values(Superseded=1)
    )


def insert_row(sess: Session, table, values: Mapping[str, Any]) -> None:
    """Generic single-row insert shared by callers writing a new active record
    (profile/threat/scenario output) — no active-row or Superseded handling of its
    own, callers are expected to `supersede` the prior row first."""
    sess.execute(insert(table).values(**values))


def append_audit(sess: Session, **cols: Any) -> None:
    """Append-only audit write; CreatedAt defaulted."""
    cols.setdefault("CreatedAt", now())
    sess.execute(insert(m.Scenario_Audit).values(**cols))


# ---------------------------------------------------------------------------
# Threat-library promotion (R10, SDD §5.7 step 1) — race-safe insert-if-not-exists,
# guarded by the M2 natural-key UNIQUE indexes (migration 0010). Same savepoint +
# catch-IntegrityError + select idiom as `create_session` above: two concurrent
# accepts proposing the identical new master lose the DB race deterministically,
# and the loser gets back the winner's id instead of a crash.
# ---------------------------------------------------------------------------
def upsert_threat_type(sess: Session, name: str, category_id: int | None, sector_id: int | None,
                       description: str | None = None) -> int:
    """Insert-if-not-exists keyed by (ThreatTypeName, PrimaryThreatCategoryID, SectorID) —
    `UX_ThreatType_NaturalKey`. Returns the winning ThreatTypeID either way."""
    try:
        with sess.begin_nested():
            res = sess.execute(insert(m.Threat_Type).values(
                ThreatTypeName=name, PrimaryThreatCategoryID=category_id, SectorID=sector_id,
                Description=description, IsActive=True, IsDeleted=False))
        return res.inserted_primary_key[0]
    except IntegrityError:
        sector_pred = m.Threat_Type.c.SectorID.is_(None) if sector_id is None else m.Threat_Type.c.SectorID == sector_id
        winner = sess.execute(
            select(m.Threat_Type.c.ThreatTypeID).where(
                m.Threat_Type.c.ThreatTypeName == name,
                m.Threat_Type.c.PrimaryThreatCategoryID == category_id, sector_pred,
                m.Threat_Type.c.IsActive == True, m.Threat_Type.c.IsDeleted == False)
        ).scalar()
        if winner is None:  # not a natural-key duplicate (NOT NULL / missing IDENTITY /
            raise           # truncation / other violation) — fail loud, never return a NULL id
        return winner


def upsert_threat_catalogue(sess: Session, name: str, type_id: int, sector_id: int | None,
                            description: str | None = None) -> int:
    """Insert-if-not-exists keyed by (ThreatTypeID, ThreatName, SectorID) —
    `UX_ThreatCatalogue_NaturalKey`. Returns the winning ThreatCatalogueID either way."""
    try:
        with sess.begin_nested():
            res = sess.execute(insert(m.Threat_Catalogue).values(
                ThreatTypeID=type_id, ThreatName=name, SectorID=sector_id,
                Description=description, IsActive=True, IsDeleted=False))
        return res.inserted_primary_key[0]
    except IntegrityError:
        sector_pred = (m.Threat_Catalogue.c.SectorID.is_(None) if sector_id is None
                       else m.Threat_Catalogue.c.SectorID == sector_id)
        winner = sess.execute(
            select(m.Threat_Catalogue.c.ThreatCatalogueID).where(
                m.Threat_Catalogue.c.ThreatTypeID == type_id, m.Threat_Catalogue.c.ThreatName == name,
                sector_pred, m.Threat_Catalogue.c.IsActive == True, m.Threat_Catalogue.c.IsDeleted == False)
        ).scalar()
        if winner is None:  # see upsert_threat_type — only a real duplicate may resolve here
            raise
        return winner


def upsert_threat_actor(sess: Session, name: str) -> int:
    """Insert-if-not-exists keyed by (ThreatActorName) — `UX_ThreatActor_NaturalKey`
    (no sector on this table). Returns the winning ThreatActorID either way."""
    try:
        with sess.begin_nested():
            res = sess.execute(insert(m.Threat_Actor).values(
                ThreatActorName=name, IsCapable=1, IsActive=True, IsDeleted=False))
        return res.inserted_primary_key[0]
    except IntegrityError:
        winner = sess.execute(
            select(m.Threat_Actor.c.ThreatActorID).where(
                m.Threat_Actor.c.ThreatActorName == name,
                m.Threat_Actor.c.IsActive == True, m.Threat_Actor.c.IsDeleted == False)
        ).scalar()
        if winner is None:  # see upsert_threat_type — only a real duplicate may resolve here
            raise
        return winner


def link_type_actor(sess: Session, type_id: int, actor_id: int) -> bool:
    """Idempotent link into `ThreatType_ThreatActor_Map` — the composite (ThreatTypeID,
    ThreatActorID) PRIMARY KEY itself guards duplicates, so a repeat call is a race-safe
    no-op (savepoint absorbs the IntegrityError; the link now exists either way).
    Returns True iff a NEW link row was inserted, False if it already existed — so callers
    (accept._promote_flagged_threats) can audit real library growth, not a re-affirmed link."""
    try:
        with sess.begin_nested():
            sess.execute(insert(m.ThreatType_ThreatActor_Map).values(ThreatTypeID=type_id, ThreatActorID=actor_id))
        return True
    except IntegrityError:
        return False
