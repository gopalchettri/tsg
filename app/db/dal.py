"""Data-access layer — the ONE place isolation and concurrency guards live
Every entity-scoped read/write goes through here so
the `EntityID` predicate and active-row rule (`Superseded=0`) can
never be forgotten, and the CAS primitives (stage claim, `_LOCK`) are written
once, correctly.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, cast

from sqlalchemy import Executable, RowMapping, and_, case, delete, func, insert, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (ActorType, ScenarioStatus, SessionStatus, StageStatus, SubsystemLevel,
                            WorkflowStage)
from app.db import models as m


def execute_dml(sess: Session, stmt: Executable) -> CursorResult[Any]:
    """Run a Core INSERT/UPDATE/DELETE, returning the result narrowed to `CursorResult` —
    the only `Result` subclass carrying `.rowcount` and `.inserted_primary_key`.

    `Session.execute()` is annotated `-> Result[Any]` because it also serves ORM queries,
    which return `ChunkedIteratorResult`/`ScalarResult`. Core DML always yields a
    `CursorResult` at runtime, but the annotation cannot say so, and every CAS below reads
    `.rowcount` off it. Narrowing once here beats a cast at each call site.

    NOTE `.rowcount` is only a trustworthy CAS signal while no `SET NOCOUNT ON` is in
    effect and no trigger fires on the target table — either would make it -1 or inflated.
    """
    return cast("CursorResult[Any]", sess.execute(stmt))


def inserted_pk(res: CursorResult[Any]) -> int:
    """First column of the primary key of the row just inserted.

    `CursorResult.inserted_primary_key` is annotated `Optional[Any]`, but for a single-row
    `insert()` against an IDENTITY table SQLAlchemy either returns a `Row` or raises
    `InvalidRequestError` — it never hands back None. Check anyway: the `upsert_*` callers
    below run inside an IntegrityError retry, where a bare `NoneType is not subscriptable`
    would be far harder to trace back here than an explicit failure.
    """
    pk = res.inserted_primary_key
    if pk is None:
        raise RuntimeError("INSERT yielded no primary key (not an IDENTITY table?)")
    return pk[0]


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

    def __init__(self, active_session_id: str):
        """Carries the conflicting session's id so the API layer can surface it in the
        409 body. Never None: `create_session` raises this only once it has positively
        identified the active row that beat us, and re-raises any IntegrityError it
        cannot attribute to a known unique index instead of mislabelling it a conflict."""
        self.active_session_id = active_session_id
        super().__init__(active_session_id)


class IdempotencyKeyConflict(Exception):
    """Idempotency-Key reused against a different (entity, asset) → 409."""

    def __init__(self, existing_session_id: str):
        """Carries the session id the reused key was already bound to, so the API
        layer's 409 body can point the caller at the (entity, asset) that actually
        owns this Idempotency-Key."""
        self.existing_session_id = existing_session_id
        super().__init__(existing_session_id)


class CapacityExceeded(Exception):
    """Active-session ceiling reached → 503 (soft, deliberately racy — see
    `count_active_sessions`)."""


class RegenerateConflict(Exception):
    """Regenerate rejected: not at REVIEW, target lock held, a concurrent regen/accept won the
    race, or (tasks.py::write_scenarios) every requested target no longer clears the scoping
    cutoff on rescoring → 409. Distinct from AcceptConflict — a different action, so it needs
    its own error_code.

    `reason` is an optional machine-readable code (e.g. "session_completed") surfaced by the
    HTTP handler as `details.reason` — same pattern as SessionConflict's `active_session_id`.
    Raise sites without a stable cause just omit it."""

    def __init__(self, message: str, reason: str | None = None):
        super().__init__(message)
        self.reason = reason


class CancelConflict(Exception):
    """Cancel rejected: the session was already terminal (completed/cancelled by a
    concurrent writer) when `cancel_session`'s CAS ran → 409. Distinct from
    AcceptConflict/RegenerateConflict — a different action, own error_code."""


class EntityForbidden(Exception):
    """Requested object is outside the caller's entity scope → 403."""


class NotFoundError(Exception):
    """Requested entity does not exist → 404."""


# ---------------------------------------------------------------------------
# Object-level authz — asset ownership
# ---------------------------------------------------------------------------
def asset_owning_entities(sess: Session, asset_id: Any) -> set[str]:
    """The group/entity id(s) that actually own `asset_id` (a `ctm_scan_entity` row), read
    straight off `ctm_scan_entity_bu.group_id` — the direct asset->entity link per the CII
    Onboarding DDD. An asset can have more than one `ctm_scan_entity_bu` row (confirmed live:
    asset 1 currently has 2), hence the set return, not a single value.

    `ctm_scan_entity.tier1_critical_service_id` (and the `onboarding_service_entity` service
    ->entity mapping it used to be joined through) is NOT this path — that field is confirmed
    unpopulated on every current asset. It's only still read by context.py to label the
    grounding context's `critical_service`, which is unrelated to ownership.

    Returns an empty set if the asset doesn't exist or has no `ctm_scan_entity_bu` row —
    callers must treat that as "no proven owner" (deny), never as "open to everyone".
    """
    rows = sess.execute(
        select(m.ctm_scan_entity_bu.group_id)
        .where(m.ctm_scan_entity_bu.ctm_scan_entity_id == asset_id)
    ).scalars().all()
    return {str(g) for g in rows}


def assert_asset_owned_by_entity(sess: Session, asset_id: Any, entity_id: Any) -> None:
    """Deny unless `asset_id` is actually owned by `entity_id`. `require_entity()`
    on its own only proves the caller may act AS entity_id — it says nothing about
    whether this particular asset belongs to that entity. Without this check, any
    caller authorized for their own entity could submit someone else's asset_id
    (a plain IDOR) and pull that asset's context, threats, or accepted scenarios.
    """
    if str(entity_id) not in asset_owning_entities(sess, asset_id):
        raise EntityForbidden(f"asset {asset_id} not owned by entity {entity_id}")


# ---------------------------------------------------------------------------
# Sessions (carry EntityID directly — filtered by it)
# ---------------------------------------------------------------------------
def create_session(sess: Session, values: Mapping[str, Any]) -> str:
    """Insert a session. Two independent unique indexes can reject the insert:
    (EntityID, AssetID) WHERE active, and (EntityID, IdempotencyKey) WHERE
    IdempotencyKey IS NOT NULL — a concurrent request racing the SAME idempotency key
    past `reserve_idempotency_key_or_get_existing`'s pre-check TOCTOU window can violate
    EITHER. Check the idempotency-key index first when a key was supplied: it's the
    more specific match, and re-scoping by (EntityID, AssetID) alone would
    silently miss a same-key/different-asset winner (that row need not share our
    AssetID), returning the wrong conflict type with no session id.

    An IntegrityError attributable to NEITHER index (NOT NULL, FK, truncation) is
    re-raised untouched. Blindly answering `SessionConflict(None)` turned every
    server-side schema fault into a 409 that told the client "asset already has an
    active session" — naming an asset that has no such session — and buried the real
    cause. Same fail-loud rule the `upsert_*` helpers below apply to their own
    natural-key retries: only a violation you can positively identify may be absorbed.
    """
    try:
        with sess.begin_nested():  # savepoint so a violation doesn't kill the txn
            sess.execute(insert(m.Scenario_Session).values(**values))
    except IntegrityError as exc:
        idem_key = values.get("IdempotencyKey")
        # If the caller sent an idempotency key, see if it already points at a session first —
        # that's the more specific match, checked before the plain asset-conflict lookup below.
        if idem_key:
            winner = sess.execute(
                select(m.Scenario_Session.SessionID).where(
                    m.Scenario_Session.EntityID == values["EntityID"],
                    m.Scenario_Session.IdempotencyKey == idem_key,
                )
            ).scalar()
            if winner is not None:
                raise IdempotencyKeyConflict(winner) from exc
        existing = sess.execute(
            select(m.Scenario_Session.SessionID).where(
                m.Scenario_Session.EntityID == values["EntityID"],
                m.Scenario_Session.AssetID == values["AssetID"],
                m.Scenario_Session.SessionStatus == SessionStatus.active,
            )
        ).scalar()
        if existing is None:
            raise  # neither unique index fired — a real constraint fault, not a conflict
        raise SessionConflict(existing) from exc
    return values["SessionID"]


def canonical_guid(value: str) -> str:
    """The one canonical spelling of a client-supplied GUID: exactly what `guid()` mints and
    what `models.GUID.result_processor` hands back from the DB (lowercase, dashed).

    Why this must exist ONCE and be used everywhere a client id meets a DB-derived id:
    `models.GUID` normalizes on BOTH bind and result, so SQL comparisons already treat
    uppercase / dashless (`Guid.ToString("N")`) / braced / `urn:uuid:` spellings as equal — but
    a PYTHON-side comparison (a set difference, a dict lookup, a `len(set(...))` count) does
    not, and silently reports a matched row as missing. That mismatch is what produced the
    false `regenerate_conflict` on a valid request, and a spurious 404 + full rollback on
    accept. Normalizing at the boundary, in one place, is what keeps both sides comparable.

    Raises ValueError on a malformed id, so callers can turn it into a 4xx instead of letting
    it reach `GUID.bind_processor` and surface as a 500."""
    return str(uuid.UUID(str(value).strip()))


def _valid_guid(value: str) -> bool:
    """SessionID (and every other row-key column) is now a real `uniqueidentifier`
    on MSSQL -- a caller-supplied id that isn't UUID-shaped (a stale bookmark, a
    scanner probe, a typo'd path param) must never reach a WHERE clause on that
    column: MSSQL rejects the conversion with a raw pyodbc.ProgrammingError, not
    a clean empty result (confirmed against a live DB). Checked here, once, so
    every id-keyed lookup gets a "not found" instead of a 500.
    """
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def load_session(sess: Session, session_id: str) -> RowMapping | None:
    """Load a session by id WITHOUT an entity filter — the API then checks the
    row's EntityID is in the caller's authorized set ([R2] object-level authz).
    """
    if not _valid_guid(session_id):
        return None
    return sess.execute(
        select(m.Scenario_Session.__table__).where(m.Scenario_Session.SessionID == session_id)
    ).mappings().first()


def get_session(sess: Session, session_id: str, entity_id: str) -> RowMapping | None:
    """Fetch a session **only within the caller's entity** — the data-layer IDOR
    guard (INV-1): another entity's session is invisible even with a valid token.
    """
    if not _valid_guid(session_id):
        return None
    return sess.execute(
        select(m.Scenario_Session.__table__).where(
            m.Scenario_Session.SessionID == session_id,
            m.Scenario_Session.EntityID == str(entity_id),
        )
    ).mappings().first()


def complete_session(sess: Session, session_id: str) -> bool:
    """Accept path: flip to completed/APPROVED — this releases the M4 lock.

    CAS-fenced on `SessionStatus == active` (same discipline as every other
    state-transition write in this file — claim_stage/acquire_lock/release_lock/
    finish_stage): returns True iff THIS call made the transition, False if the
    session was no longer active (already completed/cancelled by a concurrent
    writer, or the id doesn't exist) — a lost race the caller must surface, never
    a silent overwrite of whatever the other writer already committed.
    """
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == session_id,
            m.Scenario_Session.SessionStatus == SessionStatus.active)
        .values(
            SessionStatus=SessionStatus.completed,
            CurrentStage=WorkflowStage.APPROVED,
            CompletedAt=now(),
            UpdatedAt=now(),
        )
    )
    return res.rowcount == 1


def cancel_session(sess: Session, session_id: str) -> bool:
    """Cancel/reaper path → cancelled (also releases the M4 lock). Mirrors
    `complete_session`'s pattern: CurrentStage/StageStatus move to a real terminal
    value too, not just SessionStatus — otherwise the board keeps showing the stale
    pre-cancel stage forever (e.g. AWAITING_DECISION on a session that's actually dead).

    Same CAS fencing as `complete_session`: only a session still `active` can be
    cancelled. Returns True iff this call made the transition, False if it was
    already terminal (or never existed) — the caller must treat that as a
    conflict, not silently flip an already-completed/-cancelled session.
    """
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == session_id,
            m.Scenario_Session.SessionStatus == SessionStatus.active)
        .values(SessionStatus=SessionStatus.cancelled, CurrentStage=WorkflowStage.CANCELLED,
                StageStatus=StageStatus.CANCELLED, UpdatedAt=now())
    )
    return res.rowcount == 1


# ---------------------------------------------------------------------------
# Admission control — backpressure + idempotent create
# ---------------------------------------------------------------------------
def count_active_sessions(sess: Session) -> int:
    """Index-only-scan COUNT against the filtered `IX_Session_Active` index — never
    touches the base table. Deliberately racy under concurrency: a soft backpressure
    ceiling only needs to protect an already-saturated system, not be exact — unlike
    the M4 per-asset lock, which IS a correctness invariant and must never be racy.
    """
    return sess.execute(
        select(func.count()).select_from(m.Scenario_Session)
        .where(m.Scenario_Session.SessionStatus == SessionStatus.active)
    ).scalar() or 0


def count_active_sessions_for_entity(sess: Session, entity_id: str) -> int:
    """Same racy-by-design soft count as count_active_sessions above, scoped to one entity —
    backs the per-entity cap in assert_capacity_available so one entity looping session
    creation can't silently exhaust the global ceiling for every other entity in the tenant."""
    return sess.execute(
        select(func.count()).select_from(m.Scenario_Session)
        .where(m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.EntityID == entity_id)
    ).scalar() or 0


def assert_capacity_available(sess: Session, entity_id: str | None = None) -> None:
    """Raise CapacityExceeded if the active-session ceiling is at/over
    `max_active_sessions`. Checked before the more expensive `gather_asset_details`.

    [REVIEW-FIX] also enforces a per-entity ceiling (`max_active_sessions_per_entity`, 0 =
    disabled) when `entity_id` is given — without this, any single entity with a valid JWT
    could create sessions in a loop and starve every other entity in the tenant of the entire
    global ceiling with no isolation between them."""
    per_entity_cap = get_settings().max_active_sessions_per_entity
    if entity_id and per_entity_cap:
        # One round trip for both counts (same filtered IX_Session_Active index) instead of two
        # separate SELECT COUNT(*) calls — count_active_sessions()/count_active_sessions_for_entity()
        # stay as-is for their other standalone callers (e.g. selfcheck.py).
        total, entity_total = sess.execute(
            select(
                func.count(),
                func.sum(case((m.Scenario_Session.EntityID == entity_id, 1), else_=0)),
            ).select_from(m.Scenario_Session)
            .where(m.Scenario_Session.SessionStatus == SessionStatus.active)
        ).one()
        if total >= get_settings().max_active_sessions:
            raise CapacityExceeded()
        if (entity_total or 0) >= per_entity_cap:
            raise CapacityExceeded()
        return
    if count_active_sessions(sess) >= get_settings().max_active_sessions:
        raise CapacityExceeded()


def reserve_idempotency_key_or_get_existing(
    sess: Session, entity_id: str, idempotency_key: str, asset_id: str,
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
    racing requests need NOT share (EntityID, AssetID).
    """
    row = sess.execute(
        select(m.Scenario_Session.SessionID, m.Scenario_Session.AssetID)
        .where(m.Scenario_Session.EntityID == entity_id,
            m.Scenario_Session.IdempotencyKey == idempotency_key)
    ).mappings().first()
    if row is None:
        return None, False
    # Second value is True only when the existing row used this key for a DIFFERENT asset —
    # that's the "reused key, different payload" conflict case the caller must reject.
    return row["SessionID"], row["AssetID"] != asset_id


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

    Paired with `finish_stage`, which fences the exit on this same (epoch, task_id).

    This primitive intentionally does NOT check `_LOCK` ownership — it's usable standalone
    (poison-loop/redelivery tests exercise it directly, with no `_LOCK` row staged at all).
    A caller that must not resume work after losing the `_LOCK` mutex mid-flight needs its
    own explicit `holds_lock` check — see `write_scenarios`' `require_lock` param, which is
    exactly that: the gap this alone can't close is a zombie claiming a stage this row's
    *sibling* level never even touched (so no epoch/task_id fencing on THAT row applies yet).
    """
    s = get_settings()
    _now = now()  # one instant for lease/heartbeat/updated — three now() calls drift apart
    res = execute_dml(
        sess,
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == level,
            m.Subsystem_Stage_State.GenerationEpoch == epoch,
            m.Subsystem_Stage_State.AttemptCount < s.stage_max_attempts,
            # Claimable if the row is fresh/failed (IDLE/ERROR), OR it's already RUNNING but
            # owned by this same task (so a retry of our own in-flight attempt can resume it).
            or_(
                m.Subsystem_Stage_State.Status.in_([StageStatus.IDLE, StageStatus.ERROR]),
                and_(m.Subsystem_Stage_State.ActiveTaskID == task_id,
                    m.Subsystem_Stage_State.Status == StageStatus.RUNNING),
            ),
        )
        .values(
            Status=StageStatus.RUNNING,
            ActiveTaskID=task_id,
            LeaseExpiresAt=_now + timedelta(seconds=s.stage_lease_seconds),
            HeartbeatAt=_now,
            AttemptCount=m.Subsystem_Stage_State.AttemptCount + 1,
            UpdatedAt=_now,
        )
    )
    return res.rowcount == 1


def stage_attempt_count(
    sess: Session, session_id: str, subsystem_id: int, level: SubsystemLevel, epoch: int,
) -> int:
    """Read back the AttemptCount `claim_stage` just incremented for this stage row.
    `1` means this is the very first successful claim of this epoch (a fresh run);
    `>1` means a resumed/redelivered claim at the same epoch (`AttemptCount` resets to 0
    on every `reset_stage_for_regen` and increments on EVERY successful claim, including
    the mid-flight-resume branch). `write_scenarios` gates its once-per-epoch supersede
    on this, so a Celery retry never re-supersedes rows the failed attempt already
    committed. Deliberately a separate read, not a `claim_stage` return-value change —
    that signature ripples through every claim call site for a value only one needs."""
    return sess.execute(
        select(m.Subsystem_Stage_State.AttemptCount).where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == level,
            m.Subsystem_Stage_State.GenerationEpoch == epoch,
        )
    ).scalar() or 0


def holds_lock(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """True iff `task_id` currently holds this subsystem's `_LOCK` row (RUNNING, owned by
    it). A stalled worker whose lease expired has this reclaimed by the reaper out from
    under it — checking this right before resuming multi-step work catches that without
    needing every downstream `claim_stage` call to carry its own `_LOCK` check (see
    `write_scenarios`'s `require_lock` param, the one place this is actually needed)."""
    return sess.execute(
        select(1).select_from(m.Subsystem_Stage_State)
        .where(m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == SubsystemLevel.LOCK,
            m.Subsystem_Stage_State.Status == StageStatus.RUNNING,
            m.Subsystem_Stage_State.ActiveTaskID == task_id)
    ).first() is not None


def acquire_lock(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """Compare-and-set on the `_LOCK` row — serialises work on one subsystem.
    Only one caller can flip IDLE→RUNNING; returns True iff we hold it. A lease is
    set so the reaper can reclaim it if the holder dies.
    """
    s = get_settings()
    # A lock may only be taken while the owning session is still 'active'. This closes the
    # race where a redelivered task (or the reaper) resumes/mutates a session that was
    # concurrently cancelled/completed — the _LOCK row is the mutex, this is its session gate.
    session_active = (
        select(1)
        .where(m.Scenario_Session.SessionID == session_id,
            m.Scenario_Session.SessionStatus == SessionStatus.active)
        .exists()
    )
    res = execute_dml(
        sess,
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == SubsystemLevel.LOCK,
            m.Subsystem_Stage_State.Status == StageStatus.IDLE,
            session_active,
        )
        .values(
            Status=StageStatus.RUNNING, ActiveTaskID=task_id,
            LeaseExpiresAt=now() + timedelta(seconds=s.stage_lease_seconds), UpdatedAt=now(),
        )
    )
    return res.rowcount == 1


def release_lock(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """Flip the `_LOCK` row back to IDLE — but ONLY if we still hold it. Returns True
    iff the release landed; False means the lock was taken from us while we worked.

    Winning `acquire_lock` does NOT prove ownership *later*. A holder that stalls past
    its lease has the lock reclaimed to IDLE by the reaper (reaper.py step 2) and
    immediately re-taken by the reaper's own finalize or by a redelivered task. An
    unconditional release would then free a lock belonging to that new owner, putting
    two writers on one subsystem — precisely the [R5] mutual exclusion the `_LOCK` row
    exists to enforce. Fencing on `ActiveTaskID` makes a stale holder's release a no-op.
    """
    res = execute_dml(
        sess,
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == SubsystemLevel.LOCK,
            m.Subsystem_Stage_State.Status == StageStatus.RUNNING,
            m.Subsystem_Stage_State.ActiveTaskID == task_id,  # fencing token
        )
        # Clear the lease too: a released lock holds no lease, so the reaper's "any live
        # lease?" liveness check never mistakes a freed lock for a running worker.
        .values(Status=StageStatus.IDLE, ActiveTaskID=None, LeaseExpiresAt=None, UpdatedAt=now())
    )
    return res.rowcount == 1


def renew_lease(sess: Session, session_id: str, subsystem_id: int, level: SubsystemLevel,
                epoch: int, task_id: str) -> bool:
    """Push a held stage's lease forward — call this before a long operation (an LLM call)
    so a still-alive worker's claim doesn't expire and get reaped out from under it mid-work.
    `claim_stage` sets the lease once; a stage that makes several long calls in a row
    (write_scenarios, one per selected threat) can otherwise outlive it under entirely normal
    latency, not just a crash. Fenced on (epoch, task_id, Status==RUNNING) — same discipline as
    `finish_stage` — so a zombie that already lost the claim can never resurrect it by renewing
    a lease it no longer legitimately holds. Best-effort: a caller that gets False back should
    let the existing `finish_stage` fencing at the end of its own work catch the lost claim,
    exactly as it always has, rather than treat this as a new distinct failure to handle.
    """
    s = get_settings()
    _now = now()
    res = execute_dml(
        sess,
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == level,
            m.Subsystem_Stage_State.GenerationEpoch == epoch,
            m.Subsystem_Stage_State.ActiveTaskID == task_id,
            m.Subsystem_Stage_State.Status == StageStatus.RUNNING,
        )
        .values(LeaseExpiresAt=_now + timedelta(seconds=s.stage_lease_seconds), HeartbeatAt=_now, UpdatedAt=_now)
    )
    return res.rowcount == 1


def finish_stage(
    sess: Session, session_id: str, subsystem_id: int, level: SubsystemLevel,
    status: StageStatus, epoch: int, task_id: str, error: str | None = None,
) -> bool:
    """Terminal transition OUT of a stage — the exit half of `claim_stage`'s CAS, fenced
    on the same (epoch, task_id) identity. Only the worker that still owns THIS
    generation of the row may record its outcome. Returns True iff the write landed.

    Unfenced, a stalled worker's late result overwrites whatever replaced it. Two ways
    that bites, both observed:
      * the reaper flips an abandoned RUNNING row to ERROR; the zombie wakes and stamps
        COMPLETE back over it, so a dead session reports success;
      * a regeneration resets the row to a fresh claimable IDLE at epoch N+1; the
        epoch-N zombie stamps AWAITING_DECISION over it, after which the epoch-N+1 task
        can never claim it (`claim_stage` refuses a non-IDLE/ERROR row) and the
        subsystem serves its stale scenarios as though they were the regenerated ones.

    `LeaseExpiresAt` is cleared on the way out: the lease means "someone is actively
    RUNNING this right now", so every transition away from RUNNING must drop it, or a
    long-finished row carries a stale lease and the reaper's `dead_lease` check fires on
    a session that simply left REVIEW for a routine regeneration.
    """
    res = execute_dml(
        sess,
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == level,
            m.Subsystem_Stage_State.GenerationEpoch == epoch,   # fencing token: our generation
            m.Subsystem_Stage_State.ActiveTaskID == task_id,    # fencing token: our claim
            m.Subsystem_Stage_State.Status == StageStatus.RUNNING,
        )
        .values(Status=status, ErrorMessage=error, LeaseExpiresAt=None, UpdatedAt=now())
    )
    return res.rowcount == 1


def stage_completed_at_epoch_or_newer(
    sess: Session, session_id: str, subsystem_id: int, level: SubsystemLevel, epoch: int,
) -> bool:
    """True iff this subsystem's `level` stage row is COMPLETE at GenerationEpoch >= `epoch`.
    run_next_set gates its additive reset+find_threats on this: skip re-running the additive only
    when it has actually FINISHED (COMPLETE) at the reserved epoch — OR the row has already ADVANCED
    to a NEWER epoch (a stale broker redelivery whose reserved epoch is BEHIND the live one;
    re-entering is then a harmless no-op, since reset_stage_for_regen/claim_stage/finish_stage all
    fence on the exact epoch and match nothing).

    The COMPLETE requirement is the fix for a session-wedge bug: a status-agnostic epoch-only check
    also returned True for a row left RUNNING at `epoch` by a prior attempt that FAILED before
    finish_stage (e.g. an LLMSlotUnavailable capacity squeeze). The Celery retry then skipped the
    additive block entirely, leaving THREATS stuck RUNNING so decide_session_outcome wedged the
    session until the reaper. Requiring COMPLETE makes the retry re-enter: find_threats' claim_stage
    resumes the RUNNING row it still owns (same task_id) and finish_stage drives THREATS terminal."""
    live = sess.execute(
        select(m.Subsystem_Stage_State.GenerationEpoch).where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == level,
            m.Subsystem_Stage_State.Status == StageStatus.COMPLETE,
        )
    ).scalar()
    return live is not None and live >= epoch


def stage_settled_at_epoch(
    sess: Session, session_id: str, subsystem_id: int, level: SubsystemLevel, epoch: int,
) -> bool:
    """True iff this subsystem's `level` stage row is at `epoch` and already terminal-reviewable
    (AWAITING_DECISION or COMPLETE). run_next_set / run_regeneration use it to tell an idempotent
    redelivery of an already-landed batch (write_scenarios' claim_stage correctly no-op'd a row
    already AWAITING_DECISION and returned []) apart from a genuine lost claim — the former must
    fall through to decide_session_outcome, NOT raise + fire a spurious error SSE."""
    return sess.execute(
        select(1).select_from(m.Subsystem_Stage_State).where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == level,
            m.Subsystem_Stage_State.GenerationEpoch == epoch,
            m.Subsystem_Stage_State.Status.in_([StageStatus.AWAITING_DECISION, StageStatus.COMPLETE]),
        )
    ).first() is not None


def stage_rows(sess: Session, session_id: str) -> list[RowMapping]:
    """Per-subsystem stage rows for the status board (§6.1), excluding `_LOCK`.
    `ErrorMessage` rides along so the board can surface a partial/failed run's client-safe
    reason — in particular an AWAITING_DECISION row revived by the salvage path keeps its
    message as the "this review set may be partial" marker (see
    revive_errored_scenarios_to_review)."""
    return list(
        sess.execute(
            select(
                m.Subsystem_Stage_State.SubsystemID,
                m.Subsystem_Stage_State.Level,
                m.Subsystem_Stage_State.Status,
                m.Subsystem_Stage_State.ErrorMessage,
            ).where(
                m.Subsystem_Stage_State.SessionID == session_id,
                m.Subsystem_Stage_State.Level != SubsystemLevel.LOCK,
            )
        ).mappings()
    )


def subsystem_ids_at_level(
    sess: Session, session_id: str, level: SubsystemLevel, status: StageStatus | None = None,
) -> list[int]:
    """Every SubsystemID for this session at a given Subsystem_Stage_State Level,
    optionally narrowed to a specific Status (e.g. accept's REVIEW-barrier check:
    which subsystems are `_LOCK`ed, or which reached `SCENARIOS`/`AWAITING_DECISION`)."""
    where = [m.Subsystem_Stage_State.SessionID == session_id, m.Subsystem_Stage_State.Level == level]
    # Only filter by Status if the caller actually asked for one; otherwise return all statuses.
    if status is not None:
        where.append(m.Subsystem_Stage_State.Status == status)
    return [r[0] for r in sess.execute(select(m.Subsystem_Stage_State.SubsystemID).where(*where)).all()]


def subsystem_has_pending_work(sess: Session, session_id: str, subsystem_id: int) -> bool:
    """True iff any non-_LOCK stage for this subsystem is IDLE or RUNNING — i.e.
    genuinely unstarted or resumable. False means every stage already reached a
    terminal state (COMPLETE/AWAITING_DECISION/ERROR): re-checking this asset unit is just
    confirming already-finished work (e.g. a Celery redelivery re-invoking
    `_process_all_supporting_systems` re-attempts the same single asset-level pass even though
    a prior, committed attempt already finished it) — used to gate the one-time
    `subsystem_advanced` signal so a redelivery doesn't re-announce work nothing is actually
    about to happen to."""
    return sess.execute(
        select(1).where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level != SubsystemLevel.LOCK,
            m.Subsystem_Stage_State.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]),
        )
    ).first() is not None


# ---------------------------------------------------------------------------
# Regeneration (per-(subsystem, level) generation epoch bump
# ---------------------------------------------------------------------------
def next_epoch(sess: Session, session_id: str, subsystem_id: int, levels: tuple) -> int:
    """max(GenerationEpoch) scoped to ONLY the levels touched in this regen hop, +1.
    Deliberately narrower than a subsystem-wide max: an untouched level's epoch
    lineage is never disturbed by an unrelated regen (e.g. regenerating SCENARIOS
    doesn't bump THREATS' epoch number)."""
    current = sess.execute(
        select(func.max(m.Subsystem_Stage_State.GenerationEpoch)).where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level.in_(levels),
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
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level.in_(levels),
            # Epoch fence (mirrors claim_stage/finish_stage): only ever move a row FORWARD. next_epoch
            # is max+1, so a live endpoint reset always passes; the fence exists to make a STALE
            # in-task reset (a redelivery whose reserved epoch is behind the live one) a no-op rather
            # than let it downgrade the row backward and invert the epoch lineage.
            m.Subsystem_Stage_State.GenerationEpoch < new_epoch,
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
            "catalogue_id": r["ThreatCatalogueID"],  # keeps _dedup_key/IdentityHash identical to a full run's (find_threats) on regen
        }
        for r in sess.execute(
            select(m.Identified_Threat.ThreatID, m.Identified_Threat.GroundingStatus,
                m.Identified_Threat.ThreatType, m.Identified_Threat.ThreatName,
                m.Identified_Threat.LibraryThreatType, m.Identified_Threat.LibraryThreatName,
                m.Identified_Threat.ThreatTypeID, m.Identified_Threat.ThreatCatalogueID).where(
                m.Identified_Threat.SessionID == session_id,
                m.Identified_Threat.SubsystemID == subsystem_id,
                m.Identified_Threat.Superseded == 0,
            )
        ).mappings()
    ]


def has_active_scenarios(sess: Session, session_id: str) -> bool:
    """True iff the session has any active (Superseded=0) Threat_Scenario_Output row. decide_session_
    outcome uses it to keep a session whose stage ERROR'd but whose earlier accumulated batches left
    salvageable scenarios in REVIEW instead of cancelling — a transient next-set/regen failure must
    never destroy already-committed, reviewable work (mirrors the multi-subsystem partial-success
    rule for the single-subsystem case)."""
    return sess.execute(
        select(1).select_from(m.Threat_Scenario_Output).where(
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.Superseded == 0,
            # complete only: a FAILURE CARD (Status=error, null scenario — see tasks.py's
            # _build_error_output_row) is retryable, not reviewable; counting it here would
            # salvage a session that has nothing to review.
            m.Threat_Scenario_Output.Status == ScenarioStatus.complete,
        )
    ).first() is not None


def revive_errored_scenarios_to_review(sess: Session, session_id: str) -> int:
    """Restore the board invariant "session at REVIEW/AWAITING_DECISION => >=1 subsystem SCENARIOS
    row at AWAITING_DECISION". decide_session_outcome's salvage branch (a stage ERROR'd but earlier
    accumulated batches left active, reviewable scenarios) moves the SESSION row to REVIEW but leaves
    the per-subsystem SCENARIOS stage row ERROR — so accept's good_subs (SCENARIOS @ AWAITING_DECISION)
    comes back empty, mark_scenarios_accepted matches 0 rows, and the session completes having
    accepted nothing (silent data loss). Flip the ERRORed SCENARIOS row (in place, at its current
    epoch) of every subsystem that still has an active Threat_Scenario_Output back to
    AWAITING_DECISION so accept sees it. Returns the number of subsystem rows revived.

    `ErrorMessage` is deliberately PRESERVED (not cleared): a revived row means the run failed
    mid-batch after committing some scenarios — the surviving message is the only durable marker
    telling a reviewer (via the status board) that this review set may be PARTIAL, not a complete
    run. Wiping it here made a truncated run indistinguishable from a finished one."""
    active_subs = (
        select(m.Threat_Scenario_Output.SubsystemID)
        .where(m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.Superseded == 0,
            # complete only — a subsystem holding nothing but failure cards has nothing to
            # review, so reviving its stage would break the very invariant this restores
            m.Threat_Scenario_Output.Status == ScenarioStatus.complete)
    )
    res = execute_dml(
        sess,
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.Level == SubsystemLevel.SCENARIOS,
            m.Subsystem_Stage_State.Status == StageStatus.ERROR,
            m.Subsystem_Stage_State.SubsystemID.in_(active_subs),
        )
        .values(Status=StageStatus.AWAITING_DECISION, LeaseExpiresAt=None, UpdatedAt=now())
    )
    return res.rowcount


def subsystems_with_active_scenarios(sess: Session, session_id: str) -> set[int]:
    """Every SubsystemID in this session that still owns an active (Superseded=0)
    Threat_Scenario_Output row. accept_session compares this to good_subs so no subsystem's
    accumulated scenarios are silently dropped when its stage-state row is out of sync."""
    return set(sess.execute(
        select(m.Threat_Scenario_Output.SubsystemID)
        .where(m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.Superseded == 0,
            # complete only — accept-all's completeness check must not demand coverage of a
            # subsystem whose only active rows are unreviewable failure cards
            m.Threat_Scenario_Output.Status == ScenarioStatus.complete)
    ).scalars())


def _row_to_dedup_info(row) -> dict:
    """Map an Identified_Threat row onto the small dict tasks._dedup_key folds — the ONE shape the
    two dal identity callers rebuild from row columns."""
    return {"catalogue_id": row["ThreatCatalogueID"], "threat_type_id": row["ThreatTypeID"],
            "threat_type": row["ThreatType"], "threat_name": row["ThreatName"],
            "threat_id": row["ThreatID"]}


def identity_hash(session_id: str, subsystem_id: int, info: dict) -> str:
    """The ONE catalogue-level IdentityHash fold: sha256(SessionID|SubsystemID|_dedup_key(info)).
    Every producer/consumer of Threat_Scenario_Output.IdentityHash routes through here
    (tasks.find_threats, tasks._build_scenario_output_row, next_unserved_unique_threats,
    active_identified_threat_identities) so the app-level dedup and the UX_Scenario_ActiveIdentity
    index can never disagree. tasks._dedup_key is the folding rule; lazy-imported so app.db.dal
    (below app.pipeline) takes no load-time dependency on it (same trick reaper.py uses)."""
    from app.pipeline.tasks import _dedup_key
    return hashlib.sha256(f"{session_id}|{subsystem_id}|{_dedup_key(info)}".encode()).hexdigest()


def next_unserved_unique_threats(sess: Session, session_id: str, subsystem_id: int, n: int) -> list[str]:
    """Up to `n` active ThreatIDs for this (session, subsystem) whose catalogue-level dedup
    identity has NO active scenario yet — the pool the "generate next set" feature serves from
    before it falls back to a fresh AI batch. Best-first order (Scoped_Threat.Score desc, then
    ThreatID); a threat a fresh additive find_threats added but write_scenarios hasn't scored yet
    has a NULL score and sorts last (LEFT JOIN), but is still eligible so the very next call can
    serve it. Identity is folded EXACTLY like tasks._build_scenario_output_row's IdentityHash
    (sha256(SessionID|SubsystemID|dedup_key)), so "already shown" == an active
    Threat_Scenario_Output.IdentityHash. Two candidates sharing one identity in this same call
    collapse to the first (best-ranked) so a single call never proposes an internal duplicate."""
    active_hashes = set(sess.execute(
        select(m.Threat_Scenario_Output.IdentityHash).where(
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.SubsystemID == subsystem_id,
            m.Threat_Scenario_Output.Superseded == 0,
        )
    ).scalars())
    it, st = m.Identified_Threat, m.Scoped_Threat
    rows = sess.execute(
        select(it.ThreatID, it.ThreatCatalogueID, it.ThreatTypeID, it.ThreatType, it.ThreatName, st.Score)
        .select_from(it.__table__.join(
            st.__table__,
            and_(st.ThreatID == it.ThreatID, st.SessionID == session_id,
                st.SubsystemID == subsystem_id, st.Superseded == 0),
            isouter=True))
        .where(it.SessionID == session_id, it.SubsystemID == subsystem_id, it.Superseded == 0,
            # A threat with an ACTIVE Scoped_Threat that scoping REJECTED is only re-servable if it
            # was demoted purely by the top-N cutoff — target-mode re-scoring (top_n disabled) will
            # re-select it, so it's the legitimate "already-scored-but-unserved" pool this feature
            # serves first. A tech_gate / below-threshold rejection is PERMANENT (re-scoring fails
            # the same way), so re-serving it just churns a Selected=0 row and write_scenarios keeps
            # refusing it — the "no new threats" wedge. Keep: no scoped row yet (a fresh additive
            # find_threats threat), Selected=1, or a top-N-cutoff demote; drop the permanent zombies.
            or_(st.ScopedThreatID.is_(None), st.Selected == 1, st.Reason.like("beyond top-%")))
        # Score desc puts NULLs last on both SQLite and SQL Server (NULL sorts lowest); ThreatID
        # is a deterministic tie-break, matching scoping's own score-desc/id-asc convention.
        .order_by(st.Score.desc(), it.ThreatID)
    ).mappings()
    picked: list[str] = []
    seen: set[str] = set()
    for r in rows:
        identity = identity_hash(session_id, subsystem_id, _row_to_dedup_info(r))
        if identity in active_hashes or identity in seen:
            continue
        seen.add(identity)
        picked.append(r["ThreatID"])
        if len(picked) >= n:
            break
    return picked


def active_identified_threat_identities(sess: Session, session_id: str, subsystem_id: int) -> set[str]:
    """The set of folded catalogue-level identities (sha256(SessionID|SubsystemID|_dedup_key)) of
    this (session, subsystem)'s ACTIVE Identified_Threat rows. find_threats(supersede=False) uses it
    to skip inserting an additive proposal whose identity already matches a live threat — otherwise a
    coverage-aware round that re-proposes an already-present threat leaves a never-scored dead
    Identified_Threat row (the write_scenarios IdentityHash index would still block a duplicate
    scenario, but the leaked threat row lingers). Same folding rule as next_unserved_unique_threats."""
    identities: set[str] = set()
    for r in sess.execute(
        select(m.Identified_Threat.ThreatID, m.Identified_Threat.ThreatCatalogueID,
            m.Identified_Threat.ThreatTypeID, m.Identified_Threat.ThreatType, m.Identified_Threat.ThreatName)
        .where(m.Identified_Threat.SessionID == session_id,
            m.Identified_Threat.SubsystemID == subsystem_id,
            m.Identified_Threat.Superseded == 0)
    ).mappings():
        identities.add(identity_hash(session_id, subsystem_id, _row_to_dedup_info(r)))
    return identities


def active_threat_rules(sess: Session, threat_type_ids: list[int]) -> list[dict]:
    """Active scoping rules for the given grounded master types ([R12], SDD §5.4) — one
    query for the whole subsystem, ordered by ThreatRuleID so rule evaluation (and the
    FactorsJSON it records) is deterministic. Empty input → no query, no rules."""
    if not threat_type_ids:
        return []
    ct = m.Config_Threat_Rule
    return [dict(r) for r in sess.execute(
        select(ct.RuleType, ct.ThreatTypeID, ct.RuleKey, ct.RuleValue, ct.Metadata)
        .where(ct.ThreatTypeID.in_(threat_type_ids),
            ct.IsActive == True, ct.IsDeleted == False)  # noqa: E712 — SQLAlchemy binary expr
        .order_by(ct.ThreatRuleID)
    ).mappings()]


def active_category_names(sess: Session) -> list[str]:
    """Real STRIDE category names, read live so prompts.threats_prompt never drifts from
    Threat_Category — the same table grounding.find_category matches against. Empty result
    means the table isn't seeded yet; the caller falls back to a hardcoded default."""
    tc = m.Threat_Category
    return [r[0] for r in sess.execute(
        select(tc.ThreatCategoryName)
        .where(tc.IsActive == True, tc.IsDeleted == False)  # noqa: E712
        .order_by(tc.ThreatCategoryID)
    )]


def active_context_fields_by_group(sess: Session) -> dict[str, list[str]]:
    """Same live-read contract as active_context_fields below, but fetches BOTH the 'asset' and
    'subsystem' groups in one round-trip instead of two — every real caller (tasks.py) always
    needs both together per session, never just one. A group with no active rows comes back as
    an empty list, same "caller falls back to its hardcoded default" meaning as
    active_context_fields; a row under any OTHER ContextGroup value (e.g. a curator's typo) is
    silently excluded here too — same behavior active_context_fields already has when queried
    with an exact group name, and selfcheck.check_dead_context_fields is what surfaces that kind
    of drift to an operator, not this function."""
    cfc = m.Context_Field_Config
    by_group: dict[str, list[str]] = {"asset": [], "subsystem": []}
    for group, field in sess.execute(
        select(cfc.ContextGroup, cfc.FieldName)
        .where(cfc.IsActive == True, cfc.IsDeleted == False)  # noqa: E712
    ):
        if group in by_group:
            by_group[group].append(field)
    return by_group


def active_context_fields(sess: Session, context_group: str) -> list[str]:
    """Field names a curator has currently turned ON for the AI prompt (Context_Field_Config).
    The caller (prompts.py) intersects this with its own hardcoded ceiling before using it —
    this function returns whatever's active in the DB, unrestricted; it never decides on its own
    what's safe to send to an external model. Empty result means the table isn't seeded yet, or
    every row for this group is off; the caller falls back to its hardcoded default either way.
    Prefer active_context_fields_by_group above when both groups are needed at once (every real
    caller) — this single-group form exists for direct/test callers that only want one."""
    cfc = m.Context_Field_Config
    return [r[0] for r in sess.execute(
        select(cfc.FieldName)
        .where(cfc.ContextGroup == context_group, cfc.IsActive == True, cfc.IsDeleted == False)  # noqa: E712
    )]


def active_actor_names(sess: Session) -> list[str]:
    """Real Threat_Actor names, read live so prompts.threats_prompt never drifts from the
    table grounding.get_allowed_actor_names matches proposed actors against by exact string.
    Empty result means the table isn't seeded yet; the caller falls back to a hardcoded default."""
    ta = m.Threat_Actor
    return [r[0] for r in sess.execute(
        select(ta.ThreatActorName)
        .where(ta.IsActive == True, ta.IsDeleted == False)  # noqa: E712
        .order_by(ta.ThreatActorName)
    )]


def latest_completed_session(sess: Session, entity_id: str, asset_id: str) -> RowMapping | None:
    """The asset's most recent COMPLETED session — the downstream contract's "current
    accepted truth" ([R13]): older completed sessions' rows are never cross-session
    superseded, so without this scope a consumer would ingest stale generations
    alongside current ones. Entity filter lives here in the DAL (INV-1)."""
    return sess.execute(
        select(m.Scenario_Session.__table__)
        .where(m.Scenario_Session.EntityID == str(entity_id),
            m.Scenario_Session.AssetID == str(asset_id),
            m.Scenario_Session.SessionStatus == SessionStatus.completed)
        # SessionID tie-break: two sessions completing in the same clock tick must
        # still yield ONE deterministic "current" pick (same convention as scoping's
        # score-desc/id-asc ordering) — never a query-plan-dependent answer.
        .order_by(m.Scenario_Session.CompletedAt.desc(), m.Scenario_Session.SessionID)
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
        select(out.OutputID, out.SubsystemID, out.ScopedThreatID, out.ScenarioJSON,
            it.ThreatTypeID, it.ThreatCatalogueID, it.ThreatType, it.ThreatName,
            it.LibraryThreatType, it.LibraryThreatName)
        .select_from(out.__table__.join(st, out.ScopedThreatID == st.ScopedThreatID)
                    .join(it, st.ThreatID == it.ThreatID))
        .where(out.SessionID == session_id, out.Accepted == 1, out.Superseded == 0)
        .order_by(out.SubsystemID, out.OutputID)
    ).mappings()]


def mark_scenarios_accepted(
    sess: Session, session_id: str, subsystem_ids: list[int], subset: list[str] | None = None,
) -> int:
    """Sets Accepted=1 on every non-superseded scenario for these subsystems (accept, §5.7),
    optionally narrowed to `subset` OutputIDs ([R8] partial accept — `subset=[]` means
    "accept none", distinct from `subset=None` meaning "accept all").

    Also stamps `AcceptedSubsetJSON` with the exact `subset` list on every row this call
    touches, but ONLY for a partial accept (`subset is not None`) — NULL on a full accept,
    since "the whole session" isn't itself a subset selection; this keeps the column's meaning
    precise ("non-NULL" = this row was part of an explicit partial pick) and mirrors, per row,
    what `Scenario_Audit.DetailJSON` already records once for the decision as a whole
    (`accept.accept_session`'s `DetailJSON=json.dumps({"subset": subset})`), so a reviewer can
    see which explicit selection accepted a given row without a join. Was previously a dead
    column — see TSG_Gap_Analysis.md §13.10.

    Returns the number of rows actually flipped. A `subset` id that doesn't match any
    row here (wrong session/subsystem, already superseded, or simply never existed)
    previously vanished silently — this return value is what lets the caller
    (`accept.accept_session`) tell "N requested, N matched" apart from "N requested,
    M<N matched" instead of reporting a clean accept either way."""
    where = [m.Threat_Scenario_Output.SessionID == session_id, m.Threat_Scenario_Output.Superseded == 0,
            m.Threat_Scenario_Output.SubsystemID.in_(subsystem_ids),
            # complete only: a FAILURE CARD (null scenario) must never be marked Accepted — it
            # would flow to downstream consumers as an accepted scenario with no content. A
            # subset explicitly naming one simply doesn't match, and the caller's existing
            # requested-vs-matched check reports it as not-acceptable (404).
            m.Threat_Scenario_Output.Status == ScenarioStatus.complete]
    # Narrow to specific OutputIDs only if the caller passed a subset; None means "accept all".
    if subset is not None:
        where.append(m.Threat_Scenario_Output.OutputID.in_(subset))
    accepted_subset_json = json.dumps(subset) if subset is not None else None
    res = execute_dml(sess, update(m.Threat_Scenario_Output).where(*where)
                    .values(Accepted=1, AcceptedSubsetJSON=accepted_subset_json))
    return res.rowcount


# ---------------------------------------------------------------------------
# Generic write helpers
# ---------------------------------------------------------------------------
def _delete_control_maps_for_superseded(sess: Session, session_id: str) -> None:
    """Invariant: a superseded output owns no control-map rows. Enforced HERE, at the moment
    of superseding (every supersede path below calls this), so dead map rows can't accumulate —
    a superseded scenario is unreachable through the API and its regenerated successor gets a
    fresh mapping, so its old map rows are pure dead weight. Idempotent by construction
    (deleting for already-superseded outputs again matches nothing)."""
    superseded = select(m.Threat_Scenario_Output.OutputID).where(
        m.Threat_Scenario_Output.SessionID == session_id,
        m.Threat_Scenario_Output.Superseded == 1,
    )
    sess.execute(
        delete(m.Threat_Scenario_Control_Map)
        .where(m.Threat_Scenario_Control_Map.SessionID == session_id,
               m.Threat_Scenario_Control_Map.OutputID.in_(superseded))
    )


def supersede(sess: Session, table, session_id: str, subsystem_id: int) -> None:
    """Mark the active rows of a (session, subsystem) as superseded (§5.8)."""
    sess.execute(
        update(table)
        .where(
            table.SessionID == session_id,
            table.SubsystemID == subsystem_id,
            table.Superseded == 0,
        )
        .values(Superseded=1)
    )
    if table is m.Threat_Scenario_Output:
        _delete_control_maps_for_superseded(sess, session_id)


def active_scoped_threat_ids(sess: Session, session_id: str, subsystem_id: int, threat_ids) -> list[str]:
    """Every current active ScopedThreatID for a SET of ThreatIDs in ONE query — used by
    `write_scenarios`'s multi-target regen path so an up-to-`_MAX_BATCH` target list
    doesn't do one SELECT per id."""
    if not threat_ids:
        return []
    return list(sess.execute(
        select(m.Scoped_Threat.ScopedThreatID).where(
            m.Scoped_Threat.SessionID == session_id,
            m.Scoped_Threat.SubsystemID == subsystem_id,
            m.Scoped_Threat.ThreatID.in_(threat_ids),
            m.Scoped_Threat.Superseded == 0,
        )
    ).scalars().all())


def threats_with_active_scenario(sess: Session, session_id: str, subsystem_id: int, threat_ids) -> set[str]:
    """The subset of `threat_ids` that already have an active (Superseded=0) Threat_Scenario_Output
    (joined to it via Scoped_Threat.ScopedThreatID — the stable GUID link, resolved even if the
    scoped row itself was later superseded). write_scenarios keys its next-set cleanup on this, NOT
    on "has an active scoped row": a genuine REGEN target keeps its active scenario (leave it
    untouched); a POOL ZOMBIE — a previously-served pool threat that rescored OUT after a mid-session
    tech_gate/threshold tightening — still has its old active Selected=1/'beyond top-%' scoped row but
    NO active scenario, so it lands in the marker set and gets superseded + re-marked Selected=0
    instead of being re-served on every subsequent click."""
    if not threat_ids:
        return set()
    st, out = m.Scoped_Threat, m.Threat_Scenario_Output
    # Seek IX_ScenarioOutput_SessionSubActive: predicate `out` on the SAME (session, subsystem) as
    # `st` so this never scans active scenarios from other sessions/tenants. Result-preserving — an
    # output row always carries its scoped row's SessionID/SubsystemID.
    return set(sess.execute(
        select(st.ThreatID)
        .select_from(st.__table__.join(out, out.ScopedThreatID == st.ScopedThreatID))
        .where(st.SessionID == session_id, st.SubsystemID == subsystem_id,
            st.ThreatID.in_(threat_ids),
            out.SessionID == session_id, out.SubsystemID == subsystem_id, out.Superseded == 0,
            # complete only: a threat whose only active row is a FAILURE CARD is NOT "done" —
            # a resumed attempt must retry it (write_scenarios' already_done), and the next-set
            # marker sweep must treat it like any other unserved threat
            out.Status == ScenarioStatus.complete)
    ).scalars())


def supersede_by_threats(sess: Session, table, session_id: str, subsystem_id: int, threat_ids) -> None:
    """Every active row (Identified_Threat/Scoped_Threat) whose ThreatID is in the
    requested set — one UPDATE, not a loop."""
    if not threat_ids:
        return
    sess.execute(
        update(table)
        .where(
            table.SessionID == session_id,
            table.SubsystemID == subsystem_id,
            table.ThreatID.in_(threat_ids),
            table.Superseded == 0,
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
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.SubsystemID == subsystem_id,
            m.Threat_Scenario_Output.ScopedThreatID.in_(scoped_threat_ids),
            m.Threat_Scenario_Output.Superseded == 0,
        )
        .values(Superseded=1)
    )
    _delete_control_maps_for_superseded(sess, session_id)


def supersede_by_identity_hashes(sess: Session, session_id: str, subsystem_id: int, identity_hashes) -> None:
    """Every active Threat_Scenario_Output row in this (session, subsystem) whose IdentityHash is
    in the requested set — one UPDATE, not a loop. Used by `write_scenarios`' regen path to clear
    any already-active row that folds to the same catalogue-level dedup key before inserting the
    regenerated one, so the filtered `UX_Scenario_ActiveIdentity(SessionID, IdentityHash)` unique
    index can't collide (regen skips `_select_unique_top_n`, so nothing else guarantees the folded
    hashes are unique). Same shape as `supersede_by_scoped_threats` above."""
    if not identity_hashes:
        return
    sess.execute(
        update(m.Threat_Scenario_Output)
        .where(
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.SubsystemID == subsystem_id,
            m.Threat_Scenario_Output.IdentityHash.in_(identity_hashes),
            m.Threat_Scenario_Output.Superseded == 0,
        )
        .values(Superseded=1)
    )
    _delete_control_maps_for_superseded(sess, session_id)


def insert_row(sess: Session, table, values: Mapping[str, Any]) -> None:
    """Generic single-row insert shared by callers writing a new active record
    (threat/scenario output) — no active-row or Superseded handling of its
    own, callers are expected to `supersede` the prior row first."""
    sess.execute(insert(table).values(**values))


def audit_row(sess: Session, **cols: Any) -> dict[str, Any]:
    """One Scenario_Audit row with CreatedAt, ActorUserID and ActorType defaulted.

    `ActorUserID` = WHO IS ACCOUNTABLE for this session, not "who typed the command". A caller
    that knows the acting human passes it (session_started/cancel/accept); every other row —
    grounding_summary, scoping_complete, generation_complete, entered_review, stage_error,
    regeneration_completed — is written by a background worker minutes later with no human in
    the call stack, and used to land NULL. An auditor then had to know to join
    Scenario_Session.UserID to answer "who is answerable for this?", and a NULL read as missing
    data rather than "not applicable".

    `ActorType` answers the question the back-fill above destroys: once every row names a user,
    "gopal accepted this" and "the pipeline did this, gopal is answerable" look identical. So it
    is decided from whether the CALLER named a human, before the back-fill runs.

    Defaulting HERE, not at the 13 call sites, is the point: a future audit write cannot forget
    it. Costs one primary-key lookup per audited event (~6-10 per session) and only when the
    caller supplied nothing.
    # ponytail: per-write PK lookup; pass ActorUserID explicitly from an in-hand session dict
    # if audit volume ever makes it measurable."""
    cols.setdefault("CreatedAt", now())
    # Order matters: after the back-fill below, ActorUserID is populated either way and "did a
    # human do this?" is no longer answerable. setdefault so an explicit caller value still wins.
    cols.setdefault("ActorType", ActorType.user if cols.get("ActorUserID") else ActorType.system)
    if cols.get("ActorUserID") is None and cols.get("SessionID"):
        cols["ActorUserID"] = sess.execute(
            select(m.Scenario_Session.UserID)
            .where(m.Scenario_Session.SessionID == cols["SessionID"])
        ).scalar()
    return cols


def append_audit(sess: Session, **cols: Any) -> None:
    """Append-only audit write for ONE row. Callers accumulating many rows for a single bulk
    INSERT (accept.py's promotion loop) build them with `audit_row` instead and insert the list
    themselves — same defaults, one round trip. Two insert paths, ONE place that decides what an
    audit row means, so the bulk path cannot silently omit whatever this learns to default next."""
    sess.execute(insert(m.Scenario_Audit).values(**audit_row(sess, **cols)))


# ---------------------------------------------------------------------------
# Threat-library promotion — race-safe insert-if-not-exists,
# guarded by the M2 natural-key UNIQUE indexes (migration 0010). Same savepoint +
# catch-IntegrityError + select idiom as `create_session` above: two concurrent
# accepts proposing the identical new master lose the DB race deterministically,
# and the loser gets back the winner's id instead of a crash.
# ---------------------------------------------------------------------------
def upsert_threat_type(sess: Session, name: str, category_id: int | None, sector_id: int | None,
                    description: str | None = None, source: str = "ai_auto_promoted") -> int:
    """Insert-if-not-exists keyed by (ThreatTypeName, ThreatCategoryID, SectorID) —
    `UX_ThreatType_NaturalKey`. Returns the winning ThreatTypeID either way.

    `source` records provenance: the R10 promotion path (accept.py) relies on the default
    'ai_auto_promoted'; scripts/import_threat_libraries.py passes its per-library tag
    ('pytm', 'mitre_attack', ...). On a natural-key collision the existing row wins and
    keeps its original Source — provenance is first-writer, never overwritten."""
    # Bound to ThreatTypeName's real column width (Unicode(300)) before it ever reaches the
    # INSERT — an LLM-derived name that's too long raises a MSSQL truncation error (DataError),
    # a different exception class than the IntegrityError this function already catches for the
    # natural-key race, so an unbounded name would otherwise escape uncaught and abort the whole
    # accept-session transaction.
    name = name[:300]
    try:
        with sess.begin_nested():
            res = execute_dml(sess, insert(m.Threat_Type).values(
                ThreatTypeName=name, ThreatCategoryID=category_id, SectorID=sector_id,
                Description=description, IsActive=True, IsDeleted=False, Source=source))
        return inserted_pk(res)
    except IntegrityError:
        sector_pred = m.Threat_Type.SectorID.is_(None) if sector_id is None else m.Threat_Type.SectorID == sector_id
        winner = sess.execute(
            select(m.Threat_Type.ThreatTypeID).where(
                m.Threat_Type.ThreatTypeName == name,
                m.Threat_Type.ThreatCategoryID == category_id, sector_pred,
                m.Threat_Type.IsActive == True, m.Threat_Type.IsDeleted == False)
        ).scalar()
        if winner is None:  # not a natural-key duplicate (NOT NULL / missing IDENTITY /
            raise           # truncation / other violation) — fail loud, never return a NULL id
        return winner


def upsert_threat_catalogue(sess: Session, name: str, type_id: int, sector_id: int | None,
                            description: str | None = None, source: str = "ai_auto_promoted") -> int:
    """Insert-if-not-exists keyed by (ThreatTypeID, ThreatName, SectorID) —
    `UX_ThreatCatalogue_NaturalKey`. Returns the winning ThreatCatalogueID either way.

    Same `source` provenance contract as upsert_threat_type above. Does NOT link the new
    row into Threat_Catalogue_Category_Map — call link_catalogue_category separately once
    you have a category id, same two-step shape as upsert_threat_type + link_type_actor."""
    # See upsert_threat_type's identical comment — ThreatName's real column width is Unicode(500).
    name = name[:500]
    try:
        with sess.begin_nested():
            res = execute_dml(sess, insert(m.Threat_Catalogue).values(
                ThreatTypeID=type_id, ThreatName=name, SectorID=sector_id,
                Description=description, IsActive=True, IsDeleted=False, Source=source))
        return inserted_pk(res)
    except IntegrityError:
        sector_pred = (m.Threat_Catalogue.SectorID.is_(None) if sector_id is None
                    else m.Threat_Catalogue.SectorID == sector_id)
        winner = sess.execute(
            select(m.Threat_Catalogue.ThreatCatalogueID).where(
                m.Threat_Catalogue.ThreatTypeID == type_id, m.Threat_Catalogue.ThreatName == name,
                sector_pred, m.Threat_Catalogue.IsActive == True, m.Threat_Catalogue.IsDeleted == False)
        ).scalar()
        if winner is None:  # see upsert_threat_type — only a real duplicate may resolve here
            raise
        return winner


def upsert_threat_actor(sess: Session, name: str) -> int:
    """Insert-if-not-exists keyed by (ThreatActorName) — `UX_ThreatActor_NaturalKey`
    (no sector on this table). Returns the winning ThreatActorID either way."""
    # See upsert_threat_type's identical comment — ThreatActorName's real column width is Unicode(200).
    name = name[:200]
    try:
        with sess.begin_nested():
            res = execute_dml(sess, insert(m.Threat_Actor).values(
                ThreatActorName=name, IsCapable=1, IsActive=True, IsDeleted=False))
        return inserted_pk(res)
    except IntegrityError:
        winner = sess.execute(
            select(m.Threat_Actor.ThreatActorID).where(
                m.Threat_Actor.ThreatActorName == name,
                m.Threat_Actor.IsActive == True, m.Threat_Actor.IsDeleted == False)
        ).scalar()
        if winner is None:  # see upsert_threat_type — only a real duplicate may resolve here
            raise
        return winner


def upsert_threat_rule(sess: Session, threat_type_id: int, rule_type: str, rule_key: str,
                       rule_value: str, weight: float, source: str) -> int:
    """Insert-if-not-exists keyed by (ThreatTypeID, RuleType, RuleKey, RuleValue) —
    `UX_ConfigThreatRule_NaturalKey` (migration 0027). Returns the winning ThreatRuleID
    either way — the same race-safe shape as upsert_threat_type above: the DB's IDENTITY
    assigns the id (never MAX+1 in app code), and a concurrent import or a Celery
    crash-redelivery re-writing the same rule collapses onto the existing row instead of
    silently double-counting its weight (scoping._apply_rules sums fired weights).

    `source` lands in CreatedBy (e.g. 'auto:mitre_attack_ics') so auto-written rows are
    distinguishable from a curator's manual SQL inserts."""
    try:
        with sess.begin_nested():
            res = execute_dml(sess, insert(m.Config_Threat_Rule).values(
                RuleType=rule_type, ThreatTypeID=threat_type_id, RuleKey=rule_key,
                RuleValue=rule_value, Metadata=json.dumps({"weight": weight}),
                CreateDate=now(), CreatedBy=source, IsActive=True, IsDeleted=False))
        return inserted_pk(res)
    except IntegrityError:
        winner = sess.execute(
            select(m.Config_Threat_Rule.ThreatRuleID).where(
                m.Config_Threat_Rule.ThreatTypeID == threat_type_id,
                m.Config_Threat_Rule.RuleType == rule_type,
                m.Config_Threat_Rule.RuleKey == rule_key,
                m.Config_Threat_Rule.RuleValue == rule_value,
                m.Config_Threat_Rule.IsActive == True, m.Config_Threat_Rule.IsDeleted == False)
        ).scalar()
        if winner is None:  # see upsert_threat_type — only a real duplicate may resolve here
            raise
        return winner


def link_type_actor(sess: Session, type_id: int, actor_id: int) -> bool:
    """Idempotent link into `ThreatType_ThreatActor_Map` — the composite (ThreatTypeID,
    ThreatActorID) PRIMARY KEY itself guards duplicates, so a repeat call is a race-safe
    no-op (savepoint absorbs the IntegrityError; the link now exists either way).
    Returns True iff a NEW link row was inserted, False if it already existed — so callers
    (accept._add_flagged_threats_to_library) can audit real library growth, not a re-affirmed link.

    The IntegrityError is absorbed only once the link is CONFIRMED present. A bad
    type_id/actor_id raises an FK (or NOT NULL) violation through this same branch, and
    answering False there would report "already linked" for a link that does not exist
    and never will — the caller then audits library growth that never happened. Same
    fail-loud rule as `upsert_threat_type`: only a violation you can positively identify
    may be swallowed.
    """
    try:
        with sess.begin_nested():
            sess.execute(insert(m.ThreatType_ThreatActor_Map).values(ThreatTypeID=type_id, ThreatActorID=actor_id))
        return True
    except IntegrityError:
        exists = sess.execute(
            select(1).where(m.ThreatType_ThreatActor_Map.ThreatTypeID == type_id,
                            m.ThreatType_ThreatActor_Map.ThreatActorID == actor_id)
        ).first()
        if exists is None:  # not a duplicate link — FK/NOT NULL/other violation
            raise
        return False


def link_catalogue_category(sess: Session, catalogue_id: int, category_id: int) -> bool:
    """Idempotent link into `Threat_Catalogue_Category_Map` — same composite-PK-guards-
    duplicates, race-safe-no-op, fail-loud-on-real-violation contract as `link_type_actor`
    above (see its docstring). Returns True iff a NEW link row was inserted.

    Called once per (catalogue, category) pair a caller resolves — the map table is
    naturally multi-valued (a catalogue entry can hold several categories), so promoting a
    threat that later gains a second category is just a second call, not a schema change."""
    try:
        with sess.begin_nested():
            sess.execute(insert(m.Threat_Catalogue_Category_Map).values(
                ThreatCatalogueID=catalogue_id, ThreatCategoryID=category_id))
        return True
    except IntegrityError:
        exists = sess.execute(
            select(1).where(m.Threat_Catalogue_Category_Map.ThreatCatalogueID == catalogue_id,
                            m.Threat_Catalogue_Category_Map.ThreatCategoryID == category_id)
        ).first()
        if exists is None:  # not a duplicate link — FK/NOT NULL/other violation
            raise
        return False
