"""Data-access layer — the ONE place isolation and concurrency guards live.

Every entity-scoped read/write goes through here so the `EntityID` predicate and the
active-row rule (`Superseded=0`) can never be forgotten, and the CAS primitives (stage
claim, `_LOCK`) are written once, correctly.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, cast

from sqlalchemy import Executable, RowMapping, and_, case, exists, func, insert, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (RESERVABLE_REJECTIONS, ActorType, AuditEventType, ScenarioStatus,
                            SessionStatus, StageStatus, SubsystemLevel, WorkflowStage)
from app.core.logging import get_logger
from app.db import models as m

log = get_logger(__name__)


def execute_dml(sess: Session, stmt: Executable) -> CursorResult[Any]:
    """Run a Core INSERT/UPDATE/DELETE, narrowed to `CursorResult` — the only `Result`
    subclass carrying `.rowcount`/`.inserted_primary_key`, which every CAS below reads.
    `Session.execute()` can only be annotated `-> Result[Any]` because it also serves ORM
    queries, so narrow once here instead of casting at each call site.

    `.rowcount` is only a trustworthy CAS signal while no `SET NOCOUNT ON` is in effect and
    no trigger fires on the target table — either would make it -1 or inflated.
    """
    return cast("CursorResult[Any]", sess.execute(stmt))


def inserted_pk(res: CursorResult[Any]) -> int:
    """First column of the primary key of the row just inserted.

    SQLAlchemy never hands back None for a single-row `insert()` against an IDENTITY table,
    but check anyway: the `upsert_*` callers below run inside an IntegrityError retry, where
    a bare `NoneType is not subscriptable` would be far harder to trace back here.
    """
    pk = res.inserted_primary_key
    if pk is None:
        raise RuntimeError("INSERT yielded no primary key (not an IDENTITY table?)")
    return pk[0]


def now() -> datetime:
    """Current UTC timestamp — one clock/timezone convention for every
    CreatedAt/UpdatedAt/LeaseExpiresAt column."""
    return datetime.now(timezone.utc)


#: 48-bit millisecond clock, in the LAST 6 bytes of every generated GUID. See guid().
_COMB_TS_MASK = (1 << 48) - 1


def guid() -> str:
    """Row-key primitive. SEQUENTIAL (COMB), not uuid4: nine tables have a uniqueidentifier PK,
    which SQL Server clusters, so a random key page-splits on every insert.

    The timestamp sits in the LAST 6 bytes because SQL Server orders uniqueidentifier by bytes
    10-15 first — a UUIDv7 (timestamp in the FIRST bytes) would sort on the random tail and buy
    nothing. Generated app-side, not via NEWSEQUENTIALID(), because ids are needed before the
    insert. Valid RFC 9562 UUID (version 8); ~74 random bits remain per millisecond.
    """
    b = bytearray(os.urandom(10) + (int(time.time() * 1000) & _COMB_TS_MASK).to_bytes(6, "big"))
    b[6] = (b[6] & 0x0F) | 0x80   # version 8 — custom layout
    b[8] = (b[8] & 0x3F) | 0x80   # RFC 4122/9562 variant
    return str(uuid.UUID(bytes=bytes(b)))


# --- exceptions mapped to HTTP by the API layer ---
class SessionConflict(Exception):
    """An active session already exists for this (entity, asset) → 409."""

    def __init__(self, active_session_id: str):
        """Carries the conflicting session's id for the 409 body. Never None: `create_session`
        raises this only once it has positively identified the active row that beat us."""
        self.active_session_id = active_session_id
        super().__init__(active_session_id)


class IdempotencyKeyConflict(Exception):
    """Idempotency-Key reused against a different (entity, asset) → 409."""

    def __init__(self, existing_session_id: str):
        """Carries the session id the reused key was already bound to, so the 409 body can
        point the caller at the (entity, asset) that actually owns this Idempotency-Key."""
        self.existing_session_id = existing_session_id
        super().__init__(existing_session_id)


class CapacityExceeded(Exception):
    """Active-session ceiling reached → 503 (soft, deliberately racy — see
    `count_active_sessions`)."""


class RegenerateConflict(Exception):
    """Regenerate rejected: not at REVIEW, target lock held, a concurrent regen/accept won the
    race, or every requested target no longer clears the scoping cutoff on rescoring → 409.

    `reason` is an optional machine-readable code (e.g. "session_completed") surfaced by the
    HTTP handler as `details.reason`. Raise sites without a stable cause just omit it."""

    def __init__(self, message: str, reason: str | None = None):
        super().__init__(message)
        self.reason = reason


class CancelConflict(Exception):
    """Cancel rejected: the session was already terminal (completed/cancelled by a
    concurrent writer) when `cancel_session`'s CAS ran → 409."""


class EntityForbidden(Exception):
    """Requested object is outside the caller's entity scope → 403."""


class NotFoundError(Exception):
    """Requested entity does not exist → 404.

    `details` rides through to the response envelope's `details` key, same as
    RegenerateConflict.reason. Optional, so every plain NotFoundError("...") is unaffected."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


# ---------------------------------------------------------------------------
# Object-level authz — asset ownership
# ---------------------------------------------------------------------------
def asset_owning_entities(sess: Session, asset_id: Any) -> set[str]:
    """The group/entity id(s) that own `asset_id`, read off `ctm_scan_entity_bu.group_id` — the
    direct asset->entity link. An asset can have more than one such row, hence the set return.

    NOT `ctm_scan_entity.tier1_critical_service_id`: that field is unpopulated on every current
    asset, and context.py only reads it to label the grounding context's `critical_service`.

    Returns an empty set if the asset doesn't exist or has no `ctm_scan_entity_bu` row —
    callers must treat that as "no proven owner" (deny), never as "open to everyone".
    """
    rows = sess.execute(
        select(m.ctm_scan_entity_bu.group_id)
        .where(m.ctm_scan_entity_bu.ctm_scan_entity_id == asset_id)
    ).scalars().all()
    return {str(g) for g in rows}


def assert_asset_owned_by_entity(sess: Session, asset_id: Any, entity_id: Any) -> None:
    """Deny unless `asset_id` is actually owned by `entity_id`. `require_entity()` only proves
    the caller may act AS entity_id; without this, any authorized caller could submit someone
    else's asset_id (a plain IDOR) and pull that asset's context, threats or scenarios.
    """
    if str(entity_id) not in asset_owning_entities(sess, asset_id):
        raise EntityForbidden(f"asset {asset_id} not owned by entity {entity_id}")


# ---------------------------------------------------------------------------
# Sessions (carry EntityID directly — filtered by it)
# ---------------------------------------------------------------------------
def create_session(sess: Session, values: Mapping[str, Any]) -> str:
    """Insert a session. Two independent unique indexes can reject the insert:
    (EntityID, AssetID) WHERE active, and (EntityID, IdempotencyKey) WHERE IdempotencyKey IS
    NOT NULL. Check the idempotency-key index FIRST when a key was supplied: the two racing
    requests need not share an AssetID, so re-scoping by (EntityID, AssetID) alone would
    silently miss a same-key/different-asset winner and return the wrong conflict type with
    no session id.

    An IntegrityError attributable to NEITHER index (NOT NULL, FK, truncation) is re-raised
    untouched — answering `SessionConflict(None)` turns every schema fault into a 409 naming
    an asset that has no active session. Same fail-loud rule as the `upsert_*` helpers below:
    only a violation you can positively identify may be absorbed.
    """
    try:
        with sess.begin_nested():  # savepoint so a violation doesn't kill the txn
            sess.execute(insert(m.Scenario_Session).values(**values))
    except IntegrityError as exc:
        idem_key = values.get("IdempotencyKey")
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

    `models.GUID` normalizes on BOTH bind and result, so SQL comparisons already treat
    uppercase / dashless / braced / `urn:uuid:` spellings as equal — but a PYTHON-side
    comparison (a set difference, a dict lookup, a `len(set(...))` count) does not, and
    silently reports a matched row as missing. Normalize at the boundary, in one place.

    Raises ValueError on a malformed id, so callers can turn it into a 4xx instead of letting
    it reach `GUID.bind_processor` and surface as a 500."""
    return str(uuid.UUID(str(value).strip()))


def _valid_guid(value: str) -> bool:
    """A caller-supplied id that isn't UUID-shaped must never reach a WHERE clause on a
    `uniqueidentifier` column: MSSQL rejects the conversion with a raw pyodbc.ProgrammingError,
    not a clean empty result. Checked here, once, so every id-keyed lookup 404s, not 500s.
    """
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


# The columns the HTTP layer actually reads off a session row — the three nvarchar(max) blobs
# (SubsystemsJSON, SectorIDsJSON, AssetContextJSON) are consumed ONLY by the pipeline.
_SESSION_BOARD_COLS = (
    m.Scenario_Session.SessionID, m.Scenario_Session.TenantID, m.Scenario_Session.EntityID,
    m.Scenario_Session.UserID, m.Scenario_Session.AssetID, m.Scenario_Session.AssetName,
    m.Scenario_Session.SessionStatus, m.Scenario_Session.CurrentStage,
    m.Scenario_Session.StageStatus, m.Scenario_Session.CompletedAt,
)


def load_session_board(sess: Session, session_id: str) -> RowMapping | None:
    """`load_session` for the HTTP layer: the same row, without the three `nvarchar(max)` JSON
    blobs no route reads. Front door for the status-board poll and SSE connect/reconnect, where
    selecting the whole table drags the full gathered asset context (tens of KB) across pyodbc
    on every poll only to discard it. The pipeline keeps using `load_session`; it needs them."""
    if not _valid_guid(session_id):
        return None
    return sess.execute(
        select(*_SESSION_BOARD_COLS).where(m.Scenario_Session.SessionID == session_id)
    ).mappings().first()


def load_session(sess: Session, session_id: str) -> RowMapping | None:
    """Load a session by id WITHOUT an entity filter — the API then checks the row's EntityID is
    in the caller's authorized set ([R2] object-level authz). Returns the FULL row including the
    JSON blobs; HTTP callers want `load_session_board` above instead."""
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

    CAS-fenced on `SessionStatus == active`: returns True iff THIS call made the transition,
    False if a concurrent writer already ended the session (or the id doesn't exist) — a lost
    race the caller must surface, never a silent overwrite of what the winner committed.
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
    """Cancel/reaper path → cancelled (also releases the M4 lock). CurrentStage/StageStatus move
    to a terminal value too, not just SessionStatus — otherwise the board keeps showing the
    stale pre-cancel stage forever (e.g. AWAITING_DECISION on a session that's actually dead).

    Same CAS fence as `complete_session`: True iff this call made the transition; False means
    already terminal, which the caller must treat as a conflict.
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
    """Index-only-scan COUNT against the filtered `IX_Session_Active` index. Deliberately racy:
    a soft backpressure ceiling only needs to protect an already-saturated system, not be exact
    — unlike the M4 per-asset lock, which IS a correctness invariant and must never be racy.
    """
    return sess.execute(
        select(func.count()).select_from(m.Scenario_Session)
        .where(m.Scenario_Session.SessionStatus == SessionStatus.active)
    ).scalar() or 0


def count_active_sessions_for_entity(sess: Session, entity_id: str) -> int:
    """Same racy-by-design soft count, scoped to one entity — backs the per-entity cap so one
    entity looping session creation can't exhaust the global ceiling for everyone else."""
    return sess.execute(
        select(func.count()).select_from(m.Scenario_Session)
        .where(m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.EntityID == entity_id)
    ).scalar() or 0


def assert_capacity_available(sess: Session, entity_id: str | None = None) -> None:
    """Raise CapacityExceeded at/over the global `max_active_sessions` ceiling, and at/over the
    per-entity `max_active_sessions_per_entity` (0 = disabled) when `entity_id` is given —
    without the latter one entity could loop session creation and starve the whole tenant.
    Checked before the more expensive `gather_asset_details`."""
    per_entity_cap = get_settings().max_active_sessions_per_entity
    if entity_id and per_entity_cap:
        # One round trip for both counts (same filtered IX_Session_Active index); the two
        # standalone counters above stay for their other callers.
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
) -> tuple[str | None, bool, str | None]:
    """One indexed SELECT against `UX_Session_IdempotencyKey`. Returns:
    - (None, False, None)             — key unused, caller proceeds to create.
    - (session_id, False, user_id)    — same key + same asset → return the existing session.
    - (session_id, True, user_id)     — same key + a DIFFERENT asset → caller raises 409.
    `user_id` is the EXISTING row's owner, not the current caller's — the key is scoped by
    (EntityID, key), not by user, so a different caller authorized for the same entity can
    legitimately hit the replay branch and the response must report who actually owns it.
    The create-time race past this read is caught by `create_session`'s IntegrityError handler.
    """
    row = sess.execute(
        select(m.Scenario_Session.SessionID, m.Scenario_Session.AssetID, m.Scenario_Session.UserID)
        .where(m.Scenario_Session.EntityID == entity_id,
            m.Scenario_Session.IdempotencyKey == idempotency_key)
    ).mappings().first()
    if row is None:
        return None, False, None
    return row["SessionID"], row["AssetID"] != asset_id, row["UserID"]


# ---------------------------------------------------------------------------
# Stage state — CAS primitives
# ---------------------------------------------------------------------------
def claim_stage(
    sess: Session, session_id: str, subsystem_id: int, level: SubsystemLevel,
    epoch: int, task_id: str,
) -> bool:
    """Atomically claim a work stage for one attempt; True iff this call won the claim.
    Claimable: `IDLE`/`ERROR`, or a row THIS task left `RUNNING` (a mid-flight retry resumes
    it), AND `AttemptCount` under `stage_max_attempts`. `COMPLETE`/`AWAITING_DECISION` is NOT
    re-claimable, so a Celery redelivery of a finished stage is a true no-op, never a
    destructive re-run. At the attempt cap the row stops being claimable (so stops refreshing
    its lease) and the reaper sweep + `decide_session_outcome` carry it to a terminal state.

    Paired with `finish_stage`, which fences the exit on this same (epoch, task_id).

    Deliberately does NOT check `_LOCK` ownership, so it stays usable standalone. A caller that
    must not resume work after losing the `_LOCK` mutex mid-flight needs its own `holds_lock`
    check (see `write_scenarios`' `require_lock`) — the uncovered case is a zombie claiming a
    stage on a *sibling* level that carries no epoch/task_id fencing of its own yet.
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
    """AttemptCount as `claim_stage` just left it: `1` is the first successful claim of this
    epoch (a fresh run), `>1` a resumed/redelivered claim (it resets to 0 on every
    `reset_stage_for_regen` and increments on EVERY successful claim, resume included).
    `write_scenarios` gates its once-per-epoch supersede on this, so a Celery retry never
    re-supersedes rows the failed attempt already committed."""
    return sess.execute(
        select(m.Subsystem_Stage_State.AttemptCount).where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == level,
            m.Subsystem_Stage_State.GenerationEpoch == epoch,
        )
    ).scalar() or 0


def holds_lock(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """True iff `task_id` currently holds this subsystem's `_LOCK` row (RUNNING, owned by it).
    A stalled worker whose lease expired has it reclaimed by the reaper out from under it, so
    check this before resuming multi-step work (see `write_scenarios`'s `require_lock`)."""
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
    # A lock may only be taken while the owning session is still 'active' — otherwise a
    # redelivered task (or the reaper) resumes a session that was concurrently cancelled.
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


def renew_lock_lease(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """Push the `_LOCK` lease forward for its holder. Best-effort; True iff it landed.

    acquire_lock stamps the lease ONCE, but the work it guards is a whole click — and the variant
    top-up runs after finish_stage NULLed the stage lease, so stage-level renew_lease cannot cover
    that window. Without this the reaper reclaims an expired lock and a second writer lands on the
    subsystem. No epoch here: RUNNING + ActiveTaskID is the whole fence, same as release_lock."""
    s = get_settings()
    _now = now()
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
        .values(LeaseExpiresAt=_now + timedelta(seconds=s.stage_lease_seconds), UpdatedAt=_now)
    )
    return res.rowcount == 1


def release_lock(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """Flip the `_LOCK` row back to IDLE — but ONLY if we still hold it. Returns True iff the
    release landed; False means the lock was taken from us while we worked.

    Winning `acquire_lock` does NOT prove ownership *later*: a holder that stalls past its
    lease has the lock reclaimed to IDLE by the reaper and immediately re-taken. An
    unconditional release would free the NEW owner's lock, putting two writers on one
    subsystem — the [R5] mutual exclusion this row exists to enforce. Fencing on
    `ActiveTaskID` makes a stale holder's release a no-op.
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
    """Push a held stage's lease forward — call before a long operation (an LLM call) so a
    still-alive worker's claim isn't reaped mid-work. `claim_stage` sets the lease once; a stage
    making several long calls in a row can outlive it under entirely normal latency, not just a
    crash. Fenced on (epoch, task_id, Status==RUNNING) so a zombie that already lost the claim
    cannot resurrect it. Best-effort: on False, let `finish_stage`'s fencing catch the lost
    claim at the end of the work, as it always has.
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
    """Terminal transition OUT of a stage — the exit half of `claim_stage`'s CAS, fenced on the
    same (epoch, task_id) identity. Only the worker that still owns THIS generation of the row
    may record its outcome. Returns True iff the write landed.

    Unfenced, a stalled worker's late result overwrites whatever replaced it, both observed:
      * the reaper flips an abandoned RUNNING row to ERROR; the zombie wakes and stamps
        COMPLETE back over it, so a dead session reports success;
      * a regeneration resets the row to a fresh claimable IDLE at epoch N+1; the epoch-N
        zombie stamps AWAITING_DECISION over it, the epoch-N+1 task can then never claim it,
        and the subsystem serves stale scenarios as though they were the regenerated ones.

    `LeaseExpiresAt` is cleared on the way out: the lease means "someone is RUNNING this right
    now", so a long-finished row carrying one makes the reaper's `dead_lease` check fire on a
    session that simply left REVIEW for a routine regeneration.
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
    run_next_set skips re-running the additive reset+find_threats only when it actually FINISHED
    at the reserved epoch — or the row has ADVANCED past it (a stale redelivery; re-entering is a
    no-op since reset/claim/finish all fence on the exact epoch and match nothing).

    COMPLETE is load-bearing: an epoch-only check also returned True for a row left RUNNING by an
    attempt that FAILED before finish_stage, so the Celery retry skipped the additive block and
    THREATS stayed RUNNING, wedging decide_session_outcome until the reaper. Requiring COMPLETE
    makes the retry re-enter, resume the row it still owns, and drive THREATS terminal."""
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
    (AWAITING_DECISION or COMPLETE). Lets run_next_set / run_regeneration tell an idempotent
    redelivery of an already-landed batch apart from a genuine lost claim — the former must fall
    through to decide_session_outcome, NOT raise and fire a spurious error SSE."""
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
    """Per-subsystem stage rows for the status board (§6.1), excluding `_LOCK`. `ErrorMessage`
    rides along because an AWAITING_DECISION row revived by the salvage path keeps its message
    as the "this review set may be partial" marker (see revive_errored_scenarios_to_review)."""
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
    if status is not None:
        where.append(m.Subsystem_Stage_State.Status == status)
    return [r[0] for r in sess.execute(select(m.Subsystem_Stage_State.SubsystemID).where(*where)).all()]


def subsystem_has_pending_work(sess: Session, session_id: str, subsystem_id: int) -> bool:
    """True iff any non-_LOCK stage for this subsystem is IDLE or RUNNING — genuinely unstarted
    or resumable. False means every stage is already terminal, i.e. a redelivery is re-confirming
    finished work. Gates the one-time `subsystem_advanced` signal so a redelivery doesn't
    re-announce work nothing is about to happen to."""
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
    """max(GenerationEpoch) over ONLY the levels touched in this regen hop, +1. Narrower than a
    subsystem-wide max on purpose: regenerating SCENARIOS must not bump THREATS' epoch."""
    current = sess.execute(
        select(func.max(m.Subsystem_Stage_State.GenerationEpoch)).where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level.in_(levels),
        )
    ).scalar()
    return (current or 0) + 1


def reset_stage_for_regen(sess: Session, session_id: str, subsystem_id: int, levels: tuple, new_epoch: int) -> None:
    """Reset the target level(s) to a fresh, claimable IDLE row at `new_epoch` so `claim_stage`'s
    `GenerationEpoch == epoch` CAS matches. Also zeroes `AttemptCount` and clears `ErrorMessage`:
    otherwise a subsystem that exhausted its attempt budget under the OLD epoch stays permanently
    unclaimable under the new one too — a regenerated subsystem born poisoned."""
    sess.execute(
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level.in_(levels),
            # Epoch fence: only ever move a row FORWARD, so a STALE in-task reset (a redelivery
            # whose reserved epoch is behind the live one) is a no-op instead of downgrading the
            # row and inverting the epoch lineage. A live endpoint reset always passes (max+1).
            m.Subsystem_Stage_State.GenerationEpoch < new_epoch,
        )
        .values(GenerationEpoch=new_epoch, Status=StageStatus.IDLE, AttemptCount=0,
            ErrorMessage=None, UpdatedAt=now())
    )


def active_threats(sess: Session, session_id: str, subsystem_id: int) -> list[dict]:
    """Active threats for a subsystem, shaped for `scoping.score_threats` AND `write_scenarios`'s
    per-threat prompt enrichment (scenario-granularity regen needs the full sibling list to rank
    the target correctly, even though only ONE row is rewritten). Same dict shape `find_threats`
    returns, so `write_scenarios` consumes both sources identically."""
    return [
        {
            "threat_id": r["ThreatID"], "grounding_status": r["GroundingStatus"],
            "threat_type": r["ThreatType"], "threat_name": r["ThreatName"],
            "library_threat_type": r["LibraryThreatType"], "library_threat_name": r["LibraryThreatName"],
            "threat_type_id": r["ThreatTypeID"],  # [R12] scoping rules key on the grounded type
            "catalogue_id": r["ThreatCatalogueID"],  # keeps _dedup_key/IdentityHash identical to a full run's on regen
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
    """True iff the session has any active (Superseded=0) Threat_Scenario_Output row.
    decide_session_outcome uses it to keep a session whose stage ERROR'd but whose earlier
    batches left salvageable scenarios in REVIEW instead of cancelling — a transient failure
    must never destroy already-committed, reviewable work."""
    return sess.execute(
        select(1).select_from(m.Threat_Scenario_Output).where(
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.Superseded == 0,
            # complete only: a FAILURE CARD (Status=error, null scenario) is retryable, not
            # reviewable; counting it would salvage a session that has nothing to review.
            m.Threat_Scenario_Output.Status == ScenarioStatus.complete,
        )
    ).first() is not None


def revive_errored_scenarios_to_review(sess: Session, session_id: str) -> int:
    """Restore the board invariant "session at REVIEW/AWAITING_DECISION => >=1 subsystem SCENARIOS
    row at AWAITING_DECISION". decide_session_outcome's salvage branch moves the SESSION row to
    REVIEW but leaves the per-subsystem SCENARIOS row ERROR — so accept's good_subs comes back
    empty, mark_scenarios_accepted matches 0 rows, and the session completes having accepted
    nothing (silent data loss). Flips the ERRORed row (in place, at its current epoch) of every
    subsystem that still has an active scenario. Returns the number of rows revived.

    `ErrorMessage` is deliberately PRESERVED: it is the only durable marker telling a reviewer
    this review set may be PARTIAL rather than a complete run."""
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
    Every producer/consumer of Threat_Scenario_Output.IdentityHash routes through here so the
    app-level dedup and the UX_Scenario_ActiveIdentity index can never disagree. `_dedup_key` is
    lazy-imported so app.db.dal (below app.pipeline) takes no load-time dependency on it."""
    from app.pipeline.tasks import _dedup_key
    return hashlib.sha256(f"{session_id}|{subsystem_id}|{_dedup_key(info)}".encode()).hexdigest()


def next_unserved_unique_threats(sess: Session, session_id: str, subsystem_id: int, n: int) -> list[str]:
    """Up to `n` active ThreatIDs for this (session, subsystem) whose catalogue-level dedup
    identity has NO active scenario yet — the pool "generate next set" serves from before it
    falls back to a fresh AI batch. Best-first (Score desc, then ThreatID); a threat a fresh
    additive find_threats added but write_scenarios hasn't scored yet has a NULL score and sorts
    last (LEFT JOIN), but is still eligible. Identity is folded exactly like the IdentityHash on
    Threat_Scenario_Output, so "already shown" == an active IdentityHash. Two candidates sharing
    one identity in this call collapse to the best-ranked, so one call never proposes an
    internal duplicate."""
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
            # A rejected active Scoped_Threat is re-servable ONLY if it was demoted by the top-N
            # cutoff — target-mode re-scoring will re-select it. A tech_gate / below-threshold /
            # duplicate rejection is PERMANENT (re-scoring fails the same way), so re-serving it
            # churns a Selected=0 row and write_scenarios keeps refusing it: the "no new threats"
            # wedge. Matched on RejectionKind, NOT on the wording of Reason: this predicate was
            # `Reason.like("beyond top-%")` until 2026-08-03, so rewording one f-string in
            # scoping.py would have emptied the pool permanently and silently.
            or_(st.ScopedThreatID.is_(None), st.Selected == 1,
                st.RejectionKind.in_(RESERVABLE_REJECTIONS)))
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
    """The folded catalogue-level identities of this (session, subsystem)'s ACTIVE
    Identified_Threat rows. find_threats(supersede=False) uses it to skip an additive proposal
    whose identity already matches a live threat — otherwise a re-proposal leaves a never-scored
    dead Identified_Threat row (the IdentityHash index would still block the duplicate scenario,
    but the leaked threat row lingers)."""
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
    """Active scoping rules for the given grounded master types ([R12], SDD §5.4) — one query for
    the whole subsystem, ordered by ThreatRuleID so rule evaluation (and the FactorsJSON it
    records) is deterministic. Empty input → no query, no rules.

    The rule's OWN IsActive/IsDeleted is not sufficient: this schema has no foreign keys, so
    soft-deleting a Threat_Type leaves its Config_Threat_Rule children live and still gating and
    boosting real generations. The EXISTS re-asserts the parent, which is what an ON DELETE
    cascade would do. Enforced HERE because this is the single choke point every rule read
    passes through, so full runs, regen, next-set and the variant top-up are all covered."""
    if not threat_type_ids:
        return []
    ct, tt = m.Config_Threat_Rule, m.Threat_Type
    return [dict(r) for r in sess.execute(
        select(ct.RuleType, ct.ThreatTypeID, ct.RuleKey, ct.RuleValue, ct.Metadata)
        .where(ct.ThreatTypeID.in_(threat_type_ids),
            ct.IsActive == True, ct.IsDeleted == False,  # noqa: E712 — SQLAlchemy binary expr
            exists().where(tt.ThreatTypeID == ct.ThreatTypeID,
                        tt.IsActive == True, tt.IsDeleted == False))  # noqa: E712
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
    'subsystem' groups in one round-trip — every real caller needs both per session. A group with
    no active rows comes back empty, which prompts.py treats as "send no context for that group"
    (fail closed — no hardcoded fallback set, except critical_service, which build_base_context
    always sends because validation requires it); a row under any OTHER
    ContextGroup value is silently excluded, and selfcheck.check_dead_context_fields is what
    surfaces that drift to an operator, not this function."""
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
    This IS the allowlist prompts.py uses — no hardcoded ceiling behind it, so whatever a curator
    activates here is what reaches the external model (plus critical_service, which
    build_base_context always adds because validation requires it). Empty result (unseeded, or
    all off) means the caller sends no other context for that group.
    Prefer active_context_fields_by_group above when both groups are needed at once."""
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


def accepted_scenarios(sess: Session, session_id: str) -> list[dict]:
    """Accepted, non-superseded scenario rows for one (completed) session, joined to
    their grounded threat so every row carries the [R13] contract's join ids
    (ThreatTypeID/ThreatCatalogueID/SubsystemID). One query; ordered for stable output.
    The joins are by globally-unique GUID keys, so no extra Superseded filter is needed
    on the joined tables — a completed session's rows are immutable.

    OUTER, not INNER: this schema has no enforced foreign keys, so the ScopedThreatID/ThreatID
    linkage isn't DB-guaranteed, and accept already flipped Accepted=1 independent of whether
    this join resolves. An INNER join would silently drop an already-accepted row from this
    contract while accept's own accepted_count still counted it. Worst case with OUTER is null
    threat_* columns, never a vanished row."""
    out, st, it = m.Threat_Scenario_Output, m.Scoped_Threat, m.Identified_Threat
    return [dict(r) for r in sess.execute(
        select(out.OutputID, out.SubsystemID, out.ScopedThreatID, out.ScenarioJSON,
            it.ThreatTypeID, it.ThreatCatalogueID, it.ThreatType, it.ThreatName,
            it.LibraryThreatType, it.LibraryThreatName)
        .select_from(out.__table__.outerjoin(st, out.ScopedThreatID == st.ScopedThreatID)
                    .outerjoin(it, st.ThreatID == it.ThreatID))
        .where(out.SessionID == session_id, out.Accepted == 1, out.Superseded == 0)
        .order_by(out.SubsystemID, out.OutputID)
    ).mappings()]


#: Shared select for the cross-session scenario reads below — output row + its owning
#: session (entity/user/status truth) + grounded threat. OUTER joins for the same reason
#: as accepted_scenarios above: no enforced FKs, a broken linkage must null the threat
#: columns, never drop the row. INNER to the session: an output without a session row has
#: no entity, and entity scope is the authz boundary.
def _scenario_read_select():
    out, ss, st, it = m.Threat_Scenario_Output, m.Scenario_Session, m.Scoped_Threat, m.Identified_Threat
    return (
        select(out.OutputID, out.SessionID, out.SubsystemID, out.ScenarioJSON,
            out.Accepted, out.Superseded, out.ScenarioNumber, out.CreatedAt, out.ControlsMappedAt,
            ss.EntityID, ss.UserID, ss.SessionStatus,
            it.ThreatTypeID, it.ThreatCatalogueID, it.ThreatType, it.ThreatName,
            it.LibraryThreatType, it.LibraryThreatName)
        .select_from(out.__table__
            .join(ss, out.SessionID == ss.SessionID)
            .outerjoin(st, out.ScopedThreatID == st.ScopedThreatID)
            .outerjoin(it, st.ThreatID == it.ThreatID))
    )


def scenario_rows(sess: Session, *, entity_ids: set[str], user_id: str | None = None,
                status: str | None = None, include_superseded: bool = False,
                limit: int = 100, offset: int = 0) -> list[dict]:
    """Cross-session scenario list for GET /v1/users/{user_id}/scenarios and
    GET /v1/entities/{entity_id}/scenarios.

    `entity_ids` is ALWAYS applied and must already be authorized by the caller (the
    principal's entity set, or one require_entity'd id) — it is the object-level authz
    boundary, checked against Scenario_Session.EntityID (NOT NULL), never the nullable
    denormalized copy on the output row. Same reasoning for `user_id`: the session's
    UserID is the accountable owner; the output copy is provenance.

    `status`: 'accepted' filters the scenario flag; 'active'/'completed'/'cancelled'
    filter the parent session's status. Failure cards (Status='error') never appear —
    they have no narrative. Newest first, OutputID tiebreak for stable pages."""
    out, ss = m.Threat_Scenario_Output, m.Scenario_Session
    stmt = _scenario_read_select().where(
        ss.EntityID.in_({str(e) for e in entity_ids}),
        out.Status == ScenarioStatus.complete,
    )
    if not include_superseded:
        stmt = stmt.where(out.Superseded == 0)
    if user_id is not None:
        stmt = stmt.where(ss.UserID == user_id)
    if status == "accepted":
        stmt = stmt.where(out.Accepted == 1)
    elif status is not None:
        stmt = stmt.where(ss.SessionStatus == status)
    # ponytail: OFFSET paging is O(offset) on deep pages — fine at limit<=500 over per-entity
    # volumes; switch to keyset (WHERE (CreatedAt, OutputID) < last-seen) if offsets grow.
    return [dict(r) for r in sess.execute(
        stmt.order_by(out.CreatedAt.desc(), out.OutputID).limit(limit).offset(offset)
    ).mappings()]


def scenario_row(sess: Session, session_id: str, output_id: str) -> RowMapping | None:
    """One output row for GET /v1/sessions/{session_id}/scenarios/{output_id}. The caller
    has already authorized the session; the SessionID predicate makes an OutputID from
    another session 404 rather than leak. No Superseded/Status filter — an explicit-id
    fetch returns the row with its flags visible. None on a malformed GUID (→ 404, not a
    MSSQL 500 — see _valid_guid)."""
    if not _valid_guid(output_id):
        return None
    out = m.Threat_Scenario_Output
    return sess.execute(
        _scenario_read_select().where(out.OutputID == output_id, out.SessionID == session_id)
    ).mappings().first()


def mark_scenarios_accepted(
    sess: Session, session_id: str, subsystem_ids: list[int], subset: list[str] | None = None,
) -> int:
    """Sets Accepted=1 on every non-superseded scenario for these subsystems (accept, §5.7),
    optionally narrowed to `subset` OutputIDs ([R8] partial accept — `subset=[]` means
    "accept none", distinct from `subset=None` meaning "accept all").

    Also stamps `AcceptedSubsetJSON` with the exact `subset` list on every row this call
    touches, but ONLY for a partial accept (`subset is not None`) — NULL on a full accept, so
    "non-NULL" means precisely "this row was part of an explicit partial pick", and a reviewer
    can see which selection accepted a given row without joining Scenario_Audit.

    Returns the number of rows actually flipped, so the caller can tell "N requested, N matched"
    apart from "N requested, M<N matched" instead of reporting a clean accept either way (a
    subset id for a wrong/superseded/nonexistent row otherwise vanishes silently)."""
    where = [m.Threat_Scenario_Output.SessionID == session_id, m.Threat_Scenario_Output.Superseded == 0,
            m.Threat_Scenario_Output.SubsystemID.in_(subsystem_ids),
            # complete only: a FAILURE CARD (null scenario) must never be marked Accepted — it
            # would reach downstream consumers as an accepted scenario with no content. A subset
            # naming one simply doesn't match, and the caller reports it as not-acceptable (404).
            m.Threat_Scenario_Output.Status == ScenarioStatus.complete]
    if subset is not None:
        where.append(m.Threat_Scenario_Output.OutputID.in_(subset))
    accepted_subset_json = json.dumps(subset) if subset is not None else None
    res = execute_dml(sess, update(m.Threat_Scenario_Output).where(*where)
                    .values(Accepted=1, AcceptedSubsetJSON=accepted_subset_json))
    return res.rowcount


def unacceptable_subset_reasons(
    sess: Session, session_id: str, subset: list[str], subsystem_ids: list[int],
) -> dict[str, str]:
    """Why each requested OutputID could not be accepted — one code per id that mark_scenarios_
    accepted would reject, mirroring its four predicates. Ids it WOULD accept are absent.

    FAILURE-PATH DIAGNOSTIC. Only worth running once the caller already knows the counts
    disagree, because that request is about to 404 and roll back anyway; on the happy path it
    would be a second read of rows just written, for nobody.

    `SessionID == session_id` is a TENANT BOUNDARY, not an optimisation. The caller was
    authorized for ONE session, so an id from elsewhere must come back `unknown` — reporting
    "exists, wrong session" would confirm another tenant's row exists from an unauthenticated
    guess. Same reasoning as the ancestry walk in the results read path."""
    out = m.Threat_Scenario_Output
    rows = {str(r["OutputID"]): r for r in sess.execute(
        select(out.OutputID, out.SubsystemID, out.Status, out.Superseded)
        .where(out.SessionID == session_id, out.OutputID.in_(subset))
    ).mappings()}
    reasons: dict[str, str] = {}
    for oid in subset:
        row = rows.get(oid)
        if row is None:
            reasons[oid] = "unknown"                      # absent here, or another session's
        elif row["Superseded"]:
            reasons[oid] = "superseded"                   # an older version; regen replaced it
        elif row["Status"] != ScenarioStatus.complete:
            reasons[oid] = "failure_card"                 # no content, must never be accepted
        elif row["SubsystemID"] not in subsystem_ids:
            reasons[oid] = "subsystem_not_awaiting_decision"
    return reasons


# ---------------------------------------------------------------------------
# Generic write helpers
# ---------------------------------------------------------------------------
# A superseded output KEEPS its control-map rows: GET /results?include_replaced=true can still
# reach them. Costs ~control_map_top_k (5) rows per regeneration; nothing re-maps them
# (map_controls filters Superseded=0, per OutputID).
# ponytail: if the table ever grows enough to matter, prune by session age, not on the write path.


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
    """The subset of `threat_ids` that already have an active (Superseded=0)
    Threat_Scenario_Output, joined via Scoped_Threat.ScopedThreatID — the stable GUID link,
    resolved even if the scoped row itself was later superseded. write_scenarios keys its
    next-set cleanup on this, NOT on "has an active scoped row": a genuine REGEN target keeps its
    active scenario, while a POOL ZOMBIE (a served pool threat that rescored OUT after a
    mid-session tech_gate/threshold tightening) still has its old active scoped row but NO active
    scenario, so it lands in the marker set and gets superseded instead of re-served every
    click."""
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
            # complete only: a threat whose only active row is a FAILURE CARD is NOT "done" — a
            # resumed attempt must retry it, and the next-set sweep must treat it as unserved
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


def supersede_scoped_rows(sess: Session, scoped_threat_ids) -> None:
    """Retire exactly these Scoped_Threat rows (by their own PK) — the regen path's row-scoped
    replacement. NEVER threat-wide: with multiple coexisting scenarios per threat, a sibling
    scenario's scoring row must survive its sibling's regeneration."""
    if not scoped_threat_ids:
        return
    sess.execute(
        update(m.Scoped_Threat)
        .where(m.Scoped_Threat.ScopedThreatID.in_(scoped_threat_ids),
            m.Scoped_Threat.Superseded == 0)
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


def supersede_by_identity_hashes(sess: Session, session_id: str, subsystem_id: int, identity_hashes,
                                scenario_number: int) -> dict[str, str]:
    """Supersede every active Threat_Scenario_Output in this (session, subsystem) whose
    IdentityHash is in the requested set AND sits at `scenario_number` — one UPDATE, not a loop.
    `write_scenarios`' regen path clears the colliding active row before inserting the
    regenerated one so the filtered `UX_Scenario_ActiveIdentity(SessionID, IdentityHash,
    ScenarioNumber)` index can't collide (regen skips `_select_unique_top_n`, so nothing else
    guarantees the folded hashes are unique). `scenario_number` is REQUIRED: an identity-wide
    supersede would retire a sibling scenario while regenerating another.

    RETURNS `{IdentityHash: retired OutputID}` so the caller stamps ReplacesOutputID from what
    was ACTUALLY retired rather than the requested target id — retirement is keyed on
    (IdentityHash, ScenarioNumber), so a collapsed duplicate target could otherwise be retired
    with nothing pointing at it.

    One statement, not a SELECT then an UPDATE over the identical predicate: RETURNING reports
    exactly the rows this UPDATE changed, so the answer cannot drift from the write under a
    concurrent regen the way a separate read could. MSSQL emits OUTPUT, SQLite 3.35+ RETURNING."""
    if not identity_hashes:
        return {}
    retired = {h: oid for oid, h in sess.execute(
        update(m.Threat_Scenario_Output)
        .where(
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.SubsystemID == subsystem_id,
            m.Threat_Scenario_Output.IdentityHash.in_(identity_hashes),
            m.Threat_Scenario_Output.ScenarioNumber == scenario_number,
            m.Threat_Scenario_Output.Superseded == 0,
        )
        .values(Superseded=1)
        .returning(m.Threat_Scenario_Output.OutputID, m.Threat_Scenario_Output.IdentityHash)
    ).all()}
    return retired


def variant_eligible_primaries(sess: Session, session_id: str, subsystem_id: int, n: int,
                            max_per_threat: int,
                            exclude_threat_ids: set[str] | None = None) -> list[dict]:
    """The "who can get another scenario?" gate — the ONLY place the `max_scenarios_per_threat`
    cap is applied, and the only code path that ever assigns a ScenarioNumber > 1. Returns up to
    `n` work items, best-first by the primary's Scoped_Threat.Score, each: {"threat_id",
    "identity_hash", "next_number", "score", "scope_rank", "reason", "factors_json"} — the scoped
    fields cloned from the lowest-numbered COMPLETE scenario's own scoped row so the variant's
    fresh Scoped_Threat row carries the same scoring provenance without re-running scoping.

    Eligible = an identity with at least one active COMPLETE scenario (a threat whose only active
    row is a failure card gets no variant — no sibling text to steer against, and failure
    recovery is regenerate's job) AND fewer than `max_per_threat` active rows TOTAL (error cards
    included, so scenario numbers can never collide).

    `exclude_threat_ids` drops threats the CALLER just served in this same click: eligibility has
    no recency fence and the sort is best-score-first, so a caller topping up a short batch would
    otherwise re-pick the very primaries it committed seconds earlier. Applied in the fold BELOW,
    before sort/[:n], so an exclusion frees its slot for the next-best threat instead of silently
    shrinking the batch."""
    out = m.Threat_Scenario_Output
    rows = sess.execute(
        select(out.IdentityHash, out.ScenarioNumber, out.Status, out.ScopedThreatID)
        .where(out.SessionID == session_id, out.SubsystemID == subsystem_id,
            out.Superseded == 0, out.IdentityHash.is_not(None))
    ).all()
    by_hash: dict[str, list] = {}
    for r in rows:
        by_hash.setdefault(r.IdentityHash, []).append(r)
    candidates: dict[str, tuple[int, str]] = {}  # hash -> (next_number, primary ScopedThreatID)
    for identity, group in by_hash.items():
        if len(group) >= max_per_threat:
            continue
        complete = [r for r in group if r.Status == ScenarioStatus.complete]
        if not complete:
            continue
        primary = min(complete, key=lambda r: r.ScenarioNumber)
        next_number = max(r.ScenarioNumber for r in group) + 1
        candidates[identity] = (next_number, primary.ScopedThreatID)
    if not candidates:
        return []
    st = m.Scoped_Threat
    scoped_rows = {r.ScopedThreatID: r for r in sess.execute(
        select(st.ScopedThreatID, st.ThreatID, st.Score, st.ScopeRank, st.Reason, st.FactorsJSON)
        .where(st.ScopedThreatID.in_([sid_ for _, sid_ in candidates.values()]))
    ).all()}
    # Case-fold: MSSQL hands uniqueidentifier back upper-case while the ORM/SQLite path is
    # lower-case, so a raw string compare would silently never match and the exclusion would
    # be a no-op exactly where it matters most (production).
    excluded = {str(t).lower() for t in (exclude_threat_ids or ())}
    items = []
    for identity, (next_number, scoped_id) in candidates.items():
        sr = scoped_rows.get(scoped_id)
        if sr is None:
            continue  # primary's scoped row vanished mid-read — benign, skip this round
        if str(sr.ThreatID).lower() in excluded:
            continue  # caller just served this threat in this same click — see docstring
        items.append({"threat_id": sr.ThreatID, "identity_hash": identity, "next_number": next_number,
                    "score": sr.Score, "scope_rank": sr.ScopeRank, "reason": sr.Reason,
                    "factors_json": sr.FactorsJSON})
    items.sort(key=lambda d: (-(d["score"] or 0), str(d["threat_id"])))
    return items[:n]


def active_scenarios_by_identity(sess: Session, session_id: str, subsystem_id: int,
                                identity_hashes) -> list:
    """Every active COMPLETE scenario row for the given identity hashes, in ONE query —
    (OutputID, IdentityHash, ScenarioNumber, ScenarioJSON). The batched sibling fetch for
    variant/regen prompt-steering and the difflib similarity check: fetched once per
    write_scenarios/write_variant_scenarios call and passed down, never one SELECT per scenario
    inside the generation loop."""
    if not identity_hashes:
        return []
    out = m.Threat_Scenario_Output
    return list(sess.execute(
        select(out.OutputID, out.IdentityHash, out.ScenarioNumber, out.ScenarioJSON)
        .where(out.SessionID == session_id, out.SubsystemID == subsystem_id,
            out.Superseded == 0, out.Status == ScenarioStatus.complete,
            out.IdentityHash.in_(identity_hashes))
    ).all())


def insert_row(sess: Session, table, values: Mapping[str, Any]) -> None:
    """Generic single-row insert — no active-row or Superseded handling of its own; callers are
    expected to `supersede` the prior row first."""
    sess.execute(insert(table).values(**values))


def audit_row(sess: Session, **cols: Any) -> dict[str, Any]:
    """One Scenario_Audit row with CreatedAt, ActorUserID and ActorType defaulted.

    `ActorUserID` = WHO IS ACCOUNTABLE for this session, not "who typed the command". A caller
    that knows the acting human passes it; every background row (grounding_summary, stage_error,
    regeneration_completed, ...) has no human in the call stack and back-fills the session's
    UserID, so a NULL never reads as missing data rather than "not applicable".

    `ActorType` answers the question that back-fill destroys — "gopal accepted this" vs "the
    pipeline did this, gopal is answerable" — so it is decided from whether the CALLER named a
    human, BEFORE the back-fill runs.

    Defaulting HERE, not at the 13 call sites, is the point: a future audit write cannot forget.
    # ponytail: per-write PK lookup; pass ActorUserID explicitly from an in-hand session dict
    # if audit volume ever makes it measurable."""
    cols.setdefault("CreatedAt", now())
    # setdefault so an explicit caller value still wins; must run BEFORE the back-fill below.
    cols.setdefault("ActorType", ActorType.user if cols.get("ActorUserID") else ActorType.system)
    if cols.get("ActorUserID") is None and cols.get("SessionID"):
        cols["ActorUserID"] = sess.execute(
            select(m.Scenario_Session.UserID)
            .where(m.Scenario_Session.SessionID == cols["SessionID"])
        ).scalar()
    return cols


def append_audit(sess: Session, **cols: Any) -> None:
    """Append-only audit write for ONE row. Callers accumulating many rows for a single bulk
    INSERT (accept.py) build them with `audit_row` instead — same defaults, one round trip, and
    ONE place that decides what an audit row means."""
    sess.execute(insert(m.Scenario_Audit).values(**audit_row(sess, **cols)))


def latest_next_set_outcome(sess: Session, session_id: str, subsystem_id: int) -> dict | None:
    """DetailJSON of the newest `next_set_outcome` audit row for this (session, subsystem), or
    None if no "generate next set" click has run. Backs SessionProgress.last_next_set.

    Reads THIS event type, never `generation_complete`: one click can write TWO of the latter (the
    productive batch plus the variant top-up) which only make sense SUMMED, so "the most recent
    generation_complete" would report the top-up alone and undercount the click. `next_set_outcome`
    is written exactly once per click precisely so this read is a single row.

    Ordered by CreatedAt then AuditID — the tie-break matters because two rows of one fast click
    can land inside a single clock tick, and an unordered LIMIT would be non-deterministic."""
    row = sess.execute(
        select(m.Scenario_Audit.DetailJSON)
        .where(m.Scenario_Audit.SessionID == session_id,
            m.Scenario_Audit.SubsystemID == subsystem_id,
            m.Scenario_Audit.EventType == AuditEventType.next_set_outcome)
        .order_by(m.Scenario_Audit.CreatedAt.desc(), m.Scenario_Audit.AuditID.desc())
        .limit(1)
    ).scalar()
    if not row:
        return None
    try:
        parsed = json.loads(row)
    except (TypeError, ValueError):  # a truncated/hand-edited row must not 500 a status poll
        log.warning("audit.next_set_outcome_unparseable", session_id=session_id)
        return None
    return parsed if isinstance(parsed, dict) else None


# ---------------------------------------------------------------------------
# Threat-library promotion — race-safe insert-if-not-exists, guarded by the M2 natural-key
# UNIQUE indexes. Same savepoint + catch-IntegrityError + select idiom as `create_session`:
# two concurrent accepts proposing the identical new master lose the DB race deterministically,
# and the loser gets back the winner's id instead of a crash.
# ---------------------------------------------------------------------------
def upsert_threat_type(sess: Session, name: str, category_id: int | None, sector_id: int | None,
                    description: str | None = None, source: str = "ai_auto_promoted",
                    created_by: str | None = None) -> int:
    """Insert-if-not-exists keyed by (ThreatTypeName, ThreatCategoryID, SectorID) —
    `UX_ThreatType_NaturalKey`. Returns the winning ThreatTypeID either way.

    `source` records provenance ('ai_auto_promoted' for the accept.py promotion path, a
    per-library tag from scripts/import_threat_libraries.py); `created_by` is the accountable
    user id, or an 'auto:<tag>' / 'cli:<user>' literal when a background import had no logged-in
    caller. Both are FIRST-WRITER: the collision branch below returns the winner untouched, so
    re-importing never restamps them — and never writes UpdatedAt/UpdatedBy at all, because
    re-asserting an existing row is not an edit. Only the CRUD endpoints
    (app/api/library_crud.py) write the Updated* pair."""
    # Bound to ThreatTypeName's real column width (Unicode(300)) before it reaches the INSERT:
    # an over-long LLM-derived name raises DataError, NOT the IntegrityError this function
    # catches, so it would escape uncaught and abort the whole accept-session transaction.
    name = name[:300]
    try:
        with sess.begin_nested():
            res = execute_dml(sess, insert(m.Threat_Type).values(
                ThreatTypeName=name, ThreatCategoryID=category_id, SectorID=sector_id,
                Description=description, IsActive=True, IsDeleted=False, Source=source,
                CreatedAt=now(), CreatedBy=created_by))
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
                            description: str | None = None, source: str = "ai_auto_promoted",
                            created_by: str | None = None) -> int:
    """Insert-if-not-exists keyed by (ThreatTypeID, ThreatName, SectorID) —
    `UX_ThreatCatalogue_NaturalKey`. Returns the winning ThreatCatalogueID either way.

    Same first-writer `source`/`created_by` provenance contract as upsert_threat_type above.
    Does NOT link the new row into Threat_Catalogue_Category_Map — call link_catalogue_category
    once you have a category id."""
    # See upsert_threat_type — ThreatName's real column width is Unicode(500).
    name = name[:500]
    try:
        with sess.begin_nested():
            res = execute_dml(sess, insert(m.Threat_Catalogue).values(
                ThreatTypeID=type_id, ThreatName=name, SectorID=sector_id,
                Description=description, IsActive=True, IsDeleted=False, Source=source,
                CreatedAt=now(), CreatedBy=created_by))
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


def upsert_threat_actor(sess: Session, name: str, source: str = "ai_auto_promoted",
                        created_by: str | None = None) -> int:
    """Insert-if-not-exists keyed by (ThreatActorName) — `UX_ThreatActor_NaturalKey`
    (no sector on this table). Returns the winning ThreatActorID either way.

    Same first-writer `source`/`created_by` provenance contract as upsert_threat_type above."""
    # See upsert_threat_type — ThreatActorName's real column width is Unicode(200).
    name = name[:200]
    try:
        with sess.begin_nested():
            res = execute_dml(sess, insert(m.Threat_Actor).values(
                ThreatActorName=name, IsCapable=1, IsActive=True, IsDeleted=False,
                Source=source, CreatedAt=now(), CreatedBy=created_by))
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


# ---------------------------------------------------------------------------
# Threat-library master CRUD (app/api/library_crud.py)
#
# Generic over the four masters on purpose: create/update/soft-delete are the same four steps
# every time (write or fetch-or-404, apply, stamp Updated*, let a natural-key clash surface as
# IntegrityError) and only the column names differ. Four copies would be four places to forget
# the stamp.
#
# These are the ONLY functions that write UpdatedAt/UpdatedBy — the upsert_* family above
# re-asserts rows rather than editing them, so first-writer provenance stands.
# ---------------------------------------------------------------------------
def create_library_row(sess: Session, model, values: dict, user_id: str | None) -> int:
    """Insert one master row, stamped CreatedAt/CreatedBy. Returns the new PK.

    Lets IntegrityError escape: only the caller knows which natural key was violated, and with
    the filtered unique indexes a clash is a real 409, not a retry."""
    # IsActive first so a caller-supplied value still wins; the rest last so nothing can forge
    # its own provenance stamp or create a row that is born deleted.
    res = execute_dml(sess, insert(model).values(
        **{"IsActive": True, **values,
        "IsDeleted": False, "CreatedAt": now(), "CreatedBy": user_id}))
    return inserted_pk(res)


def get_library_row(sess: Session, model, pk_col, pk_value: int, *, include_deleted: bool = False):
    """One master row by PK, or NotFoundError. Soft-deleted rows are invisible by default —
    a deleted row must 404 like a missing one, or DELETE becomes silently repeatable."""
    stmt = select(model).where(pk_col == pk_value)
    if not include_deleted:
        stmt = stmt.where(model.IsDeleted == False)  # noqa: E712
    row = sess.execute(stmt).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"{model.__tablename__} {pk_value} not found")
    return row


def update_library_row(sess: Session, model, pk_col, pk_value: int, values: dict,
                    user_id: str | None) -> None:
    """Partial update of one master row plus the UpdatedAt/UpdatedBy stamp. `values` carries only
    the fields the caller actually sent, so an omitted field keeps its current value.
    IntegrityError escapes for the caller to translate (see create_library_row).

    The 404 comes from the UPDATE's own rowcount, not a preceding SELECT: one statement instead
    of two, and it closes the window where a concurrent soft-delete lands between the check and
    the write. `IsDeleted == False` in the WHERE makes rowcount 0 mean exactly "no live row with
    this id" — missing and already-deleted are deliberately the same 404 to a caller."""
    res = execute_dml(sess, update(model).where(pk_col == pk_value, model.IsDeleted == False)  # noqa: E712
                    .values(**values, UpdatedAt=now(), UpdatedBy=user_id))
    if not res.rowcount:
        raise NotFoundError(f"{model.__tablename__} {pk_value} not found")


def soft_delete_library_row(sess: Session, model, pk_col, pk_value: int, user_id: str | None) -> None:
    """IsDeleted=1 plus the same Updated* stamp — which is exactly why there is no DeletedBy
    column: a delete IS an update, so UpdatedBy already answers "who deleted this".

    Never a hard DELETE. Threat_Type/Threat_Catalogue/Control_Library ids are referenced by rows
    in completed sessions, so removing one would orphan historical scenarios. The natural-key
    indexes are filtered on `IsDeleted = 0`, so the freed name/code can be reused.

    Same rowcount-not-SELECT reasoning as update_library_row, which also makes this atomically
    single-shot: two concurrent deletes cannot both report success."""
    res = execute_dml(sess, update(model).where(pk_col == pk_value, model.IsDeleted == False)  # noqa: E712
                    .values(IsDeleted=True, UpdatedAt=now(), UpdatedBy=user_id))
    if not res.rowcount:
        raise NotFoundError(f"{model.__tablename__} {pk_value} not found")


def upsert_threat_rule(sess: Session, threat_type_id: int, rule_type: str, rule_key: str,
                    rule_value: str, weight: float, source: str) -> int:
    """Insert-if-not-exists keyed by (ThreatTypeID, RuleType, RuleKey, RuleValue) —
    `UX_ConfigThreatRule_NaturalKey`. Returns the winning ThreatRuleID either way, the same
    race-safe shape as upsert_threat_type above: the DB's IDENTITY assigns the id (never MAX+1
    in app code), and a concurrent import or crash-redelivery re-writing the same rule collapses
    onto the existing row instead of double-counting its weight (scoping._apply_rules sums
    fired weights).

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
                m.Config_Threat_Rule.IsActive == True, 
                m.Config_Threat_Rule.IsDeleted == False)
        ).scalar()
        if winner is None:  # see upsert_threat_type — only a real duplicate may resolve here
            raise
        return winner


def link_type_actor(sess: Session, type_id: int, actor_id: int) -> bool:
    """Idempotent link into `ThreatType_ThreatActor_Map` — the composite (ThreatTypeID,
    ThreatActorID) PRIMARY KEY guards duplicates, so a repeat call is a race-safe no-op. Returns
    True iff a NEW link row was inserted, so callers can audit real library growth rather than a
    re-affirmed link.

    The IntegrityError is absorbed only once the link is CONFIRMED present: a bad
    type_id/actor_id raises an FK/NOT NULL violation through this same branch, and answering
    False there would report "already linked" for a link that does not exist and never will.
    """
    try:
        with sess.begin_nested():
            sess.execute(insert(m.ThreatType_ThreatActor_Map).values(
                ThreatTypeID=type_id, ThreatActorID=actor_id, CreatedAt=now()))
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
    duplicates, race-safe-no-op, fail-loud-on-real-violation contract as `link_type_actor`.
    Returns True iff a NEW link row was inserted. The map is naturally multi-valued, so a
    threat that later gains a second category is just a second call, not a schema change."""
    try:
        with sess.begin_nested():
            sess.execute(insert(m.Threat_Catalogue_Category_Map).values(
                ThreatCatalogueID=catalogue_id, ThreatCategoryID=category_id, CreatedAt=now()))
        return True
    except IntegrityError:
        exists = sess.execute(
            select(1).where(m.Threat_Catalogue_Category_Map.ThreatCatalogueID == catalogue_id,
                            m.Threat_Catalogue_Category_Map.ThreatCategoryID == category_id)
        ).first()
        if exists is None:  # not a duplicate link — FK/NOT NULL/other violation
            raise
        return False
