"""Data-access layer: the one place the `EntityID` predicate, the `Superseded=0` active-row rule
and the CAS primitives (stage claim, `_LOCK`) are written."""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import (
    Executable,
    RowMapping,
    and_,
    case,
    exists,
    func,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    RESERVABLE_REJECTIONS,
    ActorType,
    AuditEventType,
    CandidateStatus,
    ScenarioStatus,
    SessionStatus,
    StageStatus,
    SubsystemLevel,
    TreatmentOutcomeReason,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.db import models as m

log = get_logger(__name__)
#: 48-bit millisecond clock, in the LAST 6 bytes of every generated GUID. See guid().
_COMB_TS_MASK = (1 << 48) - 1

# --- API authentication (header model, see app/api/deps.get_principal) ---
#: user_scope_assignment.scope_type value that means "Entity" — option_value group 1010
#: (1=Sector 2=Sub-Sector 3=Service 4=Entity 5=Asset). ref_id is then a group.id = EntityID.
SCOPE_TYPE_ENTITY = 4

#: This deployment's module name (config: TSG_API_MODULE, default 'tsg'). An API_Client key is
#: valid ONLY for its own Module, so a leaked key is contained to one module (a 'chatbot' key can't
#: authenticate TSG). Bound once at import — module identity is fixed per deployment, never changes
#: at runtime. verify_api_key and the boot check (invariants.py) both filter on this value.
API_MODULE = get_settings().api_module


def user_has_entity(sess: Session, user_id: str | int, entity_id: str | int) -> bool:
    """[R2] Does this user actually have an ACTIVE Entity-level assignment to this entity?

    The (user, entity) pair arrives self-declared in request headers; this is the check that
    makes it real. Fails CLOSED — the caller treats any exception as a deny.

    scope_type is pinned to Entity (4), not optional: the same table holds Sub-Sector/Service/
    Asset rows for the same user, and a non-entity ref_id could otherwise collide with an
    entity id. We verify the supplied pair (never derive the entity from the user), so a user
    with more than one entity assignment is handled correctly.
    """
    return sess.execute(
        select(1).where(
            m.user_scope_assignment.user_id == int(user_id),
            m.user_scope_assignment.ref_id == int(entity_id),
            m.user_scope_assignment.scope_type == SCOPE_TYPE_ENTITY,
            m.user_scope_assignment.is_active == True,  # Core bit compare (renders `= 1`); MSSQL rejects `IS 1`
        ).limit(1)
    ).first() is not None


def create_api_client(sess: Session, client_id: str, name: str, module: str,
                      key_hash: str, created_by: str | None) -> None:
    """Insert a new API client. Raises IntegrityError if `client_id` already exists (the caller
    maps that to 409). The secret is NEVER stored — only its SHA-256 hex (`key_hash`)."""
    sess.execute(insert(m.API_Client).values(
        ClientID=client_id, KeyHash=key_hash, Name=name, Module=module,
        Active=True, CreatedAt=now(), CreatedBy=created_by))


def list_api_clients(sess: Session, module: str | None = None) -> list[dict[str, Any]]:
    """API clients as metadata dicts (newest first) — NEVER includes KeyHash or the secret."""
    c = m.API_Client
    stmt = select(c.ClientID, c.Name, c.Module, c.Active, c.CreatedAt, c.CreatedBy,
                c.RevokedAt, c.RevokedBy).order_by(c.CreatedAt.desc())
    if module:
        stmt = stmt.where(c.Module == module)
    return [{"client_id": r[0], "name": r[1], "module": r[2], "active": bool(r[3]),
            "created_at": r[4], "created_by": r[5], "revoked_at": r[6], "revoked_by": r[7]}
            for r in sess.execute(stmt).all()]


def revoke_api_client(sess: Session, client_id: str, revoked_by: str | None) -> bool:
    """Deactivate an ACTIVE client (Active=0, RevokedAt, RevokedBy). Returns False if it does not
    exist or is already inactive."""
    res = execute_dml(sess, update(m.API_Client)
        .where(m.API_Client.ClientID == client_id, m.API_Client.Active == True)  # Core bit compare
        .values(Active=False, RevokedAt=now(), RevokedBy=revoked_by))
    return res.rowcount == 1


def api_client_id_for_key_hash(sess: Session, key_hash: str, module: str = API_MODULE) -> str | None:
    """The ClientID of the single ACTIVE API_Client whose hash equals `key_hash` AND whose Module
    is `module`, or None. The Module filter is what makes a key valid only for its own module —
    a key provisioned for another module never authenticates here. The caller has already hashed
    the presented secret; exact-match on the indexed SHA-256 column."""
    return sess.execute(
        select(m.API_Client.ClientID).where(
            m.API_Client.KeyHash == key_hash,
            m.API_Client.Module == module,
            m.API_Client.Active == True,  # Core bit compare (renders `= 1`); MSSQL rejects `IS 1`
        ).limit(1)
    ).scalar_one_or_none()

# --- exceptions mapped to HTTP by the API layer ---
class SessionConflict(Exception):
    """An active session already exists for this (entity, asset) → 409."""

    def __init__(self, active_session_id: str):
        """Carries the conflicting session's id for the 409 body; never None."""
        self.active_session_id = active_session_id
        super().__init__(active_session_id)

class IdempotencyKeyConflict(Exception):
    """Idempotency-Key reused against a different (entity, asset) → 409."""

    def __init__(self, existing_session_id: str):
        """Carries the session id the reused key is already bound to, for the 409 body."""
        self.existing_session_id = existing_session_id
        super().__init__(existing_session_id)

class CapacityExceeded(Exception):
    """Active-session ceiling reached → 503 (soft, deliberately racy)."""

class RegenerateConflict(Exception):
    """Regenerate rejected: wrong state, lock held, lost race, or no surviving target → 409.

    `reason` is an optional machine-readable code surfaced as `details.reason`."""

    def __init__(self, message: str, reason: str | None = None):
        super().__init__(message)
        self.reason = reason

class CancelConflict(Exception):
    """Cancel rejected: the session was already terminal when `cancel_session`'s CAS ran → 409."""

class EntityForbidden(Exception):
    """Requested object is outside the caller's entity scope → 403."""

class NotFoundError(Exception):
    """Requested entity does not exist → 404.

    `details` rides through to the response envelope's `details` key."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


# The columns the HTTP layer actually reads off a session row; the nvarchar(max) JSON blobs are
# consumed ONLY by the pipeline and are deliberately absent.
_SESSION_BOARD_COLS = (
    m.Scenario_Session.SessionID, m.Scenario_Session.TenantID, m.Scenario_Session.EntityID,
    m.Scenario_Session.UserID, m.Scenario_Session.AssetID, m.Scenario_Session.AssetName,
    m.Scenario_Session.SessionStatus, m.Scenario_Session.CurrentStage,
    m.Scenario_Session.StageStatus, m.Scenario_Session.CompletedAt,
)

def execute_dml(sess: Session, stmt: Executable) -> CursorResult[Any]:
    """INSERT/UPDATE/DELETE as `CursorResult` — the only `Result` carrying `.rowcount`.

    `.rowcount` is a trustworthy CAS signal only without `SET NOCOUNT ON` and without a trigger on
    the target table; either makes it -1 or inflated."""
    return cast("CursorResult[Any]", sess.execute(stmt))

def inserted_pk(res: CursorResult[Any]) -> int:
    """First PK column of the row just inserted. Raises rather than returning None — the `upsert_*`
    callers run inside an IntegrityError retry where `NoneType is not subscriptable` is untraceable."""
    pk = res.inserted_primary_key
    if pk is None:
        raise RuntimeError("INSERT yielded no primary key (not an IDENTITY table?)")
    return pk[0]

def now() -> datetime:
    """Current UTC timestamp — one clock convention for every CreatedAt/UpdatedAt/LeaseExpiresAt."""
    return datetime.now(timezone.utc)

def guid() -> str:
    """Sequential (COMB) uuid, never uuid4: uniqueidentifier PKs are clustered, so a random key
    page-splits on every insert.

    Timestamp in the LAST 6 bytes — SQL Server orders uniqueidentifier by bytes 10-15 first, so a
    UUIDv7 layout would sort on the random tail. App-side, not NEWSEQUENTIALID(), because ids are
    needed before the insert. Valid RFC 9562 version-8 UUID."""
    b = bytearray(os.urandom(10) + (int(time.time() * 1000) & _COMB_TS_MASK).to_bytes(6, "big"))
    b[6] = (b[6] & 0x0F) | 0x80   # version 8 — custom layout
    b[8] = (b[8] & 0x3F) | 0x80   # RFC 4122/9562 variant
    return str(uuid.UUID(bytes=bytes(b)))

# ---------------------------------------------------------------------------
# Object-level authz — asset ownership
# ---------------------------------------------------------------------------
def asset_owning_entities(sess: Session, asset_id: Any) -> set[str]:
    """Entity ids owning `asset_id`, from `ctm_scan_entity_bu.group_id`. An empty set means no
    proven owner — callers must deny, never read it as "open to everyone"."""
    rows = sess.execute(
        select(m.ctm_scan_entity_bu.group_id)
        .where(m.ctm_scan_entity_bu.ctm_scan_entity_id == asset_id)
    ).scalars().all()
    return {str(g) for g in rows}


def assert_asset_owned_by_entity(sess: Session, asset_id: Any, entity_id: Any) -> None:
    """Raise EntityForbidden unless `entity_id` owns `asset_id`. `require_entity()` only proves the
    caller may act AS entity_id, so without this any authorized caller could submit someone else's
    asset_id — a plain IDOR."""
    if str(entity_id) not in asset_owning_entities(sess, asset_id):
        raise EntityForbidden(f"asset {asset_id} not owned by entity {entity_id}")

# ---------------------------------------------------------------------------
# Sessions (carry EntityID directly — filtered by it)
# ---------------------------------------------------------------------------
def active_tuning_overrides(sess: Session) -> dict[str, tuple[float | int, str | None]]:
    """Active Config_Tuning rows as {key: (typed value, embedding_model)}. A value that doesn't
    parse as its declared ValueType is skipped loudly — a curator typo must degrade to the config
    default, never brick session creation."""
    ct = m.Config_Tuning
    out: dict[str, tuple[float | int, str | None]] = {}
    for r in sess.execute(
        select(ct.TuningKey, ct.TuningValue, ct.ValueType, ct.EmbeddingModel)
        .where(ct.IsActive == True, ct.IsDeleted == False)  # noqa: E712 — SQL boolean columns
    ):
        try:
            val: float | int = int(r.TuningValue) if r.ValueType == "int" else float(r.TuningValue)
        except (TypeError, ValueError):
            log.warning("tuning.value_unparseable", key=r.TuningKey, value=r.TuningValue,
                        value_type=r.ValueType)
            continue
        out[r.TuningKey] = (val, r.EmbeddingModel)
    return out

def create_session(sess: Session, values: Mapping[str, Any]) -> str:
    """Insert a session; raises SessionConflict / IdempotencyKeyConflict on a unique-index clash.

    Check the (EntityID, IdempotencyKey) index FIRST when a key was supplied — racing requests need
    not share an AssetID, so scoping by (EntityID, AssetID) alone misses a same-key winner. An
    IntegrityError attributable to NEITHER index is re-raised untouched."""
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
    """Canonical lowercase-dashed spelling of a client GUID; ValueError if malformed. `models.GUID`
    already normalizes SQL comparisons, but a PYTHON-side set/dict comparison does not, and
    silently reports a matched row as missing."""
    return str(uuid.UUID(str(value).strip()))

def _valid_guid(value: str) -> bool:
    """True if `value` is UUID-shaped. A non-UUID reaching a `uniqueidentifier` WHERE clause makes
    MSSQL raise pyodbc.ProgrammingError rather than return empty — unchecked ids 500, not 404."""
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def load_session_board(sess: Session, session_id: str) -> RowMapping | None:
    """Session row for the HTTP layer without the nvarchar(max) JSON blobs no route reads — the
    status-board poll and SSE connect would otherwise drag tens of KB across pyodbc per poll.
    None on a malformed GUID."""
    if not _valid_guid(session_id):
        return None
    return sess.execute(
        select(*_SESSION_BOARD_COLS).where(m.Scenario_Session.SessionID == session_id)
    ).mappings().first()


def load_session(sess: Session, session_id: str) -> RowMapping | None:
    """Full session row by id with NO entity filter; the caller must then check EntityID against
    its authorized set ([R2]). HTTP callers want `load_session_board` instead."""
    if not _valid_guid(session_id):
        return None
    return sess.execute(
        select(m.Scenario_Session.__table__).where(m.Scenario_Session.SessionID == session_id)
    ).mappings().first()


def get_session(sess: Session, session_id: str, entity_id: str) -> RowMapping | None:
    """Session row scoped to the caller's entity — the data-layer IDOR guard (INV-1).
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
    """Accept path: flip the session to completed/APPROVED/COMPLETE, releasing the M4 lock.

    StageStatus moves too, or the board shows a completed session as still AWAITING_DECISION.
    CAS-fenced on `SessionStatus == active` — False means a concurrent writer already ended it and
    the caller must surface the lost race."""
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == session_id,
            m.Scenario_Session.SessionStatus == SessionStatus.active)
        .values(
            SessionStatus=SessionStatus.completed,
            CurrentStage=WorkflowStage.APPROVED,
            StageStatus=StageStatus.COMPLETE,
            CompletedAt=now(),
            UpdatedAt=now(),
        )
    )
    return res.rowcount == 1


def cancel_session(sess: Session, session_id: str) -> bool:
    """Cancel/reaper path → cancelled/CANCELLED, releasing the M4 lock. CurrentStage/StageStatus
    move too, or the board shows the stale pre-cancel stage forever. Same CAS fence as
    `complete_session`: False means already terminal — a conflict."""
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
# Library-promotion retry tracking (accept.py's run_promotion_phase / reaper.py's
# retry_one_promotion) — 4 columns on Scenario_Session, written only while the caller holds that
# session's `_LOCK` subsystem lock, so a plain by-PK UPDATE is all the safety these need.
# ---------------------------------------------------------------------------
def stamp_promotion_failure(sess: Session, session_id: str, *, error_message: str,
                            user_id: str | None) -> None:
    """Record a failed promotion attempt: sets PromotionFailedAt=now, increments the attempt
    counter, stores the error, and stamps the accepting user so a LATER retry (automatic or
    admin-triggered) attributes any resulting promotion to that same person."""
    execute_dml(sess, update(m.Scenario_Session)
                .where(m.Scenario_Session.SessionID == session_id)
                .values(PromotionFailedAt=now(),
                        PromotionAttempts=m.Scenario_Session.PromotionAttempts + 1,
                        PromotionError=error_message, PromotionUserID=user_id))


def clear_promotion_failure(sess: Session, session_id: str) -> None:
    """A promotion attempt just succeeded: clear the 4 tracking columns back to their fresh-
    session state. Leaves no PromotionAttempts history — this column tracks "does this session
    currently need attention", not a permanent attempt log."""
    execute_dml(sess, update(m.Scenario_Session)
                .where(m.Scenario_Session.SessionID == session_id)
                .values(PromotionFailedAt=None, PromotionAttempts=0,
                        PromotionError=None, PromotionUserID=None))


def list_pending_promotions(sess: Session, *, limit: int, include_exhausted: bool,
                            max_attempts: int) -> list[RowMapping]:
    """Sessions currently stuck on a failed promotion, oldest failure first — the admin API's
    GET /v1/tsg/sessions/promotions. Uses IX_Session_PromotionFailed (filtered on
    PromotionFailedAt IS NOT NULL), so this is a narrow lookup even at large table sizes, never a
    full scan. `include_exhausted=False` hides sessions the sweep has already given up on
    (PromotionAttempts >= max_attempts), showing only what the sweep is still actively retrying."""
    ss = m.Scenario_Session
    where = [ss.PromotionFailedAt.isnot(None)]
    if not include_exhausted:
        where.append(ss.PromotionAttempts < max_attempts)
    return sess.execute(
        select(ss.SessionID, ss.EntityID, ss.AssetID, ss.AssetName, ss.PromotionFailedAt,
            ss.PromotionAttempts, ss.PromotionError, ss.PromotionUserID, ss.CompletedAt)
        .where(*where)
        .order_by(ss.PromotionFailedAt.asc())
        .limit(limit)
    ).mappings().all()


def get_pending_promotion(sess: Session, session_id: str) -> RowMapping | None:
    """One session's promotion-failure detail, or None if it isn't currently in a failed state —
    the admin API's GET /v1/tsg/sessions/promotions/{session_id} and the 404 gate for retry/dismiss."""
    ss = m.Scenario_Session
    return sess.execute(
        select(ss.SessionID, ss.EntityID, ss.AssetID, ss.AssetName, ss.PromotionFailedAt,
            ss.PromotionAttempts, ss.PromotionError, ss.PromotionUserID, ss.CompletedAt)
        .where(ss.SessionID == session_id, ss.PromotionFailedAt.isnot(None))
    ).mappings().first()

# ---------------------------------------------------------------------------
# Admission control — backpressure + idempotent create
# ---------------------------------------------------------------------------
def count_active_sessions(sess: Session) -> int:
    """Count of active sessions (index-only scan of `IX_Session_Active`). Deliberately racy — a
    soft backpressure ceiling, unlike the M4 per-asset lock, which is a correctness invariant."""
    return sess.execute(
        select(func.count()).select_from(m.Scenario_Session)
        .where(m.Scenario_Session.SessionStatus == SessionStatus.active)
    ).scalar() or 0

def count_active_sessions_for_entity(sess: Session, entity_id: str) -> int:
    """Same racy soft count, scoped to one entity. Currently uncalled: `assert_capacity_available`
    does both counts in one round trip."""
    return sess.execute(
        select(func.count()).select_from(m.Scenario_Session)
        .where(m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.EntityID == entity_id)
    ).scalar() or 0

def assert_capacity_available(sess: Session, entity_id: str | None = None) -> None:
    """Raise CapacityExceeded at/over `max_active_sessions` and, with `entity_id`, the per-entity
    `max_active_sessions_per_entity` (0 disables either). Checked before `gather_asset_details`."""
    global_cap = get_settings().max_active_sessions
    per_entity_cap = get_settings().max_active_sessions_per_entity
    if entity_id and per_entity_cap:
        # One round trip for both counts (same filtered IX_Session_Active index).
        total, entity_total = sess.execute(
            select(
                func.count(),
                func.sum(case((m.Scenario_Session.EntityID == entity_id, 1), else_=0)),
            ).select_from(m.Scenario_Session)
            .where(m.Scenario_Session.SessionStatus == SessionStatus.active)
        ).one()
        if global_cap and total >= global_cap:
            raise CapacityExceeded()
        if (entity_total or 0) >= per_entity_cap:
            raise CapacityExceeded()
        return
    if global_cap and count_active_sessions(sess) >= global_cap:
        raise CapacityExceeded()

def reserve_idempotency_key_or_get_existing(
    sess: Session, entity_id: str, idempotency_key: str, asset_id: str,
) -> tuple[str | None, bool, str | None]:
    """One indexed read of `UX_Session_IdempotencyKey`:
    - (None, False, None)          — key unused, caller proceeds to create.
    - (session_id, False, user_id) — same key + same asset → return the existing session.
    - (session_id, True, user_id)  — same key + DIFFERENT asset → caller raises 409.

    `user_id` is the EXISTING row's owner (the key is scoped by (EntityID, key), not by user). The
    race past this read is caught by `create_session`'s IntegrityError handler."""
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
    """Atomically claim a work stage for one attempt; True iff this call won.

    Claimable: IDLE/ERROR, or a row THIS task left RUNNING (a mid-flight retry resumes), under
    `stage_max_attempts`. COMPLETE/AWAITING_DECISION is NOT re-claimable, so a redelivery of a
    finished stage is a true no-op. Paired with `finish_stage`, fenced on the same (epoch,
    task_id). Does NOT check `_LOCK` ownership — see `write_scenarios`' `require_lock`."""
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
    """AttemptCount as `claim_stage` left it: 1 = first claim of this epoch, >1 = a resumed or
    redelivered claim. `write_scenarios` gates its once-per-epoch supersede on this, so a retry
    never re-supersedes rows the failed attempt already committed."""
    return sess.execute(
        select(m.Subsystem_Stage_State.AttemptCount).where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == level,
            m.Subsystem_Stage_State.GenerationEpoch == epoch,
        )
    ).scalar() or 0


def holds_lock(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """True iff `task_id` still holds this subsystem's `_LOCK` row. Check before resuming
    multi-step work: the reaper reclaims an expired lease out from under a stalled worker."""
    return sess.execute(
        select(1).select_from(m.Subsystem_Stage_State)
        .where(m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == SubsystemLevel.LOCK,
            m.Subsystem_Stage_State.Status == StageStatus.RUNNING,
            m.Subsystem_Stage_State.ActiveTaskID == task_id)
    ).first() is not None


def acquire_lock(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """CAS on the `_LOCK` row (IDLE→RUNNING) serialising work on one subsystem; True iff we hold
    it. Sets a lease so the reaper can reclaim it if the holder dies.
    """
    s = get_settings()
    # Only takeable while the session is still active, or a redelivered task resumes a session
    # that was concurrently cancelled.
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


def acquire_promotion_retry_lock(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """Like acquire_lock, but WITHOUT its `SessionStatus == active` requirement — for
    reaper.retry_one_promotion/dismiss_promotion, which only ever run on a session that has
    ALREADY completed (a promotion failure can only exist after accept's own Phase 1 has already
    completed the session). acquire_lock's active-only guard exists to stop a stale/redelivered
    LIVE PIPELINE task (regenerate, next-set, threat identification) from resuming work on a
    session that's no longer live — that scenario cannot happen here, since this caller's entire
    premise is "the session is done; only its post-completion promotion side-effect needs
    revisiting." Reusing acquire_lock unmodified here would make it CAS-fail on every single
    call, since a completed session is never 'active' — that was a real, 100%-reproducible bug,
    not a race, caught by live-testing the retry/dismiss admin endpoints against a real
    completed session."""
    res = execute_dml(
        sess,
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level == SubsystemLevel.LOCK,
            m.Subsystem_Stage_State.Status == StageStatus.IDLE,
        )
        .values(
            Status=StageStatus.RUNNING, ActiveTaskID=task_id,
            LeaseExpiresAt=now() + timedelta(seconds=get_settings().stage_lease_seconds), UpdatedAt=now(),
        )
    )
    return res.rowcount == 1


def renew_lock_lease(sess: Session, session_id: str, subsystem_id: int, task_id: str) -> bool:
    """Push the `_LOCK` lease forward for its holder. Best-effort; True iff it landed. acquire_lock
    stamps the lease once but the work spans a whole click, so without this the reaper reclaims the
    lock and a second writer lands on the subsystem. RUNNING + ActiveTaskID is the whole fence."""
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
    """Flip `_LOCK` back to IDLE, fenced on `ActiveTaskID`; True iff the release landed. Winning
    `acquire_lock` does NOT prove ownership later — a stalled holder has the lock reaped and
    re-taken, so an unconditional release would free the NEW owner's lock and put two writers on
    one subsystem, breaking [R5]."""
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
        # Clear the lease: a freed lock must not read as a running worker to the reaper.
        .values(Status=StageStatus.IDLE, ActiveTaskID=None, LeaseExpiresAt=None, UpdatedAt=now())
    )
    return res.rowcount == 1


def renew_lease(sess: Session, session_id: str, subsystem_id: int, level: SubsystemLevel,
                epoch: int, task_id: str) -> bool:
    """Push a held stage's lease forward so a live worker isn't reaped mid-work. Fenced on (epoch,
    task_id, RUNNING) so a zombie cannot resurrect a lost claim. Best-effort — on False,
    `finish_stage`'s fencing catches it at the end of the work."""
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
    """Terminal transition out of a stage, fenced on the same (epoch, task_id) as `claim_stage`.

    Unfenced, a stalled worker's late result overwrites whatever replaced it: COMPLETE over the
    reaper's ERROR, or epoch-N status over the epoch-N+1 IDLE a regen just wrote, leaving the row
    unclaimable. `LeaseExpiresAt` is cleared so a finished row never trips the reaper."""
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
    """True iff this `level` row is COMPLETE at GenerationEpoch >= `epoch` — run_next_set's test for
    "the additive block already finished". COMPLETE is load-bearing: an epoch-only check also passes
    for a row left RUNNING by a failed attempt, wedging decide_session_outcome until the reaper."""
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
    """True iff this `level` row is at `epoch` and already AWAITING_DECISION or COMPLETE. Lets
    run_next_set / run_regeneration tell a redelivery of a landed batch from a genuine lost claim —
    the former must fall through, not fire a spurious error SSE."""
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
    rides along: on a revived AWAITING_DECISION row it is the "review set may be partial" marker."""
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
    """Every SubsystemID for this session at a given Subsystem_Stage_State Level, optionally
    narrowed to one Status."""
    where = [m.Subsystem_Stage_State.SessionID == session_id, m.Subsystem_Stage_State.Level == level]
    if status is not None:
        where.append(m.Subsystem_Stage_State.Status == status)
    return [r[0] for r in sess.execute(select(m.Subsystem_Stage_State.SubsystemID).where(*where)).all()]


def subsystem_has_pending_work(sess: Session, session_id: str, subsystem_id: int) -> bool:
    """True iff any non-_LOCK stage for this subsystem is IDLE or RUNNING. Gates the one-time
    `subsystem_advanced` signal so a redelivery doesn't re-announce finished work."""
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
    """max(GenerationEpoch) over ONLY the levels in this regen hop, +1 — regenerating SCENARIOS
    must not bump THREATS' epoch."""
    current = sess.execute(
        select(func.max(m.Subsystem_Stage_State.GenerationEpoch)).where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level.in_(levels),
        )
    ).scalar()
    return (current or 0) + 1


def reset_stage_for_regen(sess: Session, session_id: str, subsystem_id: int, levels: tuple, new_epoch: int) -> None:
    """Reset the target level(s) to a claimable IDLE row at `new_epoch` so `claim_stage`'s epoch
    CAS matches. Zeroes AttemptCount and clears ErrorMessage, or a subsystem that exhausted its
    attempt budget under the old epoch stays unclaimable under the new one."""
    sess.execute(
        update(m.Subsystem_Stage_State)
        .where(
            m.Subsystem_Stage_State.SessionID == session_id,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level.in_(levels),
            # Epoch fence: only ever move a row FORWARD, so a stale in-task reset is a no-op
            # instead of downgrading the row and inverting the epoch lineage.
            m.Subsystem_Stage_State.GenerationEpoch < new_epoch,
        )
        .values(GenerationEpoch=new_epoch, Status=StageStatus.IDLE, AttemptCount=0,
            ErrorMessage=None, UpdatedAt=now())
    )


def active_threats(sess: Session, session_id: str, subsystem_id: int) -> list[dict]:
    """Active threats for a subsystem, shaped for `scoping.score_threats` AND `write_scenarios`'s
    prompt enrichment — regen needs the full sibling list to rank the target even though only ONE
    row is rewritten. Same dict shape `find_threats` returns, so both sources are consumed alike."""
    # Lazy import: app.db.dal sits below app.pipeline and takes no load-time dependency on it.
    from app.pipeline.grounding import stored_actors
    return [
        {
            "threat_id": r["ThreatID"], "grounding_status": r["GroundingStatus"],
            "category": r["ThreatCategory"],  # impact class — gates the semantic near-duplicate scan
            "threat_type": r["ThreatType"], "threat_name": r["ThreatName"],
            "library_threat_type": r["LibraryThreatType"], "library_threat_name": r["LibraryThreatName"],
            "threat_type_id": r["ThreatTypeID"],  # [R12] scoping rules key on the grounded type
            "catalogue_id": r["ThreatCatalogueID"],  # keeps _dedup_key/IdentityHash identical to a full run's on regen
            # RAW list, matching find_threats' "actors": gr.actors — validated_actors would return
            # [] for every unverified threat and reproduce the adversary-blind-reload bug.
            "actors": stored_actors(r["ThreatActorsJSON"]),
        }
        for r in sess.execute(
            select(m.Identified_Threat.ThreatID, m.Identified_Threat.GroundingStatus,
                m.Identified_Threat.ThreatCategory,
                m.Identified_Threat.ThreatType, m.Identified_Threat.ThreatName,
                m.Identified_Threat.LibraryThreatType, m.Identified_Threat.LibraryThreatName,
                m.Identified_Threat.ThreatTypeID, m.Identified_Threat.ThreatCatalogueID,
                m.Identified_Threat.ThreatActorsJSON).where(
                m.Identified_Threat.SessionID == session_id,
                m.Identified_Threat.SubsystemID == subsystem_id,
                m.Identified_Threat.Superseded == 0,
            ).order_by(m.Identified_Threat.CreatedAt.desc(), m.Identified_Threat.ThreatID.desc())
        ).mappings()
    ]


def threat_scores(sess: Session, session_id: str) -> dict[str, dict]:
    """Best score/rank per threat for one session, in ONE grouped round trip. NEVER a join from the
    threat select: a threat has MANY active scoped rows (one per variant), so a join returns it once
    per variant. The aggregates only COLLAPSE identical cloned rows, never choose between values."""
    st = m.Scoped_Threat
    return {
        r["ThreatID"]: {"score": r["Score"], "scope_rank": r["ScopeRank"]}
        for r in sess.execute(
            select(st.ThreatID, func.max(st.Score).label("Score"),
                func.min(st.ScopeRank).label("ScopeRank"))
            .where(st.SessionID == session_id, st.Superseded == 0)
            .group_by(st.ThreatID)
        ).mappings()
    }


def has_active_scenarios(sess: Session, session_id: str) -> bool:
    """True iff the session has any active (Superseded=0) scenario row. decide_session_outcome uses
    it to keep an ERROR'd session with salvageable earlier batches in REVIEW instead of cancelling —
    a transient failure must never destroy already-committed, reviewable work."""
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
    """Restore the invariant "session at REVIEW => >=1 subsystem SCENARIOS row at
    AWAITING_DECISION". The salvage branch moves the SESSION to REVIEW but leaves the subsystem row
    ERROR, so accept's good_subs is empty and the session completes having accepted nothing (silent
    data loss). Flips the ERRORed row, in place at its current epoch, for every subsystem with an
    active scenario. Returns rows revived.

    `ErrorMessage` is PRESERVED — the only durable marker that this review set may be PARTIAL."""
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
    """The ONE IdentityHash fold: sha256(SessionID|SubsystemID|_dedup_key(info)). Every producer and
    consumer routes through here, so app-level dedup and the UX_Scenario_ActiveIdentity index can
    never disagree. `_dedup_key` is lazy-imported to keep dal below app.pipeline at load time."""
    from app.pipeline.tasks import _dedup_key
    return hashlib.sha256(f"{session_id}|{subsystem_id}|{_dedup_key(info)}".encode()).hexdigest()


def next_unserved_unique_threats(sess: Session, session_id: str, subsystem_id: int, n: int) -> list[str]:
    """Up to `n` active ThreatIDs whose dedup identity has NO active scenario yet — the pool
    "generate next set" serves from before falling back to a fresh AI batch.

    Best-first (Score desc, then ThreatID); an unscored threat has a NULL score and sorts last
    (LEFT JOIN) but stays eligible. Identity folds exactly like Threat_Scenario_Output's
    IdentityHash, so "already shown" == an active IdentityHash. Candidates sharing one identity
    collapse to the best-ranked, so one call never proposes an internal duplicate."""
    active_hashes = set(sess.execute(
        select(m.Threat_Scenario_Output.IdentityHash).where(
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.SubsystemID == subsystem_id,
            m.Threat_Scenario_Output.Superseded == 0,
            # complete ONLY — the same contract threats_with_active_scenario states: a threat
            # whose only active row is a FAILURE CARD has NOT been served, and the next-set sweep
            # must treat it as unserved. Without this predicate a failed generation stamps a real
            # IdentityHash here, the threat reads as done, and it becomes permanently unreachable
            # by "generate next set" — only a per-card regenerate recovers it. Every sibling read
            # of this table filters the same way; this query was the lone exception.
            m.Threat_Scenario_Output.Status == ScenarioStatus.complete,
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


def active_identified_threat_identities(sess: Session, session_id: str, subsystem_id: int) -> dict[str, str]:
    """Folded identity -> ThreatID of this (session, subsystem)'s ACTIVE Identified_Threat rows.
    find_threats(supersede=False) skips an additive proposal matching one — otherwise a
    re-proposal leaks a never-scored dead threat row (the index still blocks the duplicate
    scenario). The ThreatID rides along so a caught duplicate can record WHICH existing threat
    it matched (Identified_Duplicate_Threat.DuplicateOfThreatID) — previously computed here and
    discarded once the hash was folded."""
    identities: dict[str, str] = {}
    for r in sess.execute(
        select(m.Identified_Threat.ThreatID, m.Identified_Threat.ThreatCatalogueID,
            m.Identified_Threat.ThreatTypeID, m.Identified_Threat.ThreatType, m.Identified_Threat.ThreatName)
        .where(m.Identified_Threat.SessionID == session_id,
            m.Identified_Threat.SubsystemID == subsystem_id,
            m.Identified_Threat.Superseded == 0)
    ).mappings():
        identities[identity_hash(session_id, subsystem_id, _row_to_dedup_info(r))] = r["ThreatID"]
    return identities


def active_threat_rules(sess: Session, threat_type_ids: list[int]) -> list[dict]:
    """Active scoping rules for the given grounded master types ([R12], SDD §5.4) — one query,
    ordered by ThreatRuleID so evaluation and the FactorsJSON it records are deterministic.

    The rule's OWN IsActive/IsDeleted is not sufficient: with no foreign keys, soft-deleting a
    Threat_Type leaves its Config_Threat_Rule children live and still gating real generations. The
    EXISTS re-asserts the parent, as ON DELETE cascade would. Enforced here because this is the
    single choke point every rule read passes through."""
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
    """Accepted, non-superseded scenarios for one session, joined to their grounded threat so every
    row carries the [R13] join ids. One ordered query; a completed session's rows are immutable, so
    the joined tables need no Superseded filter.

    OUTER, not INNER: with no enforced foreign keys the ScopedThreatID/ThreatID linkage isn't
    guaranteed, and accept flipped Accepted=1 regardless. INNER would silently drop an
    already-accepted row while accept's own count still included it. Worst case is null threat_*
    columns, never a vanished row."""
    out, st, it = m.Threat_Scenario_Output, m.Scoped_Threat, m.Identified_Threat
    return [dict(r) for r in sess.execute(
        select(out.OutputID, out.SubsystemID, out.ScopedThreatID, out.ScenarioJSON,
            it.ThreatTypeID, it.ThreatCatalogueID, it.ThreatType, it.ThreatName,
            it.LibraryThreatType, it.LibraryThreatName, it.ThreatCategory, it.ThreatActorsJSON)
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
            it.LibraryThreatType, it.LibraryThreatName,
            # treatment.build_treatment_input reads these two; every other consumer maps
            # fields by name through explicit Pydantic models, so the extra keys are inert.
            it.ThreatCategory, it.ThreatActorsJSON)
        .select_from(out.__table__
            .join(ss, out.SessionID == ss.SessionID)
            .outerjoin(st, out.ScopedThreatID == st.ScopedThreatID)
            .outerjoin(it, st.ThreatID == it.ThreatID))
    )


def scenario_rows(sess: Session, *, entity_ids: set[str], user_id: str | None = None,
                status: str | None = None, include_superseded: bool = False,
                limit: int = 100, offset: int = 0) -> list[dict]:
    """Cross-session scenario list for the users/ and entities/ scenario routes.

    `entity_ids` is ALWAYS applied and must already be authorized by the caller — it is the
    object-level authz boundary, checked against Scenario_Session.EntityID (NOT NULL), never the
    nullable copy on the output row. Same for `user_id`: the session's UserID is the accountable
    owner, the output copy is provenance.

    `status`: 'accepted' filters the scenario flag, the others filter the parent session. Failure
    cards never appear — they have no narrative. Newest first, OutputID tiebreak."""
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
    """One output row by id. The SessionID predicate makes an OutputID from another session 404
    rather than leak. No Superseded/Status filter — an explicit-id fetch returns the row with its
    flags visible. None on a malformed GUID (→ 404, not a MSSQL 500 — see _valid_guid)."""
    if not _valid_guid(output_id):
        return None
    out = m.Threat_Scenario_Output
    return sess.execute(
        _scenario_read_select().where(out.OutputID == output_id, out.SessionID == session_id)
    ).mappings().first()


def mark_scenarios_accepted(
    sess: Session, session_id: str, subsystem_ids: list[int], subset: list[str] | None = None,
) -> int:
    """Accepted=1 on every non-superseded scenario for these subsystems (§5.7), optionally narrowed
    to `subset` OutputIDs — `subset=[]` means "accept none", `subset=None` means "accept all".

    Stamps `AcceptedSubsetJSON` only for a partial accept, so non-NULL means precisely "part of an
    explicit partial pick" and a reviewer needs no Scenario_Audit join.

    Returns rows actually flipped, so the caller can tell "N requested, M<N matched" from a clean
    accept — otherwise a subset id naming a wrong/superseded row vanishes silently."""
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
    """Why each requested OutputID could not be accepted — one code per id mark_scenarios_accepted
    would reject, mirroring its four predicates. Accepted ids are absent.

    FAILURE-PATH ONLY: run it once the counts already disagree, since that request is about to 404
    and roll back anyway.

    `SessionID == session_id` is a TENANT BOUNDARY, not an optimisation: an id from elsewhere must
    come back `unknown`, because "exists, wrong session" would confirm another tenant's row from an
    unauthenticated guess."""
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
    """Which of `threat_ids` already have an active scenario, joined via ScopedThreatID — the stable
    GUID link, resolved even if the scoped row was later superseded.

    write_scenarios keys next-set cleanup on this, NOT on "has an active scoped row": a REGEN target
    keeps its scenario, while a POOL ZOMBIE (rescored out by a mid-session tightening) has the old
    scoped row but NO scenario, so it gets superseded instead of re-served every click."""
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


def supersede_outputs_for_threats(sess: Session, session_id: str, subsystem_id: int, threat_ids) -> None:
    """Retire every active scenario hanging off these threats' active Scoped_Threat rows. Needs a
    subquery because Threat_Scenario_Output has no ThreatID column.

    CALL ORDER IS LOAD-BEARING: run BEFORE supersede_by_threats(Scoped_Threat, ...). Retire the
    scoped rows first and the subquery finds nothing, leaving outputs active but parentless —
    /results then renders the row in `scenarios[]` while dropping its threat from `threats[]`."""
    if not threat_ids:
        return
    scoped = select(m.Scoped_Threat.ScopedThreatID).where(
        m.Scoped_Threat.SessionID == session_id,
        m.Scoped_Threat.SubsystemID == subsystem_id,
        m.Scoped_Threat.ThreatID.in_(threat_ids),
        m.Scoped_Threat.Superseded == 0,
    )
    sess.execute(
        update(m.Threat_Scenario_Output)
        .where(
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.SubsystemID == subsystem_id,
            m.Threat_Scenario_Output.ScopedThreatID.in_(scoped),
            m.Threat_Scenario_Output.Superseded == 0,
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
    """Supersede active scenarios in this (session, subsystem) whose IdentityHash is in the set AND
    sit at `scenario_number` — one UPDATE. Regen skips `_select_unique_top_n`, so this is what keeps
    `UX_Scenario_ActiveIdentity` from colliding. `scenario_number` is REQUIRED: an identity-wide
    supersede would retire a sibling while regenerating another.

    RETURNS `{IdentityHash: retired OutputID}` so the caller stamps ReplacesOutputID from what was
    ACTUALLY retired, not the requested id — a collapsed duplicate target would otherwise be retired
    with nothing pointing at it.

    One statement, not SELECT-then-UPDATE: RETURNING reports exactly the rows this UPDATE changed,
    so the answer can't drift under a concurrent regen. MSSQL emits OUTPUT, SQLite 3.35+ RETURNING."""
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


def _entry_ids(scenario_json: str | None, key: str) -> list[int]:
    """Entry-point ids out of a ScenarioJSON blob under `key`; [] on anything unparseable.

    Tolerates every pre-coverage row: a scenario written before entry-point grounding existed
    simply has no such key and yields [], which the caller reads as "no coverage signal"."""
    try:
        data = json.loads(scenario_json) or {}
    except (TypeError, ValueError):
        return []
    raw = data.get(key)
    if isinstance(raw, int) and not isinstance(raw, bool):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [v for v in raw if isinstance(v, int) and not isinstance(v, bool)]


def variant_eligible_primaries(sess: Session, session_id: str, n: int, *,
                            rows: list, attempt_slack: int,
                            exclude_threat_ids: set[str] | None = None) -> list[dict]:
    """Up to `n` variant work items, best-first by the primary's Score — the ONLY path assigning a
    ScenarioNumber > 1. Scoped fields are cloned from the lowest-numbered COMPLETE scenario's scoped
    row, so a variant carries the same scoring provenance without re-scoping.

    COVERAGE, NOT A CAP: an identity stays eligible while a plausible entry point its primary
    declared is uncovered, so scenario count falls out of the architecture, not a constant.

    PLAUSIBILITY IS FROZEN at that lowest-numbered scenario, never unioned across later ones —
    union-growth livelocks (each round fills one cell and declares a new one). Frozen, the uncovered
    set is monotone non-increasing, which is what makes this terminate. `attempt_slack` bounds the
    other non-termination (nothing binds the model to the cell it was asked to fill) by stopping at
    `len(plausible) + attempt_slack` active rows.

    FAILS CLOSED when no target is derivable — no plausible entry points, no variants. It must NOT
    fall back to "every system is plausible": that vocabulary is rebuilt per call from live curator
    data, so it isn't frozen and would break the monotone property this rests on.

    Row counts include error cards, so scenario numbers never collide. `exclude_threat_ids` is
    applied before sort/[:n], so an exclusion frees its slot instead of shrinking the batch."""
    by_hash: dict[str, list] = {}
    for r in rows:
        by_hash.setdefault(r.IdentityHash, []).append(r)
    candidates: dict[str, tuple[int, str]] = {}  # hash -> (next_number, primary ScopedThreatID)
    for identity, group in by_hash.items():
        complete = [r for r in group if r.Status == ScenarioStatus.complete]
        if not complete:
            continue
        primary = min(complete, key=lambda r: r.ScenarioNumber)
        # FROZEN: tasks._ground_entry_points copies the primary's declaration onto every new
        # scenario, so this read is stable even across a regeneration that replaces it in place.
        plausible = set(_entry_ids(primary.ScenarioJSON, "plausible_entry_point_ids"))
        if not plausible:
            continue  # no coverage target derivable — fail closed, see docstring
        used = {eid for r in group for eid in _entry_ids(r.ScenarioJSON, "entry_point_id")}
        if not plausible - used:
            continue  # every plausible entry point covered — this threat is DONE
        if len(group) >= len(plausible) + attempt_slack:
            continue  # attempts bound: the model keeps re-using one entry point
        next_number = max(r.ScenarioNumber for r in group) + 1
        candidates[identity] = (next_number, primary.ScopedThreatID)
    if not candidates:
        return []
    st = m.Scoped_Threat
    scoped_rows = {r.ScopedThreatID: r for r in sess.execute(
        select(st.ScopedThreatID, st.ThreatID, st.Score, st.ScopeRank, st.Reason, st.FactorsJSON,
            st.SelectionKind)
        .where(st.ScopedThreatID.in_([sid_ for _, sid_ in candidates.values()]))
    ).all()}
    # Case-fold: MSSQL returns uniqueidentifier upper-case, the ORM/SQLite path lower-case, so a
    # raw compare would make the exclusion a silent no-op exactly in production.
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
                    "factors_json": sr.FactorsJSON,
                    # cloned like Reason/FactorsJSON, else the variant gets the column default
                    # while carrying the primary's prose (prose/enum drift)
                    "selection_kind": sr.SelectionKind})
    items.sort(key=lambda d: (-(d["score"] or 0), str(d["threat_id"])))
    return items[:n]


def active_scenario_rows(sess: Session, session_id: str, subsystem_id: int) -> list:
    """THE read of a session's active scenarios, INCLUDING error cards — coverage counts them and
    scenario numbers must never be reused. One function, not three: coverage, sibling steering and
    cross-threat comparison want the same rows, so fetch once and fold in tasks._fold_scenario_rows."""
    out = m.Threat_Scenario_Output
    return list(sess.execute(
        select(out.OutputID, out.IdentityHash, out.ScenarioNumber, out.Status,
            out.ScopedThreatID, out.ScenarioJSON)
        .where(out.SessionID == session_id, out.SubsystemID == subsystem_id,
            out.Superseded == 0, out.IdentityHash.is_not(None))
    ).all())


def insert_row(sess: Session, table, values: Mapping[str, Any]) -> None:
    """Generic single-row insert; callers must `supersede` the prior active row first."""
    sess.execute(insert(table).values(**values))


def audit_row(sess: Session, **cols: Any) -> dict[str, Any]:
    """One Scenario_Audit row with CreatedAt, ActorUserID and ActorType defaulted.

    `ActorUserID` = WHO IS ACCOUNTABLE: a background row back-fills the session's UserID, so a NULL
    never reads as missing data. `ActorType` is decided from whether the CALLER named a human,
    BEFORE that back-fill destroys the signal. Defaulting here means a future write cannot forget.
    # ponytail: per-write PK lookup; pass ActorUserID explicitly if audit volume ever matters."""
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
    """Append-only audit write for one row. Bulk callers build rows with `audit_row` instead —
    same defaults, one round trip, one place that decides what an audit row means."""
    sess.execute(insert(m.Scenario_Audit).values(**audit_row(sess, **cols)))


def latest_next_set_outcome(sess: Session, session_id: str, subsystem_id: int) -> dict | None:
    """DetailJSON of the newest `next_set_outcome` audit row, backing SessionProgress.last_next_set.
    Never `generation_complete` — one click can write two of those and they only make sense summed.
    Ordered by CreatedAt then AuditID: two rows of one fast click can share a clock tick."""
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


def latest_regen_outcome(sess: Session, session_id: str, subsystem_id: int) -> dict | None:
    """DetailJSON of the newest `regeneration_completed` audit row, backing
    SessionProgress.last_regen — the durable mirror of the SSE `regen_result` event, same
    rationale as `latest_next_set_outcome` above (plan item 3). Ordered the same way, for the
    same reason: two rows of one fast regen click can share a clock tick."""
    row = sess.execute(
        select(m.Scenario_Audit.DetailJSON)
        .where(m.Scenario_Audit.SessionID == session_id,
            m.Scenario_Audit.SubsystemID == subsystem_id,
            m.Scenario_Audit.EventType == AuditEventType.regeneration_completed)
        .order_by(m.Scenario_Audit.CreatedAt.desc(), m.Scenario_Audit.AuditID.desc())
        .limit(1)
    ).scalar()
    if not row:
        return None
    try:
        parsed = json.loads(row)
    except (TypeError, ValueError):  # a truncated/hand-edited row must not 500 a status poll
        log.warning("audit.regen_outcome_unparseable", session_id=session_id)
        return None
    return parsed if isinstance(parsed, dict) else None


# ---------------------------------------------------------------------------
# Threat-library promotion — race-safe insert-if-not-exists guarded by the M2 natural-key UNIQUE
# indexes. Same savepoint + catch-IntegrityError + select idiom as `create_session`: the loser of
# a concurrent promotion gets the winner's id back instead of a crash.
# ---------------------------------------------------------------------------
def upsert_threat_type(sess: Session, name: str, category_id: int | None, sector_id: int | None,
                    description: str | None = None, source: str = "ai_auto_promoted",
                    created_by: str | None = None) -> tuple[int, bool]:
    """Insert-if-not-exists on `UX_ThreatType_NaturalKey`; returns (winning ThreatTypeID, created).

    `created` is True only when THIS call inserted — accept.py gates actor linking on it, so links
    may seed a type minted in the same accept but never extend a curated type's actors.
    `source`/`created_by` are FIRST-WRITER provenance: the collision branch never writes Updated*,
    because re-asserting a row is not an edit."""
    # Bound to ThreatTypeName's real column width (Unicode(300)) before the INSERT: an over-long
    # name raises DataError, NOT the IntegrityError caught here, so it would abort the whole
    # accept-session transaction.
    name = name[:300]
    try:
        with sess.begin_nested():
            res = execute_dml(sess, insert(m.Threat_Type).values(
                ThreatTypeName=name, ThreatCategoryID=category_id, SectorID=sector_id,
                Description=description, IsActive=True, IsDeleted=False, Source=source,
                CreatedAt=now(), CreatedBy=created_by))
        return inserted_pk(res), True
    except IntegrityError:
        # BOTH predicates must be NULL-safe: SQL Server's unique index treats NULLs as equal, so
        # a second promotion with an unresolved category IS a natural-key collision — but
        # `== NULL` matches nothing, and the recovery lookup would re-raise and abort the accept.
        cat_pred = (m.Threat_Type.ThreatCategoryID.is_(None) if category_id is None
                    else m.Threat_Type.ThreatCategoryID == category_id)
        sector_pred = m.Threat_Type.SectorID.is_(None) if sector_id is None else m.Threat_Type.SectorID == sector_id
        winner = sess.execute(
            select(m.Threat_Type.ThreatTypeID).where(
                m.Threat_Type.ThreatTypeName == name,
                cat_pred, sector_pred,
                m.Threat_Type.IsActive == True, m.Threat_Type.IsDeleted == False)
        ).scalar()
        if winner is None:  # not a natural-key duplicate — fail loud, never return a NULL id
            raise
        return winner, False


def upsert_threat_catalogue(sess: Session, name: str, type_id: int, sector_id: int | None,
                            description: str | None = None, source: str = "ai_auto_promoted",
                            created_by: str | None = None) -> int:
    """Insert-if-not-exists on `UX_ThreatCatalogue_NaturalKey`; returns the winning id either way.
    Same first-writer provenance as upsert_threat_type. Does NOT link into
    Threat_Catalogue_Category_Map — call link_catalogue_category once you have a category id."""
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
    """Insert-if-not-exists keyed by `UX_ThreatActor_NaturalKey` (ThreatActorName, no sector);
    returns the winning ThreatActorID either way. Same first-writer provenance as
    upsert_threat_type."""
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
# Threat_Candidate_Review — the curator queue CandidateStatus's own docstring calls "reserved...
# set by the curator workflow when it lands". accept.py writes `pending` rows; these functions
# are that workflow.
# ---------------------------------------------------------------------------
def list_pending_candidates(sess: Session, *, limit: int) -> list[RowMapping]:
    """Every candidate awaiting curator review, oldest first — the admin API's
    GET /v1/tsg/threat-library/candidates. No filtered index needed: unlike promotion failures,
    `Status='pending'` is this table's own overwhelmingly common value while a row is unresolved,
    so a plain index on Status already keeps this narrow."""
    cr = m.Threat_Candidate_Review
    return sess.execute(
        select(cr.CandidateID, cr.TenantID, cr.EntityID, cr.SessionID, cr.ProposedCategory,
            cr.ProposedType, cr.ProposedName, cr.ProposedGenericName, cr.Status,
            cr.ThreatTypeID, cr.ThreatCatalogueID, cr.CreatedAt)
        .where(cr.Status == CandidateStatus.pending)
        .order_by(cr.CreatedAt.asc())
        .limit(limit)
    ).mappings().all()


def get_candidate(sess: Session, candidate_id: str) -> RowMapping | None:
    """One candidate's full detail, or None if the id doesn't exist — the admin API's
    GET .../candidates/{id} and the 404 gate for approve/reject."""
    cr = m.Threat_Candidate_Review
    return sess.execute(
        select(cr.CandidateID, cr.TenantID, cr.EntityID, cr.SessionID, cr.ProposedCategory,
            cr.ProposedType, cr.ProposedName, cr.ProposedGenericName, cr.Status,
            cr.ThreatTypeID, cr.ThreatCatalogueID, cr.ReviewedBy, cr.ReviewedAt, cr.CreatedAt)
        .where(cr.CandidateID == candidate_id)
    ).mappings().first()


def close_candidate_review(sess: Session, candidate_id: str, *, status: str,
                            reviewer_user_id: str | None, type_id: int | None = None,
                            catalogue_id: int | None = None) -> bool:
    """CAS-guarded resolution of one candidate: matches only a row still `pending`, so a second
    concurrent approve/reject (two admins, or a double-click) matches 0 rows and returns False —
    the caller reports 409 instead of re-running (or silently re-reporting) a mint that already
    happened. `type_id`/`catalogue_id` are the library ids this candidate resolved to; left
    unset (None → NULL columns unless already set) on a reject, since nothing was minted."""
    cr = m.Threat_Candidate_Review
    values: dict[str, Any] = {"Status": status, "ReviewedBy": reviewer_user_id, "ReviewedAt": now()}
    if type_id is not None:
        values["ThreatTypeID"] = type_id
    if catalogue_id is not None:
        values["ThreatCatalogueID"] = catalogue_id
    res = execute_dml(sess, update(cr)
                    .where(cr.CandidateID == candidate_id, cr.Status == CandidateStatus.pending)
                    .values(**values))
    return res.rowcount == 1


# ---------------------------------------------------------------------------
# Threat-library master CRUD (app/api/library_crud.py) — generic over the four masters because
# the steps are identical and only column names differ; four copies would be four places to
# forget the Updated* stamp. These are the ONLY functions that write UpdatedAt/UpdatedBy.
# ---------------------------------------------------------------------------
def create_library_row(sess: Session, model, values: dict, user_id: str | None) -> int:
    """Insert one master row stamped CreatedAt/CreatedBy; returns the new PK.

    IntegrityError escapes: only the caller knows which natural key was violated, and a clash is
    a real 409, not a retry."""
    # IsActive first so a caller value still wins; the rest last so nothing can forge its own
    # provenance stamp or be born deleted.
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
    """Partial update plus the Updated* stamp; omitted fields keep their value. Raises
    NotFoundError; IntegrityError escapes for the caller to translate. The 404 comes from the
    UPDATE's own rowcount, not a preceding SELECT — one statement, no window for a concurrent
    soft-delete. Missing and already-deleted are deliberately the same."""
    res = execute_dml(sess, update(model).where(pk_col == pk_value, model.IsDeleted == False)  # noqa: E712
                    .values(**values, UpdatedAt=now(), UpdatedBy=user_id))
    if not res.rowcount:
        raise NotFoundError(f"{model.__tablename__} {pk_value} not found")


def soft_delete_library_row(sess: Session, model, pk_col, pk_value: int, user_id: str | None) -> None:
    """IsDeleted=1 plus the same Updated* stamp — a delete IS an update, hence no DeletedBy column.
    Never a hard DELETE: completed sessions reference these ids. The natural-key indexes are
    filtered on IsDeleted=0, so the freed name/code is reusable. Same rowcount-not-SELECT reasoning
    as update_library_row, so two concurrent deletes can't both report success."""
    res = execute_dml(sess, update(model).where(pk_col == pk_value, model.IsDeleted == False)  # noqa: E712
                    .values(IsDeleted=True, UpdatedAt=now(), UpdatedBy=user_id))
    if not res.rowcount:
        raise NotFoundError(f"{model.__tablename__} {pk_value} not found")


def upsert_threat_rule(sess: Session, threat_type_id: int, rule_type: str, rule_key: str,
                    rule_value: str, weight: float, source: str) -> int:
    """Insert-if-not-exists on `UX_ConfigThreatRule_NaturalKey`; returns the winning id either way.
    IDENTITY assigns it (never MAX+1 in app code), and a re-import collapses onto the existing row
    instead of double-counting its weight (scoping._apply_rules sums fired weights). `source` lands
    in CreatedBy, marking auto-written rules."""
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
    """Idempotent link into `ThreatType_ThreatActor_Map`; True iff a NEW row was inserted, so
    callers can audit real library growth. The IntegrityError is absorbed only once the link is
    CONFIRMED present — a bad id raises through the same branch, and answering False would report
    "already linked" for a link that does not exist."""
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
    """Idempotent link into `Threat_Catalogue_Category_Map` — same composite-PK, race-safe-no-op,
    fail-loud contract as `link_type_actor`; True iff a NEW row was inserted. The map is
    multi-valued, so a second category is just a second call."""
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


# ---------------------------------------------------------------------------
# Risk Treatment Plan rows (docs/RISK_TREATMENT_PLAN_SDD.md §6). The plan row IS the state — no
# Subsystem_Stage_State involvement, since accepted scenarios live on completed sessions where
# acquire_lock refuses to run. Every conditional-UPDATE fence lives here; treatment.py and
# api/treatment.py never build their own SQL.
# ---------------------------------------------------------------------------
def supersede_active_plan(sess: Session, output_id: str, stale_cutoff: datetime) -> int:
    """Retire the scenario's active plan row so a new attempt can insert; returns rowcount. Matches
    only replaceable rows: finished, or a RUNNING claim stalled before `stale_cutoff`. A FRESH
    RUNNING row matches nothing, so the insert hits UX_TreatmentPlan_ActiveOutput → 409."""
    p = m.Risk_Treatment_Plan
    return execute_dml(sess, update(p).where(
        p.OutputID == output_id, p.Superseded == 0,
        or_(p.Status.in_([StageStatus.COMPLETE, StageStatus.ERROR]),
            and_(p.Status == StageStatus.RUNNING, p.UpdatedAt < stale_cutoff)),
    ).values(Superseded=1, UpdatedAt=now())).rowcount


def claim_plan(sess: Session, plan_id: str, task_id: str, stale_cutoff: datetime) -> bool:
    """Worker claim CAS; True iff we hold it. Admits unclaimed, the SAME task id (acks_late and
    autoretry_for both re-run with it unchanged — without this branch every retry no-ops and wedges
    the row), or a stale claim. False = someone else holds it, or the row is finished/superseded."""
    p = m.Risk_Treatment_Plan
    return execute_dml(sess, update(p).where(
        p.PlanID == plan_id, p.Superseded == 0, p.Status == StageStatus.RUNNING,
        or_(p.ActiveTaskID.is_(None), p.ActiveTaskID == task_id, p.UpdatedAt < stale_cutoff),
    ).values(ActiveTaskID=task_id, UpdatedAt=now())).rowcount == 1


def touch_plan(sess: Session, plan_id: str) -> None:
    """Bump the progress clock before each LLM attempt, so treatment_stale_seconds measures "no
    progress", not wall time. Fenced on (RUNNING, not superseded) — a zombie must not smudge a
    retired row's stop timestamp, which is what a post-mortem reads.
    # ponytail: one UPDATE per attempt, not a heartbeat thread."""
    p = m.Risk_Treatment_Plan
    execute_dml(sess, update(p).where(
        p.PlanID == plan_id, p.Superseded == 0, p.Status == StageStatus.RUNNING,
    ).values(UpdatedAt=now()))


def finish_plan(sess: Session, plan_id: str, *, status: StageStatus, task_id: str | None,
                plan_json: str | None = None, validation_json: str | None = None,
                error_message: str | None = None,
                error_reason: TreatmentOutcomeReason | None = None) -> bool:
    """Terminal CAS to COMPLETE or ERROR. Fenced on (RUNNING, not superseded), so a superseded or
    already-finished row matches 0 rows and the caller drops its result instead of resurrecting a
    retired plan. ALSO fenced on ActiveTaskID — a zombie worker's late result must not clobber a
    claim that has since been taken over (claim_plan's stale-claim branch is what makes a
    takeover possible). Required, not defaulted: every caller must consciously state who they
    are, same discipline as claim_stage/finish_stage. `task_id=None` means "only if still
    unclaimed" (ActiveTaskID IS NULL) — for a freshly-inserted row nothing has claimed yet, or a
    caller re-asserting a value it just read off the row itself; a real task_id must match
    exactly.

    `error_reason` is the machine-readable half of an ERROR (TreatmentOutcomeReason) so no client
    ever parses `error_message`. Pass it on EVERY ERROR path; leave it None for COMPLETE, where the
    column is meaningless. It is deliberately not defaulted per-status — a silent NULL on a failure
    is exactly the ambiguity this column exists to remove."""
    p = m.Risk_Treatment_Plan
    return execute_dml(sess, update(p).where(
        p.PlanID == plan_id, p.Superseded == 0, p.Status == StageStatus.RUNNING,
        p.ActiveTaskID.is_(None) if task_id is None else p.ActiveTaskID == task_id,
    ).values(Status=status, PlanJSON=plan_json, ValidationJSON=validation_json,
            ErrorMessage=error_message, ErrorReason=error_reason,
            UpdatedAt=now(), CompletedAt=now())).rowcount == 1


def active_plan_row(sess: Session, session_id: str, output_id: str) -> RowMapping | None:
    """The scenario's one active plan row for the GET poll, with its scenario JSON alongside. The
    SessionID predicate keeps a foreign OutputID a 404, not a leak; None on a malformed GUID.
    Explicit columns, NOT the whole table — InputSnapshotJSON is tens of KB this poll never returns."""
    if not _valid_guid(output_id):
        return None
    p, out = m.Risk_Treatment_Plan, m.Threat_Scenario_Output
    st, it = m.Scoped_Threat, m.Identified_Threat
    return sess.execute(
        select(p.PlanID, p.SessionID, p.OutputID, p.TenantID, p.EntityID, p.Status,
            p.ActiveTaskID, p.TreatmentStrategy, p.RiskIdentificationDate, p.PlanJSON,
            p.ValidationJSON, p.ErrorMessage, p.RiskLevel, p.ReviewStatus, p.ReviewComment,
            p.ReviewedBy, p.ReviewedAt, p.ErrorReason, p.CreatedAt, p.UpdatedAt, p.CompletedAt,
               out.ScenarioJSON,
            # The threat's own identity — NOT part of the LLM's scenario JSON (same split as
            # sessions._build_scenario). OUTER for the same reason as _scenario_read_select:
            # no enforced FKs, so a broken linkage must null these, never drop the plan row.
            it.ThreatCategory, it.ThreatType, it.ThreatName, it.ThreatActorsJSON)
        .select_from(p.__table__.outerjoin(out, out.OutputID == p.OutputID)
                    .outerjoin(st, out.ScopedThreatID == st.ScopedThreatID)
                    .outerjoin(it, st.ThreatID == it.ThreatID))
        .where(p.SessionID == session_id, p.OutputID == output_id, p.Superseded == 0)
    ).mappings().first()


def review_plan(sess: Session, plan_id: str, *, status: str, comment: str | None,
                reviewer: str | None, reviewed_at: datetime) -> bool:
    """Record the human adoption decision, CAS-fenced on (COMPLETE, not superseded): only a
    finished, current plan is adoptable, a re-review overwrites, and a regenerated plan is a NEW
    row so approval never carries across versions. `reviewed_at` comes from the caller so the
    response echoes the exact stored instant."""
    p = m.Risk_Treatment_Plan
    return execute_dml(sess, update(p).where(
        p.PlanID == plan_id, p.Superseded == 0, p.Status == StageStatus.COMPLETE,
    ).values(ReviewStatus=status, ReviewComment=comment, ReviewedBy=reviewer,
            ReviewedAt=reviewed_at, UpdatedAt=reviewed_at)).rowcount == 1


def session_plan_board(sess: Session, session_id: str) -> list[RowMapping]:
    """One row per accepted, active scenario of the session, LEFT-joined to its active plan (NULL
    plan columns = never requested). Excludes PlanJSON — the board is a glance, the single-plan
    GET is the document; ScenarioJSON rides along only because the title lives inside it."""
    out, p = m.Threat_Scenario_Output, m.Risk_Treatment_Plan
    return sess.execute(
        select(out.OutputID, out.ScenarioJSON,
            p.PlanID, p.Status, p.RiskLevel, p.ReviewStatus, p.ErrorMessage, p.ErrorReason,
            p.CreatedAt.label("PlanCreatedAt"), p.UpdatedAt.label("PlanUpdatedAt"),
            p.CompletedAt.label("PlanCompletedAt"))
        .select_from(out.__table__.outerjoin(
            p, and_(p.OutputID == out.OutputID, p.Superseded == 0)))
        .where(out.SessionID == session_id, out.Accepted == 1, out.Superseded == 0)
        .order_by(out.CreatedAt, out.OutputID)
    ).mappings().all()


def entity_plan_rows(sess: Session, entity_id: str, *, stale_cutoff: datetime,
                    status: str | None = None, review_status: str | None = None,
                    risk_level: str | None = None, limit: int = 100,
                    offset: int = 0) -> list[RowMapping]:
    """Entity-wide remediation register: every active plan across the entity's sessions, newest
    first. Filters Scenario_Session.EntityID — the NOT NULL authz truth, never the nullable copy.

    `status` matches the PRESENTED status: a stale RUNNING row projects to ERROR at read time, so it
    must surface under status=ERROR and stay out of status=RUNNING. Branched in SQL, not
    post-filtered in Python, which would under-fill pages. ScenarioTitle comes from JSON_VALUE
    server-side rather than hauling every multi-KB blob; malformed JSON yields NULL."""
    p, ss, out = m.Risk_Treatment_Plan, m.Scenario_Session, m.Threat_Scenario_Output
    stmt = (
        select(p.PlanID, p.SessionID, p.OutputID, p.Status, p.RiskLevel, p.ReviewStatus,
            p.ReviewedBy, p.ReviewedAt, p.ErrorMessage, p.ErrorReason, p.CreatedAt, p.UpdatedAt,
            p.CompletedAt, ss.AssetName,
            func.json_value(out.ScenarioJSON, "$.scenario_title").label("ScenarioTitle"))
        .select_from(p.__table__
            .join(ss, ss.SessionID == p.SessionID)
            .outerjoin(out, out.OutputID == p.OutputID))
        .where(ss.EntityID == entity_id, p.Superseded == 0))
    if status == str(StageStatus.ERROR):
        stmt = stmt.where(or_(p.Status == StageStatus.ERROR,
                            and_(p.Status == StageStatus.RUNNING,
                                p.UpdatedAt < stale_cutoff)))
    elif status == str(StageStatus.RUNNING):
        stmt = stmt.where(p.Status == StageStatus.RUNNING, p.UpdatedAt >= stale_cutoff)
    elif status is not None:
        stmt = stmt.where(p.Status == status)
    if review_status is not None:
        stmt = stmt.where(p.ReviewStatus == review_status)
    if risk_level is not None:
        stmt = stmt.where(p.RiskLevel == risk_level)
    return sess.execute(
        stmt.order_by(p.CreatedAt.desc(), p.PlanID).limit(limit).offset(offset)
    ).mappings().all()


def plan_history_rows(sess: Session, session_id: str, output_id: str) -> list[RowMapping]:
    """Every version (active and superseded) of one scenario's plan, oldest first. Rows are never
    deleted, so this IS the complete history."""
    if not _valid_guid(output_id):
        return []
    p = m.Risk_Treatment_Plan
    return sess.execute(
        select(p.PlanID, p.Status, p.Superseded, p.ErrorMessage, p.RiskLevel, p.ReviewStatus,
            p.ReviewedBy, p.ReviewedAt, p.CreatedAt, p.UpdatedAt, p.CompletedAt)
        .where(p.SessionID == session_id, p.OutputID == output_id)
        .order_by(p.CreatedAt)
    ).mappings().all()


def plan_row_by_id(sess: Session, session_id: str, output_id: str, plan_id: str) -> RowMapping | None:
    """One specific plan version for the evidence endpoint. The session/output predicates keep a
    foreign plan id a 404 rather than a leak; superseded versions are deliberately readable.
    Explicit columns — PlanJSON and ReviewComment are blobs this endpoint never returns."""
    if not (_valid_guid(output_id) and _valid_guid(plan_id)):
        return None
    p = m.Risk_Treatment_Plan
    return sess.execute(
        select(p.PlanID, p.Status, p.InputSnapshotJSON, p.ValidationJSON).where(
            p.PlanID == plan_id, p.SessionID == session_id, p.OutputID == output_id)
    ).mappings().first()


#: The treatment-plan lifecycle events. A tuple, not a set — byte-stable SQL for the plan cache.
_TREATMENT_EVENTS = (
    AuditEventType.treatment_plan_requested, AuditEventType.treatment_plan_outcome,
    AuditEventType.treatment_plan_cancelled, AuditEventType.treatment_plan_reviewed)


def treatment_audit_rows(sess: Session, session_id: str) -> list[RowMapping]:
    """All treatment-plan audit events of one session, oldest first; the trail endpoint narrows
    them to one scenario in Python, since DetailJSON is opaque to SQL here."""
    a = m.Scenario_Audit
    return sess.execute(
        select(a.EventType, a.ActorUserID, a.ActorType, a.DetailJSON, a.CreatedAt)
        .where(a.SessionID == session_id, a.EventType.in_(_TREATMENT_EVENTS))
        .order_by(a.CreatedAt, a.AuditID)
    ).mappings().all()


def entity_treatment_audit_rows(sess: Session, entity_id: str, *, since=None, until=None,
                                actor: str | None = None, limit: int = 200,
                                offset: int = 0) -> list[RowMapping]:
    """The entity-wide treatment audit feed (compliance export), newest first. Filters the audit
    rows' own EntityID, always server-written from the session row at event time."""
    a = m.Scenario_Audit
    stmt = (
        select(a.SessionID, a.EventType, a.ActorUserID, a.ActorType, a.DetailJSON, a.CreatedAt)
        .where(a.EntityID == entity_id, a.EventType.in_(_TREATMENT_EVENTS)))
    if since is not None:
        stmt = stmt.where(a.CreatedAt >= since)
    if until is not None:
        stmt = stmt.where(a.CreatedAt <= until)
    if actor is not None:
        stmt = stmt.where(a.ActorUserID == actor)
    return sess.execute(
        stmt.order_by(a.CreatedAt.desc(), a.AuditID.desc()).limit(limit).offset(offset)
    ).mappings().all()


def prompt_logs_for_plan(sess: Session, plan_id: str) -> list[RowMapping]:
    """Every AI-call receipt for one plan version, oldest first, joined on Prompt_Log.CorrelationID
    (stamped by the worker), never by time-window guessing. Rows predating that column do not
    appear."""
    if not _valid_guid(plan_id):
        return []
    pl = m.Prompt_Log
    return sess.execute(
        select(pl.Prompt, pl.ResponseText, pl.Model, pl.ModelVersion, pl.PromptVersion,
            pl.ParseSucceeded, pl.CreatedAt)
        .where(pl.CorrelationID == plan_id)
        .order_by(pl.CreatedAt)
    ).mappings().all()
