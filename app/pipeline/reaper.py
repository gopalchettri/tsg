"""Stuck-job reaper.

A worker that dies leaves a session that never reaches its terminal state → the per-asset lock
leaks and the asset is `409` forever. The safety net for *every* abandonment point:
- a work stage RUNNING with an expired lease (died mid-stage) → ERROR;
- a `_LOCK` RUNNING with an expired lease → reclaimed to IDLE;
- then any session with NO live lease that is either proven dead or never-started-and-stale is
    driven through the SAME `decide_session_outcome` the pipeline uses — partial success →
    REVIEW, total failure → cancelled — **under the `_LOCK` mutex**, so it can never race a live
    worker or an in-flight accept.

Steps 1/2 SELECT candidate rows before UPDATEing them, deliberately: an UPDATE's own WHERE
evaluation takes locking reads (RCSI's snapshot only covers plain SELECTs), so a blind
`UPDATE ... WHERE Status='RUNNING' AND expired` would lock-check EVERY running row across every
session — including one a live worker holds open across an in-flight LLM call. On the gevent
worker that wait is a reproduced live deadlock: pyodbc's blocking wait can't yield the hub, so
the greenlet that would release the lock freezes too. Selecting first means the reaper only ever
tries to lock rows a non-blocking snapshot read already proved expired.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import and_, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import SessionStatus, StageStatus, SubsystemLevel, WorkflowStage
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import now

log = get_logger(__name__)

_IN_CHUNK = 1000  # SQL Server caps a statement near 2100 params; keep IN-lists well under it


def _split_into_batches(items):
    """Yield <=_IN_CHUNK slices so a mass-crash id list can't blow past the IN-param cap.
    Empty input yields nothing — callers need no separate `if items:` guard."""
    items = list(items)
    for i in range(0, len(items), _IN_CHUNK):
        yield items[i:i + _IN_CHUNK]


def clean_up_abandoned_sessions(sess: Session) -> list[str]:
    """The main cleanup pass. Returns the session ids driven to a terminal 'cancelled' state."""
    ss = m.Subsystem_Stage_State
    lease = ss.LeaseExpiresAt
    _now = now()
    expired = and_(lease.isnot(None), lease < _now)

    # Read-only, RCSI-safe candidate scan (module docstring) — a plain SELECT never locks what it
    # reads, so finding candidates can't collide with a live worker's open transaction.
    expired_work = sess.execute(
        select(ss.StateID, ss.SessionID).where(
            ss.Level != SubsystemLevel.LOCK, ss.Status == StageStatus.RUNNING, expired)).all()
    expired_locks = sess.execute(
        select(ss.StateID, ss.SessionID).where(
            ss.Level == SubsystemLevel.LOCK, ss.Status == StageStatus.RUNNING, expired)).all()

    # Capture which sessions are PROVEN dead BEFORE steps 1/2 clear that evidence: every terminal
    # transition clears LeaseExpiresAt, so step 1's own ERROR-flip erases the proof it acts on.
    proven_dead = {session_id for _, session_id in expired_work} | {session_id for _, session_id in expired_locks}

    # 1. Expired RUNNING work stages (worker died mid-stage) → ERROR. Clear the lease too: a
    #    terminal row carries no live lease. Targeted by StateID + re-checked status/expiry — a
    #    CAS, not a blind sweep, so it only locks rows the snapshot read above proved expired and
    #    matches nothing if one was revived in between.
    work_ids = [state_id for state_id, _ in expired_work]
    for chunk in _split_into_batches(work_ids):
        sess.execute(
            update(ss)
            .where(ss.StateID.in_(chunk), ss.Status == StageStatus.RUNNING, expired)
            .values(Status=StageStatus.ERROR, LeaseExpiresAt=None, UpdatedAt=_now)
        )
    # 2. Reclaim expired RUNNING `_LOCK` rows → IDLE so the reaper (and any redelivery) can re-take them.
    lock_ids = [state_id for state_id, _ in expired_locks]
    for chunk in _split_into_batches(lock_ids):
        sess.execute(
            update(ss)
            .where(ss.StateID.in_(chunk), ss.Status == StageStatus.RUNNING, expired)
            .values(Status=StageStatus.IDLE, ActiveTaskID=None, LeaseExpiresAt=None, UpdatedAt=_now)
        )
    sess.commit()  # durable before step 3 takes any lock

    # 3. Finalize every abandoned session through the SAME rule the pipeline uses.
    cancelled: list[str] = []
    for c in _find_abandoned_sessions(sess, _now, proven_dead):
        try:
            if _close_out_one_abandoned_session(sess, dict(c)) == "cancelled":
                cancelled.append(c["SessionID"])
        except Exception:  # one broken session must never stop the pass ([R8])
            log.warning("reaper.finalize_failed", session_id=c["SessionID"], exc_info=True)
            sess.rollback()  # or the failed attempt poisons the next session's
    if cancelled:
        log.warning("reaper.cancelled", sessions=cancelled)
    return cancelled


def _find_abandoned_sessions(sess: Session, _now: datetime, proven_dead: set[str]):
    """Active, non-REVIEW sessions with NO live lease that are either PROVEN dead this pass or
    never-started-and-stale (untouched for a full lease window — the never-enqueued leak, or a
    regen whose epoch was reserved but whose task never ran). A session at REVIEW is a legitimate
    human wait and is never reaped. A long-finished stage's lease is always NULL, so a session
    sitting briefly outside REVIEW can never look abandoned on that alone."""
    grace = _now - timedelta(seconds=get_settings().reaper_stale_grace_seconds)
    ss = m.Subsystem_Stage_State
    # some worker is still actively working on this session
    live_lease = (select(1).select_from(ss)
                .where(ss.SessionID == m.Scenario_Session.SessionID, ss.LeaseExpiresAt > _now)
                .exists())
    base = (select(m.Scenario_Session.SessionID, m.Scenario_Session.TenantID, m.Scenario_Session.EntityID)
            .where(m.Scenario_Session.SessionStatus == SessionStatus.active,
                m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW,
                ~live_lease))
    # The two abandonment branches run separately and dedupe by SessionID so `proven_dead` can be
    # chunked past SQL Server's ~2100-param IN cap on a mass crash.
    out: dict = {}
    for row in sess.execute(base.where(m.Scenario_Session.UpdatedAt < grace)).mappings():
        out[row["SessionID"]] = row
    for chunk in _split_into_batches(proven_dead):
        for row in sess.execute(base.where(m.Scenario_Session.SessionID.in_(chunk))).mappings():
            out[row["SessionID"]] = row
    return list(out.values())


def _close_out_one_abandoned_session(sess: Session, scenario_session: dict) -> str | None:
    """Finalize ONE abandoned session under the `_LOCK` mutex. Acquire every `_LOCK`; if any is
    held, a live worker or an in-flight accept owns the session → leave it untouched (return
    None). Once we hold them all the session is provably quiescent: flag its un-runnable leftover
    work rows ERROR, then run the SAME finalize — partial→REVIEW, total→cancelled."""
    from app.pipeline.tasks import decide_session_outcome  # local import breaks a circular import

    sid = scenario_session["SessionID"]
    lock_subs = [r[0] for r in sess.execute(
        select(m.Subsystem_Stage_State.SubsystemID)
        .where(m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.Level == SubsystemLevel.LOCK)).all()]
    acquired: list[int] = []
    try:
        for ssid in lock_subs:
            if not dal.acquire_lock(sess, sid, ssid, task_id=sid):
                return None  # a live worker/accept holds this subsystem → don't touch the session
            acquired.append(ssid)
        # Quiescent: leftover un-runnable work rows can never complete now → mark them ERROR so
        # finalize sees a fully-terminal board instead of waiting forever on a dead worker's row.
        sess.execute(
            update(m.Subsystem_Stage_State)
            .where(m.Subsystem_Stage_State.SessionID == sid,
                m.Subsystem_Stage_State.Level != SubsystemLevel.LOCK,
                m.Subsystem_Stage_State.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]))
            # now(), not _now: this write happens later, under the lock
            .values(Status=StageStatus.ERROR, ErrorMessage="reaped: worker gone", LeaseExpiresAt=None, UpdatedAt=now())
        )
        return decide_session_outcome(sess, scenario_session)
    finally:
        # Isolate each release: one raising must not skip the remaining locks or the commit
        # below — the releases are only durable once committed, so a mid-loop escape leaves even
        # the already-released ones stuck RUNNING until the next pass's lease-expiry reclaim.
        for ssid in acquired:
            try:
                dal.release_lock(sess, sid, ssid, task_id=sid)  # same holder id we acquired under
            except Exception:
                log.warning("reaper.lock_release_failed", session_id=sid, subsystem=ssid, exc_info=True)
        sess.commit()
