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
from app.core.enums import (
    RetryOutcome,
    SessionStatus,
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import now
from app.pipeline.accept import run_promotion_phase
from app.sse import bus

log = get_logger(__name__)

def _split_into_batches(items):
    """Yield <=Settings.reaper_sql_in_chunk_size slices (default 1000; bounded <=2000 by config —
    SQL Server caps a statement near 2100 params) so a mass-crash id list can't blow past the
    IN-param cap. Empty input yields nothing — callers need no separate `if items:` guard."""
    items = list(items)
    chunk = get_settings().reaper_sql_in_chunk_size
    for i in range(0, len(items), chunk):
        yield items[i:i + chunk]


def clean_up_abandoned_sessions(sess: Session) -> list[str]:
    """The main cleanup pass. Returns the session ids driven to a terminal 'cancelled' state."""
    ss = m.Subsystem_Stage_State
    lease = ss.LeaseExpiresAt
    _now = now()
    expired = and_(lease.isnot(None), lease < _now)

    # Read-only, RCSI-safe candidate scan (module docstring) — a plain SELECT never locks what it
    # reads, so finding candidates can't collide with a live worker's open transaction.
    # SubsystemID rides along so the publish below can carry it (dual-scope `error` convention).
    expired_work = sess.execute(
        select(ss.StateID, ss.SessionID, ss.SubsystemID).where(
            ss.Level != SubsystemLevel.LOCK, ss.Status == StageStatus.RUNNING, expired)).all()
    expired_locks = sess.execute(
        select(ss.StateID, ss.SessionID, ss.SubsystemID).where(
            ss.Level == SubsystemLevel.LOCK, ss.Status == StageStatus.RUNNING, expired)).all()

    # Capture which sessions are PROVEN dead BEFORE steps 1/2 clear that evidence: every terminal
    # transition clears LeaseExpiresAt, so step 1's own ERROR-flip erases the proof it acts on.
    proven_dead = {row[1] for row in expired_work} | {row[1] for row in expired_locks}

    # 1. Expired RUNNING work stages (worker died mid-stage) → ERROR. Clear the lease too: a
    #    terminal row carries no live lease. Targeted by StateID + re-checked status/expiry — a
    #    CAS, not a blind sweep, so it only locks rows the snapshot read above proved expired and
    #    matches nothing if one was revived in between.
    work_ids = [row[0] for row in expired_work]
    for chunk in _split_into_batches(work_ids):
        sess.execute(
            update(ss)
            .where(ss.StateID.in_(chunk), ss.Status == StageStatus.RUNNING, expired)
            .values(Status=StageStatus.ERROR, LeaseExpiresAt=None, UpdatedAt=_now)
        )
    # 2. Reclaim expired RUNNING `_LOCK` rows → IDLE so the reaper (and any redelivery) can re-take them.
    lock_ids = [row[0] for row in expired_locks]
    for chunk in _split_into_batches(lock_ids):
        sess.execute(
            update(ss)
            .where(ss.StateID.in_(chunk), ss.Status == StageStatus.RUNNING, expired)
            .values(Status=StageStatus.IDLE, ActiveTaskID=None, LeaseExpiresAt=None, UpdatedAt=_now)
        )
    sess.commit()  # durable before step 3 takes any lock

    # Publish AFTER commit, so a client's refetch (triggered by the event) sees the write above
    # already durable — never publish-then-commit. Item 5: these are the reaper's first two
    # bus.publish sites (a client watching live no longer waits for the next board refetch).
    for _, session_id, subsystem_id in expired_work:
        bus.publish(session_id, {"type": str(SSEEventType.error), "session_id": session_id,
                                "subsystem_id": subsystem_id,
                                "message": "stage lease expired: worker presumed dead",
                                "ts": _now.isoformat()})
    for _, session_id, subsystem_id in expired_locks:
        bus.publish(session_id, {"type": str(SSEEventType.error), "session_id": session_id,
                                "subsystem_id": subsystem_id,
                                "message": "asset lock reclaimed: worker presumed dead",
                                "ts": _now.isoformat()})

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
    from app.pipeline.tasks import (
        decide_session_outcome,  # local import breaks a circular import
    )

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
        result = sess.execute(
            update(m.Subsystem_Stage_State)
            .where(m.Subsystem_Stage_State.SessionID == sid,
                m.Subsystem_Stage_State.Level != SubsystemLevel.LOCK,
                m.Subsystem_Stage_State.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]))
            # now(), not _now: this write happens later, under the lock
            .values(Status=StageStatus.ERROR, ErrorMessage="reaped: worker gone", LeaseExpiresAt=None, UpdatedAt=now())
        )
        # decide_session_outcome runs first — with every leftover row now ERROR (or already
        # terminal), it is guaranteed to take the AWAITING_DECISION or ERROR branch below and
        # commit there, so our publish (item 5's third write site) fires only once that commit
        # has made this UPDATE durable, never before it, matching the publish-after-commit
        # ordering steps 1/2 above use.
        outcome = decide_session_outcome(sess, scenario_session)
        # Session-scoped (no single subsystem_id: this can flip several subsystems' leftover rows
        # at once), and only when rows actually changed, or a session with nothing left to reap
        # would fire a spurious error on every abandoned-session sweep pass.
        if result.rowcount:
            bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid,
                            "message": "reaped: worker gone, unfinished work marked failed",
                            "ts": now().isoformat()})
        return outcome
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


def retry_one_promotion(sess: Session, session_id: str, entity_id: str,
                        promotion_user_id: str | None) -> RetryOutcome:
    """Retry exactly one session's previously-failed library promotion. Used by BOTH the
    periodic sweep below and the admin API's manual retry-now action, so there is exactly one
    place that acquires the session's locks and decides the RetryOutcome — not two copies that
    could drift apart.

    Has NO concept of promotion_max_attempts — that cap is applied only by the sweep's own
    candidate query below, never here, so a human-triggered retry can never be blocked by a limit
    meant for the unattended sweep.

    Returns RetryOutcome.skipped if the session's subsystem locks are already held (a live
    worker, or another retry already in flight for this same session) — WITHOUT touching
    PromotionAttempts/PromotionError, since lock contention is not a functional failure and must
    never burn one of the sweep's limited automatic attempts. Returns .succeeded or .failed per
    accept.run_promotion_phase's own outcome otherwise; never raises."""
    scenario_session = dal.get_session(sess, session_id, entity_id)
    if scenario_session is None:
        return RetryOutcome.skipped  # session vanished/reassigned between the candidate scan and this call

    lock_subsystem_ids = dal.subsystem_ids_at_level(sess, session_id, SubsystemLevel.LOCK)
    acquired: list[int] = []
    try:
        for subsystem_id in lock_subsystem_ids:
            # acquire_promotion_retry_lock, NOT acquire_lock: this session is always already
            # completed by the time a promotion retry runs, and plain acquire_lock's CAS
            # requires SessionStatus == active — it would never succeed here at all.
            if not dal.acquire_promotion_retry_lock(sess, session_id, subsystem_id, task_id=session_id):
                return RetryOutcome.skipped  # a concurrent retry/dismiss owns this session right now
            acquired.append(subsystem_id)
            sess.commit()  # durable before other work — same reasoning as accept_session's own lock loop
        good_subsystem_ids = dal.subsystem_ids_at_level(
            sess, session_id, SubsystemLevel.SCENARIOS, status=StageStatus.AWAITING_DECISION)
        succeeded = run_promotion_phase(sess, scenario_session, good_subsystem_ids, promotion_user_id, acquired)
        return RetryOutcome.succeeded if succeeded else RetryOutcome.failed
    finally:
        # Isolate each release: one raising must not skip the remaining locks or the commit
        # below, same discipline as _close_out_one_abandoned_session above.
        for subsystem_id in acquired:
            try:
                dal.release_lock(sess, session_id, subsystem_id, task_id=session_id)
            except Exception:
                log.warning("reaper.promotion_retry_lock_release_failed", session_id=session_id,
                            subsystem_id=subsystem_id, exc_info=True)
        sess.commit()


def dismiss_promotion(sess: Session, session_id: str, entity_id: str,
                    dismissed_by: str | None) -> RetryOutcome:
    """Admin "dismiss" — stop tracking/retrying this session's failed promotion, without
    attempting the promotion again. Acquires the SAME per-session lock retry_one_promotion uses
    before clearing the 4 columns, so a dismiss can never be silently undone by a retry that was
    already mid-flight and fails again right after (or vice versa — the two are fully serialized).

    Returns RetryOutcome.skipped (nothing changed) if the lock is currently held — a live worker
    or an in-flight retry owns this session right now; the caller should ask the admin to try
    again shortly. Returns .succeeded otherwise; never .failed — dismissing cannot fail once the
    lock is acquired, it is a single unconditional column clear."""
    lock_subsystem_ids = dal.subsystem_ids_at_level(sess, session_id, SubsystemLevel.LOCK)
    acquired: list[int] = []
    try:
        for subsystem_id in lock_subsystem_ids:
            # acquire_promotion_retry_lock, NOT acquire_lock — see retry_one_promotion's own
            # comment: this session is always already completed here, and plain acquire_lock's
            # CAS requires SessionStatus == active, so it would never succeed at all.
            if not dal.acquire_promotion_retry_lock(sess, session_id, subsystem_id, task_id=session_id):
                return RetryOutcome.skipped
            acquired.append(subsystem_id)
            sess.commit()
        dal.clear_promotion_failure(sess, session_id)
        sess.commit()
        log.info("session.promotion_dismissed", session_id=session_id, entity_id=entity_id,
                dismissed_by=dismissed_by)
        return RetryOutcome.succeeded
    finally:
        for subsystem_id in acquired:
            try:
                dal.release_lock(sess, session_id, subsystem_id, task_id=session_id)
            except Exception:
                log.warning("reaper.promotion_dismiss_lock_release_failed", session_id=session_id,
                            subsystem_id=subsystem_id, exc_info=True)
        sess.commit()


def retry_failed_promotions(sess: Session) -> list[str]:
    """Periodic sweep: automatically retries every session whose library promotion previously
    failed and hasn't exhausted `promotion_max_attempts`, IF `promotion_auto_retry_enabled` is
    on. Returns the session ids that succeeded this pass.

    Re-reads `promotion_auto_retry_enabled` on EVERY call rather than caching it at process
    start, so an admin flipping the setting takes effect on the very next scheduled tick with no
    worker/beat restart needed."""
    settings = get_settings()
    if not settings.promotion_auto_retry_enabled:
        log.info("reaper.promotion_auto_retry_disabled")
        return []

    candidates = dal.list_pending_promotions(
        sess, limit=settings.promotion_sweep_batch_limit, include_exhausted=False,
        max_attempts=settings.promotion_max_attempts)
    succeeded: list[str] = []
    for candidate in candidates:
        session_id = candidate["SessionID"]
        try:
            outcome = retry_one_promotion(
                sess, session_id, candidate["EntityID"], candidate["PromotionUserID"])
            if outcome == RetryOutcome.succeeded:
                succeeded.append(session_id)
        except Exception:  # one broken session must never stop the pass ([R8], same as clean_up_abandoned_sessions)
            log.warning("reaper.promotion_retry_failed", session_id=session_id, exc_info=True)
            sess.rollback()
    if succeeded:
        log.info("reaper.promotions_retried", sessions=succeeded)
    return succeeded
