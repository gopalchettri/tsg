"""Stuck-job reaper.

A worker that dies leaves a session stuck mid-run — the per-asset lock never releases and the
asset returns 409 forever. This is the safety net for every abandonment point:
- a work stage RUNNING with an expired lease (died mid-stage) -> ERROR
- a `_LOCK` RUNNING with an expired lease -> reclaimed to IDLE
- any session left with no live lease, proven dead or stale-and-never-started, is finalized
  through the SAME decide_session_outcome the pipeline uses (partial -> REVIEW, total ->
  cancelled) under the `_LOCK` mutex, so it can never race a live worker or an in-flight accept.

Steps 1/2 SELECT candidates before UPDATEing them, on purpose: a blind
`UPDATE ... WHERE Status='RUNNING' AND expired` takes a locking read on EVERY running row,
including one a live worker holds open across an LLM call. Under gevent that blocking wait can't
yield the hub, so the worker that would release the lock freezes too — a real deadlock. SELECT
first, then only ever try to lock rows a non-blocking read already proved expired.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import and_, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import (
    RetryOutcome,
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import execute_dml, now
from app.pipeline.accept import run_promotion_phase
from app.sse import bus

log = get_logger(__name__)

def _split_into_batches(items):
    """Yield <=Settings.reaper_sql_in_chunk_size slices (default 1000, capped at 2000 — SQL
    Server's IN-list limit is ~2100 params) so a mass-crash id list never blows past it. Empty
    input yields nothing, so callers need no separate `if items:` guard."""
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

    # Read-only candidate scan (see module docstring) — a plain SELECT never locks what it reads.
    # SubsystemID rides along so the publish below can include it.
    expired_work = sess.execute(
        select(ss.StateID, ss.SessionID, ss.SubsystemID).where(
            ss.Level != SubsystemLevel.LOCK, ss.Status == StageStatus.RUNNING, expired)).all()
    expired_locks = sess.execute(
        select(ss.StateID, ss.SessionID, ss.SubsystemID).where(
            ss.Level == SubsystemLevel.LOCK, ss.Status == StageStatus.RUNNING, expired)).all()

    # Capture proven-dead sessions BEFORE steps 1/2 run: a terminal transition clears
    # LeaseExpiresAt, so step 1's own ERROR-flip would erase the evidence it acts on.
    proven_dead = {row[1] for row in expired_work} | {row[1] for row in expired_locks}

    # 1. Expired RUNNING work stages (worker died mid-stage) -> ERROR, lease cleared (a terminal
    #    row carries no lease). Re-checks status/expiry as a CAS, so it only touches rows the
    #    snapshot above proved expired and matches nothing if one was revived meanwhile.
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

    # Publish AFTER commit, so a client's refetch (triggered by the event) sees this write
    # already durable — never publish-then-commit. (Item 5: the reaper's first two publish
    # sites — a client watching live no longer waits for the next board refetch.)
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
            sess.rollback()  # or the failed attempt poisons the next session's transaction
    if cancelled:
        log.warning("reaper.cancelled", sessions=cancelled)
    return cancelled


def _find_abandoned_sessions(sess: Session, _now: datetime, proven_dead: set[str]):
    """Active, non-REVIEW sessions with no live lease, that are either proven dead this pass or
    stale-and-never-started (untouched for a full lease window — a never-enqueued task, or a
    regen whose epoch was reserved but never ran). REVIEW sessions are a legitimate human wait
    and are never reaped; a finished stage's lease is always NULL, so briefly sitting outside
    REVIEW alone never looks abandoned."""
    grace = _now - timedelta(seconds=get_settings().reaper_stale_grace_seconds)
    ss = m.Subsystem_Stage_State
    # some worker is still actively working on this session
    live_lease = (select(1).select_from(ss)
                .where(ss.SessionID == m.Scenario_Session.SessionID, ss.LeaseExpiresAt > _now)
                .exists())
    base = (select(m.Scenario_Session.SessionID, m.Scenario_Session.TenantID, m.Scenario_Session.EntityID)
            .where(dal.session_active(),  # literal — only IX_Session_Active makes this sweep O(active)
                m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW,
                ~live_lease))
    # Runs as two separate queries, deduped by SessionID, so `proven_dead` can be chunked past
    # SQL Server's ~2100-param IN cap on a mass crash.
    out: dict = {}
    for row in sess.execute(base.where(m.Scenario_Session.UpdatedAt < grace)).mappings():
        out[row["SessionID"]] = row
    for chunk in _split_into_batches(proven_dead):
        for row in sess.execute(base.where(m.Scenario_Session.SessionID.in_(chunk))).mappings():
            out[row["SessionID"]] = row
    return list(out.values())


def _close_out_one_abandoned_session(sess: Session, scenario_session: dict) -> str | None:
    """Finalize ONE abandoned session under the `_LOCK` mutex. Acquires every `_LOCK`; if any is
    already held, a live worker or in-flight accept owns the session, so leave it untouched
    (return None). Once every lock is held the session is provably quiescent: flag its leftover
    un-runnable work rows ERROR, then run the same finalize (partial -> REVIEW, total ->
    cancelled)."""
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
        # Now quiescent: leftover un-runnable work rows can never complete, so mark them ERROR —
        # finalize needs a fully-terminal board, not to wait forever on a dead worker's row.
        result = execute_dml(sess,
            update(m.Subsystem_Stage_State)
            .where(m.Subsystem_Stage_State.SessionID == sid,
                m.Subsystem_Stage_State.Level != SubsystemLevel.LOCK,
                m.Subsystem_Stage_State.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]))
            # now(), not _now: this write happens later, under the lock
            .values(Status=StageStatus.ERROR, ErrorMessage="reaped: worker gone", LeaseExpiresAt=None, UpdatedAt=now())
        )
        # decide_session_outcome runs next — with every leftover row now ERROR (or already
        # terminal) it's guaranteed to take a terminal branch and commit there, so the publish
        # below only fires once that commit makes this UPDATE durable (same publish-after-commit
        # ordering as steps 1/2 above; Item 5's third publish site).
        outcome = decide_session_outcome(sess, scenario_session)
        # Session-scoped, not per-subsystem (this can flip several subsystems' rows at once), and
        # only fires when rows actually changed — otherwise a clean session would get a spurious
        # error event on every sweep pass.
        if result.rowcount:
            bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid,
                            "message": "reaped: worker gone, unfinished work marked failed",
                            "ts": now().isoformat()})
        return outcome
    finally:
        # Isolate each release: one raising must not skip the rest or the commit below — releases
        # only become durable once committed, so a mid-loop escape would leave even the already-
        # released locks stuck RUNNING until the next pass's lease-expiry reclaim.
        for ssid in acquired:
            try:
                dal.release_lock(sess, sid, ssid, task_id=sid)  # same holder id we acquired under
            except Exception:
                log.warning("reaper.lock_release_failed", session_id=sid, subsystem=ssid, exc_info=True)
        sess.commit()


def retry_one_promotion(sess: Session, session_id: str, entity_id: str,
                        promotion_user_id: str | None) -> RetryOutcome:
    """Retry exactly one session's previously-failed library promotion. Used by both the periodic
    sweep below and the admin API's manual retry-now action, so there is exactly one place that
    acquires the session's locks and decides the RetryOutcome — not two copies that could drift.

    No concept of promotion_max_attempts here — that cap is applied only by the sweep's candidate
    query below, so a human-triggered retry can never be blocked by a limit meant for the sweep.

    Returns .skipped if the session's locks are already held (a live worker, or another retry in
    flight) — without touching PromotionAttempts/PromotionError, since lock contention isn't a
    functional failure and must not burn one of the sweep's limited attempts. Otherwise returns
    .succeeded/.failed per accept.run_promotion_phase's outcome; never raises."""
    scenario_session = dal.get_session(sess, session_id, entity_id)
    if scenario_session is None:
        return RetryOutcome.skipped  # session vanished/reassigned between the candidate scan and this call

    lock_subsystem_ids = dal.subsystem_ids_at_level(sess, session_id, SubsystemLevel.LOCK)
    acquired: list[int] = []
    try:
        for subsystem_id in lock_subsystem_ids:
            # acquire_execution_lock, not acquire_lock: a promotion retry always runs after
            # the session is already completed, and acquire_lock's CAS requires an active
            # session, so it would never succeed here.
            if not dal.acquire_execution_lock(sess, session_id, subsystem_id, task_id=session_id):
                return RetryOutcome.skipped  # a concurrent retry/dismiss owns this session right now
            acquired.append(subsystem_id)
            sess.commit()  # durable before other work — same reasoning as accept_session's own lock loop
        good_subsystem_ids = dal.subsystem_ids_at_level(
            sess, session_id, SubsystemLevel.SCENARIOS, status=StageStatus.AWAITING_DECISION)
        succeeded = run_promotion_phase(sess, scenario_session, good_subsystem_ids, promotion_user_id, acquired)
        return RetryOutcome.succeeded if succeeded else RetryOutcome.failed
    finally:
        # Isolate each release: one raising must not skip the rest or the commit below — same
        # discipline as _close_out_one_abandoned_session above.
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
    retrying it. Acquires the SAME per-session lock retry_one_promotion uses before clearing the
    4 columns, so a dismiss can never be silently undone by a retry that was already mid-flight
    (or vice versa) — the two are fully serialized.

    Returns .skipped (nothing changed) if the lock is already held — a live worker or in-flight
    retry owns this session; ask the admin to try again shortly. Returns .succeeded otherwise;
    never .failed — once the lock is acquired, dismissing is a single unconditional column clear
    that cannot fail."""
    lock_subsystem_ids = dal.subsystem_ids_at_level(sess, session_id, SubsystemLevel.LOCK)
    acquired: list[int] = []
    try:
        for subsystem_id in lock_subsystem_ids:
            # acquire_execution_lock, not acquire_lock — same reason as retry_one_promotion
            # above: this session is always already completed, so acquire_lock's active-session
            # CAS would never succeed.
            if not dal.acquire_execution_lock(sess, session_id, subsystem_id, task_id=session_id):
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
    """Periodic sweep: retries every session whose library promotion previously failed and
    hasn't exhausted `promotion_max_attempts`, if `promotion_auto_retry_enabled` is on. Returns
    the session ids that succeeded this pass.

    Re-reads `promotion_auto_retry_enabled` on every call instead of caching it at process
    start, so an admin flipping the setting takes effect on the next scheduled tick — no restart
    needed."""
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
