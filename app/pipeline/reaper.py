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
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import execute_dml, now
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


def _revoke_zombie_tasks(expired_rows) -> None:
    """Terminate the Celery tasks that were still holding the rows this pass just reclaimed.

    An expired lease is an EXACT frozen-detector, not a heuristic: `tasks._ask_ai` renews both the
    stage lease and the `_LOCK` lease before every single LLM call, so a healthy task — however
    long it legitimately runs — never stops renewing. A holder that has gone a full lease window
    without one has stopped executing. That is why this needs no wall-clock budget and no tuned
    constant: it reads the same signal in dev, UAT and prod, and it can never fire on live work.

    Reclaiming the DB row alone frees the SESSION but leaves the greenlet pinning a worker slot and
    a DB connection for good, with a redelivery free to run beside it. `terminate=True` kills the
    greenlet, which unwinds through `_subsystem_lock`'s `finally` and releases the lock properly.

    Best-effort by design: revoking is an optimisation on top of the row reclaim above, which has
    already happened and is already durable. A broker that will not take the control message must
    never fail the sweep. (A GUID that is a session id rather than a Celery task id — accept and
    the reaper both lock under `task_id=session_id` — simply matches no task; ids are never reused.)

    KNOWN LIMIT: gevent can only kill a greenlet at a yield point, so a task blocked in a truly
    non-yielding native call (pyodbc, the local-model threadpool) survives this. The session is
    still recovered; only the slot leaks."""
    task_ids = {row[3] for row in expired_rows if row[3]}
    if not task_ids:
        return
    try:
        from app.pipeline.celery_app import celery_app  # local: celery_app imports THIS module
        celery_app.control.revoke(list(task_ids), terminate=True)
    except Exception:  # see "best-effort" above
        log.warning("reaper.revoke_failed", task_ids=sorted(task_ids), exc_info=True)
        return
    log.warning("reaper.revoked_zombie_tasks", task_ids=sorted(task_ids),
                note="lease expired while still RUNNING — task was not executing")


def clean_up_abandoned_sessions(sess: Session) -> list[str]:
    """The main cleanup pass. Returns the session ids driven to a terminal 'cancelled' state."""
    ss = m.Subsystem_Stage_State
    lease = ss.LeaseExpiresAt
    _now = now()
    expired = and_(lease.isnot(None), lease < _now)

    # Read-only candidate scan (see module docstring) — a plain SELECT never locks what it reads.
    # SubsystemID rides along so the publish below can include it; ActiveTaskID so _revoke_zombie_
    # tasks below can kill the greenlet that is still holding the row.
    expired_work = sess.execute(
        select(ss.StateID, ss.SessionID, ss.SubsystemID, ss.ActiveTaskID).where(
            ss.Level != SubsystemLevel.LOCK, ss.Status == StageStatus.RUNNING, expired)).all()
    expired_locks = sess.execute(
        select(ss.StateID, ss.SessionID, ss.SubsystemID, ss.ActiveTaskID).where(
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
    for _, session_id, subsystem_id, _tid in expired_work:
        bus.publish(session_id, {"type": str(SSEEventType.error), "session_id": session_id,
                                "subsystem_id": subsystem_id,
                                "message": "stage lease expired: worker presumed dead",
                                "ts": _now.isoformat()})
    for _, session_id, subsystem_id, _tid in expired_locks:
        bus.publish(session_id, {"type": str(SSEEventType.error), "session_id": session_id,
                                "subsystem_id": subsystem_id,
                                "message": "asset lock reclaimed: worker presumed dead",
                                "ts": _now.isoformat()})

    # 2b. Kill the greenlets that were still holding those rows. Reclaiming the DB row frees the
    # SESSION, but a task frozen mid-flight keeps its worker slot and DB connection forever, and
    # a redelivery would then run beside it. See _revoke_zombie_tasks for why an expired lease is
    # an exact frozen-detector rather than a heuristic.
    _revoke_zombie_tasks(expired_work + expired_locks)

    # 3. Finalize every abandoned session through the SAME rule the pipeline uses.
    cancelled: list[str] = []
    for c in _find_abandoned_sessions(sess, _now, proven_dead):
        try:
            if recover_abandoned_session(sess, dict(c)) == "cancelled":
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
    # some worker is still actively working on this session. dal.live_lease_exists is the SOLE
    # definition of "a worker is alive" — accept.ensure_review_gate asks the same question before
    # it tells a caller that generation is still running, and the two must never diverge.
    live_lease = dal.live_lease_exists(m.Scenario_Session.SessionID, _now)
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


def recover_session_now(sess: Session, scenario_session: dict) -> str | None:
    """A whole reaper pass, scoped to ONE session, run on demand. Returns decide_session_outcome's
    verdict ("review" / "cancelled" / None).

    THE ORDER IS THE POINT. `recover_abandoned_session` below is only step 3 of the sweep: it
    acquires every `_LOCK` first and bails out untouched if one is held. But a session abandoned by
    a dead or hung worker is stuck *precisely because* its `_LOCK` is still RUNNING, so step 3 on
    its own can never recover the very case it exists for — it needs steps 1/2 to have reclaimed
    the expired rows first. clean_up_abandoned_sessions gets that for free by running them in
    sequence; an on-demand caller does not, and calling step 3 alone silently returns None forever.

    Same predicates and same SELECT-then-UPDATE discipline as the batched sweep (see the module
    docstring for why a blind UPDATE deadlocks under gevent) — just narrowed to one SessionID,
    which also makes the batching unnecessary: one session has a handful of rows, not thousands."""
    sid = scenario_session["SessionID"]
    ss = m.Subsystem_Stage_State
    _now = now()
    expired = and_(ss.LeaseExpiresAt.isnot(None), ss.LeaseExpiresAt < _now)
    rows = sess.execute(
        select(ss.StateID, ss.SessionID, ss.SubsystemID, ss.ActiveTaskID, ss.Level)
        .where(ss.SessionID == sid, ss.Status == StageStatus.RUNNING, expired)).all()
    if rows:
        # Work stages the dead worker left mid-flight can never finish -> ERROR, so the board is
        # fully terminal and decide_session_outcome is not left waiting on them.
        work_ids = [r[0] for r in rows if r[4] != SubsystemLevel.LOCK]
        lock_ids = [r[0] for r in rows if r[4] == SubsystemLevel.LOCK]
        if work_ids:
            sess.execute(
                update(ss).where(ss.StateID.in_(work_ids), ss.Status == StageStatus.RUNNING, expired)
                .values(Status=StageStatus.ERROR, ErrorMessage="reaped: worker gone",
                        LeaseExpiresAt=None, UpdatedAt=_now))
        if lock_ids:
            sess.execute(
                update(ss).where(ss.StateID.in_(lock_ids), ss.Status == StageStatus.RUNNING, expired)
                .values(Status=StageStatus.IDLE, ActiveTaskID=None, LeaseExpiresAt=None,
                        UpdatedAt=_now))
        sess.commit()  # durable before recover_abandoned_session tries to take the lock
        log.warning("reaper.on_demand_reclaim", session_id=sid,
                    work_rows=len(work_ids), lock_rows=len(lock_ids))
        _revoke_zombie_tasks(rows)
    return recover_abandoned_session(sess, scenario_session)


def recover_abandoned_session(sess: Session, scenario_session: dict) -> str | None:
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

