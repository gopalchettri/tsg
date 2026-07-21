""" A background cleanup job that runs on a schedule — if a
worker crashes partway through its work, or a piece of work never got picked
up at all, this notices and fixes the affected session so it doesn't get stuck
forever, without ever getting in the way of a worker that's still genuinely busy.

Stuck-job reaper.

A worker that dies leaves a session that never reaches its terminal state → the per-asset
lock leaks and the asset is `409` forever. The reaper is the safety net for *every*
abandonment point:
- a work stage RUNNING with an expired lease (died mid-stage) → ERROR;
- a `_LOCK` RUNNING with an expired lease → reclaimed to IDLE;
- then any session with NO live lease (no worker running now) that is either proven dead
    (a row carries an expired lease) or never-started-and-stale is driven through the SAME
    `decide_session_outcome` rule the pipeline uses — partial success → REVIEW, total failure →
    cancelled — **under the `_LOCK` mutex** so it can never race a live worker or an
    in-flight accept. That is what makes the leaked-lock symptom unable to recur from ANY
    crash point: mid-stage, between the loop and finalize, or never-enqueued.

Steps 1/2 below SELECT candidate rows before UPDATEing them, deliberately — an UPDATE's
own WHERE-clause evaluation takes locking reads (RCSI's snapshot only covers plain SELECTs),
so a single blind `UPDATE ... WHERE Status='RUNNING' AND expired` would have to lock-check
EVERY currently-RUNNING row across every session just to decide none of them qualify,
including a row a live worker legitimately still holds open for the duration of an in-flight
LLM call. On the gevent worker that lock wait is a real, reproduced worker freeze: pyodbc's
blocking wait can't yield the hub (see celery_worker.py note), so every other greenlet —
including the one that would eventually release the very lock being waited on — freezes too
(a live deadlock, not just a slow reap). The SELECT-then-targeted-UPDATE split means the
reaper only ever tries to lock rows it already knows (via a non-blocking snapshot read) are
actually expired — which a live worker's row, by definition, never is.
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

# The database can only safely handle a limited number of items in one request at a
# time; this keeps every batch well under that limit. SQL Server caps a statement
# near 2100 params; keep IN-lists well under it.
_IN_CHUNK = 1000


def _split_into_batches(items):
    """ splits a long list into smaller batches, since the
    database can't handle too many items in one query at once.

    Yield <=_IN_CHUNK slices so a mass-crash id list can't blow past the IN-param cap.
    Empty input yields nothing — callers need no separate `if items:` guard."""
    items = list(items)
    for i in range(0, len(items), _IN_CHUNK):
        yield items[i:i + _IN_CHUNK]


def clean_up_abandoned_sessions(sess: Session) -> list[str]:
    """ the main cleanup pass — finds crashed work, marks it
    as failed, and finishes off any session that looks abandoned.

    Return the session ids driven to a terminal 'cancelled' state this pass."""
    ss = m.Subsystem_Stage_State
    lease = ss.LeaseExpiresAt
    _now = now()
    # A row only counts as "expired" if it actually has a lease AND that lease's time has already passed.
    expired = and_(lease.isnot(None), lease < _now)

    #  this step only LOOKS at the data first, without changing
    # anything — a read never blocks or gets blocked by other work, so checking for
    # crashed sessions can't accidentally interfere with a worker that's still
    # genuinely busy.
    #
    # Read-only, RCSI-safe candidate scan (module docstring) — a plain SELECT never locks
    # what it reads, so finding candidates can't collide with a live worker's open transaction.
    expired_work = sess.execute(
        select(ss.StateID, ss.SessionID).where(
            ss.Level != SubsystemLevel.LOCK, ss.Status == StageStatus.RUNNING, expired)).all()
    expired_locks = sess.execute(
        select(ss.StateID, ss.SessionID).where(
            ss.Level == SubsystemLevel.LOCK, ss.Status == StageStatus.RUNNING, expired)).all()

    #  before we touch anything, we write down exactly which
    # sessions are DEFINITELY dead right now — because the very next steps are
    # about to fix (and thereby erase) that evidence, and we need proof captured
    # before it disappears.
    #
    # Capture which sessions are PROVEN dead this pass — a row genuinely RUNNING with
    # an expired lease, right now — BEFORE step 1/2 clear that very evidence. set_stage
    # (and every other terminal-transition writer) clears LeaseExpiresAt on completion,
    # so a long-finished row never looks abandoned; but that means step 1's own
    # ERROR-flip must not erase the proof it's about to act on before we've recorded it.
    proven_dead = {session_id for _, session_id in expired_work} | {session_id for _, session_id in expired_locks}

    #  step 1 — any piece of work that was marked "in progress" but
    # has clearly timed out (because the worker doing it died) gets marked as failed,
    # so the record matches reality.
    #
    # 1. Expired RUNNING work stages (worker died mid-stage) → ERROR, so the board is consistent.
    #    Clear the lease too (see set_stage's docstring): a terminal row carries no live lease.
    #    Targeted by StateID (primary key) + re-checked status/expiry — a CAS, not a blind
    #    sweep: it only ever locks rows already proven expired by the snapshot read above, and
    #    self-corrects (matches nothing) if one was revived between the read and this update.
    work_ids = [state_id for state_id, _ in expired_work]
    for chunk in _split_into_batches(work_ids):  # split into batches: a big crash could affect more rows than the database can handle in one request
        sess.execute(
            update(ss)
            .where(ss.StateID.in_(chunk), ss.Status == StageStatus.RUNNING, expired)
            .values(Status=StageStatus.ERROR, LeaseExpiresAt=None, UpdatedAt=_now)
        )
    #  step 2 — any "lock" that a dead worker never released also
    # gets freed up, so another worker (or this same cleanup job) can use it.
    #
    # 2. Reclaim expired RUNNING `_LOCK` rows → IDLE so the reaper (and any redelivery) can re-take them.
    lock_ids = [state_id for state_id, _ in expired_locks]
    for chunk in _split_into_batches(lock_ids):
        sess.execute(
            update(ss)
            .where(ss.StateID.in_(chunk), ss.Status == StageStatus.RUNNING, expired)
            .values(Status=StageStatus.IDLE, ActiveTaskID=None, LeaseExpiresAt=None, UpdatedAt=_now)
        )
    sess.commit()  # make sure steps 1-2 are safely saved before we go on to lock anything in step 3

    #  step 3 — wrap up every abandoned session using the exact
    # same decision logic the normal pipeline uses, so an abandoned session is
    # treated no differently than one that finished normally.
    #
    # 3. Finalize every abandoned session through the SAME rule the pipeline uses.
    cancelled: list[str] = []
    for c in _find_abandoned_sessions(sess, _now, proven_dead):
        try:
            if _close_out_one_abandoned_session(sess, dict(c)) == "cancelled":
                cancelled.append(c["SessionID"])
        except Exception:  # if fixing up one broken session hits an unexpected error, that must never stop this cleanup job from continuing on to check every other session ([R8])
            log.warning("reaper.finalize_failed", session_id=c["SessionID"], exc_info=True)
            sess.rollback()  # undo whatever that one failed attempt changed, so it doesn't leave the next session's attempt in a broken state too
    if cancelled:
        log.warning("reaper.cancelled", sessions=cancelled)
    return cancelled


def _find_abandoned_sessions(sess: Session, _now: datetime, proven_dead: set[str]):
    """ finds every session that looks abandoned — either
    proven dead this pass, or just untouched for too long.

    Active, non-REVIEW sessions with NO live lease (no worker running now) that are either
    PROVEN dead this pass (a row was genuinely RUNNING+expired, captured by `clean_up_abandoned_sessions`
    before step 1/2 cleared it) OR never-started-and-stale (untouched for a full lease window — the
    never-enqueued leak, or a regen whose epoch was reserved but whose task never ran). A
    session at REVIEW is a legitimate human wait and is never reaped. Note: a routine
    long-finished stage's lease is always NULL (cleared on completion), so it can never look
    abandoned just because a session happens to sit outside REVIEW for a while (e.g. the brief
    window between a regenerate request's CAS and its Celery task actually starting)."""
    grace = _now - timedelta(seconds=get_settings().reaper_stale_grace_seconds)
    ss = m.Subsystem_Stage_State
    # True if this session still has a row whose lease hasn't expired yet — i.e. some worker is still actively working on it.
    live_lease = (select(1).select_from(ss)
                .where(ss.SessionID == m.Scenario_Session.SessionID, ss.LeaseExpiresAt > _now)
                .exists())
    base = (select(m.Scenario_Session.SessionID, m.Scenario_Session.TenantID, m.Scenario_Session.EntityID)
            .where(m.Scenario_Session.SessionStatus == SessionStatus.active,
                m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW,
                ~live_lease))
    #  a session can qualify as abandoned for two different
    # reasons (definitely dead, or just untouched too long) — this checks both
    # reasons separately, then combines the results so the same session is never
    # counted twice.
    #
    # Run the two abandonment branches separately and dedupe by SessionID: `proven_dead` is
    # chunked so a mass crash can't exceed SQL Server's ~2100-param IN cap (the staleness branch
    # carries no IN list). Equivalent to the old `or_(UpdatedAt<grace, SessionID IN proven_dead)`.
    out: dict = {}
    for row in sess.execute(base.where(m.Scenario_Session.UpdatedAt < grace)).mappings():
        out[row["SessionID"]] = row
    for chunk in _split_into_batches(proven_dead):
        for row in sess.execute(base.where(m.Scenario_Session.SessionID.in_(chunk))).mappings():
            out[row["SessionID"]] = row
    return list(out.values())


def _close_out_one_abandoned_session(sess: Session, scenario_session: dict) -> str | None:
    """ safely closes out ONE abandoned session, but only if
    no other live worker is still using it.

    Finalize ONE abandoned session under the `_LOCK` mutex ([R5] discipline). Acquire every
    `_LOCK`; if any is held, a live worker or an in-flight accept owns the session → leave it
    untouched (return None). Once we hold them all the session is provably quiescent: flag its
    un-runnable leftover work rows ERROR (a dead worker will never finish them), then run the
    SAME finalize — partial→REVIEW (preserving committed partial success), total→cancelled."""
    from app.pipeline.tasks import decide_session_outcome  # imported here, not at the top of the file, only to avoid these two files needing each other at the same time when the app starts up

    sid = scenario_session["SessionID"]
    # Find every subsystem that has a _LOCK row for this session — we need to grab all of their locks before we can safely touch anything.
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
        #  now that we're sure nobody else is using this session,
        # any work that's stuck "waiting"/"in progress" can never actually finish
        # (the worker that would have finished it is gone) — so mark it failed
        # too, otherwise the wrap-up logic below would wait forever for something
        # that will never happen.
        #
        # Quiescent: leftover un-runnable work rows can never complete now → mark them ERROR so
        # finalize sees a fully-terminal board (and doesn't wait forever on a dead worker's IDLE row).
        sess.execute(
            update(m.Subsystem_Stage_State)
            .where(m.Subsystem_Stage_State.SessionID == sid,
                m.Subsystem_Stage_State.Level != SubsystemLevel.LOCK,
                m.Subsystem_Stage_State.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]))
            # use the current time here (not the time this whole cleanup pass started), since this write happens later, while we're holding the lock
            .values(Status=StageStatus.ERROR, ErrorMessage="reaped: worker gone", LeaseExpiresAt=None, UpdatedAt=now())
        )
        return decide_session_outcome(sess, scenario_session)
    finally:
        # Isolate each release attempt (same discipline as accept.py's lock-release cleanup):
        # one lock's release raising (e.g. a transient connection error) must not skip the
        # remaining acquired locks, and must not stop us from reaching the commit below —
        # otherwise a mid-loop failure would leave every lock from that point on (including
        # ones already released earlier in this same loop, since the release is only durable
        # once committed) stuck RUNNING until the reaper's own next-pass lease-expiry reclaim.
        for ssid in acquired:
            try:
                dal.release_lock(sess, sid, ssid, task_id=sid)  # same holder id we acquired under
            except Exception:
                log.warning("reaper.lock_release_failed", session_id=sid, subsystem=ssid, exc_info=True)
        sess.commit()
