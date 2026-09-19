"""Keep a task's leases alive while the task itself is alive — not only while it talks to the AI.

WHY. A lease used to move forward only right before an LLM call (pipeline_common._ask_ai). Any
long step with no LLM call therefore let a LIVE task's lease expire and the reaper cancel a run
that was still working: on 18 Sep scenario generation spent 14+ minutes embedding a cold
technique corpus before its first LLM call and was reaped at minute 14. The same trap covered the
THREATS relevance-gate rerank, control mapping after finish_stage (measured 604 s) and a THREATS
round that needs no LLM call at all — and only _ask_ai ever renewed the `_LOCK` lease.

WHAT. A thread (a greenlet under the gevent patch — same shape as joblock._renew_loop and
llm._heartbeat_loop) started right after the lock is acquired and stopped in the task's
`finally` before the lock is released. Every stage_lease_seconds/3 it pushes forward EVERY lease
the task holds on the session in one UPDATE, on its own short transaction.

WHAT AN EXPIRED LEASE MEANS NOW. The keeper runs as long as the task greenlet's process and hub
are alive, so a lease can only lapse when (1) the worker process died, (2) the hub was frozen for
a whole lease window (nothing yields, so the keeper cannot run either), or (3) the task outlived
the ceiling below. A task that hangs while still yielding is ended by its hard time limit (which
does fire under gevent, as gevent.Timeout), whose unwind stops the keeper — the lease then lapses
and the reaper reclaims it. So "expired lease = dead or frozen" is exact again, and the cost is
detection latency for a yielding hang: at most the hard limit plus one lease window.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import timedelta

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import StageStatus
from app.core.logging import get_logger
from app.db import models as m
from app.db.dal import execute_dml, now

log = get_logger(__name__)


def renew_task_leases(sess: Session, session_id: str, task_id: str) -> int:
    """ONE round trip: push forward every lease `task_id` holds on this session — its `_LOCK` row
    and whichever stage row it has claimed. Returns the rows renewed.

    Fences, all in the statement:
      * ActiveTaskID + RUNNING — rows after finish_stage, release_lock, a reaper reclaim or an
        epoch bump never match, so a lost claim is never resurrected;
      * LeaseExpiresAt > now — a lease that already lapsed is never revived: once expired, the
        reaper owns the row.
    WITH (READPAST): a row the task's own open transaction has locked is SKIPPED, never waited
    on. A pyodbc lock-wait cannot yield the gevent hub, so waiting on our own task would freeze
    the very greenlet that has to commit to release the lock. RCSI is a boot invariant, so the
    hint is valid; the skipped row's own writer renews or finishes it."""
    ss = m.Subsystem_Stage_State
    _now = now()
    return execute_dml(
        sess,
        update(ss)
        .with_hint("WITH (READPAST)", dialect_name="mssql")
        .where(ss.SessionID == session_id, ss.ActiveTaskID == task_id,
               ss.Status == StageStatus.RUNNING, ss.LeaseExpiresAt > _now)
        .values(LeaseExpiresAt=_now + timedelta(seconds=get_settings().stage_lease_seconds),
                HeartbeatAt=_now, UpdatedAt=_now),
    ).rowcount


def start(session_id: str, task_id: str, *, session_factory: Callable | None = None,
          max_hold_s: float | None = None) -> Callable[[], None]:
    """Start renewing; returns `stop` — call it in the task's `finally`, BEFORE releasing the lock.

    `max_hold_s` (default: the broker visibility timeout, the ceiling every task time limit sits
    under) caps how long a task can be kept alive; past it the keeper stops and the lease lapses
    normally. `session_factory` defaults to app.db.engine.db_session, resolved at first tick."""
    s = get_settings()
    interval = s.stage_lease_seconds / 3
    ceiling = time.monotonic() + (s.broker_visibility_timeout_seconds if max_hold_s is None
                                  else max_hold_s)
    stop_event = threading.Event()

    def _loop() -> None:
        factory = session_factory
        if factory is None:
            from app.db.engine import db_session  # local: engine is not needed until first tick
            factory = db_session
        while not stop_event.wait(interval):
            if time.monotonic() > ceiling:
                log.warning("lease_keeper.ceiling_reached", session_id=session_id, task_id=task_id)
                return
            try:
                with factory() as sess:
                    # UPDATE then commit with no yield between them (pyodbc calls do not yield),
                    # so the rows are locked for one round trip, never across a greenlet switch.
                    renew_task_leases(sess, session_id, task_id)
                    sess.commit()
            except Exception:
                # Two ticks of slack remain before expiry; a transient DB error costs one tick.
                log.warning("lease_keeper.renew_failed", session_id=session_id, task_id=task_id,
                            exc_info=True)

    thread = threading.Thread(target=_loop, name=f"lease-keeper-{task_id}", daemon=True)
    try:
        thread.start()
    except BaseException:
        # Thread.start() YIELDS under gevent (it waits for the new greenlet to begin), so a revoke
        # or the hard time limit can land right here — after the keeper exists but before the
        # caller holds `stop`. Unhandled, that orphan kept a dead task's lock alive until the
        # ceiling (an hour). Setting the event makes it exit at its first wait.
        stop_event.set()
        raise

    def stop() -> None:
        stop_event.set()
        thread.join(timeout=interval)

    return stop
