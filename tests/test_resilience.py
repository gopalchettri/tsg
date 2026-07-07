"""[R8] Poison-terminal — a stage that can never complete (worker crashes the
process itself, redelivered forever with a fresh lease each time) must stop
being reclaimable once it exhausts its attempt budget, so the existing reaper
sweep + `decide_session_outcome` can carry it to a terminal state.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select, update

from app.core.config import get_settings
from app.core.enums import StageStatus, SubsystemLevel, WorkflowStage
from app.db import dal
from app.db import models as m
from app.db.dal import load_session, now
from app.pipeline.reaper import clean_up_abandoned_sessions
from tests.test_slice import SUB, _seed_session


def _attempt_count(sess, sid) -> int:
    return sess.execute(
        select(m.Subsystem_Stage_State.c.AttemptCount).where(
            m.Subsystem_Stage_State.c.SessionID == sid,
            m.Subsystem_Stage_State.c.SubsystemID == SUB["id"],
            m.Subsystem_Stage_State.c.Level == SubsystemLevel.THREATS,
        )
    ).scalar()


def test_poison_stage_stops_after_max_attempts(db, monkeypatch):
    monkeypatch.setattr(get_settings(), "stage_max_attempts", 3)
    session = _seed_session(db)
    sid = session["SessionID"]
    tid = str(uuid.uuid4())  # Celery redelivers the SAME message/task_id after a worker crash

    # Simulate a worker that crashes the whole PROCESS every time before it can ever
    # leave the stage RUNNING (never reaches _record_failure). The row never
    # leaves RUNNING; each "attempt" is the mid-flight-resume branch (same task_id)
    # re-claiming and refreshing the lease — the real poison loop.
    results = [dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) for _ in range(4)]

    assert results == [True, True, True, False]
    assert _attempt_count(db, sid) == 3


def test_normal_retry_within_limit_succeeds(db):
    session = _seed_session(db)
    sid = session["SessionID"]
    tid = str(uuid.uuid4())

    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) is True
    # A transient hiccup: the SAME task resumes its own mid-flight claim (still RUNNING).
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) is True
    dal.set_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, StageStatus.COMPLETE)
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) is False  # COMPLETE, not reclaimable


def test_attempt_count_increments_atomically(db):
    session = _seed_session(db)
    sid = session["SessionID"]
    for i in range(1, 4):
        db.execute(update(m.Subsystem_Stage_State)
                   .where(m.Subsystem_Stage_State.c.SessionID == sid,
                          m.Subsystem_Stage_State.c.SubsystemID == SUB["id"],
                          m.Subsystem_Stage_State.c.Level == SubsystemLevel.THREATS)
                   .values(Status=StageStatus.ERROR))
        dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, str(uuid.uuid4()))
        assert _attempt_count(db, sid) == i


def test_reaper_sweeps_exhausted_stage_into_error(db, monkeypatch):
    monkeypatch.setattr(get_settings(), "stage_max_attempts", 1)
    session = _seed_session(db)
    sid = session["SessionID"]

    # Exhaust the one allowed attempt, leaving the row RUNNING with an expired lease —
    # exactly the state a redelivery-looping poison session ends up in once claim_stage
    # finally refuses to re-claim it (the lease stops refreshing).
    dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, str(uuid.uuid4()))
    db.execute(update(m.Subsystem_Stage_State)
               .where(m.Subsystem_Stage_State.c.SessionID == sid,
                      m.Subsystem_Stage_State.c.SubsystemID == SUB["id"],
                      m.Subsystem_Stage_State.c.Level == SubsystemLevel.THREATS)
               .values(LeaseExpiresAt=now().replace(year=2000)))
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, str(uuid.uuid4())) is False  # exhausted

    cancelled = clean_up_abandoned_sessions(db)  # the EXISTING reaper sweep — no new code needed
    assert sid in cancelled
    assert load_session(db, sid)["SessionStatus"] != "active"
