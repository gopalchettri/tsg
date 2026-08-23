"""Item 5 / verification 4: the reaper's three `bus.publish` write sites -- before this plan
reaper.py fired zero SSE events, so a client watching live had to wait for the next board
refetch to see a worker-death sweep. Real SQLite tables, no live MSSQL/Redis: reaper.py's own
queries run through SQLAlchemy Core against `Subsystem_Stage_State`/`Scenario_Session`.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.enums import SSEEventType, StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import reaper
from app.sse import bus


def _engine():
    engine = create_engine("sqlite://")
    m.Scenario_Session.__table__.create(engine)
    m.Subsystem_Stage_State.__table__.create(engine)
    return engine


def _stage_row(session_id: str, level: str, lease_expired: bool) -> dict:
    now = datetime.now(UTC)
    return dict(
        StateID=str(uuid.uuid4()), SessionID=session_id, TenantID="t", EntityID="e",
        SubsystemID=0, Level=level, Status=StageStatus.RUNNING, GenerationEpoch=1,
        ActiveTaskID=str(uuid.uuid4()),
        LeaseExpiresAt=now - timedelta(minutes=1) if lease_expired else now + timedelta(minutes=10),
        AttemptCount=1, UpdatedAt=now, CreatedAt=now,
    )


def test_expired_work_and_lock_rows_each_publish_an_error_event(monkeypatch):
    """Sites 1 and 2 (`clean_up_abandoned_sessions`): an expired RUNNING work stage and an
    expired RUNNING `_LOCK` row must each fire their own `bus.publish` -- distinct messages, so a
    client can tell "worker died mid-stage" from "an asset lock was reclaimed"."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)

    sid_work, sid_lock = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Subsystem_Stage_State.__table__.insert().values(
            **_stage_row(sid_work, SubsystemLevel.THREATS, lease_expired=True)))
        s.execute(m.Subsystem_Stage_State.__table__.insert().values(
            **_stage_row(sid_lock, SubsystemLevel.LOCK, lease_expired=True)))
        s.commit()

    published: list[tuple[str, dict]] = []
    monkeypatch.setattr(bus, "publish", lambda sid, ev: published.append((sid, ev)))

    with Session() as s:
        cancelled = reaper.clean_up_abandoned_sessions(s)

    # Neither session_id resolves in Scenario_Session (empty table, deliberately) -- step 3 finds
    # nothing to finalize, isolating this test to sites 1+2 only.
    assert cancelled == []
    assert len(published) == 2
    by_session = {sid: ev for sid, ev in published}
    assert by_session[sid_work]["type"] == str(SSEEventType.error)
    assert by_session[sid_work]["message"] == "stage lease expired: worker presumed dead"
    assert by_session[sid_work]["subsystem_id"] == 0
    assert by_session[sid_lock]["message"] == "asset lock reclaimed: worker presumed dead"


def test_expired_lease_below_grace_does_not_publish(monkeypatch):
    """Control: a live (non-expired) lease must never be treated as abandoned."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Subsystem_Stage_State.__table__.insert().values(
            **_stage_row(sid, SubsystemLevel.THREATS, lease_expired=False)))
        s.commit()

    published: list[tuple[str, dict]] = []
    monkeypatch.setattr(bus, "publish", lambda sid, ev: published.append((sid, ev)))
    with Session() as s:
        reaper.clean_up_abandoned_sessions(s)
    assert published == []


def test_close_out_abandoned_session_publishes_error(monkeypatch):
    """Site 3 (`_close_out_one_abandoned_session`): a session finalized under the reaper's own
    lock, with leftover un-runnable rows flipped to ERROR, must publish once -- and only once
    that flip is durable (it runs the update, then `decide_session_outcome`, then publishes).
    `decide_session_outcome` itself is plan item 4/27's territory (tasks.py), stubbed here so
    this test isolates reaper.py's own publish call."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = str(uuid.uuid4())
    with Session() as s:
        # No _LOCK-level row for this session -- lock_subs is empty, so the function never needs
        # dal.acquire_lock/release_lock at all (both require a live Scenario_Session CAS).
        s.execute(m.Subsystem_Stage_State.__table__.insert().values(
            **_stage_row(sid, SubsystemLevel.THREATS, lease_expired=True)))
        s.commit()

    import app.pipeline.tasks as tasks_mod
    monkeypatch.setattr(tasks_mod, "decide_session_outcome", lambda sess, ss: "cancelled")

    published: list[tuple[str, dict]] = []
    monkeypatch.setattr(bus, "publish", lambda sid, ev: published.append((sid, ev)))

    scenario_session = {"SessionID": sid, "TenantID": "t", "EntityID": "e"}
    with Session() as s:
        outcome = reaper._close_out_one_abandoned_session(s, scenario_session)

    assert outcome == "cancelled"
    assert len(published) == 1
    assert published[0][0] == sid
    assert published[0][1]["type"] == str(SSEEventType.error)
    assert published[0][1]["message"] == "reaped: worker gone, unfinished work marked failed"


def test_close_out_publishes_nothing_when_no_rows_changed(monkeypatch):
    """If nothing was left IDLE/RUNNING (already fully terminal), the update's rowcount is 0 and
    the reaper must NOT fire a spurious error on an otherwise-clean sweep pass."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = str(uuid.uuid4())
    # No Subsystem_Stage_State rows at all for this session -- nothing to flip to ERROR.

    import app.pipeline.tasks as tasks_mod
    monkeypatch.setattr(tasks_mod, "decide_session_outcome", lambda sess, ss: None)
    published: list[tuple[str, dict]] = []
    monkeypatch.setattr(bus, "publish", lambda sid, ev: published.append((sid, ev)))

    scenario_session = {"SessionID": sid, "TenantID": "t", "EntityID": "e"}
    with Session() as s:
        reaper._close_out_one_abandoned_session(s, scenario_session)

    assert published == []


if __name__ == "__main__":
    print("run via pytest")
