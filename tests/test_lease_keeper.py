"""lease_keeper: a live task's leases stay alive for as long as the task does — and not a moment
longer.

THE BUG (18 Sep, session 0b4e96f5): leases moved forward only right before an LLM call. Scenario
generation spent 14+ minutes on a pre-LLM step, its lease lapsed, and the reaper cancelled a run
that was still working. These tests run the keeper against a real (file) database with a
sub-second lease and judge it by the REAPER's own rule (`reaper._lease_expired` on RUNNING rows —
exactly what clean_up_abandoned_sessions selects), so "kept" means "the sweep would not touch it".
"""
from __future__ import annotations

import threading
import time
import uuid
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects import mssql
from sqlalchemy.orm import sessionmaker

from app.core.enums import StageStatus, SubsystemLevel
from app.db import models as m
from app.db.dal import now
from app.pipeline import cascade, lease_keeper, tasks
from app.pipeline.reaper import _lease_expired

LEASE = 0.9   # seconds; the keeper ticks every LEASE / 3
ss = m.Subsystem_Stage_State


@pytest.fixture
def db(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'keeper.db'}",
                        connect_args={"check_same_thread": False})
    ss.__table__.create(eng)
    return sessionmaker(bind=eng, future=True)


@pytest.fixture(autouse=True)
def short_lease(monkeypatch):
    monkeypatch.setattr(lease_keeper, "get_settings", lambda: SimpleNamespace(
        stage_lease_seconds=LEASE, broker_visibility_timeout_seconds=3600))


def _seed(maker, task_id: str, *, level=SubsystemLevel.SCENARIOS, status="RUNNING",
          lease=timedelta(seconds=LEASE)) -> str:
    """The shape a task leaves behind after acquire_lock + claim_stage: its `_LOCK` row and one
    claimed stage row, both RUNNING under its task id with a fresh lease."""
    sid, t = str(uuid.uuid4()), now()
    with maker() as s:
        for lvl in (SubsystemLevel.LOCK, level):
            s.execute(ss.__table__.insert().values(
                StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="78",
                SubsystemID=0, Level=lvl, Status=status, GenerationEpoch=1, ActiveTaskID=task_id,
                LeaseExpiresAt=t + lease, HeartbeatAt=t, UpdatedAt=t, CreatedAt=t))
        s.commit()
    return sid


def _reapable(maker, sid: str) -> int:
    """How many of this session's rows the reaper's sweep would reclaim right now."""
    with maker() as s:
        return len(s.execute(select(ss.StateID).where(
            ss.SessionID == sid, ss.Status == StageStatus.RUNNING, _lease_expired(now()))).all())


def test_a_live_task_outlives_many_lease_windows(db) -> None:
    """THE regression: a task busy for longer than its lease, with no LLM call, is never
    reapable while its keeper runs — checked continuously, not just at the end."""
    task = str(uuid.uuid4())
    sid = _seed(db, task)
    stop = lease_keeper.start(sid, task, session_factory=db)
    try:
        deadline = time.monotonic() + 2.5 * LEASE
        while time.monotonic() < deadline:
            assert _reapable(db, sid) == 0, "a live task's lease lapsed: the reaper would kill it"
            time.sleep(0.05)
    finally:
        stop()


def test_once_stopped_the_lease_lapses_and_the_reaper_reclaims(db) -> None:
    """A crashed worker's keeper dies with it; stop() is the in-process equivalent. Detection must
    stay exactly one lease window, as before the keeper existed."""
    task = str(uuid.uuid4())
    sid = _seed(db, task)
    lease_keeper.start(sid, task, session_factory=db)()
    time.sleep(LEASE + 0.2)
    assert _reapable(db, sid) == 2


def test_a_lapsed_lease_is_never_revived(db) -> None:
    """Once a lease has expired the reaper owns the row: renewing it would resurrect a claim the
    sweep may already be reclaiming."""
    task = str(uuid.uuid4())
    sid = _seed(db, task, lease=timedelta(seconds=-1))
    with db() as s:
        assert lease_keeper.renew_task_leases(s, sid, task) == 0
        s.commit()
    assert _reapable(db, sid) == 2


@pytest.mark.parametrize("owner, status", [("other", "RUNNING"), ("self", "COMPLETE")])
def test_only_this_tasks_running_rows_are_renewed(db, owner, status) -> None:
    """Another task's claim, or a row this task already finished, is never touched."""
    task = str(uuid.uuid4())
    sid = _seed(db, str(uuid.uuid4()) if owner == "other" else task, status=status)
    with db() as s:
        before = s.execute(select(ss.LeaseExpiresAt).where(ss.SessionID == sid)).scalars().all()
        assert lease_keeper.renew_task_leases(s, sid, task) == 0
        s.commit()
        after = s.execute(select(ss.LeaseExpiresAt).where(ss.SessionID == sid)).scalars().all()
    assert before == after


def test_the_keeper_gives_up_at_its_ceiling(db) -> None:
    """A task past its ceiling is not kept alive forever: the keeper exits and the lease lapses."""
    task = str(uuid.uuid4())
    sid = _seed(db, task)
    stop = lease_keeper.start(sid, task, session_factory=db, max_hold_s=LEASE / 3 + 0.05)
    try:
        time.sleep(2 * LEASE)
        assert _reapable(db, sid) == 2
        assert not any(t.name == f"lease-keeper-{task}" for t in threading.enumerate())
    finally:
        stop()


def test_a_task_killed_while_its_keeper_starts_leaves_no_keeper_behind(monkeypatch) -> None:
    """Thread.start() yields under gevent, so a revoke or the hard time limit can land inside
    start() — after the keeper exists, before the caller holds `stop`. That orphan used to keep
    a dead task's lock alive until the ceiling (an hour)."""

    class _Killed(BaseException):
        pass

    class _KilledDuringStart(threading.Thread):
        def start(self):
            super().start()
            raise _Killed

    ticks = []

    @contextmanager
    def _factory():
        ticks.append(1)
        yield SimpleNamespace(commit=lambda: None)

    monkeypatch.setattr(lease_keeper, "renew_task_leases", lambda *a: 1)
    monkeypatch.setattr(lease_keeper.threading, "Thread", _KilledDuringStart)
    with pytest.raises(_Killed):
        lease_keeper.start("s", "orphan-task", session_factory=_factory)
    time.sleep(LEASE)                                  # three tick intervals
    assert ticks == [], "an orphaned keeper kept renewing a dead task's leases"
    assert not any(t.name == "lease-keeper-orphan-task" for t in threading.enumerate())


def test_the_renewal_skips_locked_rows_on_sql_server(monkeypatch) -> None:
    """READPAST: the keeper must never WAIT on a row its own task's open transaction has locked
    (a pyodbc lock-wait cannot yield the gevent hub — it would freeze that very task)."""
    captured = []
    monkeypatch.setattr(lease_keeper, "execute_dml",
                        lambda _s, stmt: captured.append(stmt) or SimpleNamespace(rowcount=0))
    lease_keeper.renew_task_leases(None, "s", "t")
    assert "READPAST" in str(captured[0].compile(dialect=mssql.dialect()))


# --- wiring: started after the lock is won, stopped before it is released ------------------------
def _recorder(monkeypatch, module):
    events: list[str] = []

    def _start(sid, task_id):
        events.append("keeper.start")
        return lambda: events.append("keeper.stop")

    monkeypatch.setattr(module.lease_keeper, "start", _start)
    sess = SimpleNamespace(commit=lambda: events.append("commit"),
                           rollback=lambda: events.append("rollback"))
    return events, sess


def test_subsystem_lock_keeps_its_leases_alive(monkeypatch) -> None:
    """Regenerate, next-set and the control-map sweep all run under _subsystem_lock."""
    events, sess = _recorder(monkeypatch, cascade)
    monkeypatch.setattr(cascade.dal, "acquire_execution_lock",
                        lambda *a: events.append("acquire") or True)
    monkeypatch.setattr(cascade.dal, "release_lock", lambda *a: events.append("release") or True)
    with cascade._subsystem_lock(sess, "s", 1, "t", "regen") as acquired:
        assert acquired
        events.append("work")
    assert events == ["acquire", "commit", "keeper.start", "work", "keeper.stop", "release",
                      "commit"]


def test_a_lock_not_won_starts_no_keeper(monkeypatch) -> None:
    events, sess = _recorder(monkeypatch, cascade)
    monkeypatch.setattr(cascade.dal, "acquire_execution_lock", lambda *a: False)
    with cascade._subsystem_lock(sess, "s", 1, "t", "regen") as acquired:
        assert not acquired
    assert "keeper.start" not in events


def test_the_full_pipeline_keeps_its_leases_alive(monkeypatch) -> None:
    """The first-run path (_process_all_supporting_systems), including when its work fails."""
    events, sess = _recorder(monkeypatch, tasks)
    monkeypatch.setattr(tasks.dal, "load_session", lambda *a: {
        "CurrentStage": "THREAT_IDENTIFICATION", "SubsystemsJSON": "[]",
        "AssetContextJSON": "{}", "SessionStatus": "active"})
    monkeypatch.setattr(tasks.dal, "acquire_lock", lambda *a: events.append("acquire") or True)
    monkeypatch.setattr(tasks.dal, "release_lock", lambda *a: events.append("release") or True)

    def _boom(*_a):
        events.append("work")
        raise RuntimeError("stage failed")

    monkeypatch.setattr(tasks.dal, "active_category_names", _boom)
    monkeypatch.setattr(tasks, "_record_failure", lambda *a: None)
    monkeypatch.setattr(tasks, "decide_session_outcome", lambda *a: None)
    tasks._process_all_supporting_systems(sess, "s", llm=None, task_id="t")
    assert events == ["acquire", "commit", "keeper.start", "work", "commit", "keeper.stop",
                      "release", "commit"]
