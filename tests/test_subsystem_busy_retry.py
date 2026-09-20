"""A click must never be swallowed because the subsystem was busy.

THE BUG. `run_regeneration` and `run_next_set` used to log a warning and return when another
execution held the subsystem lock — the control-map sweep (every 300s, minutes long), an accept,
or a second click. But the ENDPOINT had already reset the SCENARIOS stage to IDLE at a new epoch
and answered 202, so the session was left mid-flight with nobody owning it:

  * `decide_session_outcome` does nothing while a stage is IDLE,
  * the reaper only scans ACTIVE, non-REVIEW sessions — which a regenerating session is not,

so the stage stayed IDLE indefinitely. `progress.overall` read `complete` while accept answered
404 `subsystem_not_awaiting_decision` and accept-all answered 409, until somebody happened to
click again. Next-set was worse: its request had re-reserved the asset, so the session also sat
`active` holding it until the reaper cancelled the whole thing.

The fix has three halves, and all three are pinned here: the run RAISES `SubsystemBusy` so the
task has something to retry, the CELERY TASK catches it and routes it to the bounded retry, and
when the retries run out the stage is handed back exactly as found.

The middle one was added late. The first two were tested by calling `cascade` and
`settle_unstarted` directly, which left the task's `except cascade.SubsystemBusy` handler
uncovered: renaming it to a different exception kept all 1087 tests green while every busy
regeneration would have crashed the worker instead of retrying. That is the same
tested-helper/untested-caller shape that cost this codebase its library approval path for a year,
so the handler now has a test that drives the task itself.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.enums import SessionStatus, StageStatus, SubsystemLevel, WorkflowStage
from app.db import dal
from app.db import models as m
from app.pipeline import cascade

NOW = datetime.now(UTC)


def _engine():
    engine = create_engine("sqlite://")
    for table in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario,
                m.Scenario_Audit, m.Identified_Threat, m.Scoped_Threat):
        table.__table__.create(engine)
    return engine


def _seed(Session, *, status: SessionStatus, stage: WorkflowStage) -> tuple[str, str]:
    """A session whose SCENARIOS stage is IDLE at epoch 2 — exactly what the endpoint leaves
    behind after it reserves the epoch, resets the stage and answers 202."""
    sid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=sid, TenantID="t", EntityID="86", UserID="u1", AssetID=7,
            AssetName="Power Generation System", SessionStatus=status, CurrentStage=stage,
            StageStatus=StageStatus.RUNNING, Mode="AUTO", CurrentSubsystemIndex=0,
            SubsystemsJSON="[]", AssetContextJSON="{}", CreatedAt=NOW, UpdatedAt=NOW))
        # _LOCK is RUNNING: somebody else — the sweep, an accept — holds this subsystem.
        s.execute(m.Subsystem_Stage_State.__table__.insert().values(
            StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            Level=SubsystemLevel.LOCK, Status=StageStatus.RUNNING, GenerationEpoch=1,
            ActiveTaskID=str(uuid.uuid4()), LeaseExpiresAt=NOW + timedelta(minutes=10),
            AttemptCount=1, UpdatedAt=NOW, CreatedAt=NOW))
        s.execute(m.Subsystem_Stage_State.__table__.insert().values(
            StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            Level=SubsystemLevel.SCENARIOS, Status=StageStatus.IDLE, GenerationEpoch=2,
            AttemptCount=0, LeaseExpiresAt=NOW + timedelta(minutes=10), UpdatedAt=NOW,
            CreatedAt=NOW))
        # A real, regeneratable target: get_threat_id_to_redo resolves the scenario THROUGH its
        # Scoped_Threat row, and an unresolvable id is refused before the lock is ever touched —
        # which would make this test pass for the wrong reason.
        scoped_id, oid = str(uuid.uuid4()), str(uuid.uuid4())
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatID=str(uuid.uuid4()), Score=9.0, ScopeRank=1, Selected=1, Superseded=0,
            CreatedAt=NOW))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=oid, SessionID=sid, TenantID="t", EntityID="86", UserID="u1",
            SubsystemID=0, ScopedThreatID=scoped_id, Status="complete",
            ScenarioJSON=json.dumps({"scenario_title": "x"}), Accepted=0, Superseded=0,
            IdentityHash="h" * 64, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=NOW))
        s.commit()
    return sid, oid


def _stage(Session, sid: str) -> tuple[str, int]:
    with Session() as s:
        row = s.execute(
            select(m.Subsystem_Stage_State.Status, m.Subsystem_Stage_State.GenerationEpoch)
            .where(m.Subsystem_Stage_State.SessionID == sid,
                m.Subsystem_Stage_State.Level == SubsystemLevel.SCENARIOS)).one()
    return str(row[0]), row[1]


def test_a_busy_subsystem_raises_instead_of_dropping_the_request(monkeypatch):
    """The first half. Returning quietly is what made the click vanish; raising is what gives the
    task something to retry."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, oid = _seed(Session, status=SessionStatus.completed, stage=WorkflowStage.REVIEW)
    monkeypatch.setattr(cascade.lease_keeper, "start", lambda *a, **k: None)

    with Session() as s:
        row = dict(dal.load_session(s, sid))
        with pytest.raises(cascade.SubsystemBusy):
            cascade.run_regeneration(s, row, 0, cascade.RegenGranularity.scenario,
                                    [oid], 2, object(), str(uuid.uuid4()))

    assert _stage(Session, sid) == (str(StageStatus.IDLE), 2), (
        "nothing was written — the stage is still where the endpoint left it")


def test_giving_up_hands_the_stage_back_so_review_works_again(monkeypatch):
    """The second half, for a REGENERATE: the session is completed at REVIEW, where no reaper
    will ever look, so settling has to restore the review barrier itself."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, _oid = _seed(Session, status=SessionStatus.completed, stage=WorkflowStage.REVIEW)
    published: list[dict] = []
    monkeypatch.setattr(cascade.bus, "publish", lambda _sid, payload: published.append(payload))

    with Session() as s:
        row = dict(dal.load_session(s, sid))
        cascade.settle_unstarted(s, row, 0, 2, str(uuid.uuid4()), "regen", target_ids=["a"])

    assert _stage(Session, sid) == (str(StageStatus.AWAITING_DECISION), 2), (
        "the stage is back at the review barrier, so accept and reject work again")
    assert published and published[-1]["reason"] == "subsystem_busy"
    assert published[-1]["message"], "the client is told why, so a screen stops polling"


def test_giving_up_releases_the_asset_a_next_set_had_reserved(monkeypatch):
    """The second half, for NEXT-SET: its request flipped the session back to `active` to hold the
    asset. Settling must return it, or nobody can start an assessment for that asset again."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, _oid = _seed(Session, status=SessionStatus.active, stage=WorkflowStage.SCENARIO_GENERATION)
    monkeypatch.setattr(cascade.bus, "publish", lambda *a, **k: None)

    with Session() as s:
        row = dict(dal.load_session(s, sid))
        cascade.settle_unstarted(s, row, 0, 2, str(uuid.uuid4()), "next_set")

    with Session() as s:
        session_row = dal.load_session(s, sid)
    assert str(session_row["SessionStatus"]) == str(SessionStatus.completed), (
        "the asset is free again — this is what the reaper used to 'fix' by cancelling")
    assert str(session_row["CurrentStage"]) == str(WorkflowStage.REVIEW)


def test_the_retry_window_outlasts_a_control_map_sweep():
    """The numbers are part of the fix. A window shorter than the usual lock holder would give up
    while the sweep is still running, which is the very case this exists for."""
    from app.core.config import get_settings

    window = sum(cascade.BUSY_RETRY_SECONDS * (attempt + 1)
                for attempt in range(cascade.BUSY_MAX_RETRIES))
    assert window > get_settings().control_map_sweep_interval_seconds


# --------------------------------------------------------------------------- the task's handler

def test_the_celery_task_routes_a_busy_lock_to_the_bounded_retry(monkeypatch):
    """Drives regenerate_task, not cascade — the handler, not the thing it handles.

    Every test above calls cascade or settle_unstarted directly, so the task's
    `except cascade.SubsystemBusy` was covered by nothing: swap it for another exception class
    and the whole suite stayed green while a busy lock would crash the worker. A raised
    SubsystemBusy must reach _retry_or_settle and NOT escape the task.
    """
    from app.pipeline import celery_app as ca

    Session = sessionmaker(bind=_engine(), future=True)
    sid, _ = _seed(Session, status=SessionStatus.completed, stage=WorkflowStage.REVIEW)

    seen: dict[str, object] = {}
    monkeypatch.setattr(ca, "db_session", Session)
    monkeypatch.setattr(ca, "get_llm", lambda: object())
    monkeypatch.setattr(ca.cascade, "run_regeneration",
                        lambda *a, **k: (_ for _ in ()).throw(
                            cascade.SubsystemBusy("held by the sweep")))
    monkeypatch.setattr(ca, "_retry_or_settle",
                        lambda *a, **k: seen.update(kind=a[6], subsystem=a[4]))

    # bind=True, so Celery binds `self` itself: .run() is the task body, no broker needed.
    ca.regenerate_task.run(sid, 0, "scenario", None, 2)

    assert seen.get("kind") == "regen", (
        "the task must hand a busy lock to _retry_or_settle — if this passes with the handler "
        "renamed, it is pinning nothing")

