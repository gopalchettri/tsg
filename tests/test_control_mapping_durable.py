"""Verification for the control-mapping durability fix (2026-08-20 incident: 30/30 outputs
mapped, logged as `controls.mapped`, then wiped by the caller's claim-loss `sess.rollback()`
before ever reaching disk). Two things are under test:

1. `map_controls(durable=True)` commits its own writes for real, so a later rollback on the
   SAME session (mirroring write_scenarios' claim-loss path) can no longer undo them.
2. The independent `except Exception: sp.rollback()` bug: once the mid-function commit has
   released the savepoint, an exception raised after that point used to hit `sp.rollback()` on
   an already-closed transaction (`sqlalchemy.exc.ResourceClosedError`), escaping the function
   and crashing the caller's whole stage instead of being swallowed as designed.

Real SQLite tables, no live MSSQL/Redis, no real LLM/grounding calls -- same house pattern as
test_reaper_publish.py, with grounding.get_control_candidates / _min_score / ground_control_queries
stubbed so the test isolates map_controls' own transaction handling.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.enums import ScenarioStatus, StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import control_mapping, grounding


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario_Output,
                m.Threat_Scenario_Control_Map, m.Scenario_Audit):
        tbl.__table__.create(engine)
    return engine


def _seed(s, session_id: str, task_id: str, epoch: int = 1) -> None:
    now = datetime.now(UTC)
    s.execute(m.Scenario_Session.__table__.insert().values(
        SessionID=session_id, TenantID="t", EntityID="e", UserID="u",
        AssetName="a", AssetID="1", SessionStatus="active", CurrentStage="SCENARIOS",
        StageStatus="RUNNING", Mode="full", SubsystemsJSON="[]",
    ))
    s.execute(m.Subsystem_Stage_State.__table__.insert().values(
        StateID=str(uuid.uuid4()), SessionID=session_id, TenantID="t", EntityID="e",
        SubsystemID=0, Level=SubsystemLevel.SCENARIOS, Status=StageStatus.RUNNING,
        GenerationEpoch=epoch, ActiveTaskID=task_id,
        LeaseExpiresAt=now + timedelta(minutes=10), HeartbeatAt=now, AttemptCount=1, UpdatedAt=now,
    ))
    s.execute(m.Threat_Scenario_Output.__table__.insert().values(
        OutputID=str(uuid.uuid4()), SessionID=session_id, TenantID="t", EntityID="e", UserID="u",
        SubsystemID=0, ScopedThreatID=str(uuid.uuid4()), Status=ScenarioStatus.complete,
        ScenarioJSON=json.dumps({"controls": [{"name": "MFA", "why": "reduces credential abuse"}],
                                "scenario_title": "t", "scenario_statement": "s"}),
        Accepted=0, Superseded=0, ScenarioNumber=1, GenerationEpoch=epoch, CreatedAt=now,
    ))
    s.commit()


def _stub_grounding(monkeypatch, *, raise_after_release: bool = False) -> None:
    monkeypatch.setattr(grounding, "get_control_candidates",
                        lambda sess, itot: [{"ControlLibraryID": 1, "ControlCode": "C1",
                                            "Domain": "d", "ControlName": "MFA", "text": "MFA"}])
    monkeypatch.setattr(control_mapping, "_min_score", lambda sess, llm, s: 0.0)
    if raise_after_release:
        def _boom(*a, **k):
            raise RuntimeError("systemic rerank failure")
        monkeypatch.setattr(grounding, "ground_control_queries", _boom)
    else:
        # Contract: one ControlMatches per query — the reranked list best-first, plus
        # `answered`, which separates "we reranked and nothing matched" from "we never got
        # an answer". map_controls iterates .matches and caps at top_k.
        monkeypatch.setattr(grounding, "ground_control_queries",
                            lambda llm, flat, candidates, s: [
                                grounding.ControlMatches([({"ControlLibraryID": 1}, 90.0)], True)
                                for _ in flat])


class _FakeLLM:
    def embed(self, texts, kind):
        return [[0.0] for _ in texts]


def _counts(Session):
    with Session() as s:
        maps = s.execute(m.Threat_Scenario_Control_Map.__table__.select()).fetchall()
        outputs = s.execute(m.Threat_Scenario_Output.__table__.select()).fetchall()
        audits = s.execute(m.Scenario_Audit.__table__.select()).fetchall()
    return maps, outputs, audits


def test_durable_commit_survives_caller_rollback(monkeypatch):
    """The exact bug: mapping succeeds ('controls.mapped' would be logged), then the caller
    hits a claim-loss and rolls back its session. With durable=True, nothing is lost."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        _seed(s, sid, task_id)

    _stub_grounding(monkeypatch)
    scenario_session = {"SessionID": sid, "TenantID": "t", "EntityID": "e"}
    with Session() as s:
        control_mapping.map_controls(s, scenario_session, {}, [], _FakeLLM(), 0, task_id, 1,
                                    durable=True)
        s.rollback()  # mirrors write_scenarios' finish_stage-failed path

    maps, outputs, audits = _counts(Session)
    assert len(maps) == 1
    assert outputs[0].ControlsMappedAt is not None
    assert len(audits) == 1  # audit trail commits together with the data it describes


def test_durable_false_is_wiped_by_caller_rollback(monkeypatch):
    """Control: without durable=True (today's default, targeted/variant callers), the same
    rollback DOES wipe the mapping -- proves the two modes are actually distinguished."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        _seed(s, sid, task_id)

    _stub_grounding(monkeypatch)
    scenario_session = {"SessionID": sid, "TenantID": "t", "EntityID": "e"}
    with Session() as s:
        control_mapping.map_controls(s, scenario_session, {}, [], _FakeLLM(), 0, task_id, 1,
                                    durable=False)
        s.rollback()

    maps, outputs, audits = _counts(Session)
    assert maps == []
    assert outputs[0].ControlsMappedAt is None
    assert audits == []


def test_exception_after_savepoint_release_does_not_raise(monkeypatch):
    """Independent bug: an exception raised after the mid-function commit (savepoint already
    released) must not escape as ResourceClosedError -- for both durable values, since the
    fix applies to every caller, not just the durable one."""
    for durable in (False, True):
        engine = _engine()
        Session = sessionmaker(bind=engine, future=True)
        sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
        with Session() as s:
            _seed(s, sid, task_id)

        _stub_grounding(monkeypatch, raise_after_release=True)
        scenario_session = {"SessionID": sid, "TenantID": "t", "EntityID": "e"}
        with Session() as s:
            control_mapping.map_controls(s, scenario_session, {}, [], _FakeLLM(), 0, task_id, 1,
                                        durable=durable)
            # No exception propagated above -- pytest would already have failed this test.

        maps, outputs, audits = _counts(Session)
        assert maps == [], f"durable={durable}"
        assert outputs[0].ControlsMappedAt is None, f"durable={durable}"
        assert audits == [], f"durable={durable}"


if __name__ == "__main__":
    print("run via pytest")
