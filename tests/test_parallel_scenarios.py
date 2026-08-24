"""Phase 5: write_scenarios generates a batch CONCURRENTLY (tasks._generate_scenario_batch).

Every other test drives write_scenarios with session_factory=None, which takes the sequential
branch on the caller's own session -- so without this file the concurrent path ships untested.
What is actually risky about it, and therefore what is pinned here:

  - CONCURRENCY IS REAL. A threading.Barrier inside the fake LLM only clears when all three
    calls are in flight at once; a sequential regression deadlocks it and the test fails
    instead of quietly passing slower.
  - ORDER SURVIVES. Results come back in submission order, so scenario text still lands on the
    threat that asked for it. Mis-pairing here would be invisible in the API and catastrophic
    in a risk register.
  - ONE FAILURE DOES NOT TAKE THE BATCH. The failed threat gets its error card; its siblings
    still persist.
  - LLMSlotUnavailable IS DEFERRED, not raised where it lands: already-generated (already
    billed) scenarios commit first, then the stage raises so Celery can resume.

Real SQLite on a temp FILE, not ":memory:" -- worker sessions open their own connections, and
an in-memory database would give each thread a private, empty one.
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.enums import StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import tasks
from app.pipeline.llm import LLMSlotUnavailable

SID = str(uuid.uuid4())
TASK_ID = str(uuid.uuid4())
NOW = datetime.now(UTC)

# Real GUIDs: ThreatID is a GUID column, so "threat-0" fails at the driver, not the assert.
TID = [str(uuid.uuid4()) for _ in range(3)]
THREATS = [
    {"threat_id": TID[i], "grounding_status": "verified", "category": "Tampering",
     "threat_type": f"Type {i}", "threat_name": f"Threat number {i}",
     "library_threat_type": None, "library_threat_name": None,
     "threat_type_id": None, "catalogue_id": None, "actors": []}
    for i in range(3)
]


def _engine(tmp_path):
    return create_engine(f"sqlite:///{tmp_path / 'p5.db'}",
                         connect_args={"check_same_thread": False})


def _create_all(engine):
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Scoped_Threat, m.Threat_Scenario_Output, m.Threat_Scenario_Control_Map,
                m.Scenario_Audit, m.Prompt_Log, m.Config_Threat_Rule):
        tbl.__table__.create(engine)
    return engine


def _seed(s) -> dict:
    row = {"SessionID": SID, "TenantID": "t", "EntityID": "e", "UserID": "u",
           "AssetName": "Pumping Station", "AssetID": "1", "SessionStatus": "active",
           "CurrentStage": "SCENARIO_GENERATION", "StageStatus": "RUNNING", "Mode": "AUTO",
           "SubsystemsJSON": json.dumps([{"id": 41, "name": "SCADA HMI", "asset_type": "OT"}]),
           "SectorIDsJSON": "[]", "CreatedAt": NOW, "UpdatedAt": NOW}
    s.execute(m.Scenario_Session.__table__.insert().values(**row))
    for level in (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS, SubsystemLevel.LOCK):
        s.execute(m.Subsystem_Stage_State.__table__.insert().values(
            StateID=str(uuid.uuid4()), SessionID=SID, TenantID="t", EntityID="e", SubsystemID=0,
            Level=level, Status=StageStatus.IDLE, GenerationEpoch=1,
            LeaseExpiresAt=NOW + timedelta(minutes=30), UpdatedAt=NOW, CreatedAt=NOW))
    s.commit()
    return row


class _BarrierLLM:
    """Answers scenario prompts, but only once `parties` calls are simultaneously in flight.

    The barrier IS the concurrency assertion: run sequentially, call 1 waits for calls 2 and 3
    that cannot start until it returns, and the test fails on timeout instead of silently
    passing slower. `fail_on` / `slot_on` inject a per-item fault to prove isolation.
    """

    def __init__(self, parties: int, fail_on: str | None = None, slot_on: str | None = None):
        self.barrier = threading.Barrier(parties, timeout=15)
        self.fail_on, self.slot_on = fail_on, slot_on
        self.lock = threading.Lock()
        self.threads: set[str] = set()

    def chat(self, messages, temperature=None, expected_type=None):
        user = messages[-1]["content"]
        with self.lock:
            self.threads.add(threading.current_thread().name)
        self.barrier.wait()
        for t in THREATS:
            if t["threat_type"] in user:
                if self.fail_on == t["threat_id"]:
                    raise RuntimeError("provider exploded")
                if self.slot_on == t["threat_id"]:
                    raise LLMSlotUnavailable("no capacity")
                return json.dumps({
                    "scenario_title": f"Title for {t['threat_name']}",
                    "scenario_statement": f"An attacker exploits {t['threat_name']} at the site.",
                    "risk_statement": f"Loss of service via {t['threat_name']}.",
                    "supporting_system_applicability": [],
                }), None
        raise AssertionError("prompt matched no seeded threat: " + user[:200])

    def embed(self, texts, kind=None):
        return [[0.0] * 8 for _ in texts]


def _run(monkeypatch, engine, llm, *, concurrency=3):
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "_fetch_intel", lambda *a, **k: None)
    # Step-4 control mapping is a separate stage with its own tests; stubbed so this file
    # isolates the generation batch.
    monkeypatch.setattr(tasks, "_finalize_scenario_batch", lambda *a, **k: None)
    monkeypatch.setattr(get_settings(), "scenario_generation_concurrency", concurrency)

    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        scenario_session = _seed(s)
        provs = tasks.write_scenarios(
            s, scenario_session, json.loads(scenario_session["SubsystemsJSON"]),
            {"name": "Pumping Station", "asset_type": "Pumping Station"},
            THREATS, llm, TASK_ID, session_factory=Session)
    return Session, provs


def _outputs(Session):
    with Session() as s:
        rows = s.execute(m.Threat_Scenario_Output.__table__.select()).mappings().all()
        scoped = {r["ScopedThreatID"]: r["ThreatID"] for r in s.execute(
            m.Scoped_Threat.__table__.select()).mappings()}
    return {scoped.get(r["ScopedThreatID"]): r for r in rows}


def test_batch_runs_concurrently_and_keeps_its_pairing(monkeypatch, tmp_path):
    llm = _BarrierLLM(parties=3)
    Session, provs = _run(monkeypatch, _create_all(_engine(tmp_path)), llm)

    assert len(provs) == 3
    # The barrier already proved simultaneity; this proves it used the pool, not one thread.
    assert len(llm.threads) == 3

    # ORDER/PAIRING: every scenario's text names the threat it was generated from. A lost
    # ordering would attach threat 0's narrative to threat 2's card with no error anywhere.
    for threat_id, row in _outputs(Session).items():
        scenario = json.loads(row["ScenarioJSON"])
        expected = next(t for t in THREATS if t["threat_id"] == threat_id)
        assert expected["threat_name"] in scenario["scenario_statement"]
        assert scenario["scenario_title"] == f"Title for {expected['threat_name']}"


def test_one_provider_failure_does_not_take_the_batch(monkeypatch, tmp_path):
    llm = _BarrierLLM(parties=3, fail_on=TID[1])
    Session, provs = _run(monkeypatch, _create_all(_engine(tmp_path)), llm)

    assert len(provs) == 2                      # the two survivors still generated
    by_threat = _outputs(Session)
    assert len(by_threat) == 3                  # ...and the failure left a card, not a hole
    assert str(by_threat[TID[1]]["Status"]) == "error"
    assert str(by_threat[TID[0]]["Status"]) == "complete"
    assert str(by_threat[TID[2]]["Status"]) == "complete"


def test_slot_exhaustion_commits_the_billed_work_before_raising(monkeypatch, tmp_path):
    """LLMSlotUnavailable means "retry, don't fail". Raising it where it lands would discard
    two scenarios that were already generated and already paid for; Celery would then retry
    and buy them a second time."""
    engine = _create_all(_engine(tmp_path))
    llm = _BarrierLLM(parties=3, slot_on=TID[2])
    with pytest.raises(LLMSlotUnavailable):
        _run(monkeypatch, engine, llm)

    rows = _outputs(sessionmaker(bind=engine, future=True))
    assert set(rows) == {TID[0], TID[1]}                    # committed before the raise
    assert all(str(r["Status"]) == "complete" for r in rows.values())
    assert TID[2] not in rows                              # no error card: it never failed
