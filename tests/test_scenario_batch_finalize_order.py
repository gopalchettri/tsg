"""Step-4 control mapping must run AFTER the batch is settled and committed — never before.

THE BUG. `_finalize_scenario_batch` (control mapping) used to be called BEFORE
`dal.finish_stage`, inside the caller's still-unvalidated transaction. `map_controls` commits
mid-function to end its lease transaction before the slow rerank, and a commit cannot tell its own
write apart from whatever else the caller has pending — so a targeted regenerate's buffered rows
(`_reconcile_targeted_regen`) were made permanent by it. When `finish_stage` then failed on a lost
claim, `sess.rollback()` discarded nothing: a regenerate that lost its claim left scenario rows
behind that the code believed it had thrown away, with the stage recorded as never completed.

`durable=not targeted` was meant to prevent exactly this and could not: that flag guards the two
commits at the END of map_controls, never the mid-function one. The fix is ordering, not a flag.

Safe only because tsg.map_controls_sweep now exists: a worker death in the new gap between the
commit and mapping leaves ControlsMappedAt NULL, and the sweep maps it within one tick. Before the
sweep, this reordering would have traded a rare corruption for a permanent empty control list.

NOTE FOR THE NEXT READER — do not "strengthen" these tests into asserting that a lost claim
rolls the scenario rows back. On the FULL-RUN path it never did and never should:
`_persist_full_run_scenario` commits per item on purpose, so an already-billed scenario survives a
mid-batch failure. The rollback only ever protected the TARGETED path's buffered rows. What is
path-independent, and therefore what is pinned here, is the ORDER.

Real SQLite on a temp file, fake LLM — mirrors test_parallel_scenarios.py's write_scenarios
harness. The three existing tests that stub `_finalize_scenario_batch` to a no-op are structurally
blind to when it runs, which is why this file exists separately.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.enums import StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import tasks

SID = str(uuid.uuid4())
TASK_ID = str(uuid.uuid4())
NOW = datetime.now(UTC)
TID = str(uuid.uuid4())

THREATS = [{"threat_id": TID, "grounding_status": "verified", "category": "Tampering",
            "threat_type": "Supply Chain Compromise", "threat_name": "Compromised OT firmware",
            "library_threat_type": None, "library_threat_name": None,
            "threat_type_id": None, "catalogue_id": None, "actors": []}]


def _engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'order.db'}",
                           connect_args={"check_same_thread": False})
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Scoped_Threat, m.Threat_Scenario, m.Threat_Scenario_Control_Map,
                m.Scenario_Audit, m.Prompt_Log):
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


class _FakeLLM:
    def chat(self, messages, temperature=None, expected_type=None):
        return json.dumps({
            "scenario_title": "Compromised vendor firmware on the SCADA HMI",
            "scenario_statement": "An attacker ships signed-looking firmware to the site.",
            "risk_statement": "Loss of view and control at the pumping station.",
            "supporting_systems_involved": [],
        }), None

    def embed(self, texts, kind=None):
        return [[0.0] * 8 for _ in texts]


def _run(monkeypatch, tmp_path, *, finish_ok: bool) -> list[str]:
    """Drive one real write_scenarios batch, recording the order of the two steps under test."""
    order: list[str] = []
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "_fetch_intel", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "_finalize_scenario_batch",
                        lambda *a, **k: order.append("map_controls"))

    real_finish = tasks.dal.finish_stage

    def _finish(*a, **k):
        order.append("finish_stage")
        # finish_ok=False is the claim-loss path: another worker took the stage over mid-batch.
        return real_finish(*a, **k) if finish_ok else False

    monkeypatch.setattr(tasks.dal, "finish_stage", _finish)

    Session = sessionmaker(bind=_engine(tmp_path), future=True)
    with Session() as s:
        scenario_session = _seed(s)
        tasks.write_scenarios(s, scenario_session,
                            json.loads(scenario_session["SubsystemsJSON"]),
                            {"name": "Pumping Station", "asset_type": "Pumping Station"},
                            THREATS, _FakeLLM(), TASK_ID)
    return order


def test_control_mapping_runs_after_the_batch_is_settled(monkeypatch, tmp_path):
    """THE regression, stated as the order it is.

    Pre-fix this reads ['map_controls', 'finish_stage'] — mapping ran first, inside the caller's
    unvalidated transaction, where its mid-function commit could make a targeted regenerate's
    buffered rows permanent before finish_stage had a chance to reject the whole batch.
    """
    assert _run(monkeypatch, tmp_path, finish_ok=True) == ["finish_stage", "map_controls"]


def test_a_lost_claim_runs_no_control_mapping_at_all(monkeypatch, tmp_path):
    """The consequence that makes the fix complete: a rejected batch maps nothing.

    Mapping that never started cannot commit anything, so there is no longer any route by which a
    lost claim leaves committed rows behind. Pre-fix, mapping had already run — and committed —
    by the time the claim loss was discovered.
    """
    assert _run(monkeypatch, tmp_path, finish_ok=False) == ["finish_stage"]
