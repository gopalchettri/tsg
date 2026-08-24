"""Phase 5b end to end: the second asset of a profile pays NOTHING for its scenarios.

Two sessions, two different customers' assets, identical profile (same sector scope, asset
type, sub-sector, and the same technology on each supporting system, in the same order) but
different asset and system NAMES.

  session 1  generates, and fills Scenario_Library on the way past
  session 2  serves the same threat from that row with ZERO chat calls, its own system names
             substituted in, and ScenarioSource="library" recorded on the output

The two assertions that matter most are the negative ones: session 2 makes no LLM call, and no
trace of session 1's customer names survives into session 2's scenario. A cache that leaks one
customer's system name into another's risk register is worse than no cache.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.enums import StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import prompts, tasks

NOW = datetime.now(UTC)
CATALOGUE_ID = 418

#: Same profile, different customers. Only the NAMES differ.
ASSET_A = {"name": "Al Qusais Pumping Station", "asset_type": "Pumping Station",
           "sector": "Energy & Water", "sub_sector": "Water Supply",
           "critical_service": ["Potable water supply"]}
ASSET_B = {**ASSET_A, "name": "Jebel Ali Pumping Station"}
SYSTEMS_A = [{"id": 41, "name": "Qusais SCADA HMI", "asset_type": "OT", "criticality": "High",
              "technology_used": ["Siemens SCADA"], "vendor_name": "Siemens"}]
SYSTEMS_B = [{"id": 88, "name": "Jebel Control Console", "asset_type": "OT",
              "criticality": "High", "technology_used": ["Siemens SCADA"],
              "vendor_name": "Siemens"}]

THREAT = {"threat_id": None, "grounding_status": "verified", "category": "Tampering",
          "threat_type": "Logic/Configuration Manipulation",
          "threat_name": "Unauthorised setpoint modification",
          "library_threat_type": "Logic/Configuration Manipulation",
          "library_threat_name": "Unauthorised setpoint modification",
          "threat_type_id": 7, "catalogue_id": CATALOGUE_ID, "actors": ["APT33"]}


class _CountingLLM:
    """Writes a scenario that names BOTH the asset and its supporting system, so a failed
    substitution is visible rather than theoretical. Counts chat calls: session 2 must make 0."""

    def __init__(self, asset_name: str, system_name: str):
        self.asset_name, self.system_name = asset_name, system_name
        self.calls = 0

    def chat(self, messages, temperature=None, expected_type=None):
        self.calls += 1
        return json.dumps({
            "scenario_title": f"{self.system_name} — unauthorised setpoint push",
            "scenario_statement": (
                f"An attacker with OT network access alters pump setpoints on the "
                f"{self.system_name}, degrading control of {self.asset_name}."),
            "risk_statement": (
                f"{self.asset_name} provides Potable water supply; corrupted setpoints "
                f"could cause a sustained outage."),
            "supporting_system_applicability": [
                {"supporting_system": self.system_name, "applicable": True,
                 "justification": "Direct target of this scenario."}],
        }), None

    def embed(self, texts, kind=None):
        return [[0.0] * 8 for _ in texts]


def _engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'lib.db'}")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Scoped_Threat, m.Threat_Scenario_Output, m.Threat_Scenario_Control_Map,
                m.Scenario_Audit, m.Prompt_Log, m.Scenario_Library,
                m.Config_Threat_Rule, m.Threat_Type):
        tbl.__table__.create(engine)
    return engine


def _seed(s, sid: str, asset: dict, systems: list[dict]) -> dict:
    row = {"SessionID": sid, "TenantID": "t", "EntityID": "e", "UserID": "u",
           "AssetName": asset["name"], "AssetID": "1", "SessionStatus": "active",
           "CurrentStage": "SCENARIO_GENERATION", "StageStatus": "RUNNING", "Mode": "AUTO",
           "SubsystemsJSON": json.dumps(systems), "SectorIDsJSON": json.dumps([4, 2]),
           "CreatedAt": NOW, "UpdatedAt": NOW}
    s.execute(m.Scenario_Session.__table__.insert().values(**row))
    for level in (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS, SubsystemLevel.LOCK):
        s.execute(m.Subsystem_Stage_State.__table__.insert().values(
            StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="e", SubsystemID=0,
            Level=level, Status=StageStatus.IDLE, GenerationEpoch=1,
            LeaseExpiresAt=NOW + timedelta(minutes=30), UpdatedAt=NOW, CreatedAt=NOW))
    s.commit()
    return row


def _run(monkeypatch, Session, asset, systems, llm):
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "_fetch_intel", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "_finalize_scenario_batch", lambda *a, **k: None)
    sid = str(uuid.uuid4())
    threat = {**THREAT, "threat_id": str(uuid.uuid4())}
    with Session() as s:
        scenario_session = _seed(s, sid, asset, systems)
        tasks.write_scenarios(s, scenario_session, systems, asset, [threat], llm,
                            str(uuid.uuid4()))
    return sid


def _output(Session, sid):
    with Session() as s:
        return s.execute(m.Threat_Scenario_Output.__table__.select().where(
            m.Threat_Scenario_Output.SessionID == sid)).mappings().one()


def test_second_asset_of_a_profile_reuses_the_text_for_free(monkeypatch, tmp_path):
    Session = sessionmaker(bind=_engine(tmp_path), future=True)

    llm_a = _CountingLLM("Al Qusais Pumping Station", "Qusais SCADA HMI")
    sid_a = _run(monkeypatch, Session, ASSET_A, SYSTEMS_A, llm_a)
    assert llm_a.calls == 1                                   # asset 1 pays once

    # ...and the text was banked against the PROFILE, not the asset.
    with Session() as s:
        lib = s.execute(select(m.Scenario_Library)).scalars().all()
    assert len(lib) == 1
    assert lib[0].ThreatCatalogueID == CATALOGUE_ID
    assert lib[0].PromptVersion == prompts.PROMPT_VERSION
    assert lib[0].ModelID == get_settings().inference_model
    assert json.loads(lib[0].SourceNamesJSON) == ["Al Qusais Pumping Station", "Qusais SCADA HMI"]

    llm_b = _CountingLLM("Jebel Ali Pumping Station", "Jebel Control Console")
    sid_b = _run(monkeypatch, Session, ASSET_B, SYSTEMS_B, llm_b)

    # THE POINT: asset 2 generated nothing.
    assert llm_b.calls == 0

    row_b = _output(Session, sid_b)
    assert row_b["ScenarioSource"] == "library"
    body = json.dumps(json.loads(row_b["ScenarioJSON"]))
    # its own names are in...
    assert "Jebel Control Console" in body and "Jebel Ali Pumping Station" in body
    # ...and NOTHING of the first customer survived. This is the assertion that makes the
    # cache safe to share across tenants at all.
    assert "Qusais" not in body and "Al Qusais Pumping Station" not in body

    assert _output(Session, sid_a)["ScenarioSource"] == "generated"
    with Session() as s:                       # one row per profile, not one per asset
        assert len(s.execute(select(m.Scenario_Library)).scalars().all()) == 1


def test_a_different_profile_does_not_borrow_the_text(monkeypatch, tmp_path):
    """A cache hit must require the profile to actually match. Swap the technology and the key
    changes, so asset 2 generates its own."""
    Session = sessionmaker(bind=_engine(tmp_path), future=True)
    _run(monkeypatch, Session, ASSET_A, SYSTEMS_A,
        _CountingLLM("Al Qusais Pumping Station", "Qusais SCADA HMI"))

    other_tech = [{**SYSTEMS_B[0], "technology_used": ["Rockwell ControlLogix"]}]
    llm_b = _CountingLLM("Jebel Ali Pumping Station", "Jebel Control Console")
    sid_b = _run(monkeypatch, Session, ASSET_B, other_tech, llm_b)

    assert llm_b.calls == 1
    assert _output(Session, sid_b)["ScenarioSource"] == "generated"
    with Session() as s:                       # two profiles, two rows
        assert len(s.execute(select(m.Scenario_Library)).scalars().all()) == 2


def test_prompt_version_change_invalidates_without_a_purge(monkeypatch, tmp_path):
    """Invalidation is by non-match, not by deletion: bump the prompt version and the stored
    row simply stops being found, so a rollback re-matches the rows it produced."""
    Session = sessionmaker(bind=_engine(tmp_path), future=True)
    original = prompts.PROMPT_VERSION
    _run(monkeypatch, Session, ASSET_A, SYSTEMS_A,
        _CountingLLM("Al Qusais Pumping Station", "Qusais SCADA HMI"))

    monkeypatch.setattr(prompts, "PROMPT_VERSION", original + "-next")
    llm_b = _CountingLLM("Jebel Ali Pumping Station", "Jebel Control Console")
    sid_b = _run(monkeypatch, Session, ASSET_B, SYSTEMS_B, llm_b)

    assert llm_b.calls == 1                    # regenerated under the new prompt
    assert _output(Session, sid_b)["ScenarioSource"] == "generated"
    with Session() as s:                       # the old row is kept, just not served
        rows = s.execute(select(m.Scenario_Library)).scalars().all()
    assert {r.PromptVersion for r in rows} == {original, original + "-next"}
