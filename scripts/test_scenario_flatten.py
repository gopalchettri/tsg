"""Self-check: scenarios[] in GET /sessions/{id}/results nests threat_category/type/name/actors
and supporting_system_applicability inside `scenario`, alongside the existing controls.

Run:  .venv/Scripts/python.exe scripts/test_scenario_flatten.py

Assert-based, no framework — matches scripts/test_prompt_no_db_keys.py's style. Exercises
sessions.py::_scenario_with_controls and schemas.py::ScenarioNarrative directly with synthetic
data; no DB/LLM needed since the merge is pure dict logic.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api import sessions
from app.api.schemas import MappedControl, ScenarioNarrative

RAW_SCENARIO_JSON = json.dumps({
    "scenario_title": "PGS outage",
    "scenario_statement": "s",
    "risk_statement": "r",
    "controls": [{"name": "Network segmentation", "why": "Limits pivot."}],
    "supporting_system_applicability": [
        {"supporting_system": "SCADA System", "applicable": True, "justification": "Entry point."},
        {"supporting_system": "OT Telecom Network", "applicable": False, "justification": "Not involved."},
    ],
})

THREAT_ROW = {
    "ThreatCategory": "Denial of Service", "ThreatType": "loss of availability",
    "ThreatName": "Loss of control and generation availability of PGS",
    # ThreatActorsJSON's real shape (grounding.py::_actors_meta): {"actors": [...], "validated": bool}
    "ThreatActorsJSON": json.dumps({"actors": ["External attacker", "Nation-state/APT"], "validated": False}),
}

CONTROLS = [MappedControl(control_library_id=28, control_code="CII-CID-028", domain="BCDR",
                          control_name="Testing for Reliability", rank=1, score=99.0,
                          suggested_control="Network segmentation", standards=["DESC ISR v3"])]


def main() -> None:
    # 1 — threat_row merges threat_category/type/name/actors into the scenario dict, alongside
    #     the existing controls merge.
    merged = sessions._scenario_with_controls(RAW_SCENARIO_JSON, CONTROLS, True, THREAT_ROW)
    assert merged["threat_category"] == "Denial of Service"
    assert merged["threat_type"] == "loss of availability"
    assert merged["threat_name"] == "Loss of control and generation availability of PGS"
    assert merged["threat_actors"] == ["External attacker", "Nation-state/APT"]
    assert merged["controls"][0]["control_code"] == "CII-CID-028"
    print("1 OK  threat fields merged in alongside the existing controls merge")

    # 2 — the merged dict validates as ScenarioNarrative, with supporting_system_applicability
    #     parsed from the LLM's own scenario JSON (untouched by the merge).
    narrative = ScenarioNarrative(**merged)
    assert narrative.threat_category == "Denial of Service"
    assert len(narrative.supporting_system_applicability) == 2
    assert narrative.supporting_system_applicability[0].supporting_system == "SCADA System"
    assert narrative.supporting_system_applicability[0].applicable is True
    assert narrative.supporting_system_applicability[1].applicable is False
    print("2 OK  ScenarioNarrative validates threat fields + supporting_system_applicability")

    # 3 — threat_row=None (the accepted-scenarios/scenario-list call sites, unchanged by this
    #     work) must still validate: new fields default to None/[], not a validation error.
    no_threat = sessions._scenario_with_controls(RAW_SCENARIO_JSON, CONTROLS, True, None)
    assert no_threat.get("threat_category") is None
    narrative_no_threat = ScenarioNarrative(**no_threat)
    assert narrative_no_threat.threat_category is None
    assert narrative_no_threat.threat_actors == []
    print("3 OK  threat_row=None still validates — existing call sites unaffected")

    # 4 — a pre-existing scenario written before this field existed (no supporting_system_
    #     applicability key at all) still validates, defaulting to an empty list.
    old_json = json.dumps({"scenario_title": "t", "scenario_statement": "s", "risk_statement": "r"})
    old = sessions._scenario_with_controls(old_json, [], True, THREAT_ROW)
    narrative_old = ScenarioNarrative(**old)
    assert narrative_old.supporting_system_applicability == []
    print("4 OK  pre-existing scenarios (no applicability key) default to an empty list")

    # 5 — accepted-scenarios / scenario-list wiring: _scenario_list_item must put the SAME
    #     library-preferred threat_type/name on the nested scenario as on the sibling field —
    #     never two different answers to "what is this scenario's threat_type" in one response.
    list_row = {
        "OutputID": "out-1", "SessionID": "sess-1", "SubsystemID": 7, "ScenarioJSON": RAW_SCENARIO_JSON,
        "Accepted": 1, "Superseded": 0, "ScenarioNumber": 1, "CreatedAt": None, "ControlsMappedAt": "x",
        "EntityID": "78", "UserID": "gc", "SessionStatus": "completed",
        "ThreatTypeID": None, "ThreatCatalogueID": None,
        "ThreatType": "loss of availability", "ThreatName": "raw stage-1 name",
        "LibraryThreatType": "Loss of Availability (curated)", "LibraryThreatName": "Curated name",
        "ThreatCategory": "Denial of Service",
        "ThreatActorsJSON": json.dumps({"actors": ["External attacker"], "validated": True}),
    }
    item = sessions._scenario_list_item(list_row, CONTROLS)
    assert item.threat_type == "Loss of Availability (curated)" == item.scenario.threat_type
    assert item.threat_name == "Curated name" == item.scenario.threat_name
    assert item.scenario.threat_category == "Denial of Service"
    assert item.scenario.threat_actors == ["External attacker"]
    print("5 OK  _scenario_list_item's nested scenario matches its sibling threat_type/name exactly")

    print("\nscenario flatten self-check OK")


if __name__ == "__main__":
    main()
