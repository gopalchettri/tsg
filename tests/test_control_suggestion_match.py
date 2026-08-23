"""A whitespace-padded LLM control suggestion must still match the map row it produced.

`control_mapping.collect_control_queries` stores the suggestion name STRIPPED then truncated to
500 into Threat_Scenario_Control_Map.SuggestedControl; `_scenario_with_controls` used to key its
`whys` lookup and its unmatched-diff on the UNSTRIPPED name. A padded suggestion therefore came
back in `unmatched_suggested_controls` (a phantom library gap) while its real, grounded control
carried `suggested_why: null`.

Real SQLite tables, no live MSSQL: the read runs through `_controls_by_output`'s actual
SQLAlchemy Core join, and the stored key comes from the writer itself -- so this fails if
EITHER side's normalization drifts again.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import sessions
from app.db import models as m
from app.pipeline.control_mapping import collect_control_queries

_PADDED_NAME = "  Multi-factor authentication for privileged accounts "
_WHY = "Stolen operator credentials otherwise grant direct HMI access."
_SCENARIO_JSON = json.dumps({
    "scenario_title": "Credential theft against the engineering workstation",
    "scenario_statement": "An attacker replays harvested operator credentials.",
    "controls": [{"name": _PADDED_NAME, "why": _WHY}],
})


def _engine():
    engine = create_engine("sqlite://")
    for table in (m.Threat_Scenario_Control_Map, m.Control_Library,
                m.Control_Library_Standard_Map, m.Control_Standard):
        table.__table__.create(engine)
    return engine


def test_whitespace_padded_suggestion_lands_in_controls_not_unmatched():
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    output_id, now = str(uuid.uuid4()), datetime.now(UTC)

    # Exactly what map_controls persists for this suggestion -- stripped, then truncated.
    queries, used_fallback = collect_control_queries(_SCENARIO_JSON, top_k=10)
    assert not used_fallback
    stored_suggestion = queries[0][1]
    assert stored_suggestion == _PADDED_NAME.strip()  # the writer's contract, restated

    with Session() as s:
        s.execute(m.Control_Library.__table__.insert().values(
            ControlLibraryID=1, ControlCode="CII-CID-001", ITOT="IT", Domain="Access Control",
            ControlName="Multi-factor authentication", ControlDescription="MFA on privileged accounts.",
            CreatedAt=now, IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Scenario_Control_Map.__table__.insert().values(
            OutputID=output_id, ControlLibraryID=1, SessionID=str(uuid.uuid4()), MapRank=1,
            Score=87.5, SuggestedControl=stored_suggestion, CreatedAt=now))
        s.commit()

    with Session() as s:
        controls = sessions._controls_by_output(s, [output_id])[output_id]
    assert len(controls) == 1  # guard: _controls_by_output degrades to {} on a bad query

    scenario = sessions._scenario_with_controls(_SCENARIO_JSON, controls, controls_mapped=True)

    assert scenario["controls"][0]["suggested_why"] == _WHY
    assert scenario["unmatched_suggested_controls"] == []
