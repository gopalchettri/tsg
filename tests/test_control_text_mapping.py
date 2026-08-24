"""The library-first control-mapping invariant: ONE scenario-text query per output yields up to
control_map_top_k DISTINCT ControlLibraryIDs with MapRank strictly 1..K, best score first,
below-threshold matches dropped, and SuggestedControl NEVER written (the LLM no longer
proposes controls).

Replaces test_control_suggestion_match.py, whose premise was the deleted LLM-suggestion path.
Real SQLite tables, grounding stubbed — same house pattern as test_control_mapping_durable.py.
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
from app.pipeline.control_mapping import collect_control_query


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario_Output,
                m.Threat_Scenario_Control_Map, m.Scenario_Audit):
        tbl.__table__.create(engine)
    return engine


def _seed(s, session_id: str, task_id: str) -> str:
    now = datetime.now(UTC)
    output_id = str(uuid.uuid4())
    s.execute(m.Scenario_Session.__table__.insert().values(
        SessionID=session_id, TenantID="t", EntityID="e", UserID="u",
        AssetName="a", AssetID="1", SessionStatus="active", CurrentStage="SCENARIOS",
        StageStatus="RUNNING", Mode="full", SubsystemsJSON="[]",
    ))
    s.execute(m.Subsystem_Stage_State.__table__.insert().values(
        StateID=str(uuid.uuid4()), SessionID=session_id, TenantID="t", EntityID="e",
        SubsystemID=0, Level=SubsystemLevel.SCENARIOS, Status=StageStatus.RUNNING,
        GenerationEpoch=1, ActiveTaskID=task_id,
        LeaseExpiresAt=now + timedelta(minutes=10), HeartbeatAt=now, AttemptCount=1, UpdatedAt=now,
    ))
    s.execute(m.Threat_Scenario_Output.__table__.insert().values(
        OutputID=output_id, SessionID=session_id, TenantID="t", EntityID="e", UserID="u",
        SubsystemID=0, ScopedThreatID=str(uuid.uuid4()), Status=ScenarioStatus.complete,
        ScenarioJSON=json.dumps({"scenario_title": "Credential theft against the HMI",
                                "scenario_statement": "An attacker replays operator credentials."}),
        Accepted=0, Superseded=0, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=now,
    ))
    s.commit()
    return output_id


def test_collect_control_query_is_scenario_text_only():
    q = collect_control_query(json.dumps({
        "scenario_title": "T", "scenario_statement": "S",
        # a legacy model-authored controls list must be IGNORED, not queried
        "controls": [{"name": "MFA", "why": "w"}],
    }))
    assert q == "T S"
    assert collect_control_query(None) is None          # error card: NULL ScenarioJSON
    assert collect_control_query("not json{") is None or collect_control_query("not json{") == ""
    assert collect_control_query(json.dumps([1, 2])) is None  # valid JSON, wrong shape


def test_one_query_yields_top_k_distinct_ranked_controls(monkeypatch):
    """The GAP the redesign guards against: collapsing to one best match per query would cap
    every scenario at ONE control. 7 reranked matches (one duplicate id, one below threshold)
    must persist as top-5 distinct rows, MapRank 1..5, no SuggestedControl."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        output_id = _seed(s, sid, task_id)

    matches = [
        ({"ControlLibraryID": 1}, 95.0),
        ({"ControlLibraryID": 2}, 90.0),
        ({"ControlLibraryID": 1}, 88.0),   # duplicate id — best[cid] keeps the 95.0 row
        ({"ControlLibraryID": 3}, 85.0),
        ({"ControlLibraryID": 4}, 80.0),
        ({"ControlLibraryID": 5}, 75.0),
        ({"ControlLibraryID": 6}, 40.0),   # below min score — dropped
    ]
    monkeypatch.setattr(grounding, "get_control_candidates",
                        lambda sess, itot: [{"ControlLibraryID": i, "text": f"c{i}"}
                                            for i in range(1, 7)])
    monkeypatch.setattr(control_mapping, "_min_score", lambda sess, llm, s: 60.0)
    monkeypatch.setattr(grounding, "ground_control_queries",
                        lambda llm, flat, candidates, s: [
                            grounding.ControlMatches(list(matches), True) for _ in flat])

    class _FakeLLM:
        def embed(self, texts, kind):
            return [[0.0] for _ in texts]

    scenario_session = {"SessionID": sid, "TenantID": "t", "EntityID": "e"}
    with Session() as s:
        control_mapping.map_controls(s, scenario_session, {}, [], _FakeLLM(), 0, task_id, 1,
                                     durable=True)

    with Session() as s:
        rows = s.execute(m.Threat_Scenario_Control_Map.__table__.select()
                         .order_by(m.Threat_Scenario_Control_Map.MapRank)).fetchall()
    assert [r.ControlLibraryID for r in rows] == [1, 2, 3, 4, 5]      # distinct, best-first
    assert [r.MapRank for r in rows] == [1, 2, 3, 4, 5]               # strictly increasing
    assert [r.Score for r in rows] == [95.0, 90.0, 85.0, 80.0, 75.0]  # dedup kept the best
    assert all(r.SuggestedControl is None for r in rows)              # LLM suggestions are gone
    assert all(r.OutputID == output_id for r in rows)
