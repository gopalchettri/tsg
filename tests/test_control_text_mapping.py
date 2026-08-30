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
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario,
                m.Threat_Scenario_Control_Map, m.Scenario_Audit,
                # map_controls joins these to put the THREAT in the control query
                # (control_mapping.collect_control_query) — without them the join
                # errors and mapping silently degrades to zero controls.
                m.Scoped_Threat, m.Identified_Threat):
        tbl.__table__.create(engine)
    return engine


def _seed(s, session_id: str, task_id: str) -> str:
    now = datetime.now(UTC)
    scenario_id = str(uuid.uuid4())
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
    s.execute(m.Threat_Scenario.__table__.insert().values(
        ScenarioID=scenario_id, SessionID=session_id, TenantID="t", EntityID="e", UserID="u",
        SubsystemID=0, ScopedThreatID=str(uuid.uuid4()), Status=ScenarioStatus.complete,
        ScenarioJSON=json.dumps({"scenario_title": "Credential theft against the HMI",
                                "scenario_statement": "An attacker replays operator credentials."}),
        Accepted=0, Superseded=0, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=now,
    ))
    s.commit()
    return scenario_id


def test_collect_control_query_leads_with_the_threat_then_scenario_text():
    """THE regression this pins. Narrative-only queries matched IMPACT-shaped controls and
    buried MECHANISM-shaped ones: measured against the real 557-row OT library, a
    "Compromised OT supply chain or hardware" scenario scored `Telecommunications Services
    Availability` 14.0 and the correct `Signed Components` 1.9 — nothing cleared the cutoff, so
    the API published `controls: []` as if the library had no coverage. With the threat
    prefixed, `Supply Chain Risk Assessment` scored 90.98 and `Signed Components` 60.6 against
    the same library, reranker and threshold. Drop the threat from this query and that silent
    empty-controls failure comes straight back."""
    body = {
        "scenario_title": "T", "scenario_statement": "S",
        # a legacy model-authored controls list must be IGNORED, not queried
        "controls": [{"name": "MFA", "why": "w"}],
    }
    assert collect_control_query(json.dumps(body), "Compromised OT supply chain",
                                "Supply Chain Compromise") == \
        "Compromised OT supply chain Supply Chain Compromise T S"
    # No threat context (the measurement script's --text-file mode) degrades to the narrative
    # rather than crashing or emitting stray separators.
    assert collect_control_query(json.dumps(body)) == "T S"
    assert collect_control_query(json.dumps(body), None, "Supply Chain Compromise") == \
        "Supply Chain Compromise T S"
    assert collect_control_query(None) is None          # error card: NULL ScenarioJSON
    assert collect_control_query("not json{") is None or collect_control_query("not json{") == ""
    assert collect_control_query(json.dumps([1, 2])) is None  # valid JSON, wrong shape


def test_map_controls_actually_threads_the_threat_into_the_query(monkeypatch):
    """THE regression the pure-function test above cannot catch.

    collect_control_query taking a threat proves nothing unless map_controls PASSES one. An
    audit reverted map_controls' call to the narrative-only form and the entire suite still
    passed: every existing map_controls test seeds a ScopedThreatID with no matching
    Scoped_Threat row, so the OUTER join yields NULLs and the threat-augmented call is
    byte-identical to the reverted one — and all of them stub ground_control_queries with a
    lambda that ignores `flat`, so the query TEXT is never observed.

    This test seeds the real chain and asserts on the query map_controls BUILDS. It pins, in
    one assertion: the two join predicates, the library-spelling preference (ltname/lttype over
    tname/ttype), the argument order, and the threat's position as a PREFIX. Break any of them
    and the measured failure returns — the correct control scoring 1.9/100 while the API
    publishes `controls: []` as a library gap."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    scoped_id, threat_id = str(uuid.uuid4()), str(uuid.uuid4())
    now = datetime.now(UTC)
    with Session() as s:
        scenario_id = _seed(s, sid, task_id)
        # Point the seeded output at a REAL scoped/threat chain — the piece every other
        # map_controls test leaves dangling.
        s.execute(m.Threat_Scenario.__table__.update()
                .where(m.Threat_Scenario.ScenarioID == scenario_id)
                .values(ScopedThreatID=scoped_id))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=sid, TenantID="t", EntityID="e",
            SubsystemID=0, ThreatID=threat_id, Score=90.0, ScopeRank=1, Selected=1,
            Superseded=0, CreatedAt=now))
        # Proposed vs library spelling deliberately DIFFER, so the assertion below proves the
        # curator's wording wins — the library is what the controls were written against.
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=threat_id, SessionID=sid, TenantID="t", EntityID="e", SubsystemID=0,
            ThreatCategory="Tampering", ThreatType="model wording for the type",
            ThreatName="model wording for the name",
            LibraryThreatType="Supply Chain Compromise",
            LibraryThreatName="Compromised OT supply chain or hardware",
            GroundingStatus="verified", GroundingScore=100.0, Superseded=0, CreatedAt=now))
        s.commit()

    seen: list[str] = []

    def _capture(llm, flat, candidates, s_):
        seen.extend(q for q, _qv in flat)
        return [grounding.ControlMatches([], True) for _ in flat]

    monkeypatch.setattr(grounding, "get_control_candidates",
                        lambda sess, itot: [{"ControlLibraryID": 1, "text": "c1"}])
    monkeypatch.setattr(control_mapping, "_min_score",
                        lambda sess, llm, s_: grounding.Threshold(60.0, "test"))
    monkeypatch.setattr(grounding, "ground_control_queries", _capture)

    class _FakeLLM:
        def embed(self, texts, kind):
            return [[0.0] for _ in texts]

    with Session() as s:
        control_mapping.map_controls(s, {"SessionID": sid, "TenantID": "t", "EntityID": "e"},
                                    {}, [], _FakeLLM(), 0, task_id, 1, durable=True)

    assert seen == [
        "Compromised OT supply chain or hardware Supply Chain Compromise "
        "Credential theft against the HMI An attacker replays operator credentials."
    ], seen


def test_one_query_yields_top_k_distinct_ranked_controls(monkeypatch):
    """The GAP the redesign guards against: collapsing to one best match per query would cap
    every scenario at ONE control. 7 reranked matches (one duplicate id, one below threshold)
    must persist as top-5 distinct rows, MapRank 1..5, no SuggestedControl."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        scenario_id = _seed(s, sid, task_id)

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
    monkeypatch.setattr(control_mapping, "_min_score",
                        lambda sess, llm, s: grounding.Threshold(60.0, "test"))
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
    assert all(r.ScenarioID == scenario_id for r in rows)


def test_empty_candidate_library_still_returns_control_matches_not_bare_lists():
    """ground_control_queries is typed `-> list[ControlMatches]`. Its empty-`rows` fast path
    used to return `[[] for _ in queries]` — a bare list, not the NamedTuple every caller
    trusts. map_controls (above) reads `.answered` on every returned item unconditionally, so
    an empty control library would have crashed with AttributeError instead of the intended
    "answered, zero matches" outcome the type exists to express."""
    class _UncalledLLM:
        def embed(self, texts, kind):
            raise AssertionError("the empty-rows fast path must return before touching the LLM")

    from app.core.config import get_settings

    out = grounding.ground_control_queries(
        _UncalledLLM(), [("q1", None), ("q2", None)], [], get_settings())
    assert out == [grounding.ControlMatches([], True), grounding.ControlMatches([], True)]
    assert all(isinstance(r, grounding.ControlMatches) for r in out)
    assert all(r.answered is True and r.matches == [] for r in out)
