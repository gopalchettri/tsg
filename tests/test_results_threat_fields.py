"""Regression: GET /results 500'd on the FIRST real end-to-end run against real data.

Phase 4 added four columns to ThreatResult (ThreatCategory, ThreatTypeID, LibraryThreatType,
LibraryThreatName) and updated sessions.get_results' ThreatResult(...) construction to read
them off each threat dict -- but never updated the two SELECTs that BUILD that dict
(sessions.py's `threats = get_current_rows(it, [...])` and the `missing_tids` backfill query).
Both kept selecting only the pre-Phase-4 column set, so `t["ThreatCategory"]` raised KeyError
the moment a session actually had an active, scenario-carrying threat.

Every SQLite fixture in the suite that drives get_results happened to end up with an EMPTY
threats[] list (see test_accept_any_version.py's test_results_default_view_shows_accepted_
superseded_row, which passes both before and after this fix -- its seeded scenarios never
resolve to an active Identified_Threat row), so the missing columns were invisible to 259
passing tests. It took one real session against a real SQL Server database to reach the
construction path at all. This is Gate 1 of the UAT plan doing its job.

Root cause removed, not a warning bolted on: the two SELECTs now name every column ThreatResult
reads. This test seeds the ONE thing every existing fixture in this suite was missing -- a
scenario whose threat is genuinely reachable through get_results' own EXISTS predicate -- so a
future field added to ThreatResult without updating its SELECT fails here immediately.
"""
from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.enums import ScenarioStatus, SessionStatus, StageStatus, SubsystemLevel
from app.db import dal
from app.db import models as m

NOW = datetime.now(UTC)
SID = str(uuid.uuid4())
ENTITY = "86"


def _engine():
    engine = create_engine("sqlite://")

    # session_plan_board / other reads use SQL Server's JSON_VALUE; SQLite needs the shim to
    # even load app.api.sessions' module-level query builders. Same UDF as
    # test_accept_any_version.py's _engine, duplicated rather than imported so this file has no
    # cross-file fixture coupling.
    @event.listens_for(engine, "connect")
    def _register_json_value(dbapi_conn, _record):
        def json_value(blob, path):
            try:
                doc = json.loads(blob)
                for key in path.lstrip("$.").split("."):
                    doc = doc[key]
                return doc
            except Exception:  # noqa: BLE001 — SQLite UDF shim: ANY failure must return NULL
                return None
        dbapi_conn.create_function("json_value", 2, json_value)

    for table in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario_Output,
                m.Scenario_Audit, m.Identified_Threat, m.Scoped_Threat, m.Threat_Type,
                m.Threat_Catalogue, m.Risk_Treatment_Plan, m.Threat_Scenario_Control_Map,
                m.Control_Library):
        table.__table__.create(engine)
    return engine


def _seed(Session) -> tuple[str, str]:
    """One session, one threat, one ACTIVE complete scenario off it -- the exact shape a real
    session produces, which is the shape every prior SQLite fixture avoided by accident."""
    threat_id, scoped_id, output_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=SID, TenantID="t", EntityID=ENTITY, UserID="u",
            AssetName="Smart Grid Infrastructure (SGI)", AssetID="100",
            SessionStatus=SessionStatus.completed, CurrentStage="REVIEW", StageStatus="IDLE",
            Mode="AUTO", SubsystemsJSON="[]", CreatedAt=NOW, UpdatedAt=NOW))
        for level in (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS, SubsystemLevel.LOCK):
            s.execute(m.Subsystem_Stage_State.__table__.insert().values(
                StateID=str(uuid.uuid4()), SessionID=SID, TenantID="t", EntityID=ENTITY,
                SubsystemID=0, Level=level, Status=StageStatus.COMPLETE, GenerationEpoch=1,
                UpdatedAt=NOW, CreatedAt=NOW))
        # Every field Phase 4 added to ThreatResult, populated with a REAL value each -- a
        # missing SELECT column reads back as a KeyError, not a None, so this only proves
        # anything if every field genuinely round-trips.
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=threat_id, SessionID=SID, TenantID="t", EntityID=ENTITY, SubsystemID=0,
            ThreatCategory="Denial of Service", ThreatType="Ransomware on OT support systems",
            ThreatName="Ransomware on OT support systems",
            ThreatTypeID=57, ThreatCatalogueID=418,
            LibraryThreatType="Malware/Ransomware", LibraryThreatName="OT ransomware",
            GroundingStatus="verified", GroundingScore=100.0, Superseded=0, CreatedAt=NOW))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=SID, TenantID="t", EntityID=ENTITY,
            SubsystemID=0, ThreatID=threat_id, Score=90.0, ScopeRank=1, Selected=1,
            Superseded=0, CreatedAt=NOW))
        s.execute(m.Threat_Scenario_Output.__table__.insert().values(
            OutputID=output_id, SessionID=SID, TenantID="t", EntityID=ENTITY, UserID="u",
            SubsystemID=0, ScopedThreatID=scoped_id, Status=ScenarioStatus.complete,
            ScenarioJSON=json.dumps({"scenario_title": "t", "scenario_statement": "s",
                                    "risk_statement": "r"}),
            Accepted=0, Superseded=0, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=NOW))
        s.commit()
    return threat_id, output_id


def test_get_results_does_not_crash_on_a_real_active_threat(monkeypatch):
    import app.api.sessions as sessions_mod
    from app.api.deps import Principal

    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    threat_id, output_id = _seed(Session)

    @contextmanager
    def fake_db_session():
        with Session() as s:
            yield s

    with Session() as s:
        board_row = dict(dal.load_session(s, SID))
    monkeypatch.setattr(sessions_mod, "db_session", fake_db_session)
    monkeypatch.setattr(sessions_mod, "get_authorized_session", lambda *a, **kw: board_row)
    monkeypatch.setattr(sessions_mod, "build_board", lambda *a, **kw: {
        "progress": {"threats": "COMPLETE", "scenarios": "COMPLETE",
                    "overall": "completed", "error_message": {}}})

    principal = Principal(claims={"sub": "u1"}, entities={ENTITY}, client_id="c", tenant_id="t")

    # THE regression: this used to raise KeyError('ThreatCategory') here.
    results = sessions_mod.get_results(SID, include_replaced=False, principal=principal)

    assert len(results.threats) == 1
    t = results.threats[0]
    assert t.ThreatID == threat_id
    # Every Phase-4 field, round-tripped with its REAL seeded value -- not just "didn't crash".
    assert t.ThreatCategory == "Denial of Service"
    assert t.ThreatTypeID == 57
    assert t.ThreatCatalogueID == 418
    assert t.LibraryThreatType == "Malware/Ransomware"
    assert t.LibraryThreatName == "OT ransomware"
    assert results.scenarios[0].OutputID == output_id
