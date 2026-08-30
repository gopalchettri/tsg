"""Regression: GET /results 500'd on the FIRST real end-to-end run against real data.

Phase 4 added four columns to ThreatResult (ThreatCategory, ThreatTypeID, LibraryThreatType,
LibraryThreatName) and updated sessions.get_results' ThreatResult(...) construction to read
them off each threat dict -- but never updated the two SELECTs that BUILD that dict
(sessions.py's `threats = get_current_rows(it, [...])` and the `missing_tids` backfill query).
Both kept selecting only the pre-Phase-4 column set, so `t["threat_category"]` raised KeyError
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

    for table in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario,
                m.Scenario_Audit, m.Identified_Threat, m.Scoped_Threat, m.Threat_Type,
                m.Risk_Treatment_Plan, m.Threat_Scenario_Control_Map,
                m.Control_Library, m.Threat_Actor, m.Control_Standard,
                m.Control_Library_Standard_Map):
        table.__table__.create(engine)
    return engine


def _seed(Session) -> tuple[str, str]:
    """One session, one threat, one ACTIVE complete scenario off it -- the exact shape a real
    session produces, which is the shape every prior SQLite fixture avoided by accident."""
    threat_id, scoped_id, scenario_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
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
            ThreatTypeID=57, ThreatCatalogueID=418, ThreatCategoryID=5,
            Description="Ransomware encrypts OT support systems.", IsAIGenerated=False,
            LibraryThreatType="Malware/Ransomware", LibraryThreatName="OT ransomware",
            GroundingStatus="verified", GroundingScore=100.0, Superseded=0, CreatedAt=NOW,
            ThreatActorsJSON=json.dumps({"actors": ["Nation-state/APT"], "validated": True})))
        # Actor keys resolve by name against Threat_Actor at read time (the seeded blob
        # predates stored actor_ids, so the name-lookup fallback is what's exercised).
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=7, ThreatActorName="Nation-state/APT",
            IsActive=True, IsDeleted=False))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=SID, TenantID="t", EntityID=ENTITY,
            SubsystemID=0, ThreatID=threat_id, Score=90.0, ScopeRank=1, Selected=1,
            Superseded=0, CreatedAt=NOW))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=scenario_id, SessionID=SID, TenantID="t", EntityID=ENTITY, UserID="u",
            SubsystemID=0, ScopedThreatID=scoped_id, Status=ScenarioStatus.complete,
            ScenarioJSON=json.dumps({"scenario_title": "t", "scenario_statement": "s",
                                    "risk_statement": "r"}),
            Accepted=0, Superseded=0, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=NOW,
            ControlsMappedAt=NOW))
        # One mapped control referring to TWO standards — the multi-standard-per-control case
        # the StandardRef keys exist to disambiguate.
        s.execute(m.Control_Library.__table__.insert().values(
            ControlLibraryID=201, ControlCode="CII-CID-201", ITOT="OT",
            Domain="Identification & Authentication", ControlName="Multi-Factor Authentication",
            ControlDescription="d", IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Scenario_Control_Map.__table__.insert().values(
            ScenarioID=scenario_id, ControlLibraryID=201, SessionID=SID, Score=93.0, MapRank=1,
            CreatedAt=NOW))
        for std_id, std_name in ((3, "NIST SP 800-53 Rev. 5"), (7, "ISO 27001:2022")):
            s.execute(m.Control_Standard.__table__.insert().values(
                StandardID=std_id, StandardName=std_name, IsActive=True, IsDeleted=False))
            s.execute(m.Control_Library_Standard_Map.__table__.insert().values(
                ControlLibraryID=201, StandardID=std_id))
        s.commit()
    return threat_id, scenario_id


def test_get_results_does_not_crash_on_a_real_active_threat(monkeypatch):
    import app.api.sessions as sessions_mod
    from app.api.deps import Principal

    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    threat_id, scenario_id = _seed(Session)

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

    # No top-level threats[] any more: every entry it could have held was a duplicate of some
    # card's own threat, so each card carries it instead (ScenarioResult.threat), read from the
    # SAME row and therefore unable to drift from the card it describes.
    assert not hasattr(results, "threats")
    assert results.scenarios[0].scenario_id == scenario_id

    # THE threat block, on the ENVELOPE -- every database key, round-tripped with its REAL
    # seeded value. Declared here rather than inside `scenario` precisely so a failure card
    # (scenario=null) still reports which threat failed.
    t = results.scenarios[0].threat
    assert t is not None
    assert t.threat_id == threat_id
    assert t.threat_category == "Denial of Service"
    assert t.threat_type_id == 57
    assert t.threat_catalogue_id == 418
    assert t.threat_category_id == 5
    assert t.description == "Ransomware encrypts OT support systems."
    assert t.is_threat_ai_generated is False
    assert t.is_threat_type_ai_generated is False  # threat_type_id == 57, a real library match
    assert t.grounding_status == "verified"
    assert t.grounding_score == 100.0
    assert t.library_threat_type == "Malware/Ransomware"
    assert t.library_threat_name == "OT ransomware"
    # Score/ScopeRank come from THIS scenario's own Scoped_Threat row, via the same join.
    assert t.score == 90.0
    assert t.scope_rank == 1
    # Actors carry their DB keys. There is deliberately NO bare ThreatActors list beside them:
    # a second, un-keyed copy of the same names is what drifts.
    assert not hasattr(t, "ThreatActors")
    assert [(a.actor_id, a.actor_name) for a in t.actors] == [(7, "Nation-state/APT")]

    # Standards carry their DB keys alongside the legacy name list — one control referring to
    # several standards is ambiguous as bare names, which is the gap StandardRef closes.
    control = results.scenarios[0].scenario.controls[0]
    assert control.control_id == 201
    assert not hasattr(control, "StandardNames")   # keyed list only, no un-keyed duplicate
    assert [(s.standard_id, s.standard_name) for s in control.standards] == [
        (7, "ISO 27001:2022"), (3, "NIST SP 800-53 Rev. 5")]


def test_failure_card_still_reports_which_threat_failed(monkeypatch):
    """THE reason `threat` sits on the envelope and not inside `scenario`.

    A failed generation persists an error card: ScenarioJSON is NULL, so `scenario` is null in
    the response. While the threat block lived inside `scenario`, that made the card's threat
    identity vanish on exactly the rows a reviewer most needs to identify -- and it was the
    reason a parallel top-level threats[] list had to exist at all (its own query carried a
    no-Status-filter comment specifically to keep failure cards' threats reachable). On the
    envelope, the card reports its threat whether or not the narrative exists, so removing
    threats[] cannot resurrect that gap."""
    import app.api.sessions as sessions_mod
    from app.api.deps import Principal

    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    threat_id, _scenario_id = _seed(Session)

    failed_output, failed_scoped = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        # A second scoped row off the SAME threat, carrying an error card: ScenarioJSON NULL.
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=failed_scoped, SessionID=SID, TenantID="t", EntityID=ENTITY,
            SubsystemID=0, ThreatID=threat_id, Score=90.0, ScopeRank=2, Selected=1,
            Superseded=0, CreatedAt=NOW))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=failed_output, SessionID=SID, TenantID="t", EntityID=ENTITY, UserID="u",
            SubsystemID=0, ScopedThreatID=failed_scoped, Status=ScenarioStatus.error,
            ScenarioJSON=None, ErrorMessage="LLM call failed",
            Accepted=0, Superseded=0, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=NOW))
        s.commit()

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
    results = sessions_mod.get_results(SID, include_replaced=False, principal=principal)

    card = next(c for c in results.scenarios if c.scenario_id == failed_output)
    assert card.scenario is None                      # the failure card, as expected
    assert card.threat is not None, "a failure card must still say WHICH threat failed"
    assert card.threat.threat_id == threat_id
    assert card.threat.threat_name == "Ransomware on OT support systems"
    assert card.threat.threat_catalogue_id == 418       # database keys survive too
    assert card.threat.threat_type_id == 57


def test_a_failed_controls_read_is_not_published_as_a_library_gap(monkeypatch):
    """THE read-side twin of the empty-controls bug.

    `_controls_by_output` catches every exception, logs `controls.read_failed` and returns `{}` —
    deliberately, because a secondary read must never 500 the core results view
    (`_actor_ids_by_name` names that a shared contract). But `{}` was indistinguishable from
    "mapping ran and matched nothing", and `ControlsMapped` is read straight off the row, so one
    transient database error published EVERY scenario on the page as `ControlsMapped: true` with
    an empty control list — which schemas.py documents in three places as a genuine library-gap
    signal worth acting on. A reviewer could not tell a curated fact about the control library
    from a database blip, and the natural response is to go author controls that already exist.

    The fix is the house pattern for exactly this defect (grounding.ControlMatches.answered):
    stop overloading the empty value. The response still degrades rather than failing — it just
    degrades honestly now.
    """
    import app.api.sessions as sessions_mod
    from app.api.deps import Principal

    Session = sessionmaker(bind=_engine(), future=True)
    _threat_id, scenario_id = _seed(Session)

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

    def _boom(*a, **k):
        raise RuntimeError("transient database error while reading the control map")
    monkeypatch.setattr(sessions_mod, "_query_controls", _boom)

    principal = Principal(claims={"sub": "u1"}, entities={ENTITY}, client_id="c", tenant_id="t")
    results = sessions_mod.get_results(SID, include_replaced=False, principal=principal)

    card = results.scenarios[0]
    assert card.scenario_id == scenario_id
    # The deliberate contract is intact: a failed secondary read still returns the page.
    assert card.scenario is not None, "a failed controls read must not take down the results view"
    assert card.scenario.controls == []
    # ControlsMapped is correct — it reads ControlsMappedAt off the row, and mapping DID run.
    assert card.controls_mapped is True
    # ...which is precisely why the empty list beside it needed to stop being ambiguous.
    assert card.controls_unavailable is True, (
        "an unreadable control list is being published as a genuine library gap")


def test_a_healthy_read_never_claims_controls_are_unavailable(monkeypatch):
    """Control for the test above: without it, `ControlsUnavailable = True` hard-coded would
    pass. On a healthy page the flag must be false AND the mapped control must be present."""
    import app.api.sessions as sessions_mod
    from app.api.deps import Principal

    Session = sessionmaker(bind=_engine(), future=True)
    _threat_id, _scenario_id = _seed(Session)

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
    card = sessions_mod.get_results(SID, include_replaced=False,
                                    principal=principal).scenarios[0]
    assert card.controls_unavailable is False
    assert [c.control_id for c in card.scenario.controls] == [201]
