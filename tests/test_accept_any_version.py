"""Accept-any-version: Accepted decoupled from Superseded (plan eager-swimming-acorn).

A regenerated scenario keeps every version as a row; the reviewer may now accept ANY of them,
not just the newest. These are the FIRST tests of the accept path (tests/ previously had zero
coverage of accept_session/mark_scenarios_accepted). Real SQLite tables, no live MSSQL: the
functions under test run their real SQL through SQLAlchemy Core/ORM, same style as
test_reaper_publish.py.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.core.enums import (
    AcceptSubsetReason,
    ScenarioStatus,
    SessionStatus,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.db import dal
from app.db import models as m
from app.db.invariants import REQUIRED_INDEXES
from app.pipeline import accept as accept_mod
from app.pipeline.accept import _REASON_TEXT, AcceptConflict, accept_session
from app.sse import bus

HASH_10 = "a" * 64  # scenario #10's identity — shared by all its versions
HASH_03 = "b" * 64  # an unrelated scenario


def _engine():
    engine = create_engine("sqlite://")

    # session_plan_board uses SQL Server's JSON_VALUE; give SQLite an equivalent.
    @event.listens_for(engine, "connect")
    def _register_json_value(dbapi_conn, _record):
        def json_value(blob, path):
            try:
                doc = json.loads(blob)
                for key in path.lstrip("$.").split("."):
                    doc = doc[key]
                return doc
            except Exception:
                return None
        dbapi_conn.create_function("json_value", 2, json_value)

    for table in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario_Output,
                m.Scenario_Audit, m.Identified_Threat, m.Scoped_Threat, m.Threat_Type,
                m.Threat_Catalogue, m.Risk_Treatment_Plan, m.Threat_Scenario_Control_Map,
                m.Control_Library):
        table.__table__.create(engine)
    return engine


def _now():
    return datetime.now(timezone.utc)


def _seed_session(Session, *, at_review: bool = True) -> str:
    """One active session at the REVIEW barrier, with its _LOCK (IDLE) and SCENARIOS
    (AWAITING_DECISION) stage rows for the asset unit (SubsystemID 0)."""
    sid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=sid, TenantID="t", EntityID="86", UserID="u1", AssetID=7,
            AssetName="Citizen Portal", SessionStatus=SessionStatus.active,
            CurrentStage=WorkflowStage.REVIEW if at_review else WorkflowStage.SCENARIO_GENERATION,
            StageStatus=StageStatus.AWAITING_DECISION if at_review else StageStatus.RUNNING,
            Mode="AUTO", CurrentSubsystemIndex=0, SubsystemsJSON="[]",
            CreatedAt=_now(), UpdatedAt=_now()))
        for level, status in ((SubsystemLevel.LOCK, StageStatus.IDLE),
                              (SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION)):
            s.execute(m.Subsystem_Stage_State.__table__.insert().values(
                StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="86",
                SubsystemID=0, Level=level, Status=status, GenerationEpoch=1,
                LeaseExpiresAt=_now() + timedelta(minutes=10), AttemptCount=1,
                UpdatedAt=_now(), CreatedAt=_now()))
        s.commit()
    return sid


def _scenario(Session, sid: str, *, identity: str, number: int = 1, superseded: int,
              accepted: int = 0, status: str = str(ScenarioStatus.complete),
              replaces: str | None = None, title: str = "T") -> str:
    oid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Threat_Scenario_Output.__table__.insert().values(
            OutputID=oid, SessionID=sid, TenantID="t", EntityID="86", UserID="u1",
            SubsystemID=0, ScopedThreatID=str(uuid.uuid4()), Status=status,
            ScenarioJSON=json.dumps({"scenario_title": title, "scenario_statement": "s",
                                     "risk_statement": "r"}),
            Accepted=accepted, Superseded=superseded, IdentityHash=identity,
            ScenarioNumber=number, ReplacesOutputID=replaces, GenerationEpoch=1,
            CreatedAt=_now()))
        s.commit()
    return oid


def _versions_abcd(Session, sid: str) -> tuple[str, str, str, str]:
    """Scenario #10 regenerated 3x: A (original), B, C, D (newest, only D active)."""
    a = _scenario(Session, sid, identity=HASH_10, superseded=1, title="v-A")
    b = _scenario(Session, sid, identity=HASH_10, superseded=1, replaces=a, title="v-B")
    c = _scenario(Session, sid, identity=HASH_10, superseded=1, replaces=b, title="v-C")
    d = _scenario(Session, sid, identity=HASH_10, superseded=0, replaces=c, title="v-D")
    return a, b, c, d


def _accept(Session, sid: str, subset, monkeypatch) -> int:
    """Run the real accept_session with its two advisory tails stubbed (SSE + promotion —
    both out of scope here and both explicitly never-raise paths)."""
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    monkeypatch.setattr(accept_mod, "run_promotion_phase", lambda *a, **k: True)
    with Session() as s:
        return accept_session(s, sid, "86", "u1", subset=subset)


def _flags(Session, oid: str) -> tuple[int, int]:
    with Session() as s:
        row = s.execute(select(m.Threat_Scenario_Output.Accepted,
                               m.Threat_Scenario_Output.Superseded)
                        .where(m.Threat_Scenario_Output.OutputID == oid)).one()
        return row[0], row[1]


def test_accept_older_version_end_to_end(monkeypatch):
    """Accept [B] (superseded): B gets Accepted=1 with Superseded UNTOUCHED (still 1), D stays
    the newest (Superseded=0) but unaccepted — and accepted_scenarios() returns B."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    a, b, c, d = _versions_abcd(Session, sid)

    matched = _accept(Session, sid, [b], monkeypatch)

    assert matched == 1
    assert _flags(Session, b) == (1, 1)   # accepted, still superseded — flags decoupled
    assert _flags(Session, d) == (0, 0)   # newest, untouched, NOT accepted
    assert _flags(Session, a) == (0, 1)
    assert _flags(Session, c) == (0, 1)
    with Session() as s:
        rows = dal.accepted_scenarios(s, sid)
        assert [json.loads(r["ScenarioJSON"])["scenario_title"] for r in rows] == ["v-B"]
        # the session completed — the accept was real, not a partial no-op
        assert dict(dal.load_session(s, sid))["SessionStatus"] == str(SessionStatus.completed)


def test_duplicate_identity_rejected_before_any_write(monkeypatch):
    """subset=[B, D] (two versions of ONE scenario): clean pre-flight AcceptConflict with the
    typed reason, and NO row's Accepted flag changed — rejected before any write."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, [b, d], monkeypatch)

    assert exc_info.value.reason == AcceptSubsetReason.duplicate_identity
    for oid in (b, d):
        assert _flags(Session, oid)[0] == 0
    with Session() as s:  # session must still be active and re-acceptable
        assert dict(dal.load_session(s, sid))["SessionStatus"] == str(SessionStatus.active)


def test_two_distinct_scenarios_both_acceptable(monkeypatch):
    """Control: two ids with DIFFERENT identities in one subset accept fine together."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    _a, b, _c, _d = _versions_abcd(Session, sid)
    other = _scenario(Session, sid, identity=HASH_03, superseded=0, title="v-other")

    assert _accept(Session, sid, [b, other], monkeypatch) == 2
    assert _flags(Session, b)[0] == 1
    assert _flags(Session, other)[0] == 1


def test_reason_text_covers_every_enum_member_and_wire_values():
    """No AcceptSubsetReason can surface without human wording; surviving members keep the
    exact strings the old bare literals put on the wire."""
    for member in AcceptSubsetReason:
        assert member in _REASON_TEXT, f"_REASON_TEXT missing wording for {member!r}"
    assert AcceptSubsetReason.unknown == "unknown"
    assert AcceptSubsetReason.failure_card == "failure_card"
    assert AcceptSubsetReason.subsystem_not_awaiting_decision == "subsystem_not_awaiting_decision"


def test_unacceptable_reasons_no_longer_flag_superseded():
    """A superseded complete row in a good subsystem produces NO rejection reason now."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    _a, b, _c, _d = _versions_abcd(Session, sid)
    bad = _scenario(Session, sid, identity=HASH_03, superseded=0,
                    status=str(ScenarioStatus.error))  # failure card, still unacceptable
    foreign = str(uuid.uuid4())  # a well-formed id that matches nothing in this session
    with Session() as s:
        reasons = dal.unacceptable_subset_reasons(s, sid, [b, bad, foreign], [0])
    assert b not in reasons
    assert reasons[bad] == AcceptSubsetReason.failure_card
    assert reasons[foreign] == AcceptSubsetReason.unknown


def test_new_index_registered_in_boot_invariants():
    assert ("UX_Scenario_ActiveAccepted", "Threat_Scenario_Output",
            ("SessionID", "IdentityHash", "ScenarioNumber")) in REQUIRED_INDEXES


def test_plan_board_and_history_see_accepted_superseded_row(monkeypatch):
    """session_plan_board / superseded_plan_rows(board form) must surface the accepted version
    even though it is superseded — they used to require Superseded=0 too."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    _a, b, _c, _d = _versions_abcd(Session, sid)
    _accept(Session, sid, [b], monkeypatch)

    with Session() as s:
        board = dal.session_plan_board(s, sid)
        assert [r["OutputID"] for r in board] == [b]
        # board-form history: a retired plan row hanging off the ACCEPTED (superseded) scenario
        s.execute(m.Risk_Treatment_Plan.__table__.insert().values(
            PlanID=str(uuid.uuid4()), SessionID=sid, OutputID=b, TenantID="t", EntityID="86",
            Status=str(StageStatus.COMPLETE), TreatmentStrategy="Mitigate", Superseded=1,
            CreatedAt=_now(), UpdatedAt=_now()))
        s.commit()
        history = dal.superseded_plan_rows(s, sid)
        assert [r["OutputID"] for r in history] == [b]


def test_promotion_candidates_not_starved_by_superseded_accepted(monkeypatch):
    """_promotion_candidates must return a below-threshold threat whose ONLY accepted scenario
    is a superseded version — seeded with the lineage regen ACTUALLY leaves behind: the
    accepted old output hangs off a SUPERSEDED scoped row (regen supersedes the scoped row and
    mints a new ScopedThreatID for the replacement), while the current unaccepted output owns
    the active scoped row. An earlier draft seeded the accepted output on an active scoped row
    — a state the pipeline never produces — and green-lit a query that still starved."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    threat_id = str(uuid.uuid4())
    old_scoped, new_scoped = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=threat_id, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatCategory="Information Disclosure", ThreatType="Data exposure",
            ThreatName="Unauthorized disclosure of X", GroundingStatus="unverified",
            GroundingScore=None, Superseded=0, CreatedAt=_now()))
        for scoped_id, superseded in ((old_scoped, 1), (new_scoped, 0)):
            s.execute(m.Scoped_Threat.__table__.insert().values(
                ScopedThreatID=scoped_id, SessionID=sid, TenantID="t", EntityID="86",
                SubsystemID=0, ThreatID=threat_id, Score=90.0, ScopeRank=1, Selected=1,
                Superseded=superseded, CreatedAt=_now()))
        # accepted OLD version -> superseded scoped row; current version -> active scoped row
        for scoped_id, accepted, superseded in ((old_scoped, 1, 1), (new_scoped, 0, 0)):
            s.execute(m.Threat_Scenario_Output.__table__.insert().values(
                OutputID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="86",
                SubsystemID=0, ScopedThreatID=scoped_id, Status=str(ScenarioStatus.complete),
                ScenarioJSON="{}", Accepted=accepted, Superseded=superseded,
                IdentityHash=HASH_10, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=_now()))
        s.commit()
        rows = accept_mod._promotion_candidates(s, sid, [0])
    assert [r["ThreatID"] for r in rows] == [threat_id]


def test_results_default_view_shows_accepted_superseded_row(monkeypatch):
    """The GET /results default query must include the accepted-but-superseded version and
    still exclude non-accepted superseded ones. Exercised through the real route function."""
    import app.api.sessions as sessions_mod
    from app.api.deps import Principal
    from contextlib import contextmanager

    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    a, b, c, d = _versions_abcd(Session, sid)
    _accept(Session, sid, [b], monkeypatch)

    @contextmanager
    def fake_db_session():
        with Session() as s:
            yield s

    with Session() as s:
        board_row = dict(dal.load_session(s, sid))
    monkeypatch.setattr(sessions_mod, "db_session", fake_db_session)
    monkeypatch.setattr(sessions_mod, "get_authorized_session", lambda *args, **kw: board_row)
    monkeypatch.setattr(sessions_mod, "build_board", lambda *args, **kw: {
        "progress": {"threats": "COMPLETE", "scenarios": "COMPLETE",
                     "overall": "completed", "error_message": {}}})

    principal = Principal(claims={"sub": "u1"}, entities={"86"}, client_id="c", tenant_id="t")
    results = sessions_mod.get_results(sid, include_replaced=False, principal=principal)

    ids = {sc.output_id for sc in results.scenarios}
    assert b in ids          # accepted, though superseded
    assert d in ids          # current version still visible (flagged not-accepted)
    assert a not in ids and c not in ids  # plain history stays hidden by default
    # Response invariant: every threat_id a returned card carries resolves in threats[] —
    # a card must never reference a threat the same response says does not exist.
    threat_ids = {t.threat_id for t in results.threats}
    for sc in results.scenarios:
        if sc.threat_id is not None:
            assert sc.threat_id in threat_ids


def test_treatment_gate_accepts_superseded_accepted_scenario(monkeypatch):
    """post_treatment_plan: an accepted-but-superseded scenario passes the gates (proven via a
    sentinel raised by the NEXT step); a non-accepted one still 409s scenario_not_accepted."""
    import app.api.treatment as treatment_api
    from app.api.deps import Principal
    from app.core.enums import TreatmentGateReason
    from app.pipeline import treatment as treatment_mod
    from contextlib import contextmanager

    class Sentinel(Exception):
        """Raised in place of build_treatment_input — reaching it proves the gates passed."""

    @contextmanager
    def fake_db_session():
        yield object()

    session_row = {"SessionID": "s", "TenantID": "t", "EntityID": "86", "UserID": "u1"}
    monkeypatch.setattr(treatment_api, "db_session", fake_db_session)
    monkeypatch.setattr(treatment_api, "get_authorized_session", lambda *a, **k: session_row)
    monkeypatch.setattr(dal, "load_session", lambda *a, **k: session_row)
    monkeypatch.setattr(dal, "active_plan_row", lambda *a, **k: None)  # first generation
    monkeypatch.setattr(treatment_mod, "build_treatment_input",
                        lambda *a, **k: (_ for _ in ()).throw(Sentinel()))

    scn = {"OutputID": "o1", "Superseded": 1, "Accepted": 1}
    monkeypatch.setattr(dal, "scenario_row", lambda *a, **k: dict(scn))
    body = treatment_api.TreatmentPlanBody(
        existing_controls=[], likelihood_rating=4, impact_rating=5,
        final_risk_rating=20, risk_level="Critical")
    principal = Principal(claims={"sub": "u1"}, entities={"86"}, client_id="c", tenant_id="t")

    with pytest.raises(Sentinel):  # passed both gates, died at the stubbed next step
        treatment_api.post_treatment_plan("s", "o1", body, principal)

    scn["Accepted"] = 0  # not accepted -> still refused, with the surviving reason
    with pytest.raises(treatment_mod.TreatmentConflict) as exc_info:
        treatment_api.post_treatment_plan("s", "o1", body, principal)
    assert exc_info.value.reason == TreatmentGateReason.scenario_not_accepted


if __name__ == "__main__":
    print("run via pytest")
