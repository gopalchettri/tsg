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
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.core.enums import (
    AuditDecision,
    ScenarioDecisionReason,
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
            except Exception:  # noqa: BLE001 — SQLite UDF shim: ANY failure must return NULL,
                return None      # which is what MSSQL's JSON_VALUE does for a bad path/blob
        dbapi_conn.create_function("json_value", 2, json_value)

    for table in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario_Output,
                m.Scenario_Audit, m.Identified_Threat, m.Scoped_Threat, m.Threat_Type,
                m.Threat_Catalogue, m.Risk_Treatment_Plan, m.Threat_Scenario_Control_Map,
                m.Control_Library):
        table.__table__.create(engine)

    # The two filtered unique indexes that arbitrate scenario identity in production
    # (TSG_Core.sql:628, :637). SQLite supports partial indexes with the same semantics, so
    # mirroring them here is what lets a test in this file DETECT a double-accept at all.
    #
    # Without them the shim silently accepts rows the real database would reject, so a test can
    # assert a guard "prevents" a collision that the shim was never going to raise — passing for
    # the wrong reason. That is not hypothetical: it is how a test asserting an unreachable
    # duplicate-accept 500 came to look plausible. Creating them here removes the cause for every
    # present and future test in this file, rather than fixing the one test that got it wrong.
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output"
            "(SessionID, IdentityHash, ScenarioNumber) WHERE Superseded = 0")
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX UX_Scenario_ActiveAccepted ON Threat_Scenario_Output"
            "(SessionID, IdentityHash, ScenarioNumber) WHERE Accepted = 1 AND IdentityHash IS NOT NULL")
    return engine


def _now():
    return datetime.now(UTC)


def _seed_session(Session, *, at_review: bool = True) -> str:
    """One session at the REVIEW barrier, with its _LOCK (IDLE) and SCENARIOS
    (AWAITING_DECISION) stage rows for the asset unit (SubsystemID 0).

    At the barrier the session is COMPLETED, not active: generation completes it there so the
    asset is released while the reviewer decides scenario by scenario (tasks._send_to_review).
    Seeding `active` here would be seeding a state production can no longer reach, and every
    accept assertion built on it would pass for the wrong reason. `at_review=False` still seeds
    an active mid-generation session, which is exactly when accept must be refused."""
    sid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=sid, TenantID="t", EntityID="86", UserID="u1", AssetID=7,
            AssetName="Citizen Portal",
            SessionStatus=SessionStatus.completed if at_review else SessionStatus.active,
            CompletedAt=_now() if at_review else None,
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
        # The session was ALREADY completed by generation and stays that way — accept decides
        # scenarios, not sessions. C and D are still undecided and remain acceptable later.
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

    assert exc_info.value.reason == ScenarioDecisionReason.duplicate_identity
    for oid in (b, d):
        assert _flags(Session, oid)[0] == 0
    with Session() as s:  # the refusal ended nothing — the session sits where generation left it
        assert dict(dal.load_session(s, sid))["SessionStatus"] == str(SessionStatus.completed)
    # ...and "re-acceptable" is asserted by DOING it, not by reading a status string: retry with
    # one version instead of two and it goes through.
    assert _accept(Session, sid, [b], monkeypatch) == 1
    assert _flags(Session, b)[0] == 1


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


def test_identity_guard_ignores_ids_the_write_would_not_touch(monkeypatch):
    """scenario_identity_pairs mirrors mark_scenarios_accepted's predicates, so an id the write
    will not flip cannot manufacture a false conflict in the guard.

    A failed generation leaves a FAILURE CARD carrying its threat's IdentityHash; regenerating that
    threat supersedes the card and writes a real scenario under the SAME identity. Both rows then
    exist — the card superseded, the scenario active — which UX_Scenario_ActiveIdentity permits
    because only one is active.

    `mark_scenarios_accepted` skips the card (Status='error'), so it can never reach the index.
    Before the guard's lookup mirrored those predicates it still saw the card's pair, and naming
    both ids in one subset raised duplicate_identity for a collision that could not happen."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    card = _scenario(Session, sid, identity=HASH_03, superseded=1,
                    status=str(ScenarioStatus.error), title="v-card")
    good = _scenario(Session, sid, identity=HASH_03, superseded=0, replaces=card, title="v-good")

    # The guard must stay silent; the card is then reported by the normal not-acceptable path as a
    # 404-with-reasons (failure_card), NOT as a duplicate_identity 409 from the pre-flight.
    with pytest.raises(dal.NotFoundError) as exc_info:
        _accept(Session, sid, [good, card], monkeypatch)
    assert _REASON_TEXT[ScenarioDecisionReason.failure_card] in str(exc_info.value)
    assert _flags(Session, good)[0] == 0, "nothing is written when a subset id is unacceptable"


def test_reject_all_issues_no_identity_query(monkeypatch):
    """subset=[] is the reject-all close. SQLAlchemy renders an empty IN as a real round trip
    (`... IN (NULL) AND (1 != 1)`), so the early return in scenario_identity_pairs is what keeps
    the close from paying for a query whose result cannot influence anything."""
    assert dal.scenario_identity_pairs(None, "sess", [], [0]) == {}


def test_reason_text_covers_every_enum_member_and_wire_values():
    """No ScenarioDecisionReason can surface without human wording; surviving members keep the
    exact strings the old bare literals put on the wire."""
    for member in ScenarioDecisionReason:
        assert member in _REASON_TEXT, f"_REASON_TEXT missing wording for {member!r}"
    assert ScenarioDecisionReason.unknown == "unknown"
    assert ScenarioDecisionReason.failure_card == "failure_card"
    assert ScenarioDecisionReason.subsystem_not_awaiting_decision == "subsystem_not_awaiting_decision"


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
        reasons = dal.undecidable_subset_reasons(s, sid, [b, bad, foreign], [0],
                                                 decision=AuditDecision.accept)
    assert b not in reasons
    assert reasons[bad] == ScenarioDecisionReason.failure_card
    assert reasons[foreign] == ScenarioDecisionReason.unknown


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
    from contextlib import contextmanager

    import app.api.sessions as sessions_mod
    from app.api.deps import Principal

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

    ids = {sc.OutputID for sc in results.scenarios}
    assert b in ids          # accepted, though superseded
    assert d in ids          # current version still visible (flagged not-accepted)
    assert a not in ids and c not in ids  # plain history stays hidden by default
    # Response invariant: every threat_id a returned card carries resolves in threats[] —
    # a card must never reference a threat the same response says does not exist.
    threat_ids = {t.ThreatID for t in results.threats}
    for sc in results.scenarios:
        if sc.ThreatID is not None:
            assert sc.ThreatID in threat_ids


def test_treatment_gate_accepts_superseded_accepted_scenario(monkeypatch):
    """post_treatment_plan: an accepted-but-superseded scenario passes the gates (proven via a
    sentinel raised by the NEXT step); a non-accepted one still 409s scenario_not_accepted."""
    from contextlib import contextmanager

    import app.api.treatment as treatment_api
    from app.api.deps import Principal
    from app.core.enums import TreatmentGateReason
    from app.pipeline import treatment as treatment_mod

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


# --- the scenario lifecycle: decisions are per-scenario and outlive the session -------------
def test_accept_one_today_and_the_rest_days_later(monkeypatch):
    """THE requirement this lifecycle change exists for: accept one scenario now, come back
    later and accept another. Before it, the first accept completed the session and every
    remaining scenario was stranded with no reachable path back."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    first = _scenario(Session, sid, identity="ident-1", number=1, superseded=0, title="v-1")
    second = _scenario(Session, sid, identity="ident-2", number=1, superseded=0, title="v-2")

    assert _accept(Session, sid, [first], monkeypatch) == 1
    assert _flags(Session, first) == (1, 0)
    assert _flags(Session, second) == (0, 0)   # untouched — still pending, not rejected

    # ...days pass. The session is completed and the asset was released the whole time.
    with Session() as s:
        assert dict(dal.load_session(s, sid))["SessionStatus"] == str(SessionStatus.completed)

    assert _accept(Session, sid, [second], monkeypatch) == 1
    with Session() as s:
        titles = sorted(json.loads(r["ScenarioJSON"])["scenario_title"]
                        for r in dal.accepted_scenarios(s, sid))
        assert titles == ["v-1", "v-2"]


def test_second_accept_cannot_accept_another_version_of_an_accepted_scenario(monkeypatch):
    """The collision the seeded guard exists for, and it is only reachable now that accept
    repeats: accept version B, then come back and name version D of the SAME scenario.
    UX_Scenario_ActiveAccepted would reject that at statement time; the pre-flight turns it
    into a typed 409 that says the scenario is already accepted."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)

    assert _accept(Session, sid, [b], monkeypatch) == 1

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, [d], monkeypatch)
    assert exc_info.value.reason == ScenarioDecisionReason.duplicate_identity
    assert "already accepted" in str(exc_info.value)
    assert _flags(Session, d)[0] == 0   # refused before any write
    assert _flags(Session, b)[0] == 1   # the earlier decision stands


def test_accept_all_is_guarded_against_an_earlier_accepted_version(monkeypatch):
    """Accept-all is checked too. Accepting superseded version B and then clicking accept-all
    would flip active version D — two accepted versions of one identity. Proof that dropping
    the accept-all branch of the guard is not safe once accept repeats."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)

    assert _accept(Session, sid, [b], monkeypatch) == 1

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, None, monkeypatch)
    assert exc_info.value.reason == ScenarioDecisionReason.duplicate_identity
    assert _flags(Session, d)[0] == 0
