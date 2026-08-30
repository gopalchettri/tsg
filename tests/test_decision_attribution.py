"""WHO decided, recorded on the row itself.

Reject has stamped `RejectedAt`/`RejectedBy` since 2026-08-23. Accept stamped neither, so "who
rejected this" was a column read while "who accepted this" was answerable only by joining the
Scenario_Audit ledger — one class of fact living in two places. Session and plan cancellation had
the same hole: an endpoint and an audit event, but nothing on the row.

These pin the columns that close it. Each is written so the ORIGINAL behaviour fails it: before
the change `AcceptedBy`/`CancelledBy` did not exist, and the first assertion in every test below
is the one that would have raised.

The first-decider-wins test matters more than it looks. `decide_scenarios` treats deciding twice
as idempotent, not an error, and its ledger writes fire only for real TRANSITIONS — so without
`coalesce` a second accept would silently rewrite the acceptor while the audit trail still named
the first. The row and the ledger would then disagree about who decided, which is precisely what
an attribution column exists to prevent.
"""
from __future__ import annotations

from sqlalchemy.orm import sessionmaker

from app.core.enums import AuditDecision
from app.db import dal
from app.db import models as m
from app.sse import bus
from tests.test_accept_any_version import _engine, _scenario, _seed_session

CREATOR = "u1"
OTHER = "u2"


def _row(Session, oid: str):
    with Session() as s:
        return s.execute(m.Threat_Scenario.__table__.select().where(
            m.Threat_Scenario.ScenarioID == oid)).mappings().one()


def _session_row(Session, sid: str):
    with Session() as s:
        return s.execute(m.Scenario_Session.__table__.select().where(
            m.Scenario_Session.SessionID == sid)).mappings().one()


def _decide(Session, sid: str, decision: AuditDecision, *, subset, actor):
    """Straight at dal.decide_scenarios — the single writer these columns are written by, and the
    function whose coalesce behaviour is under test. Going through accept_session instead would
    exercise its gates rather than the write."""
    with Session() as s:
        n = dal.decide_scenarios(s, sid, [0], decision=decision, subset=subset,
                                 tenant_id="t", entity_id="86", user_id=actor)
        s.commit()
        return n


def _fixture(Session):
    sid = _seed_session(Session)
    return sid, _scenario(Session, sid, identity="ident-a", number=1, superseded=0, title="A")


# --- accept ------------------------------------------------------------------------------------
def test_accept_records_who_and_when(monkeypatch):
    """The gap this closes: an accepted row could not say who accepted it."""
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a = _fixture(Session)

    assert _decide(Session, sid, AuditDecision.accept, subset=[a], actor=CREATOR) == 1

    row = _row(Session, a)
    assert row["Accepted"] == 1
    assert row["AcceptedBy"] == CREATOR, "the acceptor was not recorded on the row"
    assert row["AcceptedAt"] is not None, "the acceptance time was not recorded on the row"


def test_a_second_accept_keeps_the_first_acceptor(monkeypatch):
    """Deciding twice is idempotent and writes no second ledger row — so a re-accept must NOT
    rewrite the acceptor, or the row and the trail would name different people. Mirrors
    RejectedBy's long-standing coalesce behaviour."""
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a = _fixture(Session)

    _decide(Session, sid, AuditDecision.accept, subset=[a], actor=CREATOR)
    first_at = _row(Session, a)["AcceptedAt"]
    _decide(Session, sid, AuditDecision.accept, subset=[a], actor=OTHER)

    row = _row(Session, a)
    assert row["AcceptedBy"] == CREATOR, "a re-accept overwrote the original acceptor"
    assert row["AcceptedAt"] == first_at, "a re-accept moved the original acceptance time"


def test_an_accepted_row_carries_no_rejection_attribution(monkeypatch):
    """The two decisions are mutually exclusive (CK_Scenario_DecisionExclusive); their
    attribution must be too, or a row could name a rejecter it never had."""
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a = _fixture(Session)

    _decide(Session, sid, AuditDecision.accept, subset=[a], actor=CREATOR)

    row = _row(Session, a)
    assert row["RejectedBy"] is None and row["RejectedAt"] is None


# --- reject: unchanged behaviour, guarded ------------------------------------------------------
def test_reject_attribution_is_unchanged(monkeypatch):
    """Regression guard: adding the accept columns must not disturb the pair that already worked."""
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a = _fixture(Session)

    _decide(Session, sid, AuditDecision.reject, subset=[a], actor=CREATOR)

    row = _row(Session, a)
    assert row["RejectedBy"] == CREATOR and row["RejectedAt"] is not None
    assert row["AcceptedBy"] is None and row["AcceptedAt"] is None


# --- who actually did it -----------------------------------------------------------------------
def test_a_system_audit_row_names_nobody_and_issues_no_lookup():
    """`audit_row` used to back-fill ActorUserID with Scenario_Session.UserID whenever the caller
    named no human — so every worker-written step was stamped with the session OWNER's name and a
    timeline read user1 / user1 / user2 / user1 with no way to tell who had actually acted.
    ActorType existed only to recover the signal that back-fill destroyed.

    NULL is the honest answer for system work, and removing the back-fill also deletes a PK SELECT
    on EVERY audit write — which the old docstring itself flagged as a shortcut. This asserts both:
    no name invented, and no query issued."""
    class _NoQuerySession:
        def execute(self, *a, **k):  # pragma: no cover - must never run
            raise AssertionError("audit_row issued a query; the session-owner back-fill is back")

    row = dal.audit_row(_NoQuerySession(), SessionID="s1", EventType="grounding_summary")

    assert row.get("ActorUserID") is None, "a system row was attributed to a person"
    assert row["ActorType"] == dal.ActorType.system
    assert row["CreatedAt"] is not None


def test_a_human_audit_row_keeps_its_actor():
    """The converse: naming a human must still record them, and mark the row as user-performed."""
    class _NoQuerySession:
        def execute(self, *a, **k):  # pragma: no cover
            raise AssertionError("audit_row should not query when the caller named an actor")

    row = dal.audit_row(_NoQuerySession(), SessionID="s1", EventType="scenario_accepted",
                        ActorUserID=OTHER)

    assert row["ActorUserID"] == OTHER
    assert row["ActorType"] == dal.ActorType.user


# --- derived vocabularies --------------------------------------------------------------------
def test_visible_plan_keys_match_the_plan_document_model():
    """`_VISIBLE_PLAN_KEYS` is derived from TreatmentPlanDocument rather than restated beside it.
    Pinned against the ten names it used to list by hand, so 'derive it' cannot silently change
    WHICH keys the poll endpoint serves — and a prompt change that adds a key now reaches the API
    by declaring it once, instead of being trimmed away by a tuple nobody remembered to update."""
    from app.api.treatment import _VISIBLE_PLAN_KEYS

    assert tuple(_VISIBLE_PLAN_KEYS) == (
        "title", "treatment_plan", "action_plan", "applicable_to_all_subsystems",
        "controls_to_be_implemented", "remediation_action_plan", "mitigation_timeline",
        "mitigation_owner", "risk_owner", "impacted_business_division")


def test_treatment_events_match_the_enum_prefix():
    """`_TREATMENT_EVENTS` is derived from the enum rather than restated beside it. This pins the
    derivation against the five members it used to list by hand, so 'derive it' cannot silently
    change WHICH events the audit feed serves — and a future treatment_plan_* event joins the feed
    automatically instead of being forgotten."""
    from app.core.enums import AuditEventType
    from app.db.dal import _TREATMENT_EVENTS

    assert set(_TREATMENT_EVENTS) == {
        AuditEventType.treatment_plan_requested, AuditEventType.treatment_plan_outcome,
        AuditEventType.treatment_plan_cancelled, AuditEventType.treatment_plan_reviewed,
        AuditEventType.treatment_plan_version_restored}
    assert all(e.name.startswith("treatment_plan_") for e in _TREATMENT_EVENTS)


# --- the wire ----------------------------------------------------------------------------------
def test_every_scenario_response_publishes_the_attribution():
    """Recording a decision is only half the job. `RejectedBy` was stored from August and returned
    by NO endpoint — the column existed, the API never mentioned it, and nobody noticed because
    nothing asserted it. This is that assertion, for all four fields on both scenario models.

    AcceptedScenario is the base of ScenarioListItem, so covering it covers /accepted-scenarios,
    both cross-session list routes and the single-scenario fetch at once."""
    from app.api.schemas import AcceptedScenario, ScenarioResult

    wanted = {"accepted_by", "accepted_at", "rejected_by", "rejected_at"}
    for model in (ScenarioResult, AcceptedScenario):
        missing = wanted - set(model.model_fields)
        assert not missing, f"{model.__name__} records but never publishes {sorted(missing)}"


def test_the_builder_actually_maps_the_columns_onto_the_wire_fields():
    """Declaring the fields is not enough — a builder that forgets a kwarg publishes null forever,
    which is indistinguishable from 'never decided'. Drives the real builder with a real row."""
    from app.api import sessions as sessions_api

    row = {
        "ScenarioID": "o1", "SubsystemID": 0, "ThreatTypeID": None, "ThreatCatalogueID": None,
        "ThreatType": None, "ThreatName": None, "LibraryThreatType": None,
        "LibraryThreatName": None, "ScenarioJSON": None, "SessionID": "s1", "EntityID": "86",
        "UserID": CREATOR, "SessionStatus": "completed", "ScenarioNumber": 1,
        "Accepted": 1, "Superseded": 0, "CreatedAt": None, "ThreatActorsJSON": None,
        "ThreatID": None, "ThreatCategory": None, "ThreatCategoryID": None, "Description": None,
        "GroundingStatus": None, "GroundingScore": None, "IsThreatAIGenerated": None,
        "Score": None, "ScopeRank": None, "ControlsMappedAt": None,
        "AcceptedBy": OTHER, "AcceptedAt": None, "RejectedBy": None, "RejectedAt": None,
    }
    item = sessions_api._scenario_list_item(row, [], actor_ids={}, unavailable=False)

    assert item.accepted_by == OTHER, "the builder dropped AcceptedBy on the floor"
    assert item.rejected_by is None


# --- session cancellation ----------------------------------------------------------------------
def test_session_cancel_records_the_actor():
    """POST /sessions/{id}/cancel is a deliberate human decision, so the row records who made it."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session, at_review=False)  # cancel requires an ACTIVE session

    with Session() as s:
        assert dal.cancel_session(s, sid, OTHER) is True
        s.commit()

    row = _session_row(Session, sid)
    assert row["CancelledBy"] == OTHER, "the canceller was not recorded on the row"
    assert row["CancelledAt"] is not None


def test_a_recovery_cancel_records_no_actor():
    """create_session's failed-enqueue path cancels the row it just committed. NOBODY chose that,
    so CancelledBy must stay NULL — naming the requesting principal would claim a human decision
    that never happened. That distinction is why the column is nullable rather than defaulted."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session, at_review=False)

    with Session() as s:
        assert dal.cancel_session(s, sid) is True  # no user_id — the recovery path's exact call
        s.commit()

    row = _session_row(Session, sid)
    assert row["CancelledBy"] is None, "a system recovery was attributed to a person"
    assert row["CancelledAt"] is not None, "the cancellation time should still be recorded"
