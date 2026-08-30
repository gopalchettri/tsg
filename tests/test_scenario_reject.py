"""Per-scenario reject, and the accept/reject mutual exclusion.

The two decisions are mutually exclusive by CK_Scenario_DecisionExclusive. Before
dal.decide_scenarios they were two independent UPDATEs, each enforcing only its own half — so
accepting a rejected scenario reached the database and surfaced as an IntegrityError the accept
path mislabelled `duplicate_identity`. `test_reject_then_accept_is_refused_with_the_right_reason`
is that regression; it fails on any build where the exclusion is not in the shared predicate.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import sessionmaker

from app.core.enums import (
    AuditDecision,
    AuditEventType,
    ScenarioDecisionReason,
    ScenarioStatus,
)
from app.db import dal
from app.db import models as m
from app.pipeline import accept as accept_mod
from app.pipeline.accept import AcceptConflict, reject_scenarios
from app.sse import bus
from tests.test_accept_any_version import _engine, _scenario, _seed_session


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


#: _seed_session records this as the assessment's creator, and only the creator may decide.
CREATOR = "u1"


def _reject(Session, sid: str, ids, monkeypatch, actor: str = CREATOR) -> int:
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    with Session() as s:
        return reject_scenarios(s, sid, "86", actor, ids)


def _accept(Session, sid: str, subset, monkeypatch, actor: str = CREATOR) -> int:
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    with Session() as s:
        return accept_mod.accept_session(s, sid, "86", actor, subset=subset)


def _row(Session, oid: str):
    with Session() as s:
        return s.execute(
            m.Threat_Scenario.__table__.select().where(
                m.Threat_Scenario.ScenarioID == oid)).mappings().one()


def _audit(Session, sid: str, event_type=None) -> list:
    with Session() as s:
        rows = s.execute(m.Scenario_Audit.__table__.select().where(
            m.Scenario_Audit.SessionID == sid)).mappings().all()
    return [r for r in rows if event_type is None or r["EventType"] == event_type]


def _fixture(Session):
    sid = _seed_session(Session)
    a = _scenario(Session, sid, identity="ident-a", number=1, superseded=0, title="A")
    b = _scenario(Session, sid, identity="ident-b", number=1, superseded=0, title="B")
    c = _scenario(Session, sid, identity="ident-c", number=1, superseded=0, title="C")
    return sid, a, b, c


# --- the mutual exclusion --------------------------------------------------------------------
def test_reject_then_accept_is_refused_with_the_right_reason(monkeypatch):
    """THE regression. Accepting a rejected scenario must be a typed 404 naming
    `already_rejected` — never a 500 from the CHECK constraint, and never the misleading
    `duplicate_identity` the old IntegrityError handler produced."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a, _b, _c = _fixture(Session)

    assert _reject(Session, sid, [a], monkeypatch) == 1

    with pytest.raises(dal.NotFoundError) as exc_info:
        _accept(Session, sid, [a], monkeypatch)
    reasons = {u["scenario_id"]: u["reason"] for u in exc_info.value.details["unacceptable"]}
    assert reasons[a] == ScenarioDecisionReason.already_rejected
    assert _row(Session, a)["Accepted"] == 0          # never written
    assert _row(Session, a)["RejectedAt"] is not None  # the standing decision holds


def test_accept_then_reject_is_refused_with_the_right_reason(monkeypatch):
    """The mirror direction, refused before the constraint is reached."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a, _b, _c = _fixture(Session)

    assert _accept(Session, sid, [a], monkeypatch) == 1

    with pytest.raises(dal.NotFoundError) as exc_info:
        _reject(Session, sid, [a], monkeypatch)
    reasons = {u["scenario_id"]: u["reason"] for u in exc_info.value.details["unacceptable"]}
    assert reasons[a] == ScenarioDecisionReason.already_accepted
    assert _row(Session, a)["RejectedAt"] is None
    assert _row(Session, a)["Accepted"] == 1


# --- reject behaviour ------------------------------------------------------------------------
def test_reject_records_who_and_when_and_leaves_siblings_pending(monkeypatch):
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a, b, c = _fixture(Session)

    assert _reject(Session, sid, [a, b], monkeypatch) == 2

    for oid in (a, b):
        row = _row(Session, oid)
        assert row["RejectedAt"] is not None
        assert row["RejectedBy"] == CREATOR
        assert row["Accepted"] == 0
    assert _row(Session, c)["RejectedAt"] is None      # untouched, still pending
    assert _accept(Session, sid, [c], monkeypatch) == 1  # ...and still acceptable


def test_repeat_reject_preserves_the_original_decision(monkeypatch):
    """An append-only ledger must not be able to falsify its own first entry: a second reject
    is a no-op, not a rewrite of who declined and when."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a, _b, _c = _fixture(Session)

    _reject(Session, sid, [a], monkeypatch)
    first = _row(Session, a)

    assert _reject(Session, sid, [a], monkeypatch) == 1  # idempotent success, not a 404
    after = _row(Session, a)
    assert after["RejectedAt"] == first["RejectedAt"]   # the first decision's timestamp stands
    assert after["RejectedBy"] == CREATOR


def test_rejecting_a_failure_card_is_refused(monkeypatch):
    """A failure card has no content to decide on — same rule as accept."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, _a, _b, _c = _fixture(Session)
    card = _scenario(Session, sid, identity="ident-card", number=1, superseded=0,
                    status=str(ScenarioStatus.error), title="card")

    with pytest.raises(dal.NotFoundError) as exc_info:
        _reject(Session, sid, [card], monkeypatch)
    reasons = {u["scenario_id"]: u["reason"] for u in exc_info.value.details["unacceptable"]}
    assert reasons[card] == ScenarioDecisionReason.failure_card


# --- the audit trail -------------------------------------------------------------------------
def test_each_decided_scenario_gets_its_own_ledger_row(monkeypatch):
    """The point of the change: "who decided scenario X, and when" is one indexed lookup, not a
    JSON scan of call-scoped rows."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a, b, c = _fixture(Session)

    _accept(Session, sid, [a, b], monkeypatch)
    _reject(Session, sid, [c], monkeypatch)

    accepted = _audit(Session, sid, AuditEventType.scenario_accepted)
    assert {r["ScenarioID"] for r in accepted} == {a, b}
    assert all(r["Decision"] == AuditDecision.accept for r in accepted)
    assert all(r["ActorUserID"] == CREATOR for r in accepted)

    rejected = _audit(Session, sid, AuditEventType.scenario_rejected)
    assert [r["ScenarioID"] for r in rejected] == [c]
    assert rejected[0]["ActorUserID"] == CREATOR


def test_an_undecided_scenario_has_no_decision_row(monkeypatch):
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a, _b, c = _fixture(Session)

    _accept(Session, sid, [a], monkeypatch)

    decided = {r["ScenarioID"] for r in _audit(Session, sid)
            if r["EventType"] in (AuditEventType.scenario_accepted,
                                    AuditEventType.scenario_rejected)}
    assert c not in decided


def test_deciding_twice_writes_one_ledger_row_not_two(monkeypatch):
    """The trail records DECISIONS, not requests. A double-click or a retried request still
    matches the row (deciding twice is idempotent, not a 404), but must not put two rejections
    in the evidence trail where the reviewer made one."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a, _b, _c = _fixture(Session)

    assert _reject(Session, sid, [a], monkeypatch) == 1
    assert _reject(Session, sid, [a], monkeypatch) == 1   # idempotent success

    assert len(_audit(Session, sid, AuditEventType.scenario_rejected)) == 1


def test_re_accepting_the_same_scenario_writes_one_ledger_row(monkeypatch):
    """Same rule on the accept side — the two paths share dal.decide_scenarios, and this pins
    that they share its transition semantics too."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a, _b, _c = _fixture(Session)

    assert _accept(Session, sid, [a], monkeypatch) == 1
    assert _accept(Session, sid, [a], monkeypatch) == 1

    assert len(_audit(Session, sid, AuditEventType.scenario_accepted)) == 1


# --- who may decide: a deliberate product decision, pinned here ---------------------------------
def test_a_colleague_may_decide_and_is_recorded_as_the_actor(monkeypatch):
    """DELIBERATE: entity scope is the authorization boundary — a colleague may decide someone
    else's assessment, and the ledger names THEM.

    An owner-only rule was built and removed on purpose: covering for a teammate on leave is
    normal work, and a second person approving a remediation plan is a requirement that an owner
    check makes impossible. The control is DETECTIVE, not preventive — a wrong decision is
    attributable rather than blocked.

    This test exists so nobody "fixes" that back thinking it is a bug. If per-user access control
    is ever wanted again, that is a product decision to re-make, not a hole to quietly close.
    """
    Session = sessionmaker(bind=_engine(), future=True)
    sid, a, b, _c = _fixture(Session)

    assert _accept(Session, sid, [a], monkeypatch, actor="colleague") == 1
    assert _reject(Session, sid, [b], monkeypatch, actor="colleague") == 1

    assert _row(Session, a)["Accepted"] == 1
    assert _row(Session, b)["RejectedBy"] == "colleague"   # attribution, not prevention

    trail = {(r["EventType"], r["ActorUserID"]) for r in _audit(Session, sid)
            if r["EventType"].startswith("scenario_")}
    assert trail == {(AuditEventType.scenario_accepted, "colleague"),
                    (AuditEventType.scenario_rejected, "colleague")}


def test_the_review_gate_still_refuses_a_session_not_at_a_barrier(monkeypatch):
    """Dropping ownership did NOT drop the gate: a decision must still land only on a session
    that was actually offered for review. `at_review=False` seeds one mid-generation."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session, at_review=False)
    oid = _scenario(Session, sid, identity="i-mid", number=1, superseded=0, title="mid-run")

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, [oid], monkeypatch)
    assert exc_info.value.reason == "generation_in_progress"
    assert _row(Session, oid)["Accepted"] == 0
