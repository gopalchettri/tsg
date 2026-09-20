"""Replacing the accepted version of a scenario — and what that does to its remediation plan.

The flow these exist for: a reviewer accepts scenario 6, regenerates it, and wants the rewrite
instead. Accept permits one accepted version per scenario, so until `AcceptBody.replace_accepted`
the rewrite could never be accepted and therefore never got a plan; the only plan obtainable was
for the text the reviewer had already judged wrong.

`replace_accepted` is the explicit "yes, replace it": the decision moves, the old version keeps its
row and both decisions stay in the ledger, and its plan stays attached to it — off the board and
out of the register, never deleted, and back again if that version is ever accepted again.

Helpers come from test_accept_any_version rather than a second copy of the seeds: same tables, same
session at the review barrier, same two filtered unique indexes that arbitrate identity for real.
"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from test_accept_any_version import (
    HASH_03,
    _accept,
    _engine,
    _flags,
    _now,
    _scenario,
    _seed_session,
    _versions_abcd,
)

from app.api.schemas import AcceptBody
from app.core.enums import AuditEventType, ScenarioDecisionReason, StageStatus
from app.db import dal
from app.db import models as m
from app.pipeline.accept import AcceptConflict, reject_scenarios
from app.sse import bus


def _reject(Session, sid: str, ids: list[str], monkeypatch) -> int:
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    with Session() as s:
        return reject_scenarios(s, sid, "86", "u1", ids)


def _plan(Session, sid: str, oid: str, *, review_status: str | None = "approved") -> str:
    """One ACTIVE, COMPLETE plan on a scenario — the register's view of a treated risk."""
    plan_id = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Risk_Treatment_Plan.__table__.insert().values(
            PlanID=plan_id, SessionID=sid, ScenarioID=oid, TenantID="t", EntityID="86",
            Status=str(StageStatus.COMPLETE), TreatmentStrategy="Mitigate",
            ReviewStatus=review_status, RiskLevel="Critical", Superseded=0,
            CreatedAt=_now(), UpdatedAt=_now()))
        s.commit()
    return plan_id


def _register_plan_ids(Session) -> list[str]:
    with Session() as s:
        return [str(r["PlanID"]) for r in dal.entity_plan_rows(
            s, "86", stale_cutoff=_now() - timedelta(minutes=30))]


def _audit(Session, event: AuditEventType) -> list[tuple[str, dict]]:
    with Session() as s:
        return [(str(r[0]), json.loads(r[1]) if r[1] else {}) for r in s.execute(
            select(m.Scenario_Audit.ScenarioID, m.Scenario_Audit.DetailJSON)
            .where(m.Scenario_Audit.EventType == event)).all()]


def test_replace_moves_the_decision_to_the_named_version(monkeypatch):
    """THE flow: version B accepted, regenerated to D, and the reviewer wants D. D becomes the
    accepted version, B stops being accepted, and the ledger names who replaced what."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1

    assert _accept(Session, sid, [d], monkeypatch, replace=True) == 1

    assert _flags(Session, d)[0] == 1, "the named version is now the accepted one"
    assert _flags(Session, b)[0] == 0, "the version it replaced no longer carries the decision"
    with Session() as s:
        old = s.execute(select(m.Threat_Scenario.AcceptedAt, m.Threat_Scenario.AcceptedBy,
                            m.Threat_Scenario.AcceptedSubsetJSON)
                        .where(m.Threat_Scenario.ScenarioID == b)).one()
        new = s.execute(select(m.Threat_Scenario.AcceptedAt, m.Threat_Scenario.AcceptedBy)
                        .where(m.Threat_Scenario.ScenarioID == d)).one()
    assert tuple(old) == (None, None, None), (
        "the stamps are cleared, so a later re-accept of B records who decided THEN")
    assert new[0] is not None and new[1] == "u1"

    unaccepted = _audit(Session, AuditEventType.scenario_unaccepted)
    assert unaccepted == [(b, {"replaced_by": d})]
    # Both decisions survive: an append-only trail never rewrites its first entry.
    assert b in [oid for oid, _ in _audit(Session, AuditEventType.scenario_accepted)]


def test_without_the_flag_the_refusal_explains_both_ways_out(monkeypatch):
    """The refusal is the UI's cue to ask "replace it?" — so it has to name both options, and it
    must still change nothing."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, [d], monkeypatch)

    assert exc_info.value.reason == ScenarioDecisionReason.duplicate_identity
    message = str(exc_info.value)
    assert "replace_accepted" in message and "reject" in message
    assert _flags(Session, b)[0] == 1 and _flags(Session, d)[0] == 0


def test_two_versions_in_one_call_are_refused_even_with_the_flag(monkeypatch):
    """Replacing resolves ONE accepted version per scenario. A subset naming two versions of the
    same scenario is still nonsense, flag or no flag."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, [b, d], monkeypatch, replace=True)

    assert exc_info.value.reason == ScenarioDecisionReason.duplicate_identity
    assert _flags(Session, b)[0] == 0 and _flags(Session, d)[0] == 0


def test_accept_all_never_replaces(monkeypatch):
    """One click must not be able to rewrite every decision in a session. The wire schema refuses
    the flag outside mode='subset'; this pins the pipeline underneath it, which is what would
    actually do the damage if a caller ever got past the schema."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, None, monkeypatch, replace=True)

    assert exc_info.value.reason == ScenarioDecisionReason.duplicate_identity
    assert _flags(Session, b)[0] == 1 and _flags(Session, d)[0] == 0


def test_a_rejected_version_cannot_be_replaced_in(monkeypatch):
    """Rejecting is a decision too. Replacing must not become a way to accept something the
    reviewer already declined — and the accepted version must survive the attempt."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    assert _reject(Session, sid, [d], monkeypatch) == 1

    with pytest.raises(dal.NotFoundError) as exc_info:
        _accept(Session, sid, [d], monkeypatch, replace=True)

    reasons = [u["reason"] for u in exc_info.value.details["unacceptable"]]
    assert reasons == [ScenarioDecisionReason.already_rejected]
    assert _flags(Session, b)[0] == 1, "the standing decision is untouched"


def test_accept_all_recovers_once_the_rewrite_is_rejected(monkeypatch):
    """The bug this pins: accept-all's pre-flight read rejected rows the write would never touch,
    so one accepted-then-regenerated scenario 409'd accept-all for the whole session FOREVER —
    rejecting the rewrite did not release it, because the rejected row was still offered to the
    duplicate-identity check."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    other = _scenario(Session, sid, identity=HASH_03, superseded=0, title="untouched sibling")
    assert _accept(Session, sid, [b], monkeypatch) == 1
    assert _reject(Session, sid, [d], monkeypatch) == 1

    assert _accept(Session, sid, None, monkeypatch) == 1

    assert _flags(Session, other)[0] == 1, "the sibling nobody had decided is accepted"
    assert _flags(Session, d)[0] == 0, "the rejected rewrite stays rejected"


def test_the_old_plan_stays_on_its_version_and_leaves_the_register(monkeypatch):
    """A replaced version's plan is not moved, rewritten or deleted — it is still readable at its
    own scenario id. It simply stops being an answer for this risk: off the board, out of the
    register, so one risk never shows two plans."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    plan_id = _plan(Session, sid, b)
    assert _register_plan_ids(Session) == [plan_id]

    assert _accept(Session, sid, [d], monkeypatch, replace=True) == 1

    with Session() as s:
        board = dal.session_plan_board(s, sid)
        assert [r["ScenarioID"] for r in board] == [d], "the board follows the accepted version"
        assert board[0]["PlanID"] is None, "the new version has no plan yet"
        assert dal.active_plan_row(s, sid, b) is not None, "the old plan is still readable"
    assert _register_plan_ids(Session) == [], "and no longer answers for this risk"


def test_switching_back_brings_the_old_plan_with_it(monkeypatch):
    """Because the plan was never detached, accepting the earlier version again restores its
    remediation as it stood — no regeneration, no re-approval."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    plan_id = _plan(Session, sid, b)
    assert _accept(Session, sid, [d], monkeypatch, replace=True) == 1

    assert _accept(Session, sid, [b], monkeypatch, replace=True) == 1

    with Session() as s:
        board = {r["ScenarioID"]: r for r in dal.session_plan_board(s, sid)}
    assert list(board) == [b]
    assert str(board[b]["PlanID"]) == plan_id
    assert board[b]["ReviewStatus"] == "approved", "its verdict came back with it"
    assert _register_plan_ids(Session) == [plan_id]


def test_body_refuses_the_flag_outside_subset_mode():
    """Refused, not ignored: "I sent it and nothing happened" is the one outcome a field that
    retires a decision must never have."""
    with pytest.raises(ValidationError) as exc_info:
        AcceptBody(mode="all", replace_accepted=True)
    assert "only allowed with mode='subset'" in str(exc_info.value)

    with pytest.raises(ValidationError):
        AcceptBody(mode="none", replace_accepted=True)

    body = AcceptBody(mode="subset", scenario_ids=[str(uuid.uuid4())], replace_accepted=True)
    assert body.replace_accepted is True
    assert AcceptBody(mode="all").replace_accepted is False, "off unless asked for"


def test_review_is_refused_for_a_replaced_version(monkeypatch):
    """A verdict is what a regulator reads, so it may only land on the plan of the version the
    register carries. The old plan stays readable; approving it would sign off remediation for
    text the organisation no longer stands by."""
    from contextlib import contextmanager

    import app.api.treatment as treatment_api
    from app.api.deps import Principal
    from app.core.enums import TreatmentGateReason
    from app.pipeline import treatment as treatment_mod

    @contextmanager
    def fake_db_session():
        yield object()

    plan_id = str(uuid.uuid4())
    monkeypatch.setattr(treatment_api, "db_session", fake_db_session)
    monkeypatch.setattr(treatment_api, "get_authorized_session", lambda *a, **k: {"SessionID": "s"})
    monkeypatch.setattr(dal, "active_plan_row", lambda *a, **k: {
        "PlanID": plan_id, "Accepted": 0, "Status": str(StageStatus.COMPLETE),
        "TenantID": "t", "EntityID": "86"})
    body = treatment_api.TreatmentReviewBody(plan_id=plan_id, decision="approved")
    principal = Principal(claims={"sub": "u1"}, entities={"86"}, client_id="c", tenant_id="t")

    with pytest.raises(treatment_mod.TreatmentConflict) as exc_info:
        treatment_api.post_review_treatment_plan("s", str(uuid.uuid4()), body, principal)

    assert exc_info.value.reason == TreatmentGateReason.scenario_not_accepted
