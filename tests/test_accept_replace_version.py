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

import app.pipeline.accept as accept_mod
from app.api.schemas import AcceptBody
from app.core.enums import AuditDecision, AuditEventType, ScenarioDecisionReason, StageStatus
from app.db import dal
from app.db import models as m
from app.pipeline.accept import AcceptConflict, accept_session, reject_scenarios
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


def _plan_history(Session, sid: str, oid: str) -> str:
    """A retired version of the same scenario's plan — what ?include_superseded returns."""
    plan_id = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Risk_Treatment_Plan.__table__.insert().values(
            PlanID=plan_id, SessionID=sid, ScenarioID=oid, TenantID="t", EntityID="86",
            Status=str(StageStatus.COMPLETE), TreatmentStrategy="Mitigate",
            ReviewStatus="rejected", RiskLevel="Critical", Superseded=1,
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
    same scenario is still nonsense, flag or no flag.

    A version is accepted FIRST on purpose. Without that, `already` is empty, `prior` is None and
    the replace branch is never entered — the test would pass for the same reason its no-flag twin
    does, pinning nothing. With it, the run reaches `displace[prior] = oid` and only then hits the
    duplicate check, which is the ordering that matters."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [a], monkeypatch) == 1

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, [b, d], monkeypatch, replace=True)

    assert exc_info.value.reason == ScenarioDecisionReason.duplicate_identity
    assert _flags(Session, a)[0] == 1, "the standing decision survives the refused call"
    assert _flags(Session, b)[0] == 0 and _flags(Session, d)[0] == 0
    assert _audit(Session, AuditEventType.scenario_unaccepted) == [], (
        "the displace write is rolled back with the rest of the refused call")


def test_accept_all_refusal_points_at_a_call_the_api_will_accept(monkeypatch):
    """Accept-all cannot carry replace_accepted — AcceptBody answers 422 for that pair — so its
    refusal must not tell the caller to repeat THIS call with the flag. It did, which sent a UI
    following the message straight into a 422."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, None, monkeypatch)
    all_msg = str(exc_info.value)
    assert "repeat this call" not in all_msg, "accept-all cannot be repeated with the flag"
    assert 'mode "subset"' in all_msg and "replace_accepted" in all_msg
    assert AcceptBody(mode="subset", scenario_ids=[d], replace_accepted=True), (
        "and the call it names is one the schema accepts")

    with pytest.raises(AcceptConflict) as exc_info:
        _accept(Session, sid, [d], monkeypatch)
    assert "repeat this call" in str(exc_info.value), "the subset refusal still says the short thing"


def test_the_write_reports_what_it_replaced_not_what_was_asked(monkeypatch):
    """accept_session returns what the UPDATE actually flipped. The pre-flight's `displace` is a
    request; a row another decision moved first matches nothing, and reporting it would tell a
    client to invalidate a plan that never moved."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)

    with Session() as s:
        plain = accept_session(s, sid, "86", "u1", subset=[b])
    assert plain == accept_mod.Accepted(1, []), "an ordinary accept replaces nothing"

    with Session() as s:
        swapped = accept_session(s, sid, "86", "u1", subset=[d], replace_accepted=True)
    assert swapped.count == 1
    assert swapped.replaced == [accept_mod.Replacement(scenario_id=d, replaced_scenario_id=b)]


def test_the_unaccept_row_carries_the_same_decision_as_its_sibling(monkeypatch):
    """One scenario's history must read as one story. The scenario_accepted row records the
    decision that produced it; left NULL here, the same scenario's scenario_unaccepted row showed
    a hole, and every consumer of the trail had to special-case the event type to see both."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    assert _accept(Session, sid, [d], monkeypatch, replace=True) == 1

    with Session() as s:
        rows = s.execute(
            select(m.Scenario_Audit.EventType, m.Scenario_Audit.Decision,
                m.Scenario_Audit.ActorUserID)
            .where(m.Scenario_Audit.ScenarioID == b)).all()
    decisions = {event: decision for event, decision, _actor in rows}
    assert decisions[str(AuditEventType.scenario_accepted)] == str(AuditDecision.accept)
    # Its own verb, not the enclosing call's: this row IS an un-acceptance. What the fix was
    # for is that the column is never NULL — every per-scenario row names a decision, so a
    # trail grouped by decision shows no hole.
    assert decisions[str(AuditEventType.scenario_unaccepted)] == str(AuditDecision.unaccept)
    assert all(actor == "u1" for _e, _d, actor in rows)


def test_a_failed_replace_leaves_nothing_behind(monkeypatch):
    """THE rollback path, and the only one that can strand a scenario with no accepted version:
    the displace UPDATE flips a row and writes its ledger entry, and only THEN does the call fail
    on an id it cannot decide. Everything must go back."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1

    with pytest.raises(dal.NotFoundError):
        _accept(Session, sid, [d, str(uuid.uuid4())], monkeypatch, replace=True)

    assert _flags(Session, b)[0] == 1, "the version that was accepted still is"
    assert _flags(Session, d)[0] == 0, "and the one that would have replaced it did not"
    assert _audit(Session, AuditEventType.scenario_unaccepted) == [], "no ledger entry survives"


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


def test_the_accept_response_names_what_it_replaced(monkeypatch):
    """The wire half of the same fact. A client that replaced a version has to be told which id
    lost the decision — that is the plan it must stop showing, and the response was previously
    byte-identical to an ordinary accept."""
    from contextlib import contextmanager

    import app.api.sessions as sessions_mod
    from app.api.deps import Principal

    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1

    @contextmanager
    def fake_db_session():
        with Session() as s:
            yield s

    with Session() as s:
        session_row = dict(dal.load_session(s, sid))
    monkeypatch.setattr(sessions_mod, "db_session", fake_db_session)
    monkeypatch.setattr(sessions_mod, "get_authorized_session", lambda *a, **k: session_row)
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    principal = Principal(claims={"sub": "u1"}, entities={"86"}, client_id="c", tenant_id="t")

    plain = sessions_mod.post_accept(sid, AcceptBody(mode="subset", scenario_ids=[b]), principal)
    assert plain.replaced == [], "an ordinary accept reports nothing replaced"

    swapped = sessions_mod.post_accept(
        sid, AcceptBody(mode="subset", scenario_ids=[d], replace_accepted=True), principal)
    assert swapped.accepted_count == 1
    assert [(r.scenario_id, r.replaced_scenario_id) for r in swapped.replaced] == [(d, b)]


def _results(Session, monkeypatch, sid: str):
    """GET /results through the real route, so the card fields are the ones a client receives."""
    from contextlib import contextmanager

    import app.api.sessions as sessions_mod
    from app.api.deps import Principal

    @contextmanager
    def fake_db_session():
        with Session() as s:
            yield s

    with Session() as s:
        session_row = dict(dal.load_session(s, sid))
    monkeypatch.setattr(sessions_mod, "db_session", fake_db_session)
    monkeypatch.setattr(sessions_mod, "get_authorized_session", lambda *a, **k: session_row)
    monkeypatch.setattr(sessions_mod, "build_board", lambda *a, **k: {
        "progress": {"threats": "COMPLETE", "scenarios": "COMPLETE",
                    "overall": "awaiting_review", "error_message": {}}})
    principal = Principal(claims={"sub": "u1"}, entities={"86"}, client_id="c", tenant_id="t")
    return {c.scenario_id: c for c in
            sessions_mod.get_results(sid, include_replaced=False, principal=principal).scenarios}


def test_the_card_says_which_accepted_version_it_would_replace(monkeypatch):
    """What a UI needs BEFORE the click. Until now the only way to learn that a scenario already
    had an accepted version was to attempt the accept and read the 409 — so the screen either
    guessed or surprised the reviewer."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    other = _scenario(Session, sid, identity=HASH_03, superseded=0, title="an unrelated scenario")
    assert _accept(Session, sid, [b], monkeypatch) == 1

    cards = _results(Session, monkeypatch, sid)

    assert cards[d].replaces_accepted_version == b, (
        "the rewrite names the accepted version it would displace")
    assert cards[b].replaces_accepted_version is None, (
        "the accepted version replaces nothing — re-accepting it is idempotent")
    assert cards[other].replaces_accepted_version is None, "an ordinary card says nothing"
    # And it names an id that is on this same list, so the UI can mark both sides.
    assert b in cards


def test_the_card_stops_warning_once_the_replacement_has_happened(monkeypatch):
    """After the switch the new version IS the accepted one, so there is nothing left to warn
    about — a stale warning would offer a confirmation for an ordinary accept."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    assert _accept(Session, sid, [d], monkeypatch, replace=True) == 1

    cards = _results(Session, monkeypatch, sid)

    assert cards[d].accepted is True
    assert cards[d].replaces_accepted_version is None
    assert b not in cards, "the replaced version is undecided history now, not a live card"


def _unaccept(Session, sid: str, scenario_id: str, monkeypatch) -> None:
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    with Session() as s:
        accept_mod.unaccept_scenario(s, sid, "86", "u1", scenario_id)


def test_unaccept_takes_one_acceptance_back(monkeypatch):
    """The decision a reviewer could not make: reject is refused on an accepted scenario, and
    replacing needs another version to adopt. "I accepted that by mistake" had no answer."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, _d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1

    _unaccept(Session, sid, b, monkeypatch)

    assert _flags(Session, b)[0] == 0, "undecided again, not rejected"
    with Session() as s:
        stamps = s.execute(select(m.Threat_Scenario.AcceptedAt, m.Threat_Scenario.AcceptedBy,
                                m.Threat_Scenario.RejectedAt)
                        .where(m.Threat_Scenario.ScenarioID == b)).one()
        assert tuple(stamps) == (None, None, None)
        assert dal.has_undecided_scenarios(s, sid) is True, "it is back in the review queue"
    # Nothing is erased: the acceptance and its reversal sit side by side, each naming its actor.
    assert [oid for oid, _ in _audit(Session, AuditEventType.scenario_accepted)] == [b]
    assert _audit(Session, AuditEventType.scenario_unaccepted) == [(b, {})]


def test_unaccept_is_refused_when_there_is_nothing_to_undo(monkeypatch):
    """Only an acceptance can be taken back. A pending or rejected scenario answers 409 with its
    own reason rather than silently doing nothing."""
    from app.core.enums import UnacceptGateReason

    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)

    with pytest.raises(AcceptConflict) as exc_info:
        _unaccept(Session, sid, d, monkeypatch)
    assert exc_info.value.reason == UnacceptGateReason.not_accepted

    assert _reject(Session, sid, [d], monkeypatch) == 1
    with pytest.raises(AcceptConflict):
        _unaccept(Session, sid, d, monkeypatch)
    assert _flags(Session, b)[0] == 0 and _flags(Session, d)[0] == 0


def test_unaccept_parks_the_plan_and_re_accepting_brings_it_back(monkeypatch):
    """The reason there is no treatment_plan_exists refusal. The plan is not orphaned: it stays on
    its scenario, stops being the answer for the risk while that scenario is undecided, and
    returns with its verdict when the scenario is accepted again — exactly like a replacement."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, _d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    plan_id = _plan(Session, sid, b)
    assert _register_plan_ids(Session) == [plan_id]

    _unaccept(Session, sid, b, monkeypatch)

    with Session() as s:
        assert dal.session_plan_board(s, sid) == [], "no accepted scenario, no board row"
        assert dal.active_plan_row(s, sid, b) is not None, "the plan itself is untouched"
    assert _register_plan_ids(Session) == [], "and it stops answering for the risk"

    assert _accept(Session, sid, [b], monkeypatch) == 1
    with Session() as s:
        board = dal.session_plan_board(s, sid)
    assert [str(r["PlanID"]) for r in board] == [plan_id]
    assert board[0]["ReviewStatus"] == "approved", "its verdict came back with it"


def test_accept_all_works_after_an_unaccept(monkeypatch):
    """An un-accepted scenario is undecided, so the ordinary path picks it up again — no special
    case, and no session left in a state only a regenerate could clear."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, _b, _c, d = _versions_abcd(Session, sid)
    other = _scenario(Session, sid, identity=HASH_03, superseded=0, title="sibling")
    assert _accept(Session, sid, [d], monkeypatch) == 1

    _unaccept(Session, sid, d, monkeypatch)

    assert _accept(Session, sid, None, monkeypatch) == 2, "both live scenarios accept again"
    assert _flags(Session, d)[0] == 1 and _flags(Session, other)[0] == 1


def test_the_replace_link_reads_from_both_ends(monkeypatch):
    """Walk old → new from the un-accept row, and new → old from the accept row. Before this the
    second direction had no answer at all once someone switched back, because the scenario rows
    only chain a regeneration to its immediate predecessor."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    assert _accept(Session, sid, [d], monkeypatch, replace=True) == 1

    assert _audit(Session, AuditEventType.scenario_unaccepted) == [(b, {"replaced_by": d})]
    accepted_rows = dict(_audit(Session, AuditEventType.scenario_accepted))
    assert accepted_rows[d] == {"replaces": b}, "the version that gained it names what it displaced"
    assert accepted_rows[b] == {}, "an ordinary accept carries no detail"


def _review(Session, monkeypatch, sid: str, scenario_id: str, plan_id: str):
    """Drive the real review route against these tables — no stubbed plan row.

    Handing the route a hand-written dict hid the seam that matters: the gate reads a column
    (`Accepted`) that dal.active_plan_row must actually select. With a stub, deleting that column
    from the query leaves the test green while every real review call raises KeyError → 500."""
    from contextlib import contextmanager

    import app.api.treatment as treatment_api
    from app.api.deps import Principal

    @contextmanager
    def real_session():
        with Session() as s:
            yield s

    monkeypatch.setattr(treatment_api, "db_session", real_session)
    monkeypatch.setattr(treatment_api, "get_authorized_session",
                        lambda *a, **k: {"SessionID": sid, "TenantID": "t", "EntityID": "86"})
    body = treatment_api.TreatmentReviewBody(plan_id=plan_id, decision="approved")
    principal = Principal(claims={"sub": "u1"}, entities={"86"}, client_id="c", tenant_id="t")
    return treatment_api.post_review_treatment_plan(sid, scenario_id, body, principal)


def test_review_is_refused_for_a_replaced_version(monkeypatch):
    """A verdict is what a regulator reads, so it may only land on the plan of the version the
    register carries. The old plan stays readable; approving it would sign off remediation for
    text the organisation no longer stands by."""
    from app.core.enums import TreatmentGateReason
    from app.pipeline import treatment as treatment_mod

    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    plan_id = _plan(Session, sid, b, review_status=None)
    assert _accept(Session, sid, [d], monkeypatch, replace=True) == 1

    with pytest.raises(treatment_mod.TreatmentConflict) as exc_info:
        _review(Session, monkeypatch, sid, b, plan_id)

    assert exc_info.value.reason == TreatmentGateReason.scenario_not_accepted
    with Session() as s:
        assert dal.active_plan_row(s, sid, b)["ReviewStatus"] is None, "no verdict was recorded"


def test_the_plan_screen_says_its_scenario_was_replaced(monkeypatch):
    """The other half of the same warning. Someone opening the plan of a replaced version — from
    a bookmark, or the audit trail — saw an approved plan with nothing saying it is no longer the
    answer for this risk. The flag is the same for the active row and its history, because they
    are all one scenario."""
    from contextlib import contextmanager

    import app.api.treatment as treatment_api
    from app.api.deps import Principal

    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    _plan(Session, sid, b)
    _plan_history(Session, sid, b)

    @contextmanager
    def real_session():
        with Session() as s:
            yield s

    monkeypatch.setattr(treatment_api, "db_session", real_session)
    monkeypatch.setattr(treatment_api, "get_authorized_session",
                        lambda *a, **k: {"SessionID": sid, "TenantID": "t", "EntityID": "86"})
    principal = Principal(claims={"sub": "u1"}, entities={"86"}, client_id="c", tenant_id="t")

    before = treatment_api.get_treatment_plan(sid, b, include_superseded=True, principal=principal)
    assert before.scenario_replaced is False, "while it is the accepted version, nothing to say"

    assert _accept(Session, sid, [d], monkeypatch, replace=True) == 1
    after = treatment_api.get_treatment_plan(sid, b, include_superseded=True, principal=principal)

    assert after.scenario_replaced is True
    assert [v.scenario_replaced for v in after.superseded] == [True], (
        "one scenario, one answer — the history cannot disagree with its own parent")


def test_review_still_works_when_the_scenario_row_is_missing(monkeypatch):
    """The OUTER join in active_plan_row exists so a broken linkage nulls the scenario columns
    rather than dropping the plan — and entity_plan_rows deliberately keeps those rows visible.
    A gate written as `!= 1` also caught NULL, so exactly those plans became permanently
    unapprovable, with a 409 blaming a regeneration that never happened."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    orphan = str(uuid.uuid4())            # a plan pointing at a scenario row that isn't there
    plan_id = _plan(Session, sid, orphan, review_status=None)

    result = _review(Session, monkeypatch, sid, orphan, plan_id)

    assert result.review_status == "approved"
    assert result.reviewed_by == "u1"


def test_the_unaccept_ROUTE_actually_unaccepts(monkeypatch):
    """Through post_unaccept_scenario, not through unaccept_scenario.

    Every other un-accept assertion in this repo calls the pipeline function directly, which left
    the ROUTE's one line uncovered: neutering `unaccept_scenario(...)` in app/api/sessions.py kept
    all 1087 tests green while the endpoint would have answered 200 and changed nothing. That is
    the same tested-helper/untested-caller shape as the library approval path that sat
    disconnected for a year, so the route gets its own test.
    """
    from app.api import sessions as sessions_mod
    from app.api.deps import Principal

    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _a, b, _c, _d = _versions_abcd(Session, sid)
    assert _accept(Session, sid, [b], monkeypatch) == 1
    assert _flags(Session, b)[0] == 1

    monkeypatch.setattr(sessions_mod, "db_session", Session)
    principal = Principal(claims={"sub": "u1"}, entities={"86"},
                        client_id="c", tenant_id="t")

    resp = sessions_mod.post_unaccept_scenario(sid, b, principal)

    assert resp.scenario_id == b
    assert _flags(Session, b)[0] == 0, (
        "the route must reach the pipeline — a 200 with the flag still set is the bug this pins")
    assert _audit(Session, AuditEventType.scenario_unaccepted), "and it leaves a ledger row"
