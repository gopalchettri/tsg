"""Treatment-plan route split + accept-any-version (plan eager-swimming-acorn, phase 2).

Create is first-generation-only, /regenerate takes an EMPTY body (register data carried from
the ACTIVE version's frozen snapshot), and review's optional plan_id makes approving a historical
COMPLETE version the atomic version switch. Real SQLite tables + the partial unique index
UX_TreatmentPlan_ActiveOutput (the ORM declares no indexes — without creating it here the race
tests would be toothless), route functions exercised directly with db_session/get_authorized_session
monkeypatched — same style as test_accept_any_version.py.
"""
from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from datetime import UTC, date, datetime

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

import app.api.treatment as treatment_api
from app.api.deps import Principal
from app.api.schemas import TreatmentPlanBody, TreatmentPlanRegenerateBody, TreatmentReviewBody
from app.core.enums import AuditEventType, SessionStatus, StageStatus, TreatmentGateReason
from app.db import dal
from app.db import models as m
from app.pipeline import treatment as treatment_mod
from app.sse import bus

SCENARIO_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
SESSION_ID = "5aa85f64-5717-4562-b3fc-2c963f66afa6"


def _engine():
    engine = create_engine("sqlite://")
    for table in (m.Scenario_Session, m.Threat_Scenario_Output, m.Scoped_Threat,
                m.Identified_Threat, m.Risk_Treatment_Plan, m.Scenario_Audit,
                m.Threat_Scenario_Control_Map, m.Control_Library):
        table.__table__.create(engine)
    with engine.begin() as conn:
        # The MSSQL arbiter, recreated: SQLite supports partial unique indexes, and the ORM
        # models deliberately declare none (DB-first schema) — without this the insert-race
        # and swap tests could not fail even with the fences deleted.
        conn.execute(text("CREATE UNIQUE INDEX UX_TreatmentPlan_ActiveOutput "
                          "ON Risk_Treatment_Plan(ScenarioID) WHERE Superseded = 0"))
    return engine


def _now():
    return datetime.now(UTC)


def _seed(Session) -> None:
    """One completed session with one accepted scenario (plans require Accepted=1)."""
    with Session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=SESSION_ID, TenantID="t", EntityID="86", UserID="u1", AssetID=7,
            AssetName="Citizen Portal", SessionStatus=SessionStatus.completed,
            CurrentStage="APPROVED", StageStatus=StageStatus.COMPLETE, Mode="AUTO",
            CurrentSubsystemIndex=0, SubsystemsJSON="[]", AssetContextJSON="{}",
            CreatedAt=_now(), UpdatedAt=_now()))
        s.execute(m.Threat_Scenario_Output.__table__.insert().values(
            ScenarioID=SCENARIO_ID, SessionID=SESSION_ID, TenantID="t", EntityID="86",
            UserID="u1", SubsystemID=0, ScopedThreatID=str(uuid.uuid4()), Status="complete",
            ScenarioJSON=json.dumps({"scenario_title": "T", "scenario_statement": "s",
                                     "risk_statement": "r"}),
            Accepted=1, Superseded=0, IdentityHash="a" * 64, ScenarioNumber=1,
            GenerationEpoch=1, CreatedAt=_now()))
        s.commit()


def _wire(Session, monkeypatch) -> list:
    """Point the route module at the SQLite engine; no broker, no Redis. Returns the list
    SSE publishes land in."""
    @contextmanager
    def fake_db_session():
        with Session() as s:
            yield s
            s.commit()

    published: list = []
    monkeypatch.setattr(treatment_api, "db_session", fake_db_session)
    monkeypatch.setattr(treatment_api, "get_authorized_session",
                        lambda sess, sid, principal: {"SessionID": sid, "EntityID": "86"})
    monkeypatch.setattr(treatment_api, "enqueue_treatment_plan", lambda plan_id: None)
    monkeypatch.setattr(bus, "publish", lambda sid, ev: published.append(ev))
    return published


def _principal() -> Principal:
    return Principal(claims={"sub": "u1"}, entities={"86"}, client_id="c", tenant_id="t")


def _body(**over) -> TreatmentPlanBody:
    base = dict(existing_controls=["annual patching"], likelihood_rating=4, impact_rating=5,
                final_risk_rating=20, risk_level="Critical",
                risk_identification_date=datetime(2026, 6, 14, 8, 31, tzinfo=UTC),
                risk_owner="Head of OT Operations", impacted_business_division="Water Ops",
                existing_controls_all_subsystems="No",
                existing_controls_all_subsystems_justification="IT systems only",
                # The window is set HERE, in the shared body, on purpose: it makes
                # test_regenerate_carries_register_data's `new_snap["risk_assessment"] ==
                # old_snap["risk_assessment"]` a regression pin for BOTH window bugs at once
                # (create must compute total_days; regenerate must carry the window forward).
                # Without these two kwargs assessment_window is None on both sides and that
                # assertion passes vacuously — which is exactly how both bugs survived.
                mitigation_start_date=date(2026, 6, 14),
                mitigation_end_date=date(2026, 9, 14))
    base.update(over)
    return TreatmentPlanBody(**base)


def _plans(Session) -> list[dict]:
    with Session() as s:
        return [dict(r) for r in s.execute(
            select(m.Risk_Treatment_Plan.__table__)
            .order_by(m.Risk_Treatment_Plan.CreatedAt)).mappings()]


def _set_status(Session, plan_id: str, status: str, *, updated_at=None) -> None:
    with Session() as s:
        s.execute(update(m.Risk_Treatment_Plan)
                  .where(m.Risk_Treatment_Plan.PlanID == plan_id)
                  .values(Status=status, PlanJSON="{}",
                          UpdatedAt=updated_at or _now()))
        s.commit()


def _create(Session, monkeypatch, **body_over):
    """Callers must have _wire()d already — re-wiring here would swap in a fresh published
    list and orphan the one the test asserts against."""
    return treatment_api.post_treatment_plan(SESSION_ID, SCENARIO_ID, _body(**body_over),
                                             _principal())


def test_create_then_create_conflicts(monkeypatch):
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    resp = _create(Session, monkeypatch)
    assert resp.status == str(StageStatus.RUNNING)
    with pytest.raises(treatment_mod.TreatmentConflict) as exc_info:
        treatment_api.post_treatment_plan(SESSION_ID, SCENARIO_ID, _body(), _principal())
    assert exc_info.value.reason == TreatmentGateReason.plan_already_exists


def test_enqueue_failure_answers_503_not_500(monkeypatch):
    """A broker that will not take the job is TRANSIENT and retryable. Re-raising bare made it the
    catch-all 500 — "our code is broken, don't retry" — for a condition where retrying is exactly
    right, and while the plan row's own message tells the caller to regenerate. The three sibling
    sites for this identical failure (sessions.py's create, and _recover_from_enqueue_failure for
    regenerate/next-set) already answer 503.

    Also pins the two things the fix must NOT break: the row is still parked in ERROR so the
    scenario_id is not wedged behind the staleness window, and the broker's own exception text does
    not ride out on the wire."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)

    def _broker_down(_plan_id):
        raise RuntimeError("kombu.exceptions.OperationalError: [Errno 111] Connection refused")

    monkeypatch.setattr(treatment_api, "enqueue_treatment_plan", _broker_down)

    with pytest.raises(HTTPException) as exc_info:
        treatment_api.post_treatment_plan(SESSION_ID, SCENARIO_ID, _body(), _principal())

    assert exc_info.value.status_code == 503, "a transient broker failure must not report as 500"
    for leaked in ("kombu", "Errno 111", "Connection refused"):
        assert leaked not in str(exc_info.value.detail), exc_info.value.detail

    rows = _plans(Session)
    assert len(rows) == 1, rows
    assert rows[0]["Status"] == str(StageStatus.ERROR), "row left RUNNING — scenario_id is wedged"


def test_cancel_records_who_stopped_the_plan(monkeypatch):
    """The cancel endpoint and its treatment_plan_cancelled audit event both predate the columns;
    the row itself recorded neither who nor when, so a cancelled plan could not name the person who
    stopped it without joining the ledger. FIRST test to exercise this route at all."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    _create(Session, monkeypatch)  # one RUNNING plan

    treatment_api.post_cancel_treatment_plan(SESSION_ID, SCENARIO_ID, _principal())

    row = _plans(Session)[0]
    assert row["Status"] == str(StageStatus.ERROR)
    assert row["CancelledBy"] == "u1", "the canceller was not recorded on the plan row"
    assert row["CancelledAt"] is not None


def test_a_normal_plan_completion_records_no_canceller(monkeypatch):
    """finish_plan is ALSO the normal-completion and generic-failure writer. Stamping CancelledBy
    there would claim a human stopped something that merely finished or failed — passing
    `cancelled_by` is what makes a write a cancellation, and nothing else may set it."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    _create(Session, monkeypatch)
    plan_id = _plans(Session)[0]["PlanID"]

    with Session() as s:
        assert dal.finish_plan(s, plan_id, status=StageStatus.COMPLETE, task_id=None,
                               plan_json="{}") is True
        s.commit()

    row = _plans(Session)[0]
    assert row["Status"] == str(StageStatus.COMPLETE)
    assert row["CancelledBy"] is None and row["CancelledAt"] is None, (
        "an ordinary completion was recorded as a cancellation")


def test_regenerate_with_no_rows_is_404(monkeypatch):
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    with pytest.raises(dal.NotFoundError):
        treatment_api.post_regenerate_treatment_plan(
            SESSION_ID, SCENARIO_ID, TreatmentPlanRegenerateBody(), _principal())


def test_regenerate_carries_register_data(monkeypatch):
    """The register-sourced snapshot values survive byte-for-byte — including the two
    all-subsystems keys a naive whole-block split would drop, and the assessment window — and
    the two row columns are copied.

    The risk_assessment equality below is the regression pin for both window bugs: `_body()`
    supplies a real mitigation window, so a create that fails to compute total_days, or a
    regenerate that drops the window, makes the two blocks differ. (Formerly ...and_swaps_note;
    the reviewer_note steering it also covered was removed with user_note.)"""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    first = _create(Session, monkeypatch)
    _set_status(Session, first.plan_id, str(StageStatus.COMPLETE))
    old_snap = json.loads(_plans(Session)[0]["InputSnapshotJSON"])

    resp = treatment_api.post_regenerate_treatment_plan(
        SESSION_ID, SCENARIO_ID, TreatmentPlanRegenerateBody(), _principal())

    rows = _plans(Session)
    assert [r["Superseded"] for r in rows] == [1, 0]
    new_row = rows[1]
    assert new_row["PlanID"] == resp.plan_id
    new_snap = json.loads(new_row["InputSnapshotJSON"])
    assert (new_snap["existing_controls"]["register_controls"]
            == old_snap["existing_controls"]["register_controls"])
    assert new_snap["existing_controls"]["applied_to_all_subsystems"] == "No"
    assert (new_snap["existing_controls"]["applied_to_all_subsystems_justification"]
            == old_snap["existing_controls"]["applied_to_all_subsystems_justification"])
    assert new_snap["risk_assessment"] == old_snap["risk_assessment"]
    assert new_snap["register"] == old_snap["register"]
    assert new_row["RiskLevel"] == rows[0]["RiskLevel"]
    assert new_row["RiskIdentificationDate"] == rows[0]["RiskIdentificationDate"]
    # Explicit, so a future change that makes the window None on BOTH sides cannot make the
    # equality above pass vacuously again — the exact way both bugs hid.
    assert old_snap["risk_assessment"]["assessment_window"]["total_days"] == 92

    # Chained regenerate: the register data (and the window) survive a second hop too.
    _set_status(Session, resp.plan_id, str(StageStatus.COMPLETE))
    resp3 = treatment_api.post_regenerate_treatment_plan(
        SESSION_ID, SCENARIO_ID, TreatmentPlanRegenerateBody(), _principal())
    snap3 = json.loads([r for r in _plans(Session)
                        if r["PlanID"] == resp3.plan_id][0]["InputSnapshotJSON"])
    assert "reviewer_note" not in snap3   # the steering concept was removed entirely
    assert snap3["risk_assessment"] == old_snap["risk_assessment"]


def test_fresh_running_blocks_regenerate(monkeypatch):
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    _create(Session, monkeypatch)  # fresh RUNNING row
    with pytest.raises(treatment_mod.TreatmentConflict) as exc_info:
        treatment_api.post_regenerate_treatment_plan(
            SESSION_ID, SCENARIO_ID, TreatmentPlanRegenerateBody(), _principal())
    assert exc_info.value.reason == TreatmentGateReason.generation_in_progress


def _two_complete_versions(Session, monkeypatch) -> tuple[str, str]:
    """P1 (historical COMPLETE) + P2 (active COMPLETE)."""
    p1 = _create(Session, monkeypatch).plan_id
    _set_status(Session, p1, str(StageStatus.COMPLETE))
    p2 = treatment_api.post_regenerate_treatment_plan(
        SESSION_ID, SCENARIO_ID, TreatmentPlanRegenerateBody(), _principal()).plan_id
    _set_status(Session, p2, str(StageStatus.COMPLETE))
    return p1, p2


def _review(plan_id=None, decision="approved") -> TreatmentReviewBody:
    return TreatmentReviewBody(decision=decision, plan_id=plan_id)


def test_approve_historical_complete_swaps_atomically(monkeypatch):
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    published = _wire(Session, monkeypatch)
    p1, p2 = _two_complete_versions(Session, monkeypatch)

    resp = treatment_api.post_review_treatment_plan(SESSION_ID, SCENARIO_ID,
                                                    _review(plan_id=p1), _principal())

    assert resp.plan_id == p1
    rows = {r["PlanID"]: r for r in _plans(Session)}
    assert rows[p1]["Superseded"] == 0 and rows[p1]["ReviewStatus"] == "approved"
    assert rows[p2]["Superseded"] == 1 and rows[p2]["ReviewStatus"] is None  # keeps its own (non-)verdict
    assert sum(1 for r in rows.values() if r["Superseded"] == 0) == 1
    assert any(e.get("plan_id") == p1 for e in published)  # advisory publish after the commit

    with Session() as s:  # durable audit: the switch event, visible through BOTH endpoints
        session_events = [r for r in dal.treatment_audit_rows(s, SESSION_ID)
                          if r["EventType"] == str(AuditEventType.treatment_plan_version_restored)]
        entity_events = [r for r in dal.entity_treatment_audit_rows(s, "86")
                         if r["EventType"] == str(AuditEventType.treatment_plan_version_restored)]
    assert len(session_events) == 1 and len(entity_events) == 1
    detail = json.loads(session_events[0]["DetailJSON"])
    assert detail["plan_id"] == p1          # the key the per-scenario trail filters on
    assert detail["retired_plan_id"] == p2


def test_reject_historical_is_version_not_active(monkeypatch):
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    p1, p2 = _two_complete_versions(Session, monkeypatch)
    with pytest.raises(treatment_mod.TreatmentConflict) as exc_info:
        treatment_api.post_review_treatment_plan(SESSION_ID, SCENARIO_ID,
                                                 _review(plan_id=p1, decision="rejected"),
                                                 _principal())
    assert exc_info.value.reason == TreatmentGateReason.version_not_active
    assert {r["PlanID"]: r["Superseded"] for r in _plans(Session)} == {p1: 1, p2: 0}


def test_approve_historical_error_is_not_complete_and_never_claimable(monkeypatch):
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    p1, p2 = _two_complete_versions(Session, monkeypatch)
    _set_status(Session, p1, str(StageStatus.ERROR))
    with pytest.raises(treatment_mod.TreatmentConflict) as exc_info:
        treatment_api.post_review_treatment_plan(SESSION_ID, SCENARIO_ID,
                                                 _review(plan_id=p1), _principal())
    assert exc_info.value.reason == TreatmentGateReason.not_complete
    rows = {r["PlanID"]: r for r in _plans(Session)}
    assert rows[p1]["Superseded"] == 1 and rows[p2]["Superseded"] == 0  # rollback left no half-swap
    with Session() as s:  # a historical row is never claimable by the worker
        assert not dal.claim_plan(s, p1, "task-x", treatment_mod._stale_cutoff())


def test_foreign_or_unknown_plan_id_is_404(monkeypatch):
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    _two_complete_versions(Session, monkeypatch)
    with pytest.raises(dal.NotFoundError):
        treatment_api.post_review_treatment_plan(SESSION_ID, SCENARIO_ID,
                                                 _review(plan_id=str(uuid.uuid4())), _principal())


def test_explicit_or_mixed_case_active_plan_id_takes_plain_path(monkeypatch):
    """plan_id naming the ACTIVE plan — even UPPERCASE — is byte-identical to omitting it:
    no swap machinery, no restored audit event, no publish."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    published = _wire(Session, monkeypatch)
    _p1, p2 = _two_complete_versions(Session, monkeypatch)

    resp = treatment_api.post_review_treatment_plan(SESSION_ID, SCENARIO_ID,
                                                    _review(plan_id=p2.upper()), _principal())

    assert resp.plan_id == p2
    rows = {r["PlanID"]: r for r in _plans(Session)}
    assert rows[p2]["Superseded"] == 0 and rows[p2]["ReviewStatus"] == "approved"
    assert published == []  # plain verdicts never publish
    with Session() as s:
        assert not [r for r in dal.treatment_audit_rows(s, SESSION_ID)
                    if r["EventType"] == str(AuditEventType.treatment_plan_version_restored)]


def test_regenerate_baselines_on_active_row_after_switch(monkeypatch):
    """After approving P1 back in, a regenerate must carry P1's register data — not P2's
    (newest-by-CreatedAt), which the switch deliberately discarded."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    p1, p2 = _two_complete_versions(Session, monkeypatch)
    with Session() as s:  # stamp a marker into P2's snapshot to tell the two baselines apart
        snap = json.loads([r for r in _plans(Session) if r["PlanID"] == p2][0]["InputSnapshotJSON"])
        snap["existing_controls"]["register_controls"] = ["P2-marker"]
        s.execute(update(m.Risk_Treatment_Plan).where(m.Risk_Treatment_Plan.PlanID == p2)
                  .values(InputSnapshotJSON=json.dumps(snap)))
        s.commit()
    treatment_api.post_review_treatment_plan(SESSION_ID, SCENARIO_ID, _review(plan_id=p1),
                                             _principal())

    resp = treatment_api.post_regenerate_treatment_plan(
        SESSION_ID, SCENARIO_ID, TreatmentPlanRegenerateBody(), _principal())

    new_snap = json.loads([r for r in _plans(Session)
                           if r["PlanID"] == resp.plan_id][0]["InputSnapshotJSON"])
    assert new_snap["existing_controls"]["register_controls"] == ["annual patching"]  # P1's, not P2's


def test_reactivate_refuses_already_active_row(monkeypatch):
    """Direct pin of reactivate_plan_version's Superseded=1 fence: the routes never reach it
    with an already-active target (the branch check intercepts first), so only a dal-level
    call can prove the CAS itself refuses — without this, deleting the fence is invisible."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    _p1, p2 = _two_complete_versions(Session, monkeypatch)  # p2 is ACTIVE
    with Session() as s:
        assert dal.reactivate_plan_version(s, SESSION_ID, SCENARIO_ID, p2) is False
        s.rollback()


def test_toctou_fence_on_supersede(monkeypatch):
    """dal.supersede_active_plan with a stale plan_id fence must match nothing — the caller
    409s instead of retiring (and acting on) the wrong version."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)
    _wire(Session, monkeypatch)
    p1, _p2 = _two_complete_versions(Session, monkeypatch)  # p1 is NOT the active row
    with Session() as s:
        assert dal.supersede_active_plan(s, SCENARIO_ID, treatment_mod._stale_cutoff(),
                                         plan_id=p1) == 0  # fence miss: stale read
        s.rollback()
    assert sum(1 for r in _plans(Session) if r["Superseded"] == 0) == 1


def test_index_arbitrates_double_active_insert():
    """The recreated partial unique index has teeth: a second Superseded=0 row for one
    scenario_id is rejected by SQLite exactly as MSSQL's UX_TreatmentPlan_ActiveOutput would."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed(Session)

    def _plan_row(plan_id):
        return dict(PlanID=plan_id, SessionID=SESSION_ID, ScenarioID=SCENARIO_ID, TenantID="t",
                    EntityID="86", Status=str(StageStatus.RUNNING),
                    TreatmentStrategy="Mitigate", InputSnapshotJSON="{}", Superseded=0,
                    CreatedAt=_now(), UpdatedAt=_now())
    with Session() as s:
        s.execute(m.Risk_Treatment_Plan.__table__.insert().values(**_plan_row(str(uuid.uuid4()))))
        s.commit()
    with Session() as s, pytest.raises(IntegrityError):
        s.execute(m.Risk_Treatment_Plan.__table__.insert().values(**_plan_row(str(uuid.uuid4()))))
        s.flush()


def test_gate_text_covers_every_raisable_member():
    """Every TreatmentGateReason except the HISTORICAL scenario_superseded has wording in the
    one mapping — no reason can surface without a human sentence. (Single-wording is enforced
    structurally: _conflict() is the module's only 409 constructor, so a second spelling has
    nowhere to live — this test pins coverage, not uniqueness.)"""
    for member in TreatmentGateReason:
        if member is TreatmentGateReason.scenario_superseded:
            assert member not in treatment_api._GATE_TEXT  # retired: never raised, never worded
            continue
        assert member in treatment_api._GATE_TEXT, f"_GATE_TEXT missing {member!r}"


if __name__ == "__main__":
    print("run via pytest")
