"""Regression pins for four behaviour fixes.

  * A startup-only uniqueness rule must be backed by a database index (UX_Scenario_ActiveScoped).
  * A regenerated plan names every control the previous version carried that it does not.
  * The evidence endpoint takes `plan_id`; `version` survives as a deprecated alias.
  * The session's CurrentStage/StageStatus follows the run instead of freezing at creation.
"""
from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.exceptions import RequestValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api import treatment as api_treatment
from app.core.enums import StageStatus, SubsystemLevel
from app.db import dal
from app.db import models as m
from app.db.invariants import ACTIVE_UNIQUE, REQUIRED_INDEXES
from app.pipeline import treatment

# ---------------------------------------------------------------------------------------------
# A1 — every startup-only uniqueness rule has a database index behind it
# ---------------------------------------------------------------------------------------------

def test_every_startup_uniqueness_rule_is_backed_by_an_index() -> None:
    """ACTIVE_UNIQUE is checked only at boot. Without an index, a duplicate commits silently and the
    service refuses to boot at the NEXT restart, far from its cause. So each rule must also appear in
    REQUIRED_INDEXES, which rejects the duplicate at write time. A rule added without one fails here."""
    indexed = {(table, tuple(cols)) for _name, table, cols in REQUIRED_INDEXES}
    missing = [(t.__tablename__, tuple(k)) for t, k in ACTIVE_UNIQUE
               if (t.__tablename__, tuple(k)) not in indexed]
    assert not missing, f"startup-only uniqueness rules with no index: {missing}"


# ---------------------------------------------------------------------------------------------
# A3 — a regenerated plan explains every control that dropped
# ---------------------------------------------------------------------------------------------

class _RowsSess:
    """Answers the Control_Library state read with fixed rows; `fail` makes that read raise."""

    def __init__(self, rows=(), fail: bool = False):
        self.rows, self.fail, self.rolled_back = list(rows), fail, False

    def rollback(self):
        self.rolled_back = True

    def execute(self, *a, **k):
        if self.fail:
            raise RuntimeError("db down")
        return SimpleNamespace(all=lambda: self.rows)


def _lib(control_id: int, active: bool = True, deleted: bool = False) -> SimpleNamespace:
    return SimpleNamespace(ControlLibraryID=control_id, IsActive=active, IsDeleted=deleted)


_PREV = {"CII-001": ("MFA for admin accounts", 1), "CII-002": ("Network segmentation", 2)}
_CUR = [{"control_code": "CII-002", "control_name": "Network segmentation"}]
_SESSION_ROW = {"AssetName": "Historian", "AssetContextJSON": None, "SubsystemsJSON": None}
_SCENARIO_ROW = {"ScenarioID": "s-1", "ThreatCategory": None, "ThreatType": "Tampering",
                 "ThreatName": "Setpoint tampering", "LibraryThreatType": None,
                 "LibraryThreatName": None, "ThreatActorsJSON": None, "ScenarioJSON": None}


def _msg(reason: str) -> str:
    return (f"control CII-001 (MFA for admin accounts) was in the previous version but {reason} "
            "— omitted from this version")


def test_nothing_dropped_means_no_warning() -> None:
    both = [{"control_code": "CII-001"}, {"control_code": "CII-002"}]
    assert treatment._dropped_control_warnings(_RowsSess(), _PREV, both) == []


@pytest.mark.parametrize("row, reason", [
    (_lib(1, active=False), "has been retired from the control library"),
    (_lib(1, deleted=True), "has been retired from the control library"),
    (_lib(1), "is no longer mapped to this scenario"),
    (None, "is no longer in the control library"),
])
def test_a_dropped_control_is_named_with_its_real_reason(row, reason) -> None:
    """The reason is READ, not assumed — a still-active control that dropped is a re-map, and must
    not be reported as a retirement."""
    out = treatment._dropped_control_warnings(_RowsSess([row] if row else []), _PREV, _CUR)
    assert out == [_msg(reason)]


def test_a_failed_reason_lookup_still_warns_and_never_raises() -> None:
    sess = _RowsSess(fail=True)
    assert treatment._dropped_control_warnings(sess, _PREV, _CUR) == [_msg("is no longer available")]
    assert sess.rolled_back


def test_a_retired_code_reused_by_a_new_row_is_still_reported_retired() -> None:
    """UX_Control_Library_Code lets a retired control's code be reused. Looking the reason up by CODE
    returned whichever of the two rows came back last; by the stored id it is exact."""
    rows = [_lib(1, active=False), _lib(5)]          # id 1 retired, id 5 active, same code
    out = treatment._dropped_control_warnings(_RowsSess(rows), _PREV, _CUR)
    assert out == [_msg("has been retired from the control library")]


def test_several_drops_in_one_regenerate_each_get_their_own_reason() -> None:
    """One read serves every dropped control (one IN on their ids), and each keeps its own reason
    and its previous-version order — retired, re-mapped and vanished side by side."""
    prev = {"CII-001": ("MFA", 1), "CII-002": ("Segmentation", 2), "CII-003": ("Backups", 3)}
    rows = [_lib(1, active=False), _lib(2)]                 # 3 is gone from the library
    out = treatment._dropped_control_warnings(_RowsSess(rows), prev, [])
    assert out == [
        "control CII-001 (MFA) was in the previous version but has been retired from the control "
        "library — omitted from this version",
        "control CII-002 (Segmentation) was in the previous version but is no longer mapped to "
        "this scenario — omitted from this version",
        "control CII-003 (Backups) was in the previous version but is no longer in the control "
        "library — omitted from this version",
    ]


def test_a_failed_library_lookup_reports_that_and_nothing_per_control(monkeypatch) -> None:
    """When the CURRENT map cannot be read at all, every previous control would look dropped. That
    is not what happened, so no per-control warning is raised — the one lookup-failed warning
    says what really happened instead."""
    def _boom(sess, sid):
        raise RuntimeError("db down")

    monkeypatch.setattr(treatment, "_library_controls", _boom)
    snap = treatment.build_treatment_input(
        _RowsSess(), _SESSION_ROW, _SCENARIO_ROW, {"existing_controls": [], "risk_level": "High"},
        previous_controls=_PREV)
    assert "library control lookup failed — plan generated without mapped controls" in snap["warnings"]
    assert not any("previous version" in w for w in snap["warnings"]), snap["warnings"]


def test_a_legacy_snapshot_without_an_id_gets_no_guessed_reason() -> None:
    legacy = {"CII-001": ("MFA for admin accounts", None), "CII-002": ("Network segmentation", 2)}
    out = treatment._dropped_control_warnings(_RowsSess([_lib(1, active=False)]), legacy, _CUR)
    assert out == [_msg("is no longer available")]


def test_snapshot_controls_keeps_order_ids_and_skips_malformed_entries() -> None:
    snap = {"existing_controls": {"library_mapped": [
        {"control_code": "B", "control_name": "Bee", "control_library_id": 7}, "junk",
        {"control_name": "no code"}, {"control_code": "A", "control_name": None}]}}
    assert list(treatment._snapshot_controls(snap).items()) == [("B", ("Bee", 7)), ("A", ("", None))]
    assert treatment._snapshot_controls({}) == {}


def test_regenerate_snapshot_carries_the_warning(monkeypatch) -> None:
    monkeypatch.setattr(treatment, "_library_controls", lambda sess, sid: list(_CUR))
    snap = treatment.build_treatment_input(
        _RowsSess([_lib(1, active=False)]), _SESSION_ROW, _SCENARIO_ROW,
        {"existing_controls": [], "risk_level": "High"}, previous_controls=_PREV)
    assert _msg("has been retired from the control library") in snap["warnings"]


def test_first_generation_is_unchanged(monkeypatch) -> None:
    """No previous version, no comparison — the AI first-generation path is untouched."""
    monkeypatch.setattr(treatment, "_library_controls", lambda sess, sid: list(_CUR))
    snap = treatment.build_treatment_input(
        _RowsSess(), _SESSION_ROW, _SCENARIO_ROW, {"existing_controls": [], "risk_level": "High"})
    assert not any("previous version" in w for w in snap["warnings"])


# ---------------------------------------------------------------------------------------------
# Ratings — the consistency check compares on the VALUE, never on how the client spelled it
# ---------------------------------------------------------------------------------------------

def _warns_through_the_schema(monkeypatch, likelihood, impact, final) -> bool:
    """The real path: TreatmentPlanBody -> model_dump(mode="json") -> build_treatment_input."""
    from app.api.schemas_treatment import TreatmentPlanBody

    monkeypatch.setattr(treatment, "_library_controls", lambda sess, sid: [])
    body = TreatmentPlanBody(existing_controls=[], risk_level="High", likelihood_rating=likelihood,
                             impact_rating=impact, final_risk_rating=final).model_dump(mode="json")
    snap = treatment.build_treatment_input(_RowsSess(), _SESSION_ROW, _SCENARIO_ROW, body)
    return any("does not equal likelihood x impact" in w for w in snap["warnings"])


def test_a_huge_exponent_zero_neither_crashes_nor_hides_the_mismatch(monkeypatch) -> None:
    """'0E+1000000' is a valid 0 to the schema; quantize() on its exponent raised -> a 500."""
    assert _warns_through_the_schema(monkeypatch, 4, 5, "0E+1000000")


def test_an_exponent_spelled_zero_still_reports_the_mismatch(monkeypatch) -> None:
    """'0E+5' used to become the comparison scale: 4x5 rounded to hundred-thousands equals 0."""
    assert _warns_through_the_schema(monkeypatch, 4, 5, "0E+5")


def test_the_same_value_warns_the_same_however_it_is_spelled(monkeypatch) -> None:
    """2.4 x 4.4 = 10.56 against 10: '1E+1' hid it, '10' reported it."""
    assert _warns_through_the_schema(monkeypatch, "2.4", "4.4", "1E+1")
    assert _warns_through_the_schema(monkeypatch, "2.4", "4.4", "10")


def test_trailing_zeros_do_not_change_the_verdict(monkeypatch) -> None:
    """First generation (literal '21.150') and regenerate (stored 21.15) must agree."""
    assert (_warns_through_the_schema(monkeypatch, "4.5", "4.7", "21.150")
            == _warns_through_the_schema(monkeypatch, "4.5", "4.7", "21.15"))


# ---------------------------------------------------------------------------------------------
# O1 — evidence takes plan_id; version still works
# ---------------------------------------------------------------------------------------------

def test_plan_id_is_the_canonical_parameter() -> None:
    assert api_treatment._evidence_plan_id("p1", None) == "p1"


def test_version_still_works_as_an_alias() -> None:
    assert api_treatment._evidence_plan_id(None, "p1") == "p1"


def test_both_sent_and_agreeing_is_accepted() -> None:
    assert api_treatment._evidence_plan_id("p1", "p1") == "p1"


def test_agreement_ignores_letter_case() -> None:
    """A GUID read back from SQL Server is uppercase, dal.guid() mints lowercase: the same plan id
    in two spellings is agreement, not a 422."""
    assert api_treatment._evidence_plan_id("ABCD-1234", "abcd-1234") == "ABCD-1234"


def test_an_empty_plan_id_falls_back_to_the_alias() -> None:
    """`?plan_id=&version=p1` — an empty canonical parameter is "not sent", not a disagreement, so
    an old client that appends version to a templated URL keeps working."""
    assert api_treatment._evidence_plan_id("", "p1") == "p1"


@pytest.mark.parametrize("plan_id, version", [("p1", "p2"), (None, None), ("", "")])
def test_disagreeing_or_missing_is_a_422(plan_id, version) -> None:
    with pytest.raises(RequestValidationError):
        api_treatment._evidence_plan_id(plan_id, version)


def test_openapi_publishes_plan_id_and_marks_version_deprecated() -> None:
    from app.core.config import get_settings
    from app.main import create_app

    previous = os.environ.get("TSG_RISK_MODULE_ENABLED")
    os.environ["TSG_RISK_MODULE_ENABLED"] = "true"
    get_settings.cache_clear()
    try:
        spec = create_app().openapi()
    finally:
        if previous is None:
            os.environ.pop("TSG_RISK_MODULE_ENABLED", None)
        else:
            os.environ["TSG_RISK_MODULE_ENABLED"] = previous
        get_settings.cache_clear()
    op = spec["paths"]["/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/evidence"]["get"]
    params = {p["name"]: p for p in op["parameters"]}
    assert "plan_id" in params
    assert params["version"].get("deprecated") is True


# ---------------------------------------------------------------------------------------------
# O2 — the session stage follows the run
# ---------------------------------------------------------------------------------------------

_NOW = datetime.now(UTC)


@pytest.fixture
def db(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'o2.db'}", connect_args={"check_same_thread": False})
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State):
        tbl.__table__.create(eng)
    return sessionmaker(bind=eng, future=True)


def _seed(maker, *, status="active", stage="THREAT_IDENTIFICATION", stage_status="IDLE") -> str:
    sid = str(uuid.uuid4())
    with maker() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=sid, TenantID="t", EntityID="e", AssetName="A", AssetID="1",
            SessionStatus=status, CurrentStage=stage, StageStatus=stage_status, Mode="AUTO",
            SubsystemsJSON="[]", CreatedAt=_NOW, UpdatedAt=_NOW))
        for level in (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS):
            s.execute(m.Subsystem_Stage_State.__table__.insert().values(
                StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="e",
                SubsystemID=0, Level=level, Status=StageStatus.IDLE, GenerationEpoch=1,
                LeaseExpiresAt=_NOW + timedelta(minutes=30), UpdatedAt=_NOW, CreatedAt=_NOW))
        s.commit()
    return sid


def _stage(maker, sid: str) -> tuple[str, str]:
    with maker() as s:
        row = s.execute(select(m.Scenario_Session.CurrentStage, m.Scenario_Session.StageStatus)
                        .where(m.Scenario_Session.SessionID == sid)).one()
    return str(row[0]), str(row[1])


def _claim(maker, sid: str, level: SubsystemLevel) -> bool:
    with maker() as s:
        # A real Celery task id is a UUID, and ActiveTaskID is a GUID column.
        won = dal.claim_stage(s, sid, 0, level, 1, str(uuid.uuid4()))
        s.commit()
    return won


def test_claiming_threats_marks_the_session_running(db) -> None:
    sid = _seed(db)
    assert _claim(db, sid, SubsystemLevel.THREATS)
    assert _stage(db, sid) == ("THREAT_IDENTIFICATION", "RUNNING")


def test_claiming_scenarios_advances_the_session(db) -> None:
    """The observed bug: threats and scenarios done, stage still THREAT_IDENTIFICATION/IDLE."""
    sid = _seed(db)
    assert _claim(db, sid, SubsystemLevel.SCENARIOS)
    assert _stage(db, sid) == ("SCENARIO_GENERATION", "RUNNING")


@pytest.mark.parametrize("status, stage, stage_status", [
    ("completed", "REVIEW", "AWAITING_DECISION"),   # regenerating must not close the review gate
    ("cancelled", "CANCELLED", "ERROR"),              # a cancelled run is never resurrected
])
def test_a_finished_session_is_never_touched(db, status, stage, stage_status) -> None:
    sid = _seed(db, status=status, stage=stage, stage_status=stage_status)
    _claim(db, sid, SubsystemLevel.SCENARIOS)
    assert _stage(db, sid) == (stage, stage_status)


def test_it_never_moves_backwards(db) -> None:
    """A late THREATS retry after scenarios began must not rewind the displayed stage."""
    sid = _seed(db, stage="SCENARIO_GENERATION", stage_status="RUNNING")
    _claim(db, sid, SubsystemLevel.THREATS)
    assert _stage(db, sid) == ("SCENARIO_GENERATION", "RUNNING")


def test_a_failed_display_write_never_costs_the_claim(db, monkeypatch) -> None:
    """The stage cache is display-only; its write runs in a savepoint so a failure there is logged
    and the claim it rides on still wins and commits. Never exercised before.

    Logs are recorded through dal.log itself, not structlog.testing.capture_logs: an earlier test
    in the suite caches dal's logger, after which capture_logs silently sees nothing from it."""
    events: list[tuple[str, str]] = []

    class _Recorder:
        def __getattr__(self, level):
            return lambda event, **_kw: events.append((level, event))

    monkeypatch.setattr(dal, "log", _Recorder())
    real = dal.execute_dml

    def _flaky(sess, stmt):
        if getattr(getattr(stmt, "table", None), "name", "") == "Scenario_Session":
            raise RuntimeError("cache write failed")
        return real(sess, stmt)

    monkeypatch.setattr(dal, "execute_dml", _flaky)
    sid = _seed(db)
    assert _claim(db, sid, SubsystemLevel.SCENARIOS)
    assert ("warning", "stage.session_cache_sync_failed") in events, events
    assert _stage(db, sid) == ("THREAT_IDENTIFICATION", "IDLE")        # cache untouched...
    with db() as s:                                                   # ...claim durable
        status = s.execute(select(m.Subsystem_Stage_State.Status).where(
            m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.Level == SubsystemLevel.SCENARIOS)).scalar_one()
    assert str(status) == "RUNNING"


def test_a_claim_rolled_back_under_the_savepoint_is_never_reported_as_won(db, monkeypatch) -> None:
    """SQL Server's deadlock victim (1205) rolls back the WHOLE transaction, the claim UPDATE with
    it, and then the savepoint cannot be rolled back to. Swallowing that returned won=True for a
    claim that no longer existed; the caller then committed nothing and ran the stage unclaimed.
    It must fail like a lost claim instead, so the task retries."""
    real = dal.execute_dml

    def _deadlock_victim(sess, stmt):
        if getattr(getattr(stmt, "table", None), "name", "") == "Scenario_Session":
            sess.connection().exec_driver_sql("ROLLBACK")      # the server ends the transaction
            raise RuntimeError("deadlock victim")
        return real(sess, stmt)

    monkeypatch.setattr(dal, "execute_dml", _deadlock_victim)
    sid = _seed(db)
    with pytest.raises(RuntimeError, match="deadlock victim"):
        _claim(db, sid, SubsystemLevel.SCENARIOS)
    with db() as s:
        status = s.execute(select(m.Subsystem_Stage_State.Status).where(
            m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.Level == SubsystemLevel.SCENARIOS)).scalar_one()
    assert str(status) == "IDLE", "the claim is gone, so nothing may act as if it were won"


def test_a_claim_whose_connection_died_is_never_reported_as_won(db, monkeypatch) -> None:
    """A disconnect-class error — MSSQL counts a statement timeout (HYT00) as one — invalidates
    the connection, and SQLAlchemy then skips ROLLBACK TO SAVEPOINT without raising. The
    'rollback worked' test passed for a transaction that was already gone, so the claim looked
    won. connection_invalidated is what SQLAlchemy sets on exactly those errors."""
    from sqlalchemy.exc import OperationalError

    real = dal.execute_dml

    def _connection_lost(sess, stmt):
        if getattr(getattr(stmt, "table", None), "name", "") == "Scenario_Session":
            raise OperationalError("UPDATE Scenario_Session", {}, Exception("HYT00", "timeout"),
                                   connection_invalidated=True)
        return real(sess, stmt)

    monkeypatch.setattr(dal, "execute_dml", _connection_lost)
    sid = _seed(db)
    with pytest.raises(OperationalError):
        _claim(db, sid, SubsystemLevel.SCENARIOS)
    with db() as s:
        status = s.execute(select(m.Subsystem_Stage_State.Status).where(
            m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.Level == SubsystemLevel.SCENARIOS)).scalar_one()
    assert str(status) == "IDLE"


def test_a_deadlock_is_a_transient_error_everywhere() -> None:
    """pyodbc raises its base Error for SQLSTATE 40001, which SQLAlchemy wraps as a plain
    DBAPIError, so a deadlock skipped Celery's autoretry (TRANSIENT_INFRA_ERRORS) and failed a
    healthy run. The engine hook maps it to OperationalError; other errors pass through."""
    from types import SimpleNamespace

    from sqlalchemy.exc import DBAPIError, OperationalError

    from app.db.engine import map_serialization_failure
    from app.pipeline.pipeline_common import TRANSIENT_INFRA_ERRORS

    def ctx(sqlstate, wrapped=DBAPIError):
        orig = Exception(sqlstate, f"[{sqlstate}] driver message")
        return SimpleNamespace(original_exception=orig, statement="UPDATE x", parameters=(),
                               sqlalchemy_exception=wrapped("UPDATE x", (), orig))

    mapped = map_serialization_failure(ctx("40001"))
    assert isinstance(mapped, OperationalError) and isinstance(mapped, TRANSIENT_INFRA_ERRORS)
    assert map_serialization_failure(ctx("23000")) is None                 # constraint: not transient
    assert map_serialization_failure(ctx("40001", OperationalError)) is None   # already transient
