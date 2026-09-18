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


def _lib(code: str, active: bool = True, deleted: bool = False) -> SimpleNamespace:
    return SimpleNamespace(ControlCode=code, IsActive=active, IsDeleted=deleted)


_PREV = {"CII-001": "MFA for admin accounts", "CII-002": "Network segmentation"}
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
    (_lib("CII-001", active=False), "has been retired from the control library"),
    (_lib("CII-001", deleted=True), "has been retired from the control library"),
    (_lib("CII-001"), "is no longer mapped to this scenario"),
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


def test_snapshot_control_names_keeps_order_and_skips_malformed_entries() -> None:
    snap = {"existing_controls": {"library_mapped": [
        {"control_code": "B", "control_name": "Bee"}, "junk", {"control_name": "no code"},
        {"control_code": "A", "control_name": None}]}}
    assert list(treatment._snapshot_control_names(snap).items()) == [("B", "Bee"), ("A", "")]
    assert treatment._snapshot_control_names({}) == {}


def test_regenerate_snapshot_carries_the_warning(monkeypatch) -> None:
    monkeypatch.setattr(treatment, "_library_controls", lambda sess, sid: list(_CUR))
    snap = treatment.build_treatment_input(
        _RowsSess([_lib("CII-001", active=False)]), _SESSION_ROW, _SCENARIO_ROW,
        {"existing_controls": [], "risk_level": "High"}, previous_controls=_PREV)
    assert _msg("has been retired from the control library") in snap["warnings"]


def test_first_generation_is_unchanged(monkeypatch) -> None:
    """No previous version, no comparison — the AI first-generation path is untouched."""
    monkeypatch.setattr(treatment, "_library_controls", lambda sess, sid: list(_CUR))
    snap = treatment.build_treatment_input(
        _RowsSess(), _SESSION_ROW, _SCENARIO_ROW, {"existing_controls": [], "risk_level": "High"})
    assert not any("previous version" in w for w in snap["warnings"])


# ---------------------------------------------------------------------------------------------
# O1 — evidence takes plan_id; version still works
# ---------------------------------------------------------------------------------------------

def test_plan_id_is_the_canonical_parameter() -> None:
    assert api_treatment._evidence_plan_id("p1", None) == "p1"


def test_version_still_works_as_an_alias() -> None:
    assert api_treatment._evidence_plan_id(None, "p1") == "p1"


def test_both_sent_and_agreeing_is_accepted() -> None:
    assert api_treatment._evidence_plan_id("p1", "p1") == "p1"


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
