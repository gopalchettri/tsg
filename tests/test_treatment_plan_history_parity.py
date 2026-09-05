"""A superseded plan version is served as a FULL entry, not a hollow one.

Why this file exists: `?include_superseded=true` had no test at all, on either endpoint. That
absence is the bug's actual cause — `dal.superseded_plan_rows` selects a fixed column list, and
three separate schema changes (created_by unhidden, Cancelled* added, warnings/moderation_flagged
unhidden) each updated `active_plan_row` and silently missed the history query. Nothing failed,
because `_plan_status_from_row` reads those columns with `.get()`: a missing column published
null/false instead of raising, so a superseded row reported `moderation_flagged=false` whatever it
had actually recorded.

Two rules are pinned here, and they pull in opposite directions:

  * VERSION-INDEPENDENT (scenario/threat/actors/controls) — identical for every version, so the
    route overlays the ACTIVE row's single copy rather than re-hauling multi-KB ScenarioJSON per
    version. These must MATCH the active plan.
  * PER-VERSION (created_by, cancelled_*, warnings, moderation_flagged) — describe one attempt,
    cannot be echoed, must be SELECTED. These must be the history row's OWN, and the overlay must
    never clobber them.

No database: `_plan_status_from_row` is fed synthetic row dicts, the same no-DB pattern
tests/test_treatment_actors_sibling.py uses. The route-level proof lives in
tests/test_treatment_plan_versions.py, where the SQLite scaffolding already exists.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from app.api import treatment as treatment_api
from app.api.schemas import MappedControl
from app.db import models as m

_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC).replace(tzinfo=None)
_CANCELLED = datetime(2026, 8, 29, 9, 0, tzinfo=UTC).replace(tzinfo=None)

_CONTROLS = [MappedControl(control_id=117, control_code="CII-CID-117",
                           domain="Continuous Monitoring",
                           control_name="Unauthorized Network Services",
                           map_rank=1, score=90.6, standards=[])]

#: The active row, as dal.active_plan_row selects it: plan columns PLUS the scenario/threat join.
_ACTIVE_ROW = {
    "PlanID": "plan-active", "SessionID": "sess-1", "ScenarioID": "scn-1",
    "Status": "COMPLETE", "ErrorMessage": None, "ErrorReason": None,
    "UpdatedAt": _NOW, "CreatedAt": _NOW, "CompletedAt": _NOW,
    "TreatmentStrategy": "Mitigate", "RiskLevel": "Critical",
    "ReviewStatus": None, "ReviewedBy": None, "ReviewedAt": None,
    "RiskIdentificationDate": None, "PlanJSON": None,
    "UserID": "gopal", "CancelledBy": None, "CancelledAt": None,
    "ValidationJSON": None,
    # The full Identified_Threat set _threat_block reads — GroundingStatus and ThreatType are
    # ThreatResult's required fields, so a partial fixture would 500 the presenter rather than
    # test it. Score/ScopeRank come off Scoped_Threat and are two of the three hand-written
    # names in _SCENARIO_ECHO_KEYS, so including them exercises that literal too.
    "ThreatID": "threat-1", "ThreatCategory": "Spoofing", "ThreatCategoryID": 1,
    "ThreatType": "OT Service Exploitation", "ThreatTypeID": 14,
    "ThreatName": "Internet-exposed OT service exploitation",
    "ThreatCatalogueID": 47,
    "LibraryThreatType": None, "LibraryThreatName": None,
    "GroundingStatus": "verified", "GroundingScore": 100,
    "IsThreatAIGenerated": False, "IsThreatTypeAIGenerated": False,
    "Score": 70, "ScopeRank": 6,
    "ScenarioJSON": json.dumps({
        "scenario_title": "SGI — spoofed vendor service",
        "scenario_statement": "s", "risk_statement": "r",
        "assumptions": ["the OT telecom network exposes a management interface"],
        "supporting_systems_involved": [
            {"supporting_system_id": 311, "supporting_system": "OT telecom network",
             "is_entry_point": True, "justification": "Entry point."}],
    }),
    "ThreatActorsJSON": json.dumps(
        {"actors": ["External attacker", "Nation-state/APT"], "actor_ids": [1, 3],
         "validated": True}),
}

#: A retired version as dal.superseded_plan_rows selects it: plan-table columns ONLY, no join.
#: Every per-version value here DIFFERS from the active row's, so an overlay that clobbered one
#: would be visible rather than coincidentally equal.
_HISTORY_ROW = {
    "PlanID": "plan-old", "SessionID": "sess-1", "ScenarioID": "scn-1",
    "Status": "COMPLETE", "ErrorMessage": None, "ErrorReason": None,
    "UpdatedAt": _NOW, "CreatedAt": _NOW, "CompletedAt": _NOW,
    "TreatmentStrategy": "Mitigate", "RiskLevel": "Critical",
    "ReviewStatus": "rejected", "ReviewedBy": "reviewer-2", "ReviewedAt": _NOW,
    "RiskIdentificationDate": None, "PlanJSON": None,
    "UserID": "someone-else", "CancelledBy": "ops-oncall", "CancelledAt": _CANCELLED,
    "ValidationJSON": json.dumps({"warnings": ["A3 timeline overruns the assessment window"],
                                  "moderation": {"flagged": True}}),
}


def _echo() -> dict:
    """What the route overlays: the active row's version-independent columns."""
    return {k: _ACTIVE_ROW[k] for k in treatment_api._SCENARIO_ECHO_KEYS if k in _ACTIVE_ROW}


def _present(row, **kw):
    return treatment_api._plan_status_from_row(row, _NOW, {"External attacker": 1,
                                                           "Nation-state/APT": 3}, **kw)


def test_the_overlay_gives_a_history_entry_the_same_scenario_blocks_as_the_active_plan():
    """The four version-independent blocks must MATCH — a reviewer comparing versions is looking
    at one scenario, and a null here is what made the history unusable as a version picker."""
    active = _present(_ACTIVE_ROW, controls=_CONTROLS)
    older = _present({**_echo(), **_HISTORY_ROW}, controls=_CONTROLS, superseded_row=True)

    assert older.scenario is not None
    assert older.scenario.model_dump() == active.scenario.model_dump()
    assert older.threat is not None
    assert older.threat.model_dump() == active.threat.model_dump()
    assert ([(a.actor_id, a.actor_name) for a in older.actors]
            == [(a.actor_id, a.actor_name) for a in active.actors])
    assert [c.control_code for c in older.controls] == [c.control_code for c in active.controls]


def test_the_overlay_never_clobbers_the_history_rows_own_per_version_fields():
    """The regression that motivated the whole change: these describe THIS attempt and cannot be
    echoed. `{**echo, **row}` — the history row's keys win — is what keeps them its own."""
    older = _present({**_echo(), **_HISTORY_ROW}, controls=_CONTROLS, superseded_row=True)

    assert older.plan_id == "plan-old"                    # not the active row's id
    assert older.created_by == "someone-else"             # was null before the SELECT widened
    assert older.cancelled_by == "ops-oncall"
    assert older.cancelled_at == _CANCELLED
    assert older.review_status == "rejected"              # keeps its own verdict
    assert older.warnings == ["A3 timeline overruns the assessment window"]
    assert older.moderation_flagged is True, (
        "a flagged version reported moderation_flagged=false while ValidationJSON was unselected "
        "— absent data published as a clean bill of health")


def test_a_history_entry_reports_no_live_progress():
    """A retired version is history, not a lifecycle. Echoing the active plan's progress onto it
    would assert something false, so this stays null even under full parity."""
    older = _present({**_echo(), **_HISTORY_ROW}, controls=_CONTROLS, superseded_row=True)
    assert older.progress is None
    assert _present(_ACTIVE_ROW, controls=_CONTROLS).progress is not None


def test_a_history_row_with_no_overlay_still_degrades_instead_of_raising():
    """The board serves history rows WITHOUT the overlay (its own rows carry no scenario either),
    so the presenter's .get() contract still has to hold — indexing would KeyError the response."""
    older = _present(_HISTORY_ROW, superseded_row=True)

    assert older.scenario is None and older.threat is None
    assert older.actors == [] and older.controls == []
    assert older.created_by == "someone-else"   # per-version data survives the missing join
    assert older.moderation_flagged is True


def test_every_echo_key_is_a_real_column_on_the_joined_tables():
    """The three hand-written names in _SCENARIO_ECHO_KEYS are the drift risk (the rest are
    derived from dal.scenario_threat_columns()). A key naming no column would overlay nothing and
    fail silently — exactly how this bug behaved."""
    available: set[str] = set()
    for model in (m.Threat_Scenario, m.Scoped_Threat, m.Identified_Threat):
        available |= {c.key for c in model.__table__.columns}

    unknown = [k for k in treatment_api._SCENARIO_ECHO_KEYS if k not in available]
    assert not unknown, f"echo keys naming no column on the joined tables: {unknown}"


def test_the_echo_carries_no_per_version_column():
    """The two sets must stay disjoint. A per-version column added here would be copied from the
    active row onto every history entry — silently rewriting history rather than reporting it."""
    per_version = {"PlanID", "Status", "PlanJSON", "ValidationJSON", "ReviewStatus", "ReviewedBy",
                   "ReviewedAt", "UserID", "CancelledBy", "CancelledAt", "ErrorMessage",
                   "ErrorReason", "CreatedAt", "UpdatedAt", "CompletedAt"}
    overlap = per_version & set(treatment_api._SCENARIO_ECHO_KEYS)
    assert not overlap, f"per-version columns must never be echoed: {overlap}"
