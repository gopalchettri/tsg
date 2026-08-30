"""The treatment-plan response reports adversaries as a SIBLING `actors` block, never inside
`scenario` — the same rule ScenarioResult follows.

Why this file exists: `scenario` on this surface is `dict[str, Any]`, so nothing in the type
system can catch a stray `threat_actors` key coming back. Only an explicit absence assertion
can. The superseded-row case is the one that would crash rather than merely drift: those rows
carry no threat join at all, so the builder must read ThreatActorsJSON with .get().

Exercises app/api/treatment.py::_plan_status_from_row directly with synthetic rows — the same
no-DB pattern tests/test_threat_block_parity.py uses for the scenario surface.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from app.api import treatment as treatment_api

_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC).replace(tzinfo=None)

#: A row as the single-plan GET sees it: the threat IS joined, so the actor blob is present.
_JOINED_ROW = {
    "PlanID": "plan-1", "SessionID": "sess-1", "ScenarioID": "scn-1",
    "Status": "COMPLETE", "ErrorMessage": None, "ErrorReason": None,
    "UpdatedAt": _NOW, "CreatedAt": _NOW, "CompletedAt": _NOW,
    "TreatmentStrategy": "Mitigate", "RiskLevel": "High",
    "ReviewStatus": None, "ReviewedBy": None, "ReviewedAt": None,
    "RiskIdentificationDate": None, "PlanJSON": None,
    "ThreatCategory": "Tampering", "ThreatType": "t", "ThreatName": "n",
    "LibraryThreatType": None, "LibraryThreatName": None,
    "ScenarioJSON": json.dumps({
        "scenario_title": "Firmware push", "scenario_statement": "s", "risk_statement": "r",
        "assumptions": ["the RTU accepts unsigned firmware"],
        "supporting_systems_involved": [
            {"supporting_system_id": 306, "supporting_system": "SCADA System",
             "is_entry_point": True, "justification": "Entry point."}],
        # A legacy blob may even carry its own actors key; it must not survive either.
        "threat_actors": ["stale copy from the raw blob"],
    }),
    "ThreatActorsJSON": json.dumps(
        {"actors": ["APT33", "Malicious insider"], "actor_ids": [3, 9], "validated": True}),
}

#: A superseded-version row: dal.superseded_plan_rows carries NO scenario/threat join, so
#: neither ScenarioJSON nor ThreatActorsJSON is even a column on it.
_HISTORY_ROW = {k: v for k, v in _JOINED_ROW.items()
                if k not in {"ScenarioJSON", "ThreatActorsJSON", "ThreatCategory"}}
_HISTORY_ROW["ThreatCategory"] = None


def test_actors_are_a_sibling_and_never_inside_the_scenario_block():
    ps = treatment_api._plan_status_from_row(_JOINED_ROW, _NOW, {"APT33": 3, "Malicious insider": 9})

    # The sibling carries names WITH their Threat_Actor keys, same shape as ScenarioResult.actors.
    assert [(a.actor_id, a.actor_name) for a in ps.actors] == [(3, "APT33"), (9, "Malicious insider")]

    # `scenario` is now the SAME ScenarioNarrative /results publishes, so the contract is no
    # longer a six-key whitelist: every detail the results screen shows must be here too. The
    # raw blob DID carry a threat_actors key, and _scenario_narrative's pop is what keeps it out.
    assert ps.scenario is not None
    dumped = ps.scenario.model_dump()
    assert "threat_actors" not in dumped, (
        "adversaries must not ride inside the scenario block — including a legacy blob's own copy")
    assert "controls" not in dumped, "controls are an envelope sibling, not narrative"
    # The detail a reviewer approving a plan needs, and used to be denied by the whitelist.
    assert dumped["scenario_title"] == "Firmware push"
    assert dumped["supporting_systems_involved"], "the whitelist used to drop this entirely"
    assert dumped["assumptions"], "and this"
    # Threat display wording still merged in, through the one shared coalesce.
    assert dumped["threat_category"] == "Tampering"


def test_a_superseded_row_with_no_threat_join_yields_no_actors_rather_than_raising():
    """The regression this file's .get() exists for: history rows have no ThreatActorsJSON
    COLUMN at all, so indexing it would KeyError the whole versions response."""
    ps = treatment_api._plan_status_from_row(_HISTORY_ROW, _NOW)
    assert ps.actors == []
    assert ps.scenario is None


def test_stored_ids_are_used_without_a_lookup_and_unknown_names_still_appear():
    """actor_ids=None is the no-batch-resolve path. A name with no id must still be listed —
    dropping it would silently shorten the adversary list."""
    ps = treatment_api._plan_status_from_row(_JOINED_ROW, _NOW, {"APT33": 3})
    assert [(a.actor_id, a.actor_name) for a in ps.actors] == [(3, "APT33"), (None, "Malicious insider")]
