"""dal._entry_point_id / dal.variant_eligible_primaries's coverage boundary, after the
supporting_systems_involved merge: the "used" set now reads is_entry_point from each scenario's
involved-systems list instead of a flat entry_point_id key. Load-bearing — this is what decides
whether a multi-path threat gets another scenario variant.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from app.api.schemas import ScenarioNarrative
from app.core.enums import ScenarioStatus
from app.db.dal import _entry_point_id, variant_eligible_primaries


def _row(**kw):
    base = {"IdentityHash": "h1", "Status": ScenarioStatus.complete, "ScenarioNumber": 1,
            "ScopedThreatID": "st-1", "ScenarioJSON": "{}"}
    return SimpleNamespace(**{**base, **kw})


def _scenario_json(entry_id: int | None, plausible_ids: list[int] | None = None) -> str:
    involved = [{"supporting_system_id": entry_id, "supporting_system": "x",
                "is_entry_point": True, "justification": "j"}] if entry_id is not None else []
    doc = {"supporting_systems_involved": involved}
    if plausible_ids is not None:
        doc["plausible_entry_point_ids"] = plausible_ids
    return json.dumps(doc)


def test_entry_point_id_reads_the_is_entry_point_row():
    assert _entry_point_id(_scenario_json(307)) == 307
    assert _entry_point_id(_scenario_json(None)) is None
    assert _entry_point_id(None) is None
    assert _entry_point_id("not json") is None


def test_fully_covered_threat_is_not_eligible_no_db_touched():
    """Primary declares plausible [306, 307]; the group's own entry points across both
    scenarios cover 306 AND 307 between them, so the identity is DONE. sess=None must never be
    touched — proving candidates ended up empty before any query."""
    primary = _row(ScenarioJSON=_scenario_json(306, plausible_ids=[306, 307]))
    sibling = _row(ScenarioNumber=2, ScenarioJSON=_scenario_json(307))
    result = variant_eligible_primaries(
        None, "sess-1", 5, rows=[primary, sibling], attempt_slack=2)
    assert result == []


def test_partially_covered_threat_stays_eligible_reaches_the_db_query():
    """Only 306 of the plausible [306, 307] is covered — the identity must stay a candidate,
    proving the function proceeds past the coverage check (it would AttributeError on the
    sess=None stand-in trying to query Scoped_Threat, which only happens once candidates is
    non-empty)."""
    primary = _row(ScenarioJSON=_scenario_json(306, plausible_ids=[306, 307]))
    try:
        variant_eligible_primaries(None, "sess-1", 5, rows=[primary], attempt_slack=2)
    except AttributeError:
        pass  # reached sess.execute(...) — candidates was non-empty, as expected
    else:
        raise AssertionError("expected to reach the DB query — candidates must be non-empty")


def test_no_plausible_entry_points_fails_closed():
    """No plausible_entry_point_ids at all (a legacy/pre-coverage row) -> no coverage target
    derivable -> not eligible, per the function's own fail-closed contract."""
    primary = _row(ScenarioJSON=_scenario_json(306))  # no plausible_ids key
    result = variant_eligible_primaries(None, "sess-1", 5, rows=[primary], attempt_slack=2)
    assert result == []


def test_missing_justification_degrades_instead_of_crashing_the_whole_response():
    """Cross-check finding: a stored row with justification=None (a partial repair turn, or
    any row written before tasks.py's write-time `or ""` normalization) used to raise a
    pydantic ValidationError with no per-item isolation anywhere in its callers — one bad
    scenario 500'd the ENTIRE session's results page. Both the missing-key and explicit-null
    shapes must degrade to an empty string, never crash."""
    involved = [{"supporting_system_id": 306, "supporting_system": "x", "is_entry_point": True,
                "justification": None}]
    assert ScenarioNarrative(
        supporting_systems_involved=involved).supporting_systems_involved[0].justification == ""
    del involved[0]["justification"]
    assert ScenarioNarrative(
        supporting_systems_involved=involved).supporting_systems_involved[0].justification == ""
