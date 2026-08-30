"""The register's risk scores are LOAD-BEARING in the treatment plan, not decoration.

The 2026-08-30 contract cross-check found the request's four scoring fields (likelihood_rating,
impact_rating, final_risk_rating, risk_level) plus impacted_business_division were placed in the
snapshot's risk_assessment block and sent to the model — with ZERO prompt instructions referencing
any of them. A Critical/20 and a Low/2 scenario produced plans with no systematic difference, and
rule 4 ("never invent numeric scores") actively discouraged the model from touching the ratings.

These tests pin the fix at both layers so it cannot silently regress:
  * prompt rule 6 instructs the model to calibrate urgency, control emphasis and the rollup
    citation to the risk_assessment block (deleting the rule fails the contract pin);
  * _risk_alignment_warnings flags a Critical/High plan whose output carries no Critical/High
    priority anywhere — the observable symptom of the model ignoring the scores.
"""
from __future__ import annotations

from app.core.enums import ActionPriority, RiskLevel
from app.pipeline import prompts
from app.pipeline.treatment import _risk_alignment_warnings

# ---------------------------------------------------------------------------
# Layer 1 — the prompt contract
# ---------------------------------------------------------------------------

def test_prompt_instructs_every_scoring_field():
    """Every register scoring field the request carries must be NAMED in the system message.
    Presence in the context JSON is not use — this is the pin that failed before the fix."""
    system = prompts.treatment_prompt({})[0]["content"]
    for field in ("risk_level", "likelihood_rating", "impact_rating",
                  "final_risk_rating", "impacted_business_division"):
        assert field in system, f"treatment prompt never instructs the model about {field!r}"


def test_prompt_maps_risk_level_to_urgency_and_ratings_to_control_emphasis():
    """The instruction must be OPERATIVE, not a mention: each risk level maps to a priority
    posture, and the likelihood/impact comparison steers preventive vs detective/corrective."""
    system = prompts.treatment_prompt({})[0]["content"]
    for level in RiskLevel:
        assert f"'{level}'" in system, f"rule 6 does not tell the model what {level} means"
    # LOWERCASE, matching ControlType exactly. This assertion used to require the capitalised
    # forms and so pinned the bug: this rule is the one that decides WHICH type to pick, so the
    # model copied its casing and emitted "Detective", which the vocabulary clamp then rejected
    # ("control_type out of vocabulary: 'Detective'") on a real plan. The FIELDS block builds
    # the allowed values from the enum, so the rule has to agree with it.
    for emphasis in ("preventive", "detective", "corrective"):
        assert emphasis in system, f"rule 6 must name {emphasis!r} in the enum's own casing"
        assert emphasis.capitalize() not in system, (
            f"{emphasis.capitalize()!r} contradicts the vocabulary this same prompt advertises")
    # The rollup must cite the verdict — this is what makes a plan explain its own urgency.
    assert "final_risk_rating" in system and "verbatim" in system


def test_rule4_no_longer_bans_the_supplied_ratings():
    """Rule 4 used to read as a blanket ban on rating labels, which suppressed exactly the
    behaviour rule 6 now requires. It must scope the ban to INVENTED values only."""
    system = prompts.treatment_prompt({})[0]["content"]
    assert "beyond those supplied" in system


# ---------------------------------------------------------------------------
# Layer 2 — the advisory alignment check
# ---------------------------------------------------------------------------

def _plan(*priorities: str) -> dict:
    """A minimal parsed plan whose rows carry the given priorities (first as a control,
    the rest as actions) — the only fields the alignment check reads."""
    first, rest = priorities[0], priorities[1:]
    return {
        "controls_to_be_implemented": {"control_coverage": "gaps",
                                       "controls": [{"priority": first}]},
        "remediation_action_plan": [{"priority": p} for p in rest] or [{"priority": first}],
    }


def test_critical_risk_with_no_urgent_priority_warns():
    warns = _risk_alignment_warnings(
        _plan(str(ActionPriority.low), str(ActionPriority.medium)),
        {"risk_level": str(RiskLevel.critical), "final_risk_rating": 20})
    assert len(warns) == 1 and "Critical" in warns[0], warns


def test_high_risk_with_one_high_priority_is_silent():
    assert _risk_alignment_warnings(
        _plan(str(ActionPriority.low), str(ActionPriority.high)),
        {"risk_level": str(RiskLevel.high), "final_risk_rating": 12}) == []


def test_low_risk_with_relaxed_priorities_is_silent():
    """A Low risk is ALLOWED a relaxed plan — warning here would punish correct behaviour."""
    assert _risk_alignment_warnings(
        _plan(str(ActionPriority.low), str(ActionPriority.low)),
        {"risk_level": str(RiskLevel.low), "final_risk_rating": 2}) == []


def test_legacy_snapshot_without_risk_block_is_silent():
    """Snapshots frozen before risk_assessment existed must not start warning on regenerate."""
    assert _risk_alignment_warnings(_plan(str(ActionPriority.low)), None) == []
    assert _risk_alignment_warnings(_plan(str(ActionPriority.low)), {}) == []


def test_empty_plan_for_a_critical_risk_warns():
    """INTENT REVERSED by the 2026-08-30 audit (C21): an empty plan is the LEAST urgent possible
    response to the HIGHEST risk, so it must warn the loudest — the old `rows and` guard made it
    the only Critical plan that drew no alignment warning at all."""
    empty = {"controls_to_be_implemented": {"control_coverage": "covered", "controls": []},
             "remediation_action_plan": []}
    warns = _risk_alignment_warnings(
        empty, {"risk_level": str(RiskLevel.critical), "final_risk_rating": 25})
    assert len(warns) == 1 and "Critical" in warns[0]


def test_miscased_urgent_priority_does_not_draw_the_alignment_warning():
    """C24: 'HIGH' is a vocabulary defect (the clamp reports it) but it IS urgency — claiming
    'no Critical/High priority' over a casing slip would be factually wrong."""
    assert _risk_alignment_warnings(
        _plan("HIGH"), {"risk_level": str(RiskLevel.critical), "final_risk_rating": 20}) == []


# ---------------------------------------------------------------------------
# Layer 3 — the audit fixes around the alignment check
# ---------------------------------------------------------------------------

def test_prompt_handles_null_ratings_and_empty_library():
    """C1 + C2: rule 6 is conditional on values being present (a legacy snapshot carries nulls,
    and the model must OMIT, never invent), and an empty library_mapped can never be 'covered'."""
    system = prompts.treatment_prompt({})[0]["content"]
    assert "carries non-null" in system
    assert "OMIT it from the plan" in system
    assert "When library_mapped is EMPTY" in system
    # C3 SUPERSEDED: timelines are now ABSOLUTE DATES, so "day 0" is gone — a duration had no
    # origin and so no position on the register's calendar. The contract is pinned in
    # tests/test_treatment_timeline_dates.py; this line asserts the old phrasing cannot return.
    assert "day 0" not in system


def test_zero_day_window_is_enforced_not_disabled():
    """C11/C22: a same-day window yields total_days=0 — the TIGHTEST budget, which the old falsy
    guard treated as 'no window' and switched every overrun check off."""
    from app.pipeline.treatment import _window_violations
    # LEGACY path: a stored pre-dates-contract plan still carries a relative duration, and the
    # total_days comparison is what still catches it.
    plan = {"mitigation_timeline": "within 30 days", "remediation_action_plan": []}
    warns = _window_violations(plan, {"total_days": 0})
    assert any("exceeds" in w for w in warns), warns


def test_hyphenated_durations_parse_and_unparsable_timelines_warn():
    """C23: '30-day' phrasings must not evade the window check, and a timeline the parser cannot
    read at all must SAY so instead of silently passing."""
    from app.pipeline.treatment import _window_violations
    hyphen = {"mitigation_timeline": "a 30-day hardening sprint", "remediation_action_plan": []}
    assert any("exceeds" in w for w in _window_violations(hyphen, {"total_days": 14}))
    prose = {"mitigation_timeline": "as soon as practicable", "remediation_action_plan": []}
    assert any("no parsable duration" in w for w in _window_violations(prose, {"total_days": 14}))


def test_covered_verdict_with_no_library_controls_warns():
    """C2 server half: with zero library-mapped controls, 'covered' is vacuously true — the
    verdict is unverifiable and the reviewer must be told."""
    from app.pipeline.treatment import _coverage_vs_library_warnings
    plan = {"controls_to_be_implemented": {"control_coverage": "covered", "controls": []}}
    assert _coverage_vs_library_warnings(plan, {"existing_controls": {"library_mapped": []}})
    assert _coverage_vs_library_warnings(
        plan, {"existing_controls": {"library_mapped": [{"control_code": "X"}]}}) == []


def test_empty_action_table_draws_a_validation_warning():
    """C21: the prompt mandates a never-empty action plan ('covered' -> verification actions);
    an empty table passing structurally with zero advisories was the quietest failure mode."""
    from app.pipeline.treatment import _validate_plan
    warns = _validate_plan({
        "controls_to_be_implemented": {"control_coverage": "covered", "controls": []},
        "remediation_action_plan": [],
        "applicable_to_all_subsystems": "Yes"})
    assert any("remediation_action_plan is empty" in w for w in warns), warns


def test_dropped_unresolvable_controls_are_reported_not_just_logged():
    """C19: _inject_reserved returns the dropped codes so the finish site can warn the reviewer —
    a server-edited plan must never look untouched."""
    from app.pipeline.treatment import _inject_reserved
    parsed, dropped = _inject_reserved(
        {"controls_to_be_implemented": {"control_coverage": "gaps", "controls": [
            {"control_name": "Real", "control_code": "CII-CID-028"},
            {"control_name": "Invented", "control_code": "NOT-REAL"}]}},
        {"register": {},
         "existing_controls": {"library_mapped": [
             {"control_library_id": 28, "control_code": "CII-CID-028"}]}})
    assert dropped == ["NOT-REAL"]
    kept = parsed["controls_to_be_implemented"]["controls"]
    assert [c["control_code"] for c in kept] == ["CII-CID-028"]


class _StubSess:
    """No-DB stand-in: the library lookup raises, exercising build_treatment_input's documented
    degrade-with-warning fallback, so the register-side logic runs without a database."""

    def rollback(self):
        pass

    def execute(self, *a, **k):
        raise RuntimeError("no db in this test")


_SESSION_ROW = {"AssetName": "Historian", "AssetContextJSON": None, "SubsystemsJSON": None}
_SCENARIO_ROW = {"ScenarioID": "s-1", "ThreatCategory": None, "ThreatType": "Tampering",
                 "ThreatName": "Setpoint tampering", "LibraryThreatType": None,
                 "LibraryThreatName": None, "ThreatActorsJSON": None, "ScenarioJSON": None}


def test_snapshot_advisories_for_inconsistent_scores_and_past_window():
    """C13 + C14 + C15 + C9: build_treatment_input flags a final rating that contradicts
    likelihood x impact and a window already in the past; drops blank register controls and an
    orphan justification."""
    from app.pipeline.treatment import build_treatment_input
    snap = build_treatment_input(
        _StubSess(), _SESSION_ROW, _SCENARIO_ROW,
        {"existing_controls": ["", "  ", "MFA", "MFA"],
         "likelihood_rating": 4, "impact_rating": 5, "final_risk_rating": 18,
         "risk_level": "Critical", "impacted_business_division": None,
         "existing_controls_all_subsystems": None,
         "existing_controls_all_subsystems_justification": "orphan justification",
         "mitigation_start_date": "2020-01-01", "mitigation_end_date": "2020-03-01"})

    joined = " | ".join(snap["warnings"])
    assert "does not equal likelihood x impact (4x5=20)" in joined
    assert "already in the past" in joined
    assert snap["existing_controls"]["register_controls"] == ["MFA"]  # blanks + dupe gone
    assert snap["existing_controls"]["applied_to_all_subsystems_justification"] is None
    assert snap["risk_assessment"]["assessment_window"]["total_days"] == 60


def test_legacy_snapshot_with_no_scores_is_flagged_uncalibrated():
    """C1 warning half: a regenerated pre-scores snapshot must say out loud that the plan is not
    risk-calibrated — the one case where rule 6 deliberately stands down."""
    from app.pipeline.treatment import build_treatment_input
    snap = build_treatment_input(_StubSess(), _SESSION_ROW, _SCENARIO_ROW,
                                 {"existing_controls": []})
    assert any("NOT risk-calibrated" in w for w in snap["warnings"])
