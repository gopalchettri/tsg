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
    for emphasis in ("Preventive", "Detective", "Corrective"):
        assert emphasis in system
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


def test_empty_plan_rows_do_not_warn():
    """A plan whose tables are empty already draws the structural error elsewhere
    (_validate_plan) — the alignment check must not pile a second warning onto it."""
    empty = {"controls_to_be_implemented": {"control_coverage": "covered", "controls": []},
             "remediation_action_plan": []}
    assert _risk_alignment_warnings(
        empty, {"risk_level": str(RiskLevel.critical), "final_risk_rating": 25}) == []
