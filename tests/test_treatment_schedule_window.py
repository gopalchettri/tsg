"""A mitigation window that was SENT but cannot be parsed must not read as "no window sent".

`as_date` answers None for both "absent" and "present but malformed" — correct for the arithmetic,
wrong for the reporting. Two silent failures came out of that conflation:

  * a corrupt `timeline_start_date` produced the warning "no mitigation window supplied", which
    contradicts a register that did supply one, and sent the reviewer looking for a missing input
    rather than a corrupt one;
  * a corrupt `timeline_end_date` switched the deadline-overrun check off entirely — it is gated on
    `deadline is not None` — so an overrunning plan simply looked compliant, with nothing said.

treatment._assessment_window already logs and collapses an unparseable pair before the snapshot is
built, so neither fires through that path today. These pins exist because the scheduler is
deliberately caller-independent: a legacy or hand-edited snapshot row reaching it directly would
otherwise degrade with no trace at all.
"""
from __future__ import annotations

from app.pipeline.treatment_schedule import schedule_remediation_actions


def _plan_with_one_action(days: int = 10) -> dict:
    return {"controls_to_be_implemented": {"control_coverage": "gaps", "controls": []},
            "remediation_action_plan": [{"action_id": "A1", "priority": "High", "depends_on": [],
                                        "duration_days": days, "implements_controls": []}]}


def _schedule(plan: dict, window: dict | None) -> list[str]:
    return schedule_remediation_actions(plan, {"risk_assessment": {"assessment_window": window}})


def test_an_unparseable_start_date_is_named_not_reported_as_a_missing_window():
    plan = _plan_with_one_action()
    warns = _schedule(plan, {"timeline_start_date": "not-a-date",
                             "timeline_end_date": "2026-12-31", "total_days": 92})
    assert any("mitigation window start 'not-a-date' is not a date" in w for w in warns), warns
    # The contradiction that used to ship: the register DID supply a window.
    assert not any("no mitigation window supplied" in w for w in warns), warns
    assert plan["remediation_action_plan"][0]["start_date"] is None


def test_an_unparseable_end_date_says_the_deadline_could_not_be_checked():
    """Previously the overrun check was skipped in total silence, so the plan looked compliant."""
    plan = _plan_with_one_action()
    warns = _schedule(plan, {"timeline_start_date": "2026-10-01",
                             "timeline_end_date": "31/12/2026", "total_days": 92})
    assert any("mitigation window end '31/12/2026' is not a date" in w
               and "could not be checked" in w for w in warns), warns
    # The start date still parsed, so the schedule is anchored even though the deadline is not.
    assert plan["remediation_action_plan"][0]["start_date"] == "2026-10-01"


def test_a_genuinely_absent_window_still_says_so():
    """The other side of the distinction: nothing sent must keep its own, different warning."""
    for empty in (None, {}):
        plan = _plan_with_one_action()
        warns = _schedule(plan, empty)
        assert any("no mitigation window supplied" in w for w in warns), (empty, warns)
        assert not any("is not a date" in w for w in warns), (empty, warns)


def test_a_valid_window_warns_about_neither():
    plan = _plan_with_one_action()
    warns = _schedule(plan, {"timeline_start_date": "2026-10-01",
                             "timeline_end_date": "2026-12-31", "total_days": 92})
    assert warns == [], warns
    assert plan["mitigation_end_date_planned"] == "2026-10-10"
