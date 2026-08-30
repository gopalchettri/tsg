"""Remediation timelines are ABSOLUTE DATES bounded by the register's own mitigation window.

WHY THIS EXISTS. A real plan (442b4bd2) scheduled work that could not be done. The prompt said
every timeline is "measured from the plan's start (day 0)" and never defined day 0. The window
was 2026-07-01 -> 2026-09-30 and the plan was generated 2026-08-31, so "within 60 days" meant
either 2026-08-30 (already past) or 2026-10-30 (a month past the deadline). BOTH readings failed.

`_window_violations` could not catch it either, and that is the important part: a duration has no
POSITION on a calendar, so the only comparison available was its LENGTH against the window's
length — 60 <= 91 passed, while 61 of those 91 days had already elapsed. That is a property of
the representation, which is why the fix changes what the model EMITS rather than tightening the
check. A date is inside the window or outside it, and there is no origin left to get wrong.

The bounds are the register's own dates and NOT "today": the window is chosen by the risk owner,
so a plan schedules inside it even when part of it has passed. A window opened in the past is a
register-data question for a human, never something to silently re-date around.
"""
from __future__ import annotations

from app.pipeline import prompts
from app.pipeline.treatment import _window_violations

#: The window from the plan that exposed this, and the numbers in the docstring above.
_WINDOW = {"timeline_start_date": "2026-07-01",
           "timeline_end_date": "2026-09-30",
           "total_days": 91}


def _plan(overall: str, *actions: str) -> dict:
    return {"mitigation_timeline": overall,
            "remediation_action_plan": [{"timeline": t} for t in actions]}


def test_the_prompt_demands_iso_dates_and_forbids_durations():
    """The contract itself. Both halves matter: the model must be told the shape AND told that
    the old shape is invalid, or it will keep emitting what it emitted before."""
    system = prompts.treatment_prompt({})[0]["content"]
    assert "YYYY-MM-DD" in system
    assert "ABSOLUTE DATE" in system
    assert "timeline_start_date" in system and "timeline_end_date" in system
    # The phrase that made the old contract unfollowable, and the rule that forbade the fix.
    assert "day 0" not in system
    assert "never used as a timeline value" not in system


def test_dates_inside_the_window_are_silent_including_the_boundaries():
    assert _window_violations(_plan("2026-09-20", "2026-08-15"), _WINDOW) == []
    # end == the closing date and start == the opening date are both INSIDE. An exclusive
    # comparison here would reject the only date a same-day window can ever contain.
    assert _window_violations(_plan("2026-09-30", "2026-07-01"), _WINDOW) == []


def test_a_date_after_the_window_closes_warns():
    """The real failure: 'within 60 days' read from the plan date landed on 2026-10-30."""
    warns = _window_violations(_plan("2026-10-30"), _WINDOW)
    assert any("AFTER" in w and "2026-09-30" in w for w in warns), warns


def test_a_date_before_the_window_opens_warns():
    """The other half of the same ambiguity: read from the window start, 'within 60 days' was
    2026-08-30 — but a plan due before its window even opens is equally undeliverable."""
    warns = _window_violations(_plan("2026-06-15"), _WINDOW)
    assert any("BEFORE" in w and "2026-07-01" in w for w in warns), warns


def test_each_action_is_checked_not_just_the_overall_date():
    """A plan whose overall date fits but whose actions do not is the shape that slipped
    through: the rollup looks compliant while the work inside it is not."""
    warns = _window_violations(_plan("2026-09-30", "2026-08-01", "2026-11-15"), _WINDOW)
    assert len(warns) == 1
    assert "remediation_action_plan[1].timeline" in warns[0]


def test_legacy_relative_durations_still_validate_rather_than_erroring():
    """Plans stored BEFORE this contract carry 'within 60 days', and the evidence endpoint and
    regenerate read them back. A date-only parser would report every historical plan as
    unparsable, so the old length comparison stays as the fallback — reached only when the value
    is not a date."""
    assert _window_violations(_plan("within 60 days"), _WINDOW) == []          # 60 <= 91
    over = _window_violations(_plan("within 120 days"), _WINDOW)               # 120 > 91
    assert any("exceeds" in w and "91 days" in w for w in over), over


def test_a_value_that_is_neither_a_date_nor_a_duration_says_so():
    """Silence here would be the worst outcome: the reviewer would read an unchecked plan as a
    checked one."""
    warns = _window_violations(_plan("as soon as practicable"), _WINDOW)
    assert any("not a date" in w and "could not be checked" in w for w in warns), warns


def test_no_window_supplied_disables_the_check_entirely():
    """mitigation_start/end are optional on the request (both-or-neither), so a plan with no
    window must not be warned about a window it never had."""
    assert _window_violations(_plan("2026-10-30", "2099-01-01"), None) == []
    assert _window_violations(_plan("2026-10-30"), {}) == []
