"""Seven confirmed defects in the remediation scheduler, one pin each.

All seven shipped while the whole suite was green, and they were found by reading the module
adversarially rather than by any test failing. Two of them are why this file exists at all:

  * a repeated `action_id` made an action its OWN prerequisite and the critical-path walk SPUN
    FOREVER inside `treatment.run_treatment_generation`'s try — so no `except` ran, the LLM spend
    was already committed, and the Celery worker slot and Session were held until the lease expired;
  * an anchor near the end of the calendar raised `OverflowError` out of a module whose stated
    posture is "repairs, never blocks", parking the row ERROR after the spend, unrecoverably,
    because a regenerate on the same snapshot overflowed identically.

Nothing upstream prevents either input. `_GeneratedAction.action_id` is a plain `str`, JSON-schema
strict mode cannot express cross-item uniqueness, `treatment._validate_plan` checks table presence
and vocabularies only, and `mitigation_start_date` is an unbounded pydantic `date`.

These are pure-data tests: no Session, no LLM, no fixtures — which is the reason the scheduler was
extracted into its own module in the first place.
"""
from __future__ import annotations

from datetime import date

import pytest

from app.pipeline.treatment_schedule import (
    collect_window_gap_warnings,
    normalize_action_dependencies,
    schedule_remediation_actions,
)

_WINDOW = {"timeline_start_date": "2026-10-01", "timeline_end_date": "2026-12-31",
           "total_days": 92}


def _action(action_id: str, days: int, deps=(), **extra) -> dict:
    act = {"action_id": action_id, "priority": "High", "duration_days": days,
           "depends_on": list(deps), "implements_controls": []}
    act.update(extra)
    return act


def _plan(*actions: dict, coverage: str = "gaps", controls=()) -> dict:
    return {"controls_to_be_implemented": {"control_coverage": coverage,
                                        "controls": list(controls)},
            "remediation_action_plan": list(actions)}


def _run(plan: dict, window: dict | None = None, snapshot: dict | None = None) -> list[str]:
    snap = dict(snapshot or {})
    snap["risk_assessment"] = {"assessment_window": window or {}}
    return schedule_remediation_actions(plan, snap)


# --- BLOCKER: a repeated action_id ---------------------------------------------------------------
def test_a_repeated_action_id_cannot_make_an_action_its_own_prerequisite() -> None:
    """The hang. `earlier` held IDS, so the second A1's reference to "A1" passed the is-it-earlier
    test and `via[A1] == A1`; the walk had no cycle guard.

    If this regresses it now RAISES rather than hanging (both the offsets pass and the walk assert a
    strictly smaller position), because a wrong answer is recoverable and a hung worker is not."""
    deps, warnings = normalize_action_dependencies(
        [_action("A1", 14), _action("A1", 10, ("A1",))],
        ["A1", "A1"], ["A1", "A1"])
    # NOTHING, never itself — and never the OTHER action of the same name either. With a repeated
    # id the position lookup would happily resolve "A1" to index 0, which terminates but invents a
    # dependency the model never unambiguously stated; the self-reference is dropped first.
    assert deps == [[], []], deps
    assert any("already used by remediation_action_plan[0]" in w for w in warnings), warnings
    assert any("'A1' is not an earlier action" in w for w in warnings), warnings

    plan = _plan(_action("A1", 14), _action("A1", 10, ("A1",)))
    out = _run(plan, _WINDOW)              # must simply return
    assert plan["mitigation_timeline_days"] == 14
    assert any("already used" in w for w in out), out


def test_a_repeated_action_id_does_not_understate_the_critical_path() -> None:
    """The silent half: the duplicate OVERWROTE the first action's finish offset, so A2 was
    scheduled off day 10 instead of day 14 and the stored total was 15 for a plan whose longest
    chain is 19. The only warning was the cosmetic id-order one, so corrupted arithmetic read as a
    naming nit."""
    plan = _plan(_action("A1", 14), _action("A1", 10), _action("A2", 5, ("A1",)))
    out = _run(plan, _WINDOW)
    assert plan["mitigation_timeline_days"] == 19, plan["mitigation_timeline"]
    assert plan["remediation_action_plan"][2]["start_date"] == "2026-10-15"   # day 14, inclusive
    assert any("already used" in w for w in out), out


def test_the_first_action_to_carry_an_id_owns_it() -> None:
    """The stated rule, pinned so it cannot drift into "whichever one": a reference to a repeated id
    resolves to the FIRST holder, and the later one is simply unreferenceable."""
    plan = _plan(_action("A1", 14), _action("A1", 3), _action("A2", 5, ("A1",)))
    _run(plan, _WINDOW)
    assert plan["remediation_action_plan"][2]["depends_on"] == ["A1"]
    assert plan["remediation_action_plan"][2]["timeline"].startswith("2026-10-15")


# --- BLOCKER-adjacent: the calendar edge ---------------------------------------------------------
def test_a_far_future_window_returns_a_plan_and_a_warning_instead_of_raising() -> None:
    """`OverflowError: date value out of range` used to propagate out of the scheduler and park the
    plan ERROR after the LLM spend was committed. Repairs, never blocks."""
    plan = _plan(_action("A1", 3650), _action("A2", 3650, ("A1",)))
    out = _run(plan, {"timeline_start_date": "9999-10-01", "timeline_end_date": "9999-12-31"})
    assert any("runs past the last representable date" in w for w in out), out
    assert plan["mitigation_timeline_days"] == 7300
    assert plan["remediation_action_plan"][1]["end_date"] == date.max.isoformat()


def test_an_ordinary_window_warns_nothing_about_the_calendar() -> None:
    """The other side: the clamp must not fire on a normal plan, or the warning becomes noise."""
    plan = _plan(_action("A1", 14), _action("A2", 21, ("A1",)))
    out = _run(plan, _WINDOW)
    assert not any("representable" in w for w in out), out


# --- a window with only one usable half ----------------------------------------------------------
@pytest.mark.parametrize("window, expect", [
    ({"timeline_end_date": "2026-12-31"}, "no start date"),
    ({"timeline_start_date": "2026-10-01"}, "no end date"),
    ({"timeline_start_date": "not-a-date", "timeline_end_date": "2026-12-31"}, "'not-a-date'"),
    ({"timeline_start_date": "2026-10-01", "timeline_end_date": "31/12/2026"}, "'31/12/2026'"),
])
def test_a_half_usable_window_is_always_reported(window: dict, expect: str) -> None:
    """Both halves used to fall through every reporting path: the "no window supplied" branch was
    suppressed because SOMETHING was sent, the overrun check could not run because one side was
    None, and the malformed-value warning only fired for a value that was present. A 400-day plan
    against an end-date-only window returned the SAME empty warning list as a clean 40-day plan
    inside its window."""
    out = _run(_plan(_action("A1", 400)), window)
    assert any(expect in w for w in out), (window, out)
    assert not any("no mitigation window supplied" in w for w in out), out


def test_a_genuinely_absent_window_keeps_its_own_distinct_warning() -> None:
    """The distinction the half-window fix must not erase."""
    for empty in (None, {}):
        out = _run(_plan(_action("A1", 40)), empty)
        assert any("no mitigation window supplied" in w for w in out), (empty, out)
        assert collect_window_gap_warnings(empty or {}, None, None) == []


def test_a_fully_usable_window_warns_about_neither_half() -> None:
    assert collect_window_gap_warnings(_WINDOW, date(2026, 10, 1), date(2026, 12, 31)) == []


# --- warning text that described the wrong defect ------------------------------------------------
@pytest.mark.parametrize("raw", ["A1", {"after": "A1"}, 7])
def test_a_depends_on_that_is_not_a_list_names_the_value_it_rejected(raw) -> None:
    """One message served two states. A string `depends_on: "A1"` was reported as "is missing", so a
    reviewer went looking for an omitted field and could not learn that a STATED prerequisite had
    been thrown away — and the stored total was 5 where the declared chain was 10."""
    plan = _plan(_action("A1", 5), _action("A2", 5, depends_on=raw))
    out = _run(plan, _WINDOW)
    assert any("is not a list of action ids" in w and repr(raw) in w for w in out), out
    assert not any("depends_on is missing" in w for w in out), out


def test_an_absent_depends_on_still_says_missing() -> None:
    """The other side of that split: genuinely absent keeps the original wording."""
    second = _action("A2", 5)
    del second["depends_on"]
    out = _run(_plan(_action("A1", 5), second), _WINDOW)
    assert any("A2.depends_on is missing" in w for w in out), out


def test_a_repeated_bad_reference_warns_exactly_once() -> None:
    """De-duplication was done against the ACCEPTED list, which an invalid reference never joins, so
    each repetition re-warned. The warning list is persisted into ValidationJSON and its LENGTH is
    what the audit row records, so one model slip inflated the reviewer's evidence N-fold."""
    plan = _plan(_action("A1", 5), _action("A2", 5, ("A9", "A9", "A9")))
    out = _run(plan, _WINDOW)
    unknown = [w for w in out if "'A9' is not an earlier action" in w]
    assert len(unknown) == 1, unknown


def test_every_warning_for_a_blank_action_id_names_the_same_row() -> None:
    """Control warnings fell back to a bare integer while duration and dependency warnings used the
    positional placeholder, so one row was called both `remediation_action_plan[0]` and `0` — a
    reviewer could not tie them together, and `0.` reads like a code prefix."""
    blank = _action("", 5)
    blank["implements_controls"] = None
    out = _run(_plan(blank, _action("A2", 5)), _WINDOW)
    control = [w for w in out if "implements_controls is missing" in w]
    assert control and control[0].startswith("remediation_action_plan[0]."), control
    assert not any(w.startswith("0.") for w in out), out


# --- the coverage gate the docstring promised and the code never applied -------------------------
_LIB = {"existing_controls": {"library_mapped": [{"control_code": "LIB1"}]}}
_RECOMMENDED = ({"control_code": "C1"},)


def test_a_gaps_plan_may_not_deliver_an_already_mapped_control() -> None:
    """`known` unioned library_mapped in UNCONDITIONALLY while the docstring stated the rule as
    "or (coverage 'covered') one it verifies from library_mapped". A 'gaps' plan exists because
    something is NOT covered, so an action pointing at an already-mapped control is the defect —
    and it shipped in silence."""
    plan = _plan(_action("A1", 5, implements_controls=["C1", "LIB1"]),
                 coverage="gaps", controls=_RECOMMENDED)
    out = _run(plan, _WINDOW, _LIB)
    assert any("names 'LIB1', which is not a control of this plan" in w for w in out), out


def test_a_covered_plan_may_verify_an_already_mapped_control() -> None:
    """The gate's other side, which is the whole reason it is conditional: a 'covered' plan pivots
    to verification, so naming a library_mapped control is exactly right."""
    plan = _plan(_action("A1", 5, implements_controls=["LIB1"]),
                 coverage="covered", controls=())
    out = _run(plan, _WINDOW, _LIB)
    assert not any("LIB1" in w for w in out), out
