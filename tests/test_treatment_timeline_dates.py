"""Remediation timelines are a DEPENDENCY CHAIN OF DURATIONS that TSG schedules — never dates the
model writes.

WHY. The model used to write each action's timeline as an ISO date inside the mitigation window.
With no window it had no anchor (and must not use "today"), so it guessed dates or durations and
nothing checked them; with one, the prompt still told it "timelines stay relative" in another rule.
Now the model supplies only judgement — duration_days and depends_on (earlier actions only) — and
treatment_schedule.schedule_remediation_actions does the arithmetic: start/end offsets, the
critical path, and, only
when the register sent a window, real dates counted from mitigation_start_date. The JSON shape is
the SAME either way: start_date/end_date are null without a window.
"""
from __future__ import annotations

from app.pipeline import prompts
from app.pipeline.treatment_schedule import schedule_remediation_actions as _schedule_actions

_WINDOW = {"timeline_start_date": "2026-10-01", "timeline_end_date": "2026-12-31",
           "total_days": 92}


def _plan(*actions: dict, controls: tuple[str, ...] = ("C1", "C2", "C3")) -> dict:
    return {"controls_to_be_implemented": {"control_coverage": "gaps",
                                           "controls": [{"control_code": c} for c in controls]},
            "remediation_action_plan": [dict(a) for a in actions]}


def _act(aid, days, deps=(), priority="High", codes=()) -> dict:
    return {"action_id": aid, "priority": priority, "depends_on": list(deps),
            "duration_days": days, "implements_controls": list(codes)}


#: The owner-approved example: A1 and A2 start together, A3 waits for A1, A4 for A2 and A3.
_CHAIN = (_act("A1", 14, priority="Critical", codes=["C1"]),
          _act("A2", 10, codes=["C3"]),
          _act("A3", 21, ["A1"], priority="Critical", codes=["C2"]),
          _act("A4", 5, ["A2", "A3"]))


def _schedule(plan: dict, window: dict | None) -> list[str]:
    return _schedule_actions(plan, {"risk_assessment": {"assessment_window": window}})


def test_without_a_window_the_chain_carries_durations_and_null_dates():
    plan = _plan(*_CHAIN)
    warns = _schedule(plan, None)
    rows = plan["remediation_action_plan"]
    assert [r["timeline"] for r in rows] == [
        "14 days", "10 days", "21 days, after A1 completes", "5 days, after A2 and A3 complete"]
    assert all(r["start_date"] is None and r["end_date"] is None for r in rows)
    assert plan["mitigation_timeline"] == "40 days in total (critical path A1 → A3 → A4)"
    assert plan["mitigation_timeline_days"] == 40            # parallel A2 is NOT added
    assert plan["mitigation_end_date_planned"] is None
    assert warns == ["no mitigation window supplied — the 40-day schedule is not bounded by a "
                     "register deadline"]


def test_with_a_window_the_same_chain_is_dated_from_its_start():
    plan = _plan(*_CHAIN)
    assert _schedule(plan, _WINDOW) == []                    # 40 days fits a 92-day window
    rows = plan["remediation_action_plan"]
    assert [(r["start_date"], r["end_date"]) for r in rows] == [
        ("2026-10-01", "2026-10-14"), ("2026-10-01", "2026-10-10"),
        ("2026-10-15", "2026-11-04"), ("2026-11-05", "2026-11-09")]
    # INCLUSIVE: 10-01..10-14 is 14 days, and A3 starts the day after A1 ends.
    assert rows[2]["timeline"] == "2026-10-15 → 2026-11-04 (21 days, after A1 completes)"
    assert plan["mitigation_timeline"] == ("2026-10-01 → 2026-11-09 (40 days, critical path "
                                           "A1 → A3 → A4)")
    assert plan["mitigation_end_date_planned"] == "2026-11-09"


def test_both_cases_publish_the_identical_key_set():
    """Owner rule: one JSON shape — a client never branches on whether dates were sent."""
    bare, dated = _plan(*_CHAIN), _plan(*_CHAIN)
    _schedule(bare, None)
    _schedule(dated, _WINDOW)
    assert set(bare) == set(dated)
    assert [set(r) for r in bare["remediation_action_plan"]] == \
           [set(r) for r in dated["remediation_action_plan"]]


def test_a_plan_that_overruns_the_window_says_by_how_much():
    plan = _plan(_act("A1", 60, codes=["C1", "C2", "C3"]), _act("A2", 45, ["A1"]))
    warns = _schedule(plan, _WINDOW)
    assert warns == ["the plan finishes 2027-01-13, 13 days after the mitigation window closes "
                     "(2026-12-31)"]


def test_a_same_day_window_holds_exactly_one_day_of_work():
    """A 10-01..10-01 window is ONE day (inclusive): a 1-day action fits it, a 2-day one does not.
    The old exclusive arithmetic flagged the 1-day action as an overrun."""
    same_day = {"timeline_start_date": "2026-10-01", "timeline_end_date": "2026-10-01",
                "total_days": 1}
    one = _plan(_act("A1", 1, codes=["C1", "C2", "C3"]))
    assert _schedule(one, same_day) == []
    assert one["remediation_action_plan"][0]["end_date"] == "2026-10-01"
    two = _plan(_act("A1", 2, codes=["C1", "C2", "C3"]))
    assert any("after the mitigation window closes" in w for w in _schedule(two, same_day))


def test_action_plan_stating_a_different_total_is_flagged():
    plan = _plan(*_CHAIN)
    plan["action_plan"] = "A1 (14 days) then A3 (21 days); the whole plan takes 45 days."
    warns = _schedule(plan, _WINDOW)
    assert "action_plan states 14, 21, 45 days but the computed critical path is 40 days" in warns
    plan = _plan(*_CHAIN)
    plan["action_plan"] = "A1 then A3 then A4 - 40 days on the critical path."
    assert _schedule(plan, _WINDOW) == []


def test_a_plan_saved_before_the_schedule_is_served_with_the_same_keys():
    """Read-time lift, stored row untouched: an old plan gets the new keys as null/empty so every
    plan a client receives has one shape."""
    import json

    from app.api.treatment_presenter import _visible_plan
    old = {"title": "T", "mitigation_timeline": "2026-09-28",
           "controls_to_be_implemented": {"control_coverage": "gaps", "controls": []},
           "remediation_action_plan": [{"action_id": "A1", "timeline": "2026-09-28"}]}
    served = _visible_plan(json.dumps(old), "plan-1")
    assert served["mitigation_timeline_days"] is None
    assert served["mitigation_end_date_planned"] is None
    action = served["remediation_action_plan"][0]
    assert action["depends_on"] == [] and action["implements_controls"] == []
    assert action["duration_days"] is None and action["start_date"] is None
    assert action["end_date"] is None and action["timeline"] == "2026-09-28"


def test_missing_chain_fields_are_reported_not_read_silently_as_empty():
    """Plain-JSON mode does not force these fields. Without the warning a dependent action was
    shown running in parallel and the whole plan understated its length, with nothing said."""
    plan = _plan(_act("A1", 14, codes=["C1", "C2", "C3"]),
                 {"action_id": "A2", "priority": "High", "duration_days": 21})
    warns = _schedule(plan, None)
    assert "A2.depends_on is missing — scheduled with no prerequisites" in warns
    assert "A2.implements_controls is missing — treated as delivering no control" in warns
    assert plan["mitigation_timeline_days"] == 21            # still scheduled, as parallel work


def test_dependency_text_and_ids_must_tell_the_same_story():
    text_waits = _plan(_act("A1", 5, codes=["C1", "C2", "C3"]),
                       {**_act("A2", 5), "dependencies": "MFA rollout (A1) must be complete"})
    assert "A2.dependencies mentions A1 but depends_on does not include it" in \
        _schedule(text_waits, None)
    ids_wait = _plan(_act("A1", 5, codes=["C1", "C2", "C3"]),
                     {**_act("A2", 5, ["A1"]), "dependencies": "None"})
    assert "A2.dependencies says None but it waits for A1" in _schedule(ids_wait, None)
    agree = _plan({**_act("A1", 5, codes=["C1", "C2", "C3"]), "dependencies": "None"},
                  {**_act("A2", 5, ["A1"]), "dependencies": "Remote access locked down (A1)"})
    assert not [w for w in _schedule(agree, None) if ".dependencies" in w]


def test_invalid_dependencies_are_dropped_so_no_cycle_can_exist():
    plan = _plan(_act("A1", 5, ["A2"], codes=["C1", "C2", "C3"]),   # forward ref
                 _act("A2", 5, ["A2", "A9", "A1", "A1"]))           # self, unknown, duplicate
    warns = _schedule(plan, None)
    rows = plan["remediation_action_plan"]
    assert rows[0]["depends_on"] == [] and rows[1]["depends_on"] == ["A1"]
    assert sum("is not an earlier action" in w for w in warns) == 3, warns
    assert plan["mitigation_timeline_days"] == 10


def test_bad_durations_are_clamped_and_reported():
    plan = _plan(_act("A1", 0, codes=["C1"]), _act("A2", "ten", codes=["C2"]),
                 _act("A3", True, codes=["C3"]), _act("A4", 99999), _act("A5", "7"))
    warns = _schedule(plan, None)
    days = [r["duration_days"] for r in plan["remediation_action_plan"]]
    assert days == [1, 1, 1, 3650, 7]
    assert sum("scheduled as 1 day" in w for w in warns) == 3 and any("capped" in w for w in warns)


def test_sequence_ids_and_start_order_are_checked():
    plan = _plan(_act("A1", 5, codes=["C1", "C2", "C3"]), _act("A2", 5, ["A1"]),
                 _act("A4", 5))                                       # gap in ids, starts early
    warns = _schedule(plan, None)
    assert any("action ids are not A1..A3" in w for w in warns), warns
    assert any("sequence is out of order" in w for w in warns), warns


def test_every_recommended_control_needs_an_action_and_codes_must_be_real():
    plan = _plan(_act("A1", 5, codes=["C1", "BOGUS"]), controls=("C1", "C2"))
    warns = _schedule(plan, None)
    assert "recommended control C2 is not implemented by any action" in warns
    assert any("'BOGUS', which is not a control of this plan" in w for w in warns)


def test_a_less_urgent_prerequisite_of_urgent_work_is_flagged():
    plan = _plan(_act("A1", 5, priority="Low", codes=["C1", "C2", "C3"]),
                 _act("A2", 5, ["A1"], priority="Critical"))
    warns = _schedule(plan, None)
    assert any("A1 (Low) is a prerequisite of A2 (Critical)" in w for w in warns), warns


def test_the_prompt_asks_for_durations_and_dependencies_never_dates():
    system = prompts.treatment_prompt({})[0]["content"]
    assert "duration_days" in system and "depends_on" in system
    assert "critical path" in system and "assessment_window" in system
    assert "YYYY-MM-DD" not in system and "timelines stay relative" not in system
    schema = prompts.TreatmentPlanGenerated.model_json_schema()
    action = schema["$defs"]["_GeneratedAction"]["properties"]
    assert {"depends_on", "duration_days", "implements_controls"} <= set(action)
    assert "timeline" not in action and "mitigation_timeline" not in schema["properties"]
