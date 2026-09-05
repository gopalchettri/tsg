"""SessionProgress: the `controls` roll-up, and AWAITING_DECISION published as COMPLETE.

TWO CHANGES, ONE FILE, because they are only safe TOGETHER.

1. `progress.controls` — control mapping is the tail of scenario generation and owns no stage
   row, yet it is the longest step in the pipeline (604s of one 724s run). Scenarios go visible
   before their controls do, so a UI could not tell "still mapping" from "mapped, nothing
   matched". Derived from ControlsMappedAt.

2. The wire says COMPLETE where the stage row says SCENARIOS_AWAITING_DECISION, so `scenarios`
   answers exactly one question: is GENERATION done. The stored value is untouched — every
   claim, sweep predicate and settled-epoch check still keys on it.

   That leaves `overall` to answer the other question: does a human still owe a decision. It
   CANNOT do that from the stage status, because SCENARIOS parks at the barrier permanently
   (accept never rewrites it, deliberately, so decisions stay changeable) — keyed on the stage
   alone, an untouched session and a fully reviewed one report the same value forever. So it is
   derived from the SCENARIO DECISIONS, and the load-bearing assertion in this file is that
   those two sessions come back DIFFERENT.
"""
from __future__ import annotations

from app.api import sessions as sessions_mod
from app.core.enums import ControlMappingStatus, StageStatus
from app.db import dal


def test_awaiting_decision_is_published_as_complete():
    assert sessions_mod._wire_stage_status(StageStatus.AWAITING_DECISION) == "COMPLETE"


def test_every_other_status_is_passed_through_untouched():
    for st in (StageStatus.IDLE, StageStatus.RUNNING, StageStatus.COMPLETE,
               StageStatus.ERROR, StageStatus.CANCELLED):
        assert sessions_mod._wire_stage_status(st) == str(st)


def test_overall_tells_an_unreviewed_session_from_a_fully_reviewed_one():
    """THE point of this field, and the thing a stage-only rollup could never do.

    Both sessions below are `completed` with SCENARIOS parked at the review barrier — that
    stage is NEVER moved off it, because accept deliberately leaves decisions changeable. So
    the ONLY thing separating "nobody has looked at this" from "every scenario decided" is
    whether undecided rows remain.
    """
    at_barrier = (StageStatus.COMPLETE, StageStatus.AWAITING_DECISION, "completed")
    nobody_reviewed = sessions_mod.get_overall_status(*at_barrier, undecided=True)
    all_decided = sessions_mod.get_overall_status(*at_barrier, undecided=False)

    assert str(nobody_reviewed) == "awaiting_review"
    assert str(all_decided) == "complete"
    assert nobody_reviewed != all_decided, (
        "these two sessions must not report the same status — that identity is the bug this "
        "parameter exists to remove, and it is what a stage-only rollup produced")


def test_a_terminal_state_still_outranks_the_review_barrier():
    """Priority order is load-bearing: an error or a cancellation is the answer even when a
    decision is outstanding, or a dead session sits in the review queue forever."""
    at_barrier = (StageStatus.AWAITING_DECISION, "completed")
    assert str(sessions_mod.get_overall_status(
        StageStatus.ERROR, *at_barrier, undecided=True)) == "error"
    assert str(sessions_mod.get_overall_status(
        StageStatus.COMPLETE, StageStatus.AWAITING_DECISION, "cancelled",
        undecided=True)) == "cancelled"


def test_undecided_predicate_turns_off_once_everything_is_decided():
    """The source `undecided` comes from. Keyed on the stage instead, it would read true
    FOREVER — the stage never leaves the barrier — and the review queue would never empty."""
    assert dal.has_undecided_scenarios(_CountSession(3), "s") is True   # 3 still undecided
    assert dal.has_undecided_scenarios(_CountSession(0), "s") is False  # all decided -> empties


def test_the_stored_value_is_untouched():
    """The mapping is presentation-only. Every claim, sweep predicate and settled-epoch check
    keys on the stored string; if this enum member's VALUE ever changes, the review barrier
    moves in the database and this file is the wrong place to find out."""
    assert StageStatus.AWAITING_DECISION.value == "SCENARIOS_AWAITING_DECISION"
    assert StageStatus.COMPLETE.value == "COMPLETE"


class _FakeResult:
    def __init__(self, row):
        self._row = row

    def one(self):
        return self._row

    def scalar_one(self):
        return self._row


class _CountSession:
    """Returns one scalar count — the shape has_undecided_scenarios selects."""

    def __init__(self, undecided):
        self._n = undecided

    def execute(self, *_a, **_k):
        return _FakeResult(self._n)


class _FakeSession:
    """Returns one (total, mapped, exhausted) aggregate — the shape control_mapping_progress
    selects. `exhausted` defaults to 0 so every pre-existing PENDING/RUNNING/COMPLETE case here
    can stay written as a plain (total, mapped) pair."""

    def __init__(self, total, mapped, exhausted=0):
        self._row = (total, mapped, exhausted)

    def execute(self, *_a, **_k):
        return _FakeResult(self._row)


def test_controls_progress_covers_the_three_non_error_states():
    cases = [
        ((0, 0), ControlMappingStatus.PENDING),   # no scenarios yet
        ((6, 0), ControlMappingStatus.PENDING),   # written, none mapped
        ((6, 2), ControlMappingStatus.RUNNING),   # mid-flight — the 10-minute window
        ((6, 6), ControlMappingStatus.COMPLETE),  # safe to render the finished card
    ]
    for (total, mapped), expected in cases:
        got = dal.control_mapping_progress(_FakeSession(total, mapped), "sess-1")
        assert got == str(expected), f"total={total} mapped={mapped}: {got} != {expected}"


def test_a_null_sum_is_treated_as_pending_not_complete():
    """SUM() over zero rows is NULL, not 0. Coercing that to COMPLETE would tell a client the
    card is ready before a single scenario exists."""
    assert dal.control_mapping_progress(_FakeSession(0, None, None), "s") == str(
        ControlMappingStatus.PENDING)


def test_exhausted_outranks_running_and_complete_alike():
    """Priority order is load-bearing here too, same discipline get_overall_status uses above: a
    scenario stuck past its fast retry budget must be surfaced as ERROR even while OTHER
    scenarios in the same session are still mid-flight or every one of them is otherwise mapped —
    an operator needs to see it now, not once the rest of the session finishes."""
    assert dal.control_mapping_progress(_FakeSession(6, 2, 1), "s") == str(ControlMappingStatus.ERROR)
    assert dal.control_mapping_progress(_FakeSession(6, 6, 1), "s") == str(ControlMappingStatus.ERROR)
