"""SessionProgress: the `controls` roll-up, and AWAITING_DECISION published as COMPLETE.

TWO CHANGES, ONE FILE, because they are only safe TOGETHER.

1. `progress.controls` — control mapping is the tail of scenario generation and owns no stage
   row, yet it is the longest step in the pipeline (604s of one 724s run). Scenarios go visible
   before their controls do, so a UI could not tell "still mapping" from "mapped, nothing
   matched". Derived from ControlsMappedAt.

2. The wire now says COMPLETE where the stage row says SCENARIOS_AWAITING_DECISION, and — by a
   second operator decision — `overall` reports `complete` for that state too, instead of
   `awaiting_review`. AWAITING_DECISION *is* the review barrier, so with BOTH published fields
   reading COMPLETE, nothing on the wire could tell "generated and undecided" from "reviewed and
   finished": a review queue would come back empty.

   `progress.awaiting_decision` is the field that keeps that distinction, and it is therefore the
   load-bearing assertion in this file — not the rename. It must be derived from the RAW stage
   status: reading the published value would make it False for exactly the sessions it exists to
   find. The stored value is likewise untouched, because every claim, sweep predicate and
   settled-epoch check still keys on it.
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


def test_overall_now_reports_complete_at_the_review_barrier():
    """Operator decision: `overall` no longer reports awaiting_review — a session at the review
    barrier rolls up as `complete`, matching the `scenarios` field."""
    overall = sessions_mod.get_overall_status(
        StageStatus.COMPLETE, StageStatus.AWAITING_DECISION, "completed")
    assert str(overall) == "complete"
    assert sessions_mod._wire_stage_status(StageStatus.AWAITING_DECISION) == "COMPLETE"


def test_awaiting_decision_is_the_surviving_review_queue_signal():
    """THE regression the change above could cause, and the field that now prevents it.

    With `overall` and `scenarios` BOTH reporting COMPLETE at the review barrier, neither can
    tell "generated and undecided" from "reviewed and finished". A review queue built on either
    would come back EMPTY — the failure get_overall_status's old ordering existed to avoid. The
    boolean is the whole safety net, so it must be derived from the RAW status: reading the
    published value would make it False for exactly the sessions it needs to find.
    """
    raw_at_barrier = StageStatus.AWAITING_DECISION
    assert sessions_mod._wire_stage_status(raw_at_barrier) == "COMPLETE"   # published
    assert (raw_at_barrier == StageStatus.AWAITING_DECISION) is True       # what the flag reads
    # A finished session must NOT set it, or every session looks like it needs review.
    assert (StageStatus.COMPLETE == StageStatus.AWAITING_DECISION) is False


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


class _FakeSession:
    """Returns one (total, mapped) aggregate — the shape control_mapping_progress selects."""

    def __init__(self, total, mapped):
        self._row = (total, mapped)

    def execute(self, *_a, **_k):
        return _FakeResult(self._row)


def test_controls_progress_covers_the_three_states():
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
    assert dal.control_mapping_progress(_FakeSession(0, None), "s") == str(
        ControlMappingStatus.PENDING)
