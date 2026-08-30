"""SessionProgress: the `controls` roll-up, and AWAITING_DECISION published as COMPLETE.

TWO CHANGES, ONE FILE, because they are only safe TOGETHER.

1. `progress.controls` — control mapping is the tail of scenario generation and owns no stage
   row, yet it is the longest step in the pipeline (604s of one 724s run). Scenarios go visible
   before their controls do, so a UI could not tell "still mapping" from "mapped, nothing
   matched". Derived from ControlsMappedAt.

2. The wire now says COMPLETE where the stage row says SCENARIOS_AWAITING_DECISION. That is a
   deliberate operator decision, and the DANGER is obvious: AWAITING_DECISION *is* the review
   barrier, so if the rename leaked into `overall` — or into the stored value — the API would
   announce a finished session while a human decision was still outstanding.

So the load-bearing assertion here is not that scenarios reads COMPLETE. It is that `overall`
STILL reads awaiting_review at the same moment, and that nothing about the stored status moved.
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


def test_the_review_barrier_is_not_erased_by_the_rename():
    """THE regression this whole change could cause.

    `overall` must still say awaiting_review while the scenarios field says COMPLETE — that is
    the ONLY remaining signal that a human decision is owed. It is computed from the RAW stage
    statuses; deriving it from the wire value instead would report `complete` and tell a client
    the assessment is finished.
    """
    overall = sessions_mod.get_overall_status(
        StageStatus.COMPLETE, StageStatus.AWAITING_DECISION, "active")
    assert str(overall) == "awaiting_review", (
        "renaming the wire value must not change what `overall` reports — a session awaiting a "
        "human decision would otherwise be announced as finished")
    # And the two fields genuinely disagree, which is the point: one describes the STAGE, the
    # other the SESSION.
    assert sessions_mod._wire_stage_status(StageStatus.AWAITING_DECISION) == "COMPLETE"


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
