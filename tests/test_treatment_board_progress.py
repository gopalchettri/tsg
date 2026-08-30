"""The plan board's `progress` roll-up — the remediation counterpart of SessionProgress.

WHY THIS EXISTS. `/v1/sessions/{id}` answers "how is generation going" in one object, so a UI
renders a status line without reading a list. The plan board had no equivalent: it returned a row
per accepted scenario and left every client to fold them. That means each client invents its own
rules for "is planning finished", and two screens can disagree about the same session.

The PRIORITY ORDER is the whole design, and each rule below exists because the obvious
alternative is wrong:

  * error outranks in_progress — a board with one failed and one running plan must surface the
    failure NOW, not once the other finishes;
  * awaiting_review outranks complete — for the same reason SessionProgress does it. Plans that
    are generated but unreviewed are not finished, and calling them complete empties the review
    queue;
  * an empty board is `pending`, not `complete` — "no scenarios accepted yet" folded to complete
    would announce a session as done before any work existed.

_board_progress is pure, so none of this needs a database.
"""
from __future__ import annotations

from app.api.schemas import TreatmentBoardRow
from app.api.treatment import _board_progress
from app.core.enums import TreatmentProgress


def _row(status: str | None = None, review: str | None = None) -> TreatmentBoardRow:
    """One board line. plan_id is None exactly when no plan was ever requested — the same
    coupling the route builds, since a never-requested row has NULL plan columns."""
    return TreatmentBoardRow(scenario_id="s", plan_id=("p" if status else None),
                             status=status, review_status=review)


def test_an_empty_board_is_pending_not_complete():
    """A session with nothing accepted has no planning to do YET. Folding an empty list to
    `complete` would report it as finished before any work existed."""
    assert _board_progress([]).overall == TreatmentProgress.pending


def test_no_plans_requested_is_pending():
    p = _board_progress([_row(), _row()])
    assert p.overall == TreatmentProgress.pending
    assert p.not_requested == 2


def test_some_requested_some_not_is_still_in_progress():
    """The bucket a naive rollup misses: nothing is running, but a scenario has no plan at all,
    so planning is not finished — it is waiting on a human to press Generate."""
    p = _board_progress([_row("COMPLETE", "approved"), _row()])
    assert p.overall == TreatmentProgress.in_progress
    assert (p.not_requested, p.complete) == (1, 1)


def test_a_running_plan_is_in_progress():
    p = _board_progress([_row("RUNNING"), _row("COMPLETE", "approved")])
    assert p.overall == TreatmentProgress.in_progress
    assert p.running == 1


def test_an_error_outranks_a_running_plan():
    """Priority, not counting. Reporting in_progress here would hide the failure until the other
    plan finished — and on a board where the running one never finishes, forever."""
    p = _board_progress([_row("ERROR"), _row("RUNNING")])
    assert p.overall == TreatmentProgress.error
    assert (p.error, p.running) == (1, 1)


def test_generated_but_unreviewed_is_awaiting_review_never_complete():
    """THE review-queue rule. Both plans generated cleanly; nobody has approved or rejected
    either, so the session still owes a human decision."""
    p = _board_progress([_row("COMPLETE"), _row("COMPLETE")])
    assert p.overall == TreatmentProgress.awaiting_review
    assert p.awaiting_review == 2
    assert (p.approved, p.rejected) == (0, 0)


def test_every_plan_reviewed_is_complete_whether_approved_or_rejected():
    """A REJECTED plan is still a decided one. Treating only approvals as done would leave a
    rejected plan sitting in the review queue with nothing left for a reviewer to do."""
    p = _board_progress([_row("COMPLETE", "approved"), _row("COMPLETE", "rejected")])
    assert p.overall == TreatmentProgress.complete
    assert (p.approved, p.rejected, p.awaiting_review) == (1, 1, 0)


def test_the_four_generation_buckets_partition_the_accepted_scenarios():
    """not_requested + running + complete + error must equal the row count: every scenario lands
    in exactly one. The three review buckets deliberately RE-SPLIT `complete`, so they are not
    part of that sum — a client adding all seven would double-count."""
    plans = [_row(), _row("RUNNING"), _row("ERROR"),
             _row("COMPLETE"), _row("COMPLETE", "approved"), _row("COMPLETE", "rejected")]
    p = _board_progress(plans)
    assert p.not_requested + p.running + p.complete + p.error == len(plans)
    assert p.awaiting_review + p.approved + p.rejected == p.complete


def test_the_rollup_reads_the_PRESENTED_status_not_the_stored_one():
    """_present_status projects a STALE RUNNING row to ERROR before the board row is built, and
    this fold consumes that. Reading Risk_Treatment_Plan.Status directly would report a dead
    plan as generating forever — the staleness projection would be defeated one layer up."""
    assert _board_progress([_row("ERROR")]).overall == TreatmentProgress.error
    assert _board_progress([_row("RUNNING")]).overall == TreatmentProgress.in_progress
