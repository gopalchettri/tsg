"""The plan board's `progress` roll-up — the remediation counterpart of SessionProgress.

WHY THIS EXISTS. `/v1/sessions/{id}` answers "how is generation going" in one object, so a UI
renders a status line without reading a list. The plan board had no equivalent: it returned a row
per accepted scenario and left every client to fold them. That means each client invents its own
rules for "is planning finished", and two screens can disagree about the same session.

The PRIORITY ORDER is the whole design, and each rule below exists because the obvious
alternative is wrong:

  * error outranks generating — a board with one failed and one running plan must surface the
    failure NOW, not once the other finishes;
  * awaiting_review outranks approved — for the same reason SessionProgress does it. Plans that
    are generated but unreviewed are not finished, and calling them done empties the review
    queue;
  * REJECTED IS ITS OWN STATE, not folded into approved — regenerate operates on the active
    version whatever its verdict, so a rejected plan is work still outstanding. Folding it away
    would hide the one state that needs a person to act;
  * an empty board is `pending`, not `approved` — "no scenarios accepted yet" folded to done
    would announce a session finished before any work existed.

Every overall value names a state of the real flow AND the action it implies, so the tests below
double as the UI's switch table: pending -> Generate, generating -> spinner, awaiting_review ->
Review, rejected -> Regenerate, approved -> done, error -> Retry.

_board_progress is pure, so none of this needs a database.
"""
from __future__ import annotations

from app.api.schemas import TreatmentBoardRow
from app.api.treatment import _board_progress
from app.core.enums import TreatmentProgress, TreatmentStageStatus

PENDING, RUNNING = TreatmentStageStatus.PENDING, TreatmentStageStatus.RUNNING
COMPLETE, ERROR = TreatmentStageStatus.COMPLETE, TreatmentStageStatus.ERROR


def _row(status: str | None = None, review: str | None = None) -> TreatmentBoardRow:
    """One board line. plan_id is None exactly when no plan was ever requested — the same
    coupling the route builds, since a never-requested row has NULL plan columns."""
    return TreatmentBoardRow(scenario_id="s", plan_id=("p" if status else None),
                             status=status, review_status=review)


def test_an_empty_board_is_pending_not_complete():
    """A session with nothing accepted has no planning to do YET. Folding an empty list to
    COMPLETE would report it finished before any work existed."""
    p = _board_progress([])
    assert (p.generation, p.review, p.overall) == (PENDING, PENDING, TreatmentProgress.pending)


def test_no_plans_requested_is_pending():
    p = _board_progress([_row(), _row()])
    assert (p.generation, p.review, p.overall) == (PENDING, PENDING, TreatmentProgress.pending)


def test_a_scenario_with_no_plan_keeps_GENERATION_unfinished():
    """THE case a naive fold gets wrong. Nothing is running and the one plan that exists is
    approved — but another accepted scenario has no plan at all, so generation is not done.
    Reporting COMPLETE here would tell the UI to stop offering Generate."""
    p = _board_progress([_row("COMPLETE", "approved"), _row()])
    assert p.generation == RUNNING
    assert p.overall == TreatmentProgress.generating


def test_generating_is_running_and_review_stays_pending():
    """Review is PENDING while generation is in flight — there is nothing to review yet."""
    p = _board_progress([_row("RUNNING"), _row("RUNNING")])
    assert (p.generation, p.review) == (RUNNING, PENDING)
    assert p.overall == TreatmentProgress.generating


def test_a_failure_shows_as_ERROR_and_outranks_everything():
    """Priority, not counting: one failed plan beside a healthy approved one must surface the
    failure now. Reporting COMPLETE would bury it."""
    p = _board_progress([_row("ERROR"), _row("COMPLETE", "approved")])
    assert p.generation == ERROR
    assert p.overall == TreatmentProgress.error


def test_generated_but_unreviewed_is_review_PENDING_and_awaiting_review():
    """Generation is finished; the humans are not. This is the review-queue state, and the
    reason `overall` is not simply `complete` once the machine's work ends."""
    p = _board_progress([_row("COMPLETE"), _row("COMPLETE")])
    assert (p.generation, p.review) == (COMPLETE, PENDING)
    assert p.overall == TreatmentProgress.awaiting_review


def test_partially_reviewed_is_still_pending():
    """One decided, one not. Review is all-or-nothing: a half-reviewed session must not drop
    off the queue while a plan still needs a decision."""
    p = _board_progress([_row("COMPLETE", "approved"), _row("COMPLETE")])
    assert p.review == PENDING
    assert p.overall == TreatmentProgress.awaiting_review


def test_a_rejection_is_its_own_state_not_folded_into_approved():
    """THE state a generic "complete" would hide. Both plans are decided, so REVIEW is done —
    but regenerate operates on the active version whatever its verdict, so a rejected plan is
    work still outstanding and the UI must offer Regenerate, not call the session finished."""
    p = _board_progress([_row("COMPLETE", "approved"), _row("COMPLETE", "rejected")])
    assert (p.generation, p.review) == (COMPLETE, COMPLETE)
    assert p.overall == TreatmentProgress.rejected, "a rejection must not read as done"


def test_every_plan_approved_is_the_only_terminal_success():
    p = _board_progress([_row("COMPLETE", "approved"), _row("COMPLETE", "approved")])
    assert (p.generation, p.review) == (COMPLETE, COMPLETE)
    assert p.overall == TreatmentProgress.approved


def test_every_lifecycle_state_is_reachable():
    """The enum must describe the real flow, not aspire to it: a value nothing can produce is a
    promise to a UI that will never be kept."""
    reached = {
        _board_progress([]).overall,
        _board_progress([_row("RUNNING")]).overall,
        _board_progress([_row("COMPLETE")]).overall,
        _board_progress([_row("COMPLETE", "rejected")]).overall,
        _board_progress([_row("COMPLETE", "approved")]).overall,
        _board_progress([_row("ERROR")]).overall,
    }
    assert reached == set(TreatmentProgress)


def test_review_is_never_RUNNING():
    """A person either has decided or has not — there is no in-flight review, so the stage only
    ever reports PENDING or COMPLETE. RUNNING here would imply a machine step that does not
    exist."""
    for plans in ([], [_row()], [_row("RUNNING")], [_row("ERROR")],
                  [_row("COMPLETE")], [_row("COMPLETE", "approved")]):
        assert _board_progress(plans).review in (PENDING, COMPLETE)


def test_the_fold_reads_the_PRESENTED_status_not_the_stored_one():
    """_present_status projects a STALE RUNNING row to ERROR before the board row is built, and
    this fold consumes that. Reading Risk_Treatment_Plan.Status directly would report a dead
    plan as generating forever — defeating the staleness projection one layer up."""
    assert _board_progress([_row("ERROR")]).generation == ERROR
    assert _board_progress([_row("RUNNING")]).generation == RUNNING


# ---------------------------------------------------------------------------
# The SAME fold, over one scenario — GET .../scenarios/{id}/treatment-plan
# ---------------------------------------------------------------------------

def test_one_plan_folds_through_the_same_function_as_the_board():
    """The per-scenario screen and the board must never disagree about one plan, so both go
    through _progress_of. Duplicating the priority order into a second place is exactly how two
    screens drift apart — this asserts the single-plan answer IS the board answer for the same
    row, rather than merely resembling it."""
    from app.api.treatment import _progress_of
    one = ("plan-1", "COMPLETE", None)
    assert _progress_of([one]) == _board_progress([_row("COMPLETE")])
    assert _progress_of([one]).overall == TreatmentProgress.awaiting_review


def test_a_single_plans_lifecycle_covers_its_reachable_states():
    """`pending` is absent on purpose: the single-plan GET 404s when no plan exists, so a
    per-scenario response can never carry it. The other five are all reachable."""
    from app.api.treatment import _progress_of
    got = {
        _progress_of([("p", "RUNNING", None)]).overall,
        _progress_of([("p", "COMPLETE", None)]).overall,
        _progress_of([("p", "COMPLETE", "rejected")]).overall,
        _progress_of([("p", "COMPLETE", "approved")]).overall,
        _progress_of([("p", "ERROR", None)]).overall,
    }
    assert got == set(TreatmentProgress) - {TreatmentProgress.pending}


# ---------------------------------------------------------------------------
# GET .../treatment-plan/status — the cheap poll
# ---------------------------------------------------------------------------

def test_the_status_endpoint_is_registered_for_entity_scoped_auth():
    """create_app() refuses to boot if a live route is in neither registry, so a missing entry
    is a hard failure rather than an unauthenticated endpoint. Asserted explicitly because the
    consequence of getting it wrong is a data leak, not a 500."""
    from app.api.route_audit import _ENTITY_SCOPED_ROUTES
    assert ("GET",
            "/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/status"
            ) in _ENTITY_SCOPED_ROUTES


def test_the_status_query_carries_no_plan_or_scenario_blob():
    """THE reason this endpoint exists. active_plan_row hauls PlanJSON, ScenarioJSON and the
    whole threat join — tens of KB re-downloaded on every tick of a poll that reads three
    strings. plan_status_row must select plan-table columns only; adding a blob here silently
    turns the cheap poll back into the expensive one."""
    import ast
    import inspect

    from app.db import dal
    # The DOCSTRING names the blobs it deliberately avoids, so scanning raw source would match
    # its own explanation. Strip it and scan the executable body only.
    tree = ast.parse(inspect.getsource(dal.plan_status_row).lstrip())
    fn = tree.body[0]
    body = fn.body[1:] if ast.get_docstring(fn) else fn.body
    code = " ".join(ast.dump(n) for n in body)
    for blob in ("PlanJSON", "ScenarioJSON", "ValidationJSON", "InputSnapshotJSON",
                 "Identified_Threat", "scenario_threat_columns"):
        assert blob not in code, f"{blob} would make the status poll expensive again"


def test_status_and_board_agree_because_they_share_one_fold():
    """The per-scenario poll and the session board must never disagree about one plan. Both go
    through _progress_of, so this asserts they are the SAME answer rather than two
    implementations that happen to match today."""
    from app.api.treatment import _progress_of
    for status, review in (("RUNNING", None), ("COMPLETE", None),
                           ("COMPLETE", "approved"), ("COMPLETE", "rejected"), ("ERROR", None)):
        assert _progress_of([("p", status, review)]) == _board_progress([_row(status, review)])
