"""Every worker log line carries its session, and carries the RIGHT one.

Two failures, one mechanism. The first is a partial timeline: "everything for session X" answers
with only the lines whose author remembered to pass session_id by hand — roughly a third of them
in the pipeline — and the answer does not announce itself as partial, so it reads as a complete
story with the interesting minutes missing. Binding once, where every task passes through, is what
makes the other two thirds findable.

The second is what binding introduces if the clear is ever dropped, and it is worse than the bug
it fixes: the worker runs -P gevent and reuses its greenlets, so a session id left bound stamps
the NEXT session's lines with the PREVIOUS session's id. Absent is a gap someone notices; wrong is
a timeline that reads perfectly and describes a run that never happened.

The third guard is narrower and was a real defect: session_id is bound from the task's first
argument, and only when that argument IS a session id. calibrate_grounding's first argument is
`force`, so every calibration log line said session_id="True"; plan_id/action/feed/source were
mislabelled the same way.
"""
import structlog
from structlog.testing import capture_logs

from app.core.logging import get_logger
from app.pipeline import celery_app as ca

#: A real session id, not "s-1": the point of the width check below is that a full 36-character
#: GUID survives every truncation between the bind and the stored row.
_SESSION = "6174f288-2f1e-4b2a-9c51-0d9a7b3e8c44"


def test_session_tasks_bind_their_first_argument():
    assert ca._session_of(ca.run_pipeline_task, ("s-1",)) == "s-1"
    assert ca._session_of(ca.next_set_task, ("s-2", 1, 0, 0)) == "s-2"


def test_non_session_tasks_bind_no_session():
    assert ca._session_of(ca.calibrate_grounding_task, (True,)) is None
    assert ca._session_of(ca.generate_treatment_plan_task, ("plan-1",)) is None
    assert ca._session_of(ca.map_controls_sweep_task, (True,)) is None   # unbound task
    assert ca._session_of(ca.run_pipeline_task, ()) is None
    assert ca._session_of(None, ("x",)) is None


def _lines_from(*, task_id: str, args: tuple):
    """Run one task's worth of logging: bind as the worker does, log WITHOUT passing session_id,
    clear as the worker does. Returns the captured event dicts."""
    with capture_logs(processors=[structlog.contextvars.merge_contextvars]) as entries:
        ca._bind_task_context(task_id=task_id, task=ca.run_pipeline_task, args=args)
        try:
            get_logger("app.pipeline.tasks").info("stage.claimed")
        finally:
            ca._clear_task_context()
    return entries


def test_a_log_call_that_names_no_session_still_carries_the_bound_one():
    """THE PARTIAL-TIMELINE FIX. `stage.claimed` passes no session_id and no task_id — like most
    of the pipeline's log calls — and must still come out tagged with both."""
    line = _lines_from(task_id="task-abc", args=(_SESSION,))[0]

    assert line["session_id"] == _SESSION, (
        "a log call that did not pass session_id came out without one — this is the two thirds of "
        "the pipeline's lines that a session timeline was silently missing")
    assert line["task_id"] == "task-abc"


def test_the_full_guid_survives_the_bind():
    """36 characters against a 100-character column. Asserted rather than assumed because a
    truncated id does not look broken — it looks like a session that has no lines."""
    line = _lines_from(task_id="task-abc", args=(_SESSION,))[0]

    assert len(line["session_id"]) == 36 and line["session_id"] == _SESSION


def test_the_next_task_in_the_same_process_inherits_nothing():
    """THE LEAK, which is worse than the bug it comes from. Greenlets are reused, so a bind that
    is not cleared tags the next session's lines with the previous session's id: a timeline that
    reads perfectly and belongs to a different run."""
    _lines_from(task_id="task-abc", args=(_SESSION,))

    # Second task, no session at all (a plan task): it must be tagged with its OWN task id and
    # with no session, not with the finished run's.
    with capture_logs(processors=[structlog.contextvars.merge_contextvars]) as entries:
        ca._bind_task_context(task_id="task-xyz", task=ca.generate_treatment_plan_task,
                              args=("plan-1",))
        try:
            get_logger("app.pipeline.treatment").info("plan.claimed")
        finally:
            ca._clear_task_context()

    assert entries[0].get("session_id") is None, (
        f"the previous task's session leaked into this one: {entries[0].get('session_id')}")
    assert entries[0]["task_id"] == "task-xyz"


def test_the_context_is_empty_once_the_task_ends():
    """The clear is the whole guard, so pin it directly as well as through its symptom above — a
    symptom test passes just as well if the second bind happens to overwrite the first, which it
    does not for a task that binds no session."""
    ca._bind_task_context(task_id="task-abc", task=ca.run_pipeline_task, args=(_SESSION,))
    ca._clear_task_context()

    assert structlog.contextvars.get_contextvars() == {}
