"""Worker log lines carry session_id only when the task's first argument IS a session id.

calibrate_grounding's first argument is `force`, so every calibration log line said
session_id="True"; plan_id/action/feed/source were mislabelled the same way."""
from app.pipeline import celery_app as ca


def test_session_tasks_bind_their_first_argument():
    assert ca._session_of(ca.run_pipeline_task, ("s-1",)) == "s-1"
    assert ca._session_of(ca.next_set_task, ("s-2", 1, 0, 0)) == "s-2"


def test_non_session_tasks_bind_no_session():
    assert ca._session_of(ca.calibrate_grounding_task, (True,)) is None
    assert ca._session_of(ca.generate_treatment_plan_task, ("plan-1",)) is None
    assert ca._session_of(ca.map_controls_sweep_task, (True,)) is None   # unbound task
    assert ca._session_of(ca.run_pipeline_task, ()) is None
    assert ca._session_of(None, ("x",)) is None
