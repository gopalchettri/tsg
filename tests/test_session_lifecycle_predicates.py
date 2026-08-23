"""The two predicates the scenario-lifecycle change made load-bearing.

Generation now COMPLETES the session at its review barrier so the asset is released while a
reviewer decides scenario by scenario. That makes "SessionStatus == completed" stop meaning
"finished with this session", and two places had encoded exactly that assumption:

  * `get_overall_status` reported every awaiting-decision session as `complete`, emptying the
    review queue.
  * `_stream_still_open` closed the SSE stream the instant generation ended — precisely when the
    review UI opens.

Both are covered directly here because neither had any test of its own: `get_overall_status` had
none at all, and every SSE test monkeypatches `_stream_still_open` wholesale, so its body was
never executed by the suite. A regression in either is silent in production.
"""
from __future__ import annotations

import pytest

from app.api.sessions import get_overall_status
from app.core.enums import (
    SessionStatus,
    StageStatus,
    SubsystemProgress,
    WorkflowStage,
)
from app.pipeline.accept import review_gate_reason

_DONE = str(StageStatus.COMPLETE)
_AWAIT = str(StageStatus.AWAITING_DECISION)


@pytest.mark.parametrize(("threats", "scenarios", "status", "expected"), [
    # THE regression: completed + still awaiting a decision must read as awaiting_review.
    (_DONE, _AWAIT, SessionStatus.completed, SubsystemProgress.awaiting_review),
    # A cancelled session is terminal even at the barrier — cancel outranks everything but error.
    (_DONE, _AWAIT, SessionStatus.cancelled, SubsystemProgress.cancelled),
    # An errored stage still wins outright, decision pending or not.
    (str(StageStatus.ERROR), _AWAIT, SessionStatus.completed, SubsystemProgress.error),
    # Legacy shape: completed with no decision outstanding (pre-lifecycle APPROVED rows).
    (_DONE, _DONE, SessionStatus.completed, SubsystemProgress.complete),
    # Mid-generation.
    (_DONE, str(StageStatus.RUNNING), SessionStatus.active, SubsystemProgress.in_progress),
    (str(StageStatus.IDLE), str(StageStatus.IDLE), SessionStatus.active, SubsystemProgress.pending),
])
def test_overall_status_rollup(threats, scenarios, status, expected) -> None:
    assert get_overall_status(threats, scenarios, str(status)) == expected


def _row(*, session_status, stage=WorkflowStage.REVIEW, stage_status=StageStatus.AWAITING_DECISION):
    return {"SessionID": "s", "AssetID": 7, "SessionStatus": str(session_status),
            "CurrentStage": str(stage), "StageStatus": str(stage_status), "CompletedAt": None}


def test_review_barrier_survives_completion() -> None:
    """The gate tests the stage pair BEFORE SessionStatus, which is what lets accept and
    regenerate keep working on a completed session. If that order is ever flipped, every
    post-generation accept starts returning 409 session_completed."""
    assert review_gate_reason(_row(session_status=SessionStatus.completed)) is None
    assert review_gate_reason(_row(session_status=SessionStatus.active)) is None


def test_gate_still_refuses_genuinely_finished_and_in_flight_sessions() -> None:
    legacy_done = _row(session_status=SessionStatus.completed, stage=WorkflowStage.APPROVED,
                    stage_status=StageStatus.COMPLETE)
    assert review_gate_reason(legacy_done)[0] == "session_completed"

    cancelled = _row(session_status=SessionStatus.cancelled, stage=WorkflowStage.CANCELLED,
                    stage_status=StageStatus.CANCELLED)
    assert review_gate_reason(cancelled)[0] == "session_cancelled"

    mid_run = _row(session_status=SessionStatus.active, stage=WorkflowStage.SCENARIO_GENERATION,
                stage_status=StageStatus.RUNNING)
    assert review_gate_reason(mid_run)[0] == "generation_in_progress"


def test_sse_stream_stays_open_while_a_decision_is_pending(monkeypatch) -> None:
    """`_stream_still_open`'s own body — the SSE suite monkeypatches this function everywhere,
    so without this test nothing executes it."""
    from app.api import sessions as sessions_mod

    class _FakeSession:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(sessions_mod, "db_session", lambda: _FakeSession())

    def _open_for(row):
        monkeypatch.setattr(sessions_mod.dal, "load_session_board", lambda *a, **k: row)
        return sessions_mod._stream_still_open("s", object(), verify_membership=False)

    assert _open_for(_row(session_status=SessionStatus.completed)) is True   # awaiting decision
    assert _open_for(_row(session_status=SessionStatus.active)) is True      # generating
    assert _open_for(None) is False                                          # row vanished
    assert _open_for(_row(session_status=SessionStatus.cancelled, stage=WorkflowStage.CANCELLED,
                        stage_status=StageStatus.CANCELLED)) is False
    assert _open_for(_row(session_status=SessionStatus.completed, stage=WorkflowStage.APPROVED,
                        stage_status=StageStatus.COMPLETE)) is False
