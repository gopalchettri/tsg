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
    ReviewGateReason,
    SessionStatus,
    StageStatus,
    SubsystemProgress,
    WorkflowStage,
)
from app.pipeline.accept import review_gate_reason

_DONE = str(StageStatus.COMPLETE)
_AWAIT = str(StageStatus.AWAITING_DECISION)


@pytest.mark.parametrize(("threats", "scenarios", "status", "expected", "undecided"), [
    # THE regression, and it now takes TWO rows because the stage alone cannot express it:
    # SCENARIOS parks at the barrier permanently (accept never rewrites it, so decisions stay
    # changeable), so `undecided` is what separates a session nobody has reviewed from one that
    # is fully decided. Keyed on the stage alone these two collapse into one value and a review
    # queue built on `overall` is either empty or never empties.
    (_DONE, _AWAIT, SessionStatus.completed, SubsystemProgress.awaiting_review, True),
    (_DONE, _AWAIT, SessionStatus.completed, SubsystemProgress.complete, False),
    # A cancelled session is terminal even at the barrier — cancel outranks everything but error.
    (_DONE, _AWAIT, SessionStatus.cancelled, SubsystemProgress.cancelled, True),
    # An errored stage still wins outright, decision pending or not.
    (str(StageStatus.ERROR), _AWAIT, SessionStatus.completed, SubsystemProgress.error, True),
    # Legacy shape: completed with no decision outstanding (pre-lifecycle APPROVED rows).
    (_DONE, _DONE, SessionStatus.completed, SubsystemProgress.complete, False),
    # Mid-generation.
    (_DONE, str(StageStatus.RUNNING), SessionStatus.active, SubsystemProgress.in_progress, False),
    (str(StageStatus.IDLE), str(StageStatus.IDLE), SessionStatus.active, SubsystemProgress.pending, False),
])
def test_overall_status_rollup(threats, scenarios, status, expected, undecided) -> None:
    assert get_overall_status(threats, scenarios, str(status), undecided=undecided) == expected


def _row(*, session_status, stage=WorkflowStage.REVIEW, stage_status=StageStatus.AWAITING_DECISION):
    # EntityID rides along because ensure_review_gate re-reads the session through
    # dal.get_session(sess, sid, entity_id) after a recovery — that lookup is the data-layer IDOR
    # guard (INV-1), so the gate cannot reload a row without it.
    return {"SessionID": "s", "AssetID": 7, "EntityID": "78", "SessionStatus": str(session_status),
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


# --------------------------------------------------------------------------------------------
# ensure_review_gate: the liveness reconciliation in front of review_gate_reason.
#
# review_gate_reason reads ONLY the session's denormalised CurrentStage/StageStatus columns. Those
# are a cache of pipeline progress, and nothing writes them back when a worker dies or hangs, so on
# its own the gate reported "generation still in progress" for runs that had stopped hours earlier
# — leaving the session acceptable by nobody. Observed live: a next-set task hung after committing
# its scenarios but before releasing the `_LOCK`, and both accept and regenerate 409'd on a session
# whose work was finished and sitting in the database.
#
# ensure_review_gate therefore requires a LIVE LEASE before it will claim anything is running, and
# recovers the session on the spot when there is none. The second test below is the load-bearing
# one: it proves the fix did not simply weaken the gate.
# --------------------------------------------------------------------------------------------
def _mid_run_row():
    return _row(session_status=SessionStatus.active, stage=WorkflowStage.SCENARIO_GENERATION,
                stage_status=StageStatus.RUNNING)


def test_live_lease_still_refuses_as_generation_in_progress(monkeypatch) -> None:
    """A worker really IS running: the message was true, so nothing changes. This is the guard
    against 'fixing' the false 409 by removing the gate — a real in-flight run must still 409, and
    recovery must never be attempted while a live worker could be racing it."""
    from app.pipeline import accept as accept_mod

    monkeypatch.setattr(accept_mod.dal, "session_has_live_lease", lambda _s, _sid: True)

    def _boom(*_a, **_kw):  # pragma: no cover - must never run
        raise AssertionError("recovery attempted while a worker holds a live lease")

    monkeypatch.setattr("app.pipeline.reaper.recover_session_now", _boom)

    with pytest.raises(accept_mod.AcceptConflict) as exc:
        accept_mod.ensure_review_gate(object(), _mid_run_row())
    assert exc.value.reason == ReviewGateReason.generation_in_progress


def test_no_live_lease_recovers_and_lets_the_request_through(monkeypatch) -> None:
    """THE reported bug: stale cache says RUNNING, no worker holds a lease. The gate must finalise
    the abandoned run and then pass, instead of refusing forever."""
    from app.pipeline import accept as accept_mod

    recovered = _row(session_status=SessionStatus.completed)  # REVIEW / AWAITING_DECISION
    monkeypatch.setattr(accept_mod.dal, "session_has_live_lease", lambda _s, _sid: False)
    monkeypatch.setattr(accept_mod.dal, "get_session", lambda _s, _sid, _e: recovered)
    monkeypatch.setattr("app.pipeline.reaper.recover_session_now", lambda _s, _row: "review")

    assert accept_mod.ensure_review_gate(object(), _mid_run_row()) is recovered


def test_recovery_that_cannot_reach_review_reports_generation_abandoned(monkeypatch) -> None:
    """Recovery ran and the session still is not decidable — report the honest terminal code, never
    'generation_in_progress', because waiting cannot help."""
    from app.pipeline import accept as accept_mod

    monkeypatch.setattr(accept_mod.dal, "session_has_live_lease", lambda _s, _sid: False)
    monkeypatch.setattr(accept_mod.dal, "get_session", lambda _s, _sid, _e: _mid_run_row())
    monkeypatch.setattr("app.pipeline.reaper.recover_session_now", lambda _s, _row: None)

    with pytest.raises(accept_mod.AcceptConflict) as exc:
        accept_mod.ensure_review_gate(object(), _mid_run_row())
    assert exc.value.reason == ReviewGateReason.generation_abandoned


def test_terminal_reasons_are_never_recovered(monkeypatch) -> None:
    """session_completed / session_cancelled are facts, not stale cache. Recovery could not change
    them, and attempting it would put a pointless reaper pass on every such 409."""
    from app.pipeline import accept as accept_mod

    def _boom(*_a, **_kw):  # pragma: no cover - must never run
        raise AssertionError("recovery attempted for a terminal session")

    monkeypatch.setattr("app.pipeline.reaper.recover_session_now", _boom)
    cancelled = _row(session_status=SessionStatus.cancelled, stage=WorkflowStage.CANCELLED,
                    stage_status=StageStatus.CANCELLED)
    with pytest.raises(accept_mod.AcceptConflict) as exc:
        accept_mod.ensure_review_gate(object(), cancelled)
    assert exc.value.reason == ReviewGateReason.session_cancelled


def test_subsystem_task_limits_are_derived_and_stay_under_the_broker_ceiling() -> None:
    """The single-subsystem task budget must never be a hardcoded constant: dev/prod derive a 720s
    lease, UAT derives 2880s (180s LLM timeout x two provider chains). One number cannot serve
    both — too low kills healthy UAT work, and an unclamped lease*2 puts UAT at 5760s, PAST the
    3600s visibility timeout, so the broker would redeliver while the original still runs."""
    from app.core.config import Settings

    s = Settings(_env_file=None, llm_timeout_seconds=90.0, llm_max_retries=3)
    assert s.stage_lease_seconds == 720
    assert s.subsystem_task_soft_limit_seconds == 1440          # 2 lease windows
    assert s.subsystem_task_hard_limit_seconds == 1800

    # A real run measured 227s (next-set) / 104s (regenerate): the budget must clear those easily.
    assert s.subsystem_task_soft_limit_seconds > 227 * 4

    # UAT's slower shape, clamped under the broker ceiling rather than derived past it.
    uat = Settings(_env_file=None, llm_timeout_seconds=180.0, llm_max_retries=3,
                inference_fallback_model="kimi-k2.5", llm_provider="litellm_proxy")
    assert uat.stage_lease_seconds == 2880
    assert uat.subsystem_task_soft_limit_seconds == 3240         # NOT 5760
    assert uat.subsystem_task_hard_limit_seconds <= uat.broker_visibility_timeout_seconds

    for cfg in (s, uat):
        assert cfg.subsystem_task_soft_limit_seconds >= cfg.stage_lease_seconds
        assert (cfg.subsystem_task_soft_limit_seconds
                < cfg.subsystem_task_hard_limit_seconds
                <= cfg.broker_visibility_timeout_seconds)
