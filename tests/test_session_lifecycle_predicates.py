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

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.sessions import get_overall_status
from app.core.enums import (
    ReviewGateReason,
    SessionStatus,
    StageStatus,
    SubsystemLevel,
    SubsystemProgress,
    WorkflowStage,
)
from app.db import models as m
from app.db.dal import now
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


def test_a_running_stage_is_never_reported_as_finished() -> None:
    """EXHAUSTIVE over the whole input space, not one example.

    get_overall_status is pure and its inputs are small finite sets, so the invariant can be
    checked against every combination that exists rather than the handful someone thought of.
    That is the point: the bug this pins was not a wrong branch, it was a MISSING one, and a
    missing branch is exactly what example-based tests do not catch.

    TWO BUGS, both found live, both the same shape. A regeneration or next-set re-opens a stage
    on a session that stays `completed` —
    generation completes it at the review barrier to release the asset, and a rewrite does not
    un-complete it. So `session_status == completed` fell through to `complete` while an LLM call
    was in flight. Found in live end-to-end testing: regenerate returned 202 at epoch 2, the
    SCENARIOS stage went RUNNING, and this field read `complete` for the ~75s the rewrite took.
    Every client is documented to poll exactly this field, so one that stops at `complete` shows
    the OLD version as final and never sees the replacement.

    THE SECOND ONE the first fix missed, caught 8 seconds into the very next live run: regenerate
    answers 202 and resets the stage to IDLE at a new epoch, but nothing reads RUNNING until a
    worker CLAIMS the task. That queue window reported `complete` too — and with no worker to
    claim it, the window never closes. Checking only RUNNING was checking the second half of
    "in flight" and calling it done.

    Same family as every other defect in this codebase: a terminal answer reported while work is
    still happening.
    """
    checked = 0
    for threats in StageStatus:
        for scenarios in StageStatus:
            for status in SessionStatus:
                for undecided in (True, False):
                    got = get_overall_status(threats, scenarios, status, undecided=undecided)
                    checked += 1
                    running = StageStatus.RUNNING in (threats, scenarios)
                    # QUEUED counts as in flight: regenerate resets the stage to IDLE at a new
                    # epoch and answers 202 BEFORE any worker claims it. Generation parks
                    # SCENARIOS at AWAITING_DECISION permanently, so IDLE on a COMPLETED session
                    # can only mean a rewrite was queued — possibly one no worker ever claims.
                    # SCENARIOS only: `threats` defaults to IDLE when its stage row is absent,
                    # so keying on either stage would condemn every ordinary reviewed session.
                    queued = (status == SessionStatus.completed
                            and scenarios == StageStatus.IDLE)
                    if running or queued:
                        assert got != SubsystemProgress.complete, (
                            f"reported finished with work {'running' if running else 'queued'}: "
                            f"threats={threats} scenarios={scenarios} session={status} "
                            f"undecided={undecided}")
    assert checked > 100, "the cross product collapsed — this would pass vacuously"

    # Only `complete` is asserted, deliberately. The first draft also forbade `awaiting_review`
    # while a stage runs, and the sweep immediately produced
    # threats=RUNNING / scenarios=AWAITING_DECISION / session=completed. That combination is NOT
    # REACHABLE: the only thing that runs THREATS after the barrier is next-set, and
    # sessions._do_next_set CASes the session completed -> active via dal.reserve_session before
    # enqueueing, so the session is `active` throughout. Regenerate is the opposite — it
    # deliberately does not take the asset back, which is why its SCENARIOS-RUNNING state keeps
    # session_status `completed` and produced the real bug.
    #
    # An exhaustive sweep covers states the system cannot construct, and asserting on those is
    # asserting about fantasy. `complete` is sound across the whole space because finished is
    # never the right answer while a stage runs, reachable or not.


def test_error_and_cancelled_still_outrank_a_running_stage() -> None:
    """The liveness check must not mask a terminal verdict. A stage left RUNNING by a crashed
    worker on a CANCELLED session must still read cancelled, not in_progress forever — otherwise
    the new branch trades a false 'finished' for a false 'still working'."""
    assert get_overall_status(StageStatus.RUNNING, StageStatus.RUNNING,
                            SessionStatus.cancelled) == SubsystemProgress.cancelled
    assert get_overall_status(StageStatus.ERROR, StageStatus.RUNNING,
                            SessionStatus.completed) == SubsystemProgress.error


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


def test_a_run_that_is_not_abandoned_still_refuses_as_generation_in_progress(monkeypatch) -> None:
    """Working, queued or between claims: the message is true, so nothing changes. This is the
    guard against 'fixing' the false 409 by removing the gate — a real in-flight run must still
    409, and recovery must never be attempted while a live worker could be racing it."""
    from app.pipeline import accept as accept_mod

    monkeypatch.setattr("app.pipeline.reaper.session_is_abandoned", lambda _s, _sid: False)

    def _boom(*_a, **_kw):  # pragma: no cover - must never run
        raise AssertionError("recovery attempted while a worker holds a live lease")

    monkeypatch.setattr("app.pipeline.reaper.recover_session_now", _boom)

    with pytest.raises(accept_mod.AcceptConflict) as exc:
        accept_mod.ensure_review_gate(object(), _mid_run_row())
    assert exc.value.reason == ReviewGateReason.generation_in_progress


def test_an_abandoned_run_recovers_and_lets_the_request_through(monkeypatch) -> None:
    """The original bug: stale cache says RUNNING, the worker died. The gate must finalise the
    abandoned run and then pass, instead of refusing forever."""
    from app.pipeline import accept as accept_mod

    recovered = _row(session_status=SessionStatus.completed)  # REVIEW / AWAITING_DECISION
    monkeypatch.setattr("app.pipeline.reaper.session_is_abandoned", lambda _s, _sid: True)
    monkeypatch.setattr(accept_mod.dal, "get_session", lambda _s, _sid, _e: recovered)
    monkeypatch.setattr("app.pipeline.reaper.recover_session_now", lambda _s, _row: "review")

    assert accept_mod.ensure_review_gate(object(), _mid_run_row()) is recovered


def test_recovery_that_cannot_reach_review_reports_generation_abandoned(monkeypatch) -> None:
    """Recovery ran and the session still is not decidable — report the honest terminal code, never
    'generation_in_progress', because waiting cannot help."""
    from app.pipeline import accept as accept_mod

    monkeypatch.setattr("app.pipeline.reaper.session_is_abandoned", lambda _s, _sid: True)
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


# --------------------------------------------------------------------------------------------
# reaper.session_is_abandoned — the gate's "may I finalise this run?", against a real database.
#
# THE BUG IT FIXES (found live): an accept sent 0.1 s after a create cancelled a healthy session.
# A still-QUEUED session holds no lease — nor does a next-set whose epoch was reserved but not yet
# claimed — and the gate used to read "no live lease" as "abandoned". It must use the reaper's own
# rule instead: no live lease AND (proven dead: a RUNNING row whose lease expired, OR stale).
# --------------------------------------------------------------------------------------------
@pytest.fixture
def db(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'abandon.db'}", connect_args={"check_same_thread": False})
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State):
        tbl.__table__.create(eng)
    return sessionmaker(bind=eng, future=True)


def _grace():
    from app.core.config import get_settings
    return timedelta(seconds=get_settings().reaper_stale_grace_seconds)


def _seed_session(maker, *, stage="THREAT_IDENTIFICATION", stage_status="IDLE", status="active",
                  touched=None, rows=()) -> str:
    """rows: (Level, Status, lease_offset) — lease_offset None = no lease, else now()+offset."""
    sid, t = str(uuid.uuid4()), now()
    with maker() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=sid, TenantID="t", EntityID="78", AssetName="A", AssetID="99",
            SessionStatus=status, CurrentStage=stage, StageStatus=stage_status, Mode="AUTO",
            SubsystemsJSON="[]", CreatedAt=touched or t, UpdatedAt=touched or t))
        for level, st, lease in rows:
            s.execute(m.Subsystem_Stage_State.__table__.insert().values(
                StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="78",
                SubsystemID=0, Level=level, Status=st, GenerationEpoch=1,
                LeaseExpiresAt=None if lease is None else t + lease, UpdatedAt=t, CreatedAt=t))
        s.commit()
    return sid


_IDLE_ROWS = ((SubsystemLevel.THREATS, "IDLE", None), (SubsystemLevel.SCENARIOS, "IDLE", None),
              (SubsystemLevel.LOCK, "IDLE", None))

# name -> (seed kwargs, abandoned?)
_CASES = {
    # THE regression: created, task still queued, nobody has claimed anything yet.
    "queued": (dict(rows=_IDLE_ROWS), False),
    # dal.reserve_session's shape: next-set reserved, SCENARIOS reset to IDLE, no lease yet.
    "next_set_reserved": (dict(stage="SCENARIO_GENERATION", stage_status="RUNNING",
                               rows=((SubsystemLevel.THREATS, "COMPLETE", None),
                                     (SubsystemLevel.SCENARIOS, "IDLE", None),
                                     (SubsystemLevel.LOCK, "IDLE", None))), False),
    "live_lease": (dict(stage="SCENARIO_GENERATION", stage_status="RUNNING",
                        rows=((SubsystemLevel.SCENARIOS, "RUNNING", timedelta(minutes=5)),
                              (SubsystemLevel.LOCK, "RUNNING", timedelta(minutes=5)))), False),
    # A worker claimed, then stopped renewing: the lease lapsed while the row is still RUNNING.
    "proven_dead": (dict(stage="SCENARIO_GENERATION", stage_status="RUNNING",
                         rows=((SubsystemLevel.SCENARIOS, "RUNNING", timedelta(minutes=-1)),
                               (SubsystemLevel.LOCK, "RUNNING", timedelta(minutes=-1)))), True),
    # Never started, and untouched for longer than the grace window (e.g. never enqueued).
    "stale_never_started": (dict(rows=_IDLE_ROWS, touched="STALE"), True),
    # A legitimate human wait is never abandoned, however old.
    "review_wait": (dict(stage="REVIEW", stage_status="AWAITING_DECISION", touched="STALE",
                         rows=_IDLE_ROWS), False),
}


def _seed_case(maker, name: str) -> str:
    kwargs, _ = _CASES[name]
    if kwargs.get("touched") == "STALE":
        kwargs = {**kwargs, "touched": now() - _grace() - timedelta(minutes=1)}
    return _seed_session(maker, **kwargs)


@pytest.mark.parametrize("name", list(_CASES))
def test_session_is_abandoned_follows_the_reapers_rule(db, name) -> None:
    from app.pipeline.reaper import session_is_abandoned

    sid = _seed_case(db, name)
    with db() as s:
        assert session_is_abandoned(s, sid) is _CASES[name][1], name


def test_the_gate_and_the_sweep_agree_on_every_case(db) -> None:
    """Parity: session_is_abandoned is the sweep's rule for one session. Seed every case, run the
    sweep's own selector (with proven_dead computed the way clean_up_abandoned_sessions does), and
    the two verdicts must match session by session — the drift that caused the bug, pinned."""
    from app.pipeline.reaper import _find_abandoned_sessions, _lease_expired, session_is_abandoned

    sids = {name: _seed_case(db, name) for name in _CASES}
    with db() as s:
        t = now()
        ss = m.Subsystem_Stage_State
        proven = {str(r[0]).lower() for r in s.execute(
            select(ss.SessionID).where(ss.Status == "RUNNING", _lease_expired(t))).all()}
        swept = {str(r["SessionID"]).lower() for r in _find_abandoned_sessions(s, t, proven)}
        for name, sid in sids.items():
            assert session_is_abandoned(s, sid) is (sid.lower() in swept), name


def test_an_early_accept_leaves_a_queued_session_running(db, monkeypatch) -> None:
    """End to end through the real gate and a real database: the accept is refused with the
    transient code, recovery is never attempted, and nothing about the session changes."""
    from app.pipeline import accept as accept_mod

    def _boom(*_a, **_kw):  # pragma: no cover - must never run
        raise AssertionError("a queued session was treated as abandoned")

    monkeypatch.setattr("app.pipeline.reaper.recover_session_now", _boom)
    sid = _seed_case(db, "queued")
    tbl = m.Scenario_Session.__table__
    with db() as s:
        row = dict(s.execute(select(tbl).where(tbl.c.SessionID == sid)).mappings().one())
        with pytest.raises(accept_mod.AcceptConflict) as exc:
            accept_mod.ensure_review_gate(s, row)
        assert exc.value.reason == ReviewGateReason.generation_in_progress
        statuses = {str(r[0]) for r in s.execute(
            select(m.Subsystem_Stage_State.Status).where(m.Subsystem_Stage_State.SessionID == sid))}
        session_status = s.execute(select(m.Scenario_Session.SessionStatus)
                                   .where(m.Scenario_Session.SessionID == sid)).scalar_one()
    assert statuses == {"IDLE"} and str(session_status) == "active"
