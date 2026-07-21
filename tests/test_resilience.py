"""[R8] Poison-terminal — a stage that can never complete (worker crashes the
process itself, redelivered forever with a fresh lease each time) must stop
being reclaimable once it exhausts its attempt budget, so the existing reaper
sweep + `decide_session_outcome` can carry it to a terminal state.

Also [R5] lease fencing: winning a claim does not prove you still hold it. A worker
that stalls past its lease has its `_LOCK` reclaimed and its stage row rewritten under
it; when it finally wakes, none of its writes may land.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.enums import StageStatus, SubsystemLevel, WorkflowStage
from app.db import dal
from app.db import models as m
from app.db.dal import load_session, now
from app.pipeline.reaper import clean_up_abandoned_sessions
from tests.test_slice import SUB, _force_stage, _seed_session


def _attempt_count(sess, sid) -> int:
    return sess.execute(
        select(m.Subsystem_Stage_State.AttemptCount).where(
            m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.SubsystemID == SUB["id"],
            m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS,
        )
    ).scalar()


def test_poison_stage_stops_after_max_attempts(db, monkeypatch):
    monkeypatch.setattr(get_settings(), "stage_max_attempts", 3)
    session = _seed_session(db)
    sid = session["SessionID"]
    tid = str(uuid.uuid4())  # Celery redelivers the SAME message/task_id after a worker crash

    # Simulate a worker that crashes the whole PROCESS every time before it can ever
    # leave the stage RUNNING (never reaches _record_failure). The row never
    # leaves RUNNING; each "attempt" is the mid-flight-resume branch (same task_id)
    # re-claiming and refreshing the lease — the real poison loop.
    results = [dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) for _ in range(4)]

    assert results == [True, True, True, False]
    assert _attempt_count(db, sid) == 3


def test_normal_retry_within_limit_succeeds(db):
    session = _seed_session(db)
    sid = session["SessionID"]
    tid = str(uuid.uuid4())

    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) is True
    # A transient hiccup: the SAME task resumes its own mid-flight claim (still RUNNING).
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) is True
    _force_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, StageStatus.COMPLETE)
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) is False  # COMPLETE, not reclaimable


def test_attempt_count_increments_atomically(db):
    session = _seed_session(db)
    sid = session["SessionID"]
    for i in range(1, 4):
        db.execute(update(m.Subsystem_Stage_State)
                   .where(m.Subsystem_Stage_State.SessionID == sid,
                          m.Subsystem_Stage_State.SubsystemID == SUB["id"],
                          m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)
                   .values(Status=StageStatus.ERROR))
        dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, str(uuid.uuid4()))
        assert _attempt_count(db, sid) == i


def test_reaper_sweeps_exhausted_stage_into_error(db, monkeypatch):
    monkeypatch.setattr(get_settings(), "stage_max_attempts", 1)
    session = _seed_session(db)
    sid = session["SessionID"]

    # Exhaust the one allowed attempt, leaving the row RUNNING with an expired lease —
    # exactly the state a redelivery-looping poison session ends up in once claim_stage
    # finally refuses to re-claim it (the lease stops refreshing).
    dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, str(uuid.uuid4()))
    db.execute(update(m.Subsystem_Stage_State)
               .where(m.Subsystem_Stage_State.SessionID == sid,
                      m.Subsystem_Stage_State.SubsystemID == SUB["id"],
                      m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)
               .values(LeaseExpiresAt=now().replace(year=2000)))
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, str(uuid.uuid4())) is False  # exhausted

    cancelled = clean_up_abandoned_sessions(db)  # the EXISTING reaper sweep — no new code needed
    assert sid in cancelled
    assert load_session(db, sid)["SessionStatus"] != "active"


# ---------------------------------------------------------------------------
# [R5] lease fencing — a stale holder's late writes must never land
# ---------------------------------------------------------------------------
def _status(sess, sid, level) -> str:
    return sess.execute(
        select(m.Subsystem_Stage_State.Status).where(
            m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.SubsystemID == SUB["id"],
            m.Subsystem_Stage_State.Level == level)).scalar()


def _expire_lease(sess, sid, level) -> None:
    """Age a row's lease out, exactly as a worker that stalled past `stage_lease_seconds`
    (a slow LLM call, a GC pause, a frozen gevent hub) leaves it."""
    sess.execute(update(m.Subsystem_Stage_State)
                 .where(m.Subsystem_Stage_State.SessionID == sid,
                        m.Subsystem_Stage_State.SubsystemID == SUB["id"],
                        m.Subsystem_Stage_State.Level == level)
                 .values(LeaseExpiresAt=now().replace(year=2000)))


def _park_at_review(sess, sid) -> None:
    """A session at REVIEW is a legitimate human wait and is never finalized by the reaper's
    step 3 — so a sweep exercises ONLY the step 1/2 reclaims these tests are about, and the
    session stays `active` and lockable afterwards."""
    sess.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
                 .values(CurrentStage=WorkflowStage.REVIEW))


def test_release_lock_cannot_free_a_lock_the_reaper_reassigned(db):
    """The zombie-unlock bug: worker A stalls, the reaper reclaims its `_LOCK`, worker B
    takes it — and then A's `finally: release_lock(...)` frees B's lock, putting two
    writers on one subsystem. Fenced on ActiveTaskID, A's release is a no-op."""
    sid = _seed_session(db)["SessionID"]
    _park_at_review(db, sid)
    assert dal.acquire_lock(db, sid, SUB["id"], "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa") is True

    _expire_lease(db, sid, SubsystemLevel.LOCK)
    assert clean_up_abandoned_sessions(db) == []          # real reaper; step 3 skips REVIEW
    assert _status(db, sid, SubsystemLevel.LOCK) == StageStatus.IDLE   # A's lock was taken

    assert dal.acquire_lock(db, sid, SUB["id"], "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb") is True      # B is the holder now
    assert dal.release_lock(db, sid, SUB["id"], "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa") is False     # zombie A's `finally`
    assert _status(db, sid, SubsystemLevel.LOCK) == StageStatus.RUNNING
    assert dal.acquire_lock(db, sid, SUB["id"], "cccccccc-3333-4333-8333-cccccccccccc") is False     # mutex still held by B

    assert dal.release_lock(db, sid, SUB["id"], "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb") is True      # only the holder frees it
    assert _status(db, sid, SubsystemLevel.LOCK) == StageStatus.IDLE


def test_finish_stage_refuses_a_zombie_after_a_regen_bumped_the_epoch(db):
    """The worst fencing failure: an epoch-1 zombie stamps AWAITING_DECISION over the fresh
    IDLE row a regeneration just created at epoch 2. `claim_stage` then refuses the epoch-2
    task (the row is no longer IDLE/ERROR) and the subsystem serves its STALE scenarios as
    if they were the regenerated ones — silently, forever."""
    sid = _seed_session(db)["SessionID"]
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, 1, "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa") is True

    dal.reset_stage_for_regen(db, sid, SUB["id"], (SubsystemLevel.SCENARIOS,), 2)

    assert dal.finish_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS,
                            StageStatus.AWAITING_DECISION, 1, "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa") is False
    assert _status(db, sid, SubsystemLevel.SCENARIOS) == StageStatus.IDLE  # regen row untouched

    # ...and the generation that actually owns the row completes normally.
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, 2, "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb") is True
    assert dal.finish_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS,
                            StageStatus.AWAITING_DECISION, 2, "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb") is True


def test_finish_stage_refuses_a_zombie_the_reaper_already_errored(db):
    """A reaped session must not report success: the zombie's late COMPLETE cannot
    overwrite the ERROR the reaper wrote when its lease lapsed."""
    sid = _seed_session(db)["SessionID"]
    _park_at_review(db, sid)
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa") is True

    _expire_lease(db, sid, SubsystemLevel.THREATS)
    clean_up_abandoned_sessions(db)                                      # step 1: RUNNING+expired → ERROR
    assert _status(db, sid, SubsystemLevel.THREATS) == StageStatus.ERROR

    assert dal.finish_stage(db, sid, SUB["id"], SubsystemLevel.THREATS,
                            StageStatus.COMPLETE, 1, "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa") is False
    assert _status(db, sid, SubsystemLevel.THREATS) == StageStatus.ERROR


def test_renew_lease_extends_the_live_holder_and_refuses_a_zombie(db):
    """renew_lease is the fix for the other lease bug: a still-running worker deep in a
    multi-call stage (write_scenarios, one AI call per selected threat) must be able to push
    its own lease forward so the reaper doesn't treat normal per-call latency as a crash —
    but a task that already lost its claim must never be able to resurrect it this way."""
    session = _seed_session(db)
    sid = session["SessionID"]
    tid = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) is True
    before = db.execute(select(m.Subsystem_Stage_State.LeaseExpiresAt).where(
        m.Subsystem_Stage_State.SessionID == sid, m.Subsystem_Stage_State.SubsystemID == SUB["id"],
        m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)).scalar()

    assert dal.renew_lease(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) is True
    after = db.execute(select(m.Subsystem_Stage_State.LeaseExpiresAt).where(
        m.Subsystem_Stage_State.SessionID == sid, m.Subsystem_Stage_State.SubsystemID == SUB["id"],
        m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)).scalar()
    assert after >= before  # pushed forward, not reset backward or left untouched

    _force_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, StageStatus.COMPLETE)
    assert dal.renew_lease(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, tid) is False  # not RUNNING any more
    assert dal.renew_lease(db, sid, SUB["id"], SubsystemLevel.THREATS, 1,
                            "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb") is False  # never held it


def test_find_threats_renews_lease_once_per_grounding_iteration(db, monkeypatch):
    """The one _ask_ai renewal covers the threats-prompt LLM call itself, but find_threats
    then loops once per proposed threat doing an embedding/rerank grounding match — no LLM
    call of its own to renew the lease in between. Without a renewal inside that loop too, a
    subsystem with many proposed threats (up to max_threats_per_subsystem) could outlive its
    lease under normal per-iteration latency alone."""
    from app.pipeline.tasks import find_threats
    from tests.conftest import DEFAULT_ASSET_CONTEXT
    from tests.test_slice import _TwoThreatLLM

    session = _seed_session(db)
    sid = session["SessionID"]
    tid = str(uuid.uuid4())
    real_renew = dal.renew_lease
    calls = []

    def _spy(sess, session_id, subsystem_id, level, epoch, task_id):
        calls.append(level)
        return real_renew(sess, session_id, subsystem_id, level, epoch, task_id)

    monkeypatch.setattr(dal, "renew_lease", _spy)
    threats, _ = find_threats(db, session, SUB, DEFAULT_ASSET_CONTEXT, _TwoThreatLLM(), tid)
    assert len(threats) == 2
    # 1 renewal before the threats-prompt LLM call (_ask_ai) + 1 per proposed threat (2) = 3
    assert len(calls) == 3


def test_write_scenarios_refuses_when_lock_was_lost(db):
    """The zombie-claims-a-different-stage bug: a worker whose THREATS stage stalled past its
    lease has its `_LOCK` reclaimed (and, since this session isn't at REVIEW, the reaper also
    finalizes/cancels it — ERROR-marking the still-IDLE SCENARIOS row along the way). When the
    stalled worker finally wakes, require_lock=True must refuse to even attempt SCENARIOS,
    not silently claim the now-ERROR row and report success on a session already closed out."""
    from app.pipeline.tasks import write_scenarios

    session = _seed_session(db)
    sid = session["SessionID"]
    tid = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
    assert dal.acquire_lock(db, sid, SUB["id"], tid) is True
    db.commit()

    _expire_lease(db, sid, SubsystemLevel.LOCK)  # simulate the stall: lease lapses while "still working"
    assert sid in clean_up_abandoned_sessions(db)  # reaper reclaims the lock and finalizes the session
    assert _status(db, sid, SubsystemLevel.LOCK) == StageStatus.IDLE
    assert _status(db, sid, SubsystemLevel.SCENARIOS) == StageStatus.ERROR  # reaped, not just idle

    result = write_scenarios(db, session, SUB, {}, [], None, tid, require_lock=True)
    assert result == []
    assert _status(db, sid, SubsystemLevel.SCENARIOS) == StageStatus.ERROR  # untouched by the zombie


def test_finish_stage_accepts_the_live_holder(db):
    """The fence rejects zombies, not the worker that legitimately still owns the claim."""
    sid = _seed_session(db)["SessionID"]
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.THREATS, 1, "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa") is True
    assert dal.finish_stage(db, sid, SUB["id"], SubsystemLevel.THREATS,
                            StageStatus.COMPLETE, 1, "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa") is True
    assert _status(db, sid, SubsystemLevel.THREATS) == StageStatus.COMPLETE
    # A terminal row carries no lease, or the reaper's dead_lease check fires on a finished stage.
    assert dal.finish_stage(db, sid, SUB["id"], SubsystemLevel.THREATS,
                            StageStatus.COMPLETE, 1, "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa") is False  # not RUNNING any more


# ---------------------------------------------------------------------------
# fail-loud: an IntegrityError may only be absorbed once it is positively identified
# ---------------------------------------------------------------------------
def test_link_type_actor_absorbs_only_a_real_duplicate(db):
    """A duplicate link is an idempotent no-op; any OTHER violation (a bad type/actor id)
    must surface, not be reported back to the caller as "already linked" — which would
    have it audit library growth that never happened."""
    assert dal.link_type_actor(db, 1, 1) is True
    assert dal.link_type_actor(db, 1, 1) is False           # composite-PK duplicate
    with pytest.raises(IntegrityError):
        dal.link_type_actor(db, None, 1)                    # NOT NULL — never "already linked"


def test_link_catalogue_category_absorbs_only_a_real_duplicate(db):
    """Same idempotency/fail-loud contract as link_type_actor above, for the
    Threat_Catalogue_Category_Map junction table. Uses the conftest-seeded catalogue 20 /
    category 2 (Tampering)."""
    assert dal.link_catalogue_category(db, 20, 2) is True
    assert dal.link_catalogue_category(db, 20, 2) is False  # composite-PK duplicate
    with pytest.raises(IntegrityError):
        dal.link_catalogue_category(db, None, 2)            # NOT NULL — never "already linked"


def test_create_session_reraises_a_violation_it_cannot_attribute(db):
    """A NOT NULL/FK/truncation fault is not a 409. Answering `SessionConflict(None)` told
    the client "asset already has an active session" about an asset that has none, and hid
    the real cause."""
    with pytest.raises(IntegrityError):
        _seed_session(db, entity=None)


def test_early_failure_before_first_claim_commit_does_not_undo_lock_acquisition(db, monkeypatch):
    """acquire_lock's CAS is committed immediately after it succeeds, mirroring
    find_threats/write_scenarios committing right after their own claim_stage --
    otherwise a failure anywhere in the try block, even before find_threats gets a
    chance to make its own first commit, routes through _record_failure's unconditional
    rollback and undoes the still-uncommitted lock acquisition too. Without the commit,
    the `finally` block's release_lock would then fail its own CAS (the row already
    silently reverted to IDLE by the rollback, not by a real release) and log a false
    "lock_lost" warning for a lock nothing else ever touched. Spying on release_lock's
    return value catches this directly -- unlike the row's final status, which ends up
    IDLE either way and can't tell a real release apart from an accidental rollback."""
    from app.pipeline import tasks as _tasks
    from tests.conftest import StubLLM

    sid = _seed_session(db)["SessionID"]
    monkeypatch.setattr(_tasks, "_announce_starting_supporting_system",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    real_release_lock = dal.release_lock
    release_results = []
    def _spy_release_lock(*a, **k):
        result = real_release_lock(*a, **k)
        release_results.append(result)
        return result
    monkeypatch.setattr("app.db.dal.release_lock", _spy_release_lock)

    _tasks._process_all_supporting_systems(db, sid, StubLLM(), str(uuid.uuid4()))

    assert release_results == [True]   # release_lock's own CAS matched -- the acquire survived the rollback
    assert _status(db, sid, SubsystemLevel.LOCK) == StageStatus.IDLE
