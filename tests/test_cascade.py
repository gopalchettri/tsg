"""Regeneration cascade (SDD [R9]) — redo one subsystem's profile/threat/
threat-type/scenario without re-running the whole pipeline. Row-scoped for
`scenario`/`threat` granularities (the whole point: redo one bad item without
discarding its siblings); reuses the same _LOCK/epoch/decide_session_outcome
machinery the initial pipeline uses, so it's concurrency-correct by construction.

The epoch is reserved by the CALLER (mirroring the real API endpoint's
session-level CAS) via `_reserve_epoch`, not computed inside `run_regeneration`
— that's what makes a Celery redelivery of the same task idempotent instead of
destructively re-running the hop under a freshly-minted epoch.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select, update

from app.core.enums import RegenGranularity, StageStatus, SubsystemLevel, WorkflowStage
from app.db import dal
from app.db import models as m
from app.db.dal import load_session
from app.pipeline import cascade, prompts
from app.pipeline.accept import AcceptConflict, accept_session
from app.pipeline.reaper import clean_up_abandoned_sessions
from app.pipeline.tasks import _process_all_supporting_systems, write_scenarios
from tests.conftest import StubLLM, make_client
from tests.test_slice import SUB, _seed_session


class _TwoThreatLLM(StubLLM):
    """Proposes TWO threats (both grounded via the seeded masters: type 10/catalogue
    20 and type 11/catalogue 21) so sibling-preservation tests have siblings."""

    def chat(self, messages, *, model=None):
        sysc = messages[0]["content"].lower()
        if "stride threats" in sysc:
            out = [
                {"category": "Tampering", "type": "Firmware Tampering", "name": "Bootloader implant",
                 "actors": ["Hacker"]},
                {"category": "Tampering", "type": "Config Tampering", "name": "OTA poisoning",
                 "actors": ["Hacker"]},
            ]
            from app.pipeline.llm import Provenance
            return json.dumps(out), Provenance(model="stub")
        return super().chat(messages, model=model)


class _CountingLLM(StubLLM):
    def __init__(self):
        self.chat_calls = 0

    def chat(self, messages, *, model=None):
        self.chat_calls += 1
        return super().chat(messages, model=model)


def _run_to_review(db, llm, subs=None):
    session = _seed_session(db, subs=subs)
    sid = session["SessionID"]
    _process_all_supporting_systems(db, sid, llm, "t")
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW
    return sid


def _leave_review(db, sid, stage=WorkflowStage.SCENARIO_GENERATION):
    """Simulates the API endpoint's own leave-REVIEW CAS (tested directly against
    the real endpoint in test_regen_authz_rejects_other_entity)."""
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.c.SessionID == sid)
               .values(CurrentStage=stage, StageStatus=StageStatus.RUNNING, UpdatedAt=dal.now()))


def _reserve_epoch(db, sid, subsystem_id, granularity):
    """Mirrors the real endpoint's epoch reservation (sessions.py::post_regenerate)."""
    levels = cascade.LEVELS_BY_GRANULARITY[granularity]
    epoch = dal.next_epoch(db, sid, subsystem_id, levels)
    dal.reset_stage_for_regen(db, sid, subsystem_id, levels, epoch)
    return epoch


def _output_ids(db, sid):
    return db.execute(
        select(m.Threat_Scenario_Output.c.OutputID)
        .where(m.Threat_Scenario_Output.c.SessionID == sid, m.Threat_Scenario_Output.c.Superseded == 0)
        .order_by(m.Threat_Scenario_Output.c.OutputID)
    ).scalars().all()


def _active_count(db, table, sid):
    return db.execute(select(func.count()).select_from(table).where(
        table.c.SessionID == sid, table.c.Superseded == 0)).scalar()


# --- state transitions ---
def test_regen_at_review_returns_to_review(db):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    output_id = _output_ids(db, sid)[0]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    outcome = cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [output_id], epoch,
                                       StubLLM(), "regen-t")
    assert outcome == "review"
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW


def test_accept_rejected_during_regen(db):
    sid = _run_to_review(db, StubLLM())
    dal.acquire_lock(db, sid, SUB["id"], "live-regen-task")  # simulate a regen holding the lock
    with pytest.raises(AcceptConflict):
        accept_session(db, sid, "5", "u1")


def test_concurrent_regen_same_subsystem_one_wins(db):
    sid = _run_to_review(db, StubLLM())
    res1 = db.execute(update(m.Scenario_Session).where(
        m.Scenario_Session.c.SessionID == sid, m.Scenario_Session.c.SessionStatus == "active",
        m.Scenario_Session.c.CurrentStage == WorkflowStage.REVIEW,
    ).values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING))
    res2 = db.execute(update(m.Scenario_Session).where(
        m.Scenario_Session.c.SessionID == sid, m.Scenario_Session.c.SessionStatus == "active",
        m.Scenario_Session.c.CurrentStage == WorkflowStage.REVIEW,
    ).values(CurrentStage=WorkflowStage.PROFILE, StageStatus=StageStatus.RUNNING))
    assert res1.rowcount == 1
    assert res2.rowcount == 0  # second request's identical CAS loses the race


# --- reaper must NOT prematurely re-enter REVIEW while a regen is legitimately in flight ---
def test_reaper_does_not_reenter_review_right_after_leaving_it(db):
    sid = _run_to_review(db, StubLLM())
    # Simulate the endpoint's own leave-REVIEW + epoch-reservation, exactly as
    # post_regenerate does — the real Celery task just hasn't picked it up yet.
    _leave_review(db, sid, stage=WorkflowStage.SCENARIO_GENERATION)
    _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    # The reaper must NOT treat "just left REVIEW a moment ago" as abandoned — with
    # leases correctly cleared on stage completion, dead_lease is false and the
    # grace-period (stage_lease_seconds) hasn't elapsed, so nothing should happen.
    clean_up_abandoned_sessions(db)
    row = load_session(db, sid)
    assert row["CurrentStage"] == WorkflowStage.SCENARIO_GENERATION  # NOT bounced back to REVIEW
    assert row["SessionStatus"] == "active"


def test_reaper_eventually_reclaims_a_regen_that_never_actually_started(db, monkeypatch):
    """Epoch reservation happens at the endpoint (before the task ever runs), so a
    permanently-lost broker message (the task truly never executes) leaves the
    reset SCENARIOS row stuck IDLE. The reaper's grace-period fallback still
    reclaims it — safely CANCELLING the session (releasing the M4 lock) rather
    than leaving it stuck forever, since the sole subsystem's scenario stage never
    actually got redone and there is nothing left reviewable."""
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "stage_lease_seconds", 1)
    sid = _run_to_review(db, StubLLM())
    _leave_review(db, sid, stage=WorkflowStage.SCENARIO_GENERATION)
    _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    # Backdate UpdatedAt past the (now tiny) grace window to simulate a task that
    # really did get lost (broker down, worker crash before ever starting).
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.c.SessionID == sid)
               .values(UpdatedAt=dal.now().replace(year=2000)))
    clean_up_abandoned_sessions(db)
    row = load_session(db, sid)
    assert row["SessionStatus"] == "cancelled"  # safely reclaimed — M4 lock released, asset re-runnable
    _seed_session(db, asset_id=100)


# --- epoch mechanics ---
def test_regen_creates_new_epoch_supersedes_old(db):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    old_output = _output_ids(db, sid)[0]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [old_output], epoch, StubLLM(), "regen-t")

    assert db.execute(select(m.Threat_Scenario_Output.c.Superseded)
                      .where(m.Threat_Scenario_Output.c.OutputID == old_output)).scalar() == 1

    active = db.execute(select(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.c.SessionID == sid, m.Threat_Scenario_Output.c.Superseded == 0)).mappings().all()
    assert len(active) == 1
    assert active[0]["GenerationEpoch"] == 2


def test_regen_idempotent_redelivery(db):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    old_output = _output_ids(db, sid)[0]
    threat_id = db.execute(
        select(m.Scoped_Threat.c.ThreatID)
        .select_from(m.Threat_Scenario_Output.join(
            m.Scoped_Threat, m.Threat_Scenario_Output.c.ScopedThreatID == m.Scoped_Threat.c.ScopedThreatID))
        .where(m.Threat_Scenario_Output.c.OutputID == old_output)
    ).scalar()

    epoch = dal.next_epoch(db, sid, SUB["id"], (SubsystemLevel.SCENARIOS,))
    dal.reset_stage_for_regen(db, sid, SUB["id"], (SubsystemLevel.SCENARIOS,), epoch)
    threats = dal.active_threats(db, sid, SUB["id"])
    tid = "same-redelivered-task"

    provs1 = write_scenarios(db, session, SUB, threats, StubLLM(), tid, epoch=epoch, target_threat_ids={threat_id})
    assert len(provs1) == 1
    # Redelivery: SAME task_id, SAME epoch — the stage is now AWAITING_DECISION, not
    # claimable, so this is a true no-op (mirrors test_redelivered_stage_is_noop).
    provs2 = write_scenarios(db, session, SUB, threats, StubLLM(), tid, epoch=epoch, target_threat_ids={threat_id})
    assert provs2 == []
    active = db.execute(select(func.count()).select_from(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.c.SessionID == sid, m.Threat_Scenario_Output.c.Superseded == 0)).scalar()
    assert active == 1  # no duplicate insert


def test_regen_threat_type_idempotent_under_full_task_redelivery(db):
    """Unlike scenario/threat (row-scoped, naturally guarded by get_threat_id_to_redo's
    existence check), threat_type/profile are subsystem-wide with no such natural
    guard — redelivery-safety depends ENTIRELY on the epoch being fixed by the
    caller, not re-minted per call."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat_type)
    tid = "same-redelivered-task"

    out1 = cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat_type, [10], epoch, StubLLM(), tid)
    assert out1 == "review"
    threats_after_1 = _active_count(db, m.Identified_Threat, sid)

    # Redelivery: SAME task_id, SAME epoch, session is back at REVIEW so simulate the
    # endpoint leaving it again (a real redelivery wouldn't re-enter the endpoint, but
    # cascade.run_regeneration itself must still be safe if invoked again at this epoch).
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    out2 = cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat_type, [10], epoch, StubLLM(), tid)
    assert out2 == "review"
    assert _active_count(db, m.Identified_Threat, sid) == threats_after_1  # no duplicate re-run


def test_regen_after_poison_exhaustion_not_permanently_blocked(db, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "stage_max_attempts", 1)
    session = _seed_session(db)
    sid = session["SessionID"]
    dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, 1, "poisoned-task")
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, 1, "poisoned-task") is False  # exhausted

    new_epoch = dal.next_epoch(db, sid, SUB["id"], (SubsystemLevel.SCENARIOS,))
    dal.reset_stage_for_regen(db, sid, SUB["id"], (SubsystemLevel.SCENARIOS,), new_epoch)
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, new_epoch, "fresh-task") is True


# --- row-scoping (the real fix for the "regen wipes siblings" gap) ---
def test_regen_scenario_only_targets_one_output_siblings_untouched(db):
    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    outputs = _output_ids(db, sid)
    assert len(outputs) == 2
    target, sibling = outputs[0], outputs[1]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [target], epoch, _TwoThreatLLM(), "regen-t")

    sibling_row = db.execute(select(m.Threat_Scenario_Output.c.Superseded)
                             .where(m.Threat_Scenario_Output.c.OutputID == sibling)).scalar()
    assert sibling_row == 0  # untouched

    target_row = db.execute(select(m.Threat_Scenario_Output.c.Superseded)
                            .where(m.Threat_Scenario_Output.c.OutputID == target)).scalar()
    assert target_row == 1  # regenerated — old one superseded

    active = db.execute(select(func.count()).select_from(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.c.SessionID == sid, m.Threat_Scenario_Output.c.Superseded == 0)).scalar()
    assert active == 2  # sibling + the freshly regenerated one — still 2 total, none lost


def test_regen_threat_reground_no_new_llm_call(db):
    llm = _CountingLLM()
    sid = _run_to_review(db, llm)
    session = dict(load_session(db, sid))
    threat_id = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalar()
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)

    calls_before = llm.chat_calls
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat, [threat_id], epoch, llm, "regen-t")
    # Grounding itself makes no chat() call — only the downstream scenario regen does (exactly 1).
    assert llm.chat_calls - calls_before == 1


def test_regen_threat_supersedes_old_scoped_and_output_no_duplicate(db):
    """The real fix: recheck_threat_in_library must supersede the OLD Scoped_Threat/
    Threat_Scenario_Output (keyed by the OLD threat_id) — not rely on write_scenarios's
    target_threat_id=new_tid lookup, which has no lineage for a brand-new id."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    threat_id = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalar()
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat, [threat_id], epoch, StubLLM(), "regen-t")

    assert _active_count(db, m.Identified_Threat, sid) == 1
    assert _active_count(db, m.Scoped_Threat, sid) == 1
    assert _active_count(db, m.Threat_Scenario_Output, sid) == 1


def test_regen_threat_resumes_scenario_after_midcascade_crash(db):
    """[MEDIUM-1] A `threat` regen commits its threat step (via write_scenarios' pre-LLM
    claim-commit) before the scenario step finishes; if the worker then dies mid-scenario the
    OLD target is already superseded, so a redelivery conflicts at get_threat_id_to_redo. The
    deterministic replacement id lets the redelivery RESUME the scenario step instead of
    dropping it forever (pre-fix: the scenario was left for the reaper to ERROR)."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    threat_id = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalar()
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)
    tid = "same-redelivered-task"

    # Simulate the durable crash state: threat step committed (old superseded, deterministic
    # replacement inserted, THREATS complete) + SCENARIOS claimed but the scenario never
    # generated — exactly what write_scenarios' pre-LLM claim-commit leaves if the worker dies
    # during the scenario LLM call.
    dal.acquire_lock(db, sid, SUB["id"], tid)
    cascade.recheck_threat_in_library(db, session, SUB, threat_id, StubLLM(), tid, epoch)
    dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, epoch, tid)
    db.commit()
    dal.release_lock(db, sid, SUB["id"])
    db.commit()
    assert db.execute(select(m.Identified_Threat.c.Superseded).where(
        m.Identified_Threat.c.ThreatID == threat_id)).scalar() == 1     # old target superseded (durable)
    assert _active_count(db, m.Threat_Scenario_Output, sid) == 0        # scenario dropped by the "crash"

    # Redelivery of the SAME task at the SAME epoch: get_threat_id_to_redo conflicts on the superseded
    # old target, but the resume path must finish the deterministic replacement's scenario.
    _leave_review(db, sid, stage=WorkflowStage.SCENARIO_GENERATION)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat, [threat_id], epoch, StubLLM(), tid)
    assert _active_count(db, m.Threat_Scenario_Output, sid) == 1        # RESUMED — scenario regenerated
    assert _active_count(db, m.Identified_Threat, sid) == 1             # still exactly one active threat


def test_regen_crash_resume_replacement_superseded_between_prelock_and_lock_is_caught(db, monkeypatch):
    """The `resume_tids` branch's own TOCTOU gap: the pre-lock `find_threat_to_resume_after_crash`
    computes the deterministic replacement is still active, but a DIFFERENT concurrent regen
    (its own epoch) supersedes that same replacement between that check and `acquire_lock`
    actually taking the lock. Without re-deriving `resume_tids` under the lock, a stale
    resume_tids sails into write_scenarios and scoped_all's `sc.threat_id in target_threat_ids`
    filter silently produces an empty scenario set (no error, no audit signal) instead of this
    test's asserted safe no-op. Guards against a regression that deletes that re-derivation."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    threat_id = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalar()
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)
    tid = "same-redelivered-task"

    # Simulate the durable crash state (as in test_regen_threat_resumes_scenario_after_midcascade_crash):
    # threat step committed (old superseded, deterministic replacement inserted, THREATS
    # complete) + SCENARIOS claimed but the scenario never generated.
    dal.acquire_lock(db, sid, SUB["id"], tid)
    new_tid, _ = cascade.recheck_threat_in_library(db, session, SUB, threat_id, StubLLM(), tid, epoch)
    dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, epoch, tid)
    db.commit()
    dal.release_lock(db, sid, SUB["id"])
    db.commit()
    assert _active_count(db, m.Threat_Scenario_Output, sid) == 0

    # Now simulate: between the redelivery's pre-lock resume-check and its lock acquisition,
    # an independent concurrent regen supersedes the deterministic replacement itself.
    real_acquire_lock = dal.acquire_lock

    def _acquire_then_supersede_replacement(sess, session_id, subsystem_id, task_id):
        won = real_acquire_lock(sess, session_id, subsystem_id, task_id)
        if won:
            dal.supersede_by_threat(sess, m.Identified_Threat, session_id, subsystem_id, new_tid)
            sess.commit()
        return won

    monkeypatch.setattr(cascade.dal, "acquire_lock", _acquire_then_supersede_replacement)
    _leave_review(db, sid, stage=WorkflowStage.SCENARIO_GENERATION)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat, [threat_id], epoch, StubLLM(), tid)

    # No scenario written for the now-stale replacement, and crucially SCENARIOS never gets
    # (re-)claimed/completed by write_scenarios at all — the stale-resume_tids bug's actual
    # symptom is write_scenarios silently claiming+completing SCENARIOS with a 0-scenario
    # scoped_all filter result (a "successful" no-op indistinguishable from real completion).
    # The fix must detect the conflict BEFORE ever calling write_scenarios.
    assert _active_count(db, m.Threat_Scenario_Output, sid) == 0
    assert _active_count(db, m.Identified_Threat, sid) == 0  # replacement itself now superseded too
    scenarios_status = db.execute(select(m.Subsystem_Stage_State.c.Status).where(
        m.Subsystem_Stage_State.c.SessionID == sid, m.Subsystem_Stage_State.c.SubsystemID == SUB["id"],
        m.Subsystem_Stage_State.c.Level == SubsystemLevel.SCENARIOS)).scalar()
    # Still the pre-redelivery claimed-but-never-completed state from the simulated crash
    # (RUNNING) — NOT re-completed/AWAITING_DECISION by a write_scenarios call that ran on
    # stale data. (The reaper is responsible for eventually reclaiming this RUNNING row;
    # that lease/timeout behavior is exercised elsewhere and is out of scope here.)
    assert scenarios_status == StageStatus.RUNNING


def test_find_threat_to_resume_after_crash_is_per_item_not_all_or_nothing(db):
    """find_threat_to_resume_after_crash's docstring claims per-item independence: "a partial
    crash (some threats' scenario steps finished, others didn't) resumes exactly the ones
    still pending" — but the sole existing crash-resume test only ever passes a single-element
    target list, so a bug that turned the per-item loop into an all-or-nothing check (or one
    that only ever resumed target_ids[0]) would pass every existing test. Exercises the
    function directly with a TWO-element batch where only ONE target's deterministic
    replacement is actually active."""
    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    threat_ids = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalars().all()
    assert len(threat_ids) == 2
    crashed_target, untouched_target = threat_ids
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)

    # Only ONE of the two targets actually crashed mid-scenario (its deterministic
    # replacement was inserted); the other was never touched by this regen at all — its
    # "replacement" id was never computed/inserted, so it must NOT be resumable.
    dal.acquire_lock(db, sid, SUB["id"], "t")
    new_tid = cascade._reground_one_threat(db, session, SUB, crashed_target, StubLLM(), epoch)
    db.commit()
    dal.release_lock(db, sid, SUB["id"])
    db.commit()

    resumable = cascade.find_threat_to_resume_after_crash(
        db, sid, SUB["id"], RegenGranularity.threat, [crashed_target, untouched_target], epoch)

    assert resumable == {new_tid}  # exactly the crashed target's replacement — not both, not neither


def test_regen_threat_scores_against_real_siblings_not_in_isolation(db, monkeypatch):
    """The real fix: cascade.py must pass the FULL active-threat list to
    scoping.score_threats for `threat` granularity too, not a synthetic
    single-element list (which would always rank the target #1 regardless of its
    true standing, since score_threats ranks purely by position within whatever
    list it's given). Spies on score_threats directly rather than asserting on the
    resulting rank number, since the untouched sibling's OWN persisted rank is a
    separate, unrelated concern this fix doesn't (and doesn't need to) touch."""
    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    threats_before = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalars().all()
    assert len(threats_before) == 2
    target_threat_id = threats_before[0]
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)

    from app.pipeline import scoping
    seen_lengths = []
    real_score_threats = scoping.score_threats

    def _spy(threats, **kwargs):  # [R12] score_threats also takes subsystem/rules/cutoff kwargs now
        seen_lengths.append(len(threats))
        return real_score_threats(threats, **kwargs)

    monkeypatch.setattr("app.pipeline.tasks.scoping.score_threats", _spy)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat, [target_threat_id], epoch,
                             _TwoThreatLLM(), "regen-t")

    assert seen_lengths == [2]  # scored against BOTH threats (target + its real sibling), never a singleton


# --- authz (through the real endpoint) ---
def test_regen_authz_rejects_other_entity(engine, monkeypatch):
    def sync_regen(session_id, subsystem_id, granularity, target_ids, epoch, user_note):
        from app.db.engine import db_session
        with db_session() as s:
            session = dal.load_session(s, session_id)
            cascade.run_regeneration(s, dict(session), subsystem_id, granularity, target_ids, epoch, StubLLM(), "t")

    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    monkeypatch.setattr("app.api.sessions.enqueue_regeneration", sync_regen)
    client5 = make_client({"5"})
    sid = client5.post("/v1/sessions", json={"asset_id": 100, "entity": "5"}).json()["session_id"]

    from app.db.engine import db_session
    with db_session() as s:
        _process_all_supporting_systems(s, sid, StubLLM(), "t")

    r = make_client({"6"}).post(f"/v1/sessions/{sid}/regenerate/profile",
                                json={"subsystem_id": SUB["id"]})
    assert r.status_code == 403


# --- prompt-quality fix: threat context threading survives the regen cascade ---
def _spy_scenario_prompt(monkeypatch, captured):
    real_scenario_prompt = prompts.scenario_prompt

    def _spy(asset_name, sub, threat_type, threat_name):
        captured.append((threat_type, threat_name))
        return real_scenario_prompt(asset_name, sub, threat_type, threat_name)

    monkeypatch.setattr("app.pipeline.prompts.scenario_prompt", _spy)


def test_regen_scenario_granularity_threads_target_threat_not_sibling(db, monkeypatch):
    """Row-scoped `scenario` regen must thread THAT threat's context, not its
    sibling's — proves the enrichment survives the dal.active_threats round trip
    (not just the in-memory find_threats path the initial pipeline uses)."""
    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    target, sibling = _output_ids(db, sid)
    target_threat_id = db.execute(
        select(m.Scoped_Threat.c.ThreatID)
        .select_from(m.Threat_Scenario_Output.join(
            m.Scoped_Threat, m.Threat_Scenario_Output.c.ScopedThreatID == m.Scoped_Threat.c.ScopedThreatID))
        .where(m.Threat_Scenario_Output.c.OutputID == target)
    ).scalar()
    expected_name = db.execute(select(m.Identified_Threat.c.LibraryThreatName)
                               .where(m.Identified_Threat.c.ThreatID == target_threat_id)).scalar()
    sibling_threat_id = db.execute(
        select(m.Scoped_Threat.c.ThreatID)
        .select_from(m.Threat_Scenario_Output.join(
            m.Scoped_Threat, m.Threat_Scenario_Output.c.ScopedThreatID == m.Scoped_Threat.c.ScopedThreatID))
        .where(m.Threat_Scenario_Output.c.OutputID == sibling)
    ).scalar()
    sibling_name = db.execute(select(m.Identified_Threat.c.LibraryThreatName)
                              .where(m.Identified_Threat.c.ThreatID == sibling_threat_id)).scalar()
    assert expected_name != sibling_name  # the two threats really are distinguishable

    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    captured = []
    _spy_scenario_prompt(monkeypatch, captured)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [target], epoch, _TwoThreatLLM(), "regen-t")

    assert len(captured) == 1
    assert captured[0][1] == expected_name  # matches the TARGET, not the sibling


def test_regen_threat_granularity_threads_newly_regrounded_fields(db, monkeypatch):
    """`threat` granularity re-grounds one threat then regenerates its scenario —
    proves the post-insert re-query (dal.active_threats called again after
    recheck_threat_in_library's insert) picks up the freshly-regenerated threat's
    enrichment fields, not stale/blank data."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    threat_id = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalar()
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)

    captured = []
    _spy_scenario_prompt(monkeypatch, captured)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat, [threat_id], epoch, StubLLM(), "regen-t")

    assert captured == [("Firmware Tampering", "Bootloader implant")]


def test_regen_profile_granularity_threads_correctly(db, monkeypatch):
    """`profile` is subsystem-wide (no target ids) -- the enrichment comes from
    find_threats's own fresh return value, not row-scoping. Guards against a mistaken
    belief (raised and refuted during an adversarial review pass, which conflated
    `target_threat_ids`'s row-scoping role with the separate enrichment-lookup
    mechanism) that this path would silently pass None, None to scenario_prompt
    because it doesn't set `target_threat_ids`."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    _leave_review(db, sid, stage=WorkflowStage.PROFILE)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.profile)

    captured = []
    _spy_scenario_prompt(monkeypatch, captured)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.profile, None, epoch, StubLLM(), "regen-t")

    assert captured == [("Firmware Tampering", "Bootloader implant")]


def test_regen_threat_type_granularity_threads_correctly(db, monkeypatch):
    """`threat_type` is now genuinely scoped (plan item [threat_type regen fix]) — still
    subsystem-wide in the sense of no ROW-scoping (`target_threat_ids` isn't set on the
    write_scenarios call the same way `scenario`/`threat` set it), but DOES require a
    type id list. The enrichment comes from find_threats's own fresh return value."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat_type)

    captured = []
    _spy_scenario_prompt(monkeypatch, captured)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat_type, [10], epoch, StubLLM(), "regen-t")

    assert captured == [("Firmware Tampering", "Bootloader implant")]


# --- post-lock re-validation: the actual TOCTOU race the fix targets ---
def test_regen_target_superseded_between_prelock_check_and_lock_is_caught(db, monkeypatch):
    """The race this fix targets: a concurrent regen supersedes our target in the window
    between the pre-lock `get_threat_id_to_redo` check and `acquire_lock` actually taking
    the lock. Simulated by superseding the target from inside a monkeypatched
    `acquire_lock` (the last thing that runs before the post-lock re-validation). Without
    the post-lock re-check in the `else` branch, a stale threat_ids would sail into
    `redo_the_requested_parts` and silently no-op (no scenario written, no error) instead
    of this test's asserted no-op-with-no-crash outcome. Guards against a regression that
    deletes that re-validation."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    threat_id = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalar()
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)

    real_acquire_lock = dal.acquire_lock

    def _acquire_then_supersede_target(sess, session_id, subsystem_id, task_id):
        won = real_acquire_lock(sess, session_id, subsystem_id, task_id)
        if won:
            # Simulate an independent concurrent regen that resolved+superseded the SAME
            # threat between our pre-lock check and this lock acquisition.
            dal.supersede_by_threat(sess, m.Identified_Threat, session_id, subsystem_id, threat_id)
            sess.commit()
        return won

    monkeypatch.setattr(cascade.dal, "acquire_lock", _acquire_then_supersede_target)
    outcome = cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat, [threat_id], epoch,
                                       StubLLM(), "regen-t")

    # No REPLACEMENT threat/scenario written for the now-stale target — the post-lock
    # re-validation raised RegenerateConflict (caught by run_regeneration's own
    # except Exception -> _record_failure) instead of a stale threat_ids silently sailing
    # into redo_the_requested_parts/_reground_one_threat's row-miss no-op. The ORIGINAL
    # scenario (from the initial run, untouched by our simulated concurrent supersede of
    # only Identified_Threat) is still the sole active one — proof nothing new was inserted.
    assert _active_count(db, m.Identified_Threat, sid) == 0  # old superseded, no replacement inserted
    assert _active_count(db, m.Threat_Scenario_Output, sid) == 1  # still just the ORIGINAL, pre-regen scenario
    # THREATS/SCENARIOS both land ERROR (the only subsystem), so the session is
    # terminally cancelled rather than silently re-entering REVIEW as if nothing happened.
    assert outcome == "cancelled"
    assert load_session(db, sid)["SessionStatus"] == "cancelled"
