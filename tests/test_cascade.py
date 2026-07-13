"""Regeneration cascade (SDD [R9]) — redo one subsystem's scenario(s) without
re-running the whole pipeline. Row-scoped (the whole point: redo one bad item
without discarding its siblings); reuses the same _LOCK/epoch/decide_session_outcome
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
from tests.conftest import DEFAULT_ASSET_CONTEXT, StubLLM
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


def _run_to_review(db, llm, subs=None):
    session = _seed_session(db, subs=subs)
    sid = session["SessionID"]
    _process_all_supporting_systems(db, sid, llm, "11111111-1111-4111-8111-111111111111")
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW
    return sid


def _leave_review(db, sid, stage=WorkflowStage.SCENARIO_GENERATION):
    """Simulates the API endpoint's own leave-REVIEW CAS."""
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
               .values(CurrentStage=stage, StageStatus=StageStatus.RUNNING, UpdatedAt=dal.now()))


def _reserve_epoch(db, sid, subsystem_id, granularity):
    """Mirrors the real endpoint's epoch reservation (sessions.py::post_regenerate)."""
    levels = cascade.LEVELS_BY_GRANULARITY[granularity]
    epoch = dal.next_epoch(db, sid, subsystem_id, levels)
    dal.reset_stage_for_regen(db, sid, subsystem_id, levels, epoch)
    return epoch


def _output_ids(db, sid):
    return db.execute(
        select(m.Threat_Scenario_Output.OutputID)
        .where(m.Threat_Scenario_Output.SessionID == sid, m.Threat_Scenario_Output.Superseded == 0)
        .order_by(m.Threat_Scenario_Output.OutputID)
    ).scalars().all()


# --- state transitions ---
def test_regen_at_review_returns_to_review(db):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    output_id = _output_ids(db, sid)[0]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    outcome = cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [output_id], epoch,
                                       StubLLM(), "55555555-5555-4555-8555-555555555555")
    assert outcome == "review"
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW


def test_accept_rejected_during_regen(db):
    sid = _run_to_review(db, StubLLM())
    dal.acquire_lock(db, sid, SUB["id"], "66666666-6666-4666-8666-666666666666")  # simulate a regen holding the lock
    with pytest.raises(AcceptConflict):
        accept_session(db, sid, "5", "u1")


def test_concurrent_regen_same_subsystem_one_wins(db):
    sid = _run_to_review(db, StubLLM())
    res1 = db.execute(update(m.Scenario_Session).where(
        m.Scenario_Session.SessionID == sid, m.Scenario_Session.SessionStatus == "active",
        m.Scenario_Session.CurrentStage == WorkflowStage.REVIEW,
    ).values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING))
    res2 = db.execute(update(m.Scenario_Session).where(
        m.Scenario_Session.SessionID == sid, m.Scenario_Session.SessionStatus == "active",
        m.Scenario_Session.CurrentStage == WorkflowStage.REVIEW,
    ).values(CurrentStage=WorkflowStage.THREAT_IDENTIFICATION, StageStatus=StageStatus.RUNNING))
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
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
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
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [old_output], epoch, StubLLM(), "55555555-5555-4555-8555-555555555555")

    assert db.execute(select(m.Threat_Scenario_Output.Superseded)
                      .where(m.Threat_Scenario_Output.OutputID == old_output)).scalar() == 1

    active = db.execute(select(m.Threat_Scenario_Output.__table__).where(
        m.Threat_Scenario_Output.SessionID == sid, m.Threat_Scenario_Output.Superseded == 0)).mappings().all()
    assert len(active) == 1
    assert active[0]["GenerationEpoch"] == 2


def test_regen_idempotent_redelivery(db):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    old_output = _output_ids(db, sid)[0]
    threat_id = db.execute(
        select(m.Scoped_Threat.ThreatID)
        .select_from(m.Threat_Scenario_Output.__table__.join(
            m.Scoped_Threat, m.Threat_Scenario_Output.ScopedThreatID == m.Scoped_Threat.ScopedThreatID))
        .where(m.Threat_Scenario_Output.OutputID == old_output)
    ).scalar()

    epoch = dal.next_epoch(db, sid, SUB["id"], (SubsystemLevel.SCENARIOS,))
    dal.reset_stage_for_regen(db, sid, SUB["id"], (SubsystemLevel.SCENARIOS,), epoch)
    threats = dal.active_threats(db, sid, SUB["id"])
    tid = "44444444-4444-4444-8444-444444444444"  # same task_id both calls -- exercises redelivery

    provs1 = write_scenarios(db, session, SUB, DEFAULT_ASSET_CONTEXT, threats, StubLLM(), tid, epoch=epoch, target_threat_ids={threat_id})
    assert len(provs1) == 1
    # Redelivery: SAME task_id, SAME epoch — the stage is now AWAITING_DECISION, not
    # claimable, so this is a true no-op (mirrors test_redelivered_stage_is_noop).
    provs2 = write_scenarios(db, session, SUB, DEFAULT_ASSET_CONTEXT, threats, StubLLM(), tid, epoch=epoch, target_threat_ids={threat_id})
    assert provs2 == []
    active = db.execute(select(func.count()).select_from(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.SessionID == sid, m.Threat_Scenario_Output.Superseded == 0)).scalar()
    assert active == 1  # no duplicate insert


def test_regen_after_poison_exhaustion_not_permanently_blocked(db, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "stage_max_attempts", 1)
    session = _seed_session(db)
    sid = session["SessionID"]
    dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, 1, "77777777-7777-4777-8777-777777777777")
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, 1, "77777777-7777-4777-8777-777777777777") is False  # exhausted

    new_epoch = dal.next_epoch(db, sid, SUB["id"], (SubsystemLevel.SCENARIOS,))
    dal.reset_stage_for_regen(db, sid, SUB["id"], (SubsystemLevel.SCENARIOS,), new_epoch)
    assert dal.claim_stage(db, sid, SUB["id"], SubsystemLevel.SCENARIOS, new_epoch, "88888888-8888-4888-8888-888888888888") is True


# --- row-scoping (the real fix for the "regen wipes siblings" gap) ---
def test_regen_scenario_only_targets_one_output_siblings_untouched(db):
    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    outputs = _output_ids(db, sid)
    assert len(outputs) == 2
    target, sibling = outputs[0], outputs[1]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [target], epoch, _TwoThreatLLM(), "55555555-5555-4555-8555-555555555555")

    sibling_row = db.execute(select(m.Threat_Scenario_Output.Superseded)
                             .where(m.Threat_Scenario_Output.OutputID == sibling)).scalar()
    assert sibling_row == 0  # untouched

    target_row = db.execute(select(m.Threat_Scenario_Output.Superseded)
                            .where(m.Threat_Scenario_Output.OutputID == target)).scalar()
    assert target_row == 1  # regenerated — old one superseded

    active = db.execute(select(func.count()).select_from(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.SessionID == sid, m.Threat_Scenario_Output.Superseded == 0)).scalar()
    assert active == 2  # sibling + the freshly regenerated one — still 2 total, none lost


# --- prompt-quality fix: threat context threading survives the regen cascade ---
def _spy_scenario_prompt(monkeypatch, captured):
    real_scenario_prompt = prompts.scenario_prompt

    def _spy(asset_name, asset_context, sub, threat_type, threat_name, actors=None):
        captured.append((threat_type, threat_name))
        return real_scenario_prompt(asset_name, asset_context, sub, threat_type, threat_name, actors=actors)

    monkeypatch.setattr("app.pipeline.prompts.scenario_prompt", _spy)


def test_regen_scenario_granularity_threads_target_threat_not_sibling(db, monkeypatch):
    """Row-scoped `scenario` regen must thread THAT threat's context, not its
    sibling's — proves the enrichment survives the dal.active_threats round trip
    (not just the in-memory find_threats path the initial pipeline uses)."""
    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    target, sibling = _output_ids(db, sid)
    target_threat_id = db.execute(
        select(m.Scoped_Threat.ThreatID)
        .select_from(m.Threat_Scenario_Output.__table__.join(
            m.Scoped_Threat, m.Threat_Scenario_Output.ScopedThreatID == m.Scoped_Threat.ScopedThreatID))
        .where(m.Threat_Scenario_Output.OutputID == target)
    ).scalar()
    expected_name = db.execute(select(m.Identified_Threat.LibraryThreatName)
                               .where(m.Identified_Threat.ThreatID == target_threat_id)).scalar()
    sibling_threat_id = db.execute(
        select(m.Scoped_Threat.ThreatID)
        .select_from(m.Threat_Scenario_Output.__table__.join(
            m.Scoped_Threat, m.Threat_Scenario_Output.ScopedThreatID == m.Scoped_Threat.ScopedThreatID))
        .where(m.Threat_Scenario_Output.OutputID == sibling)
    ).scalar()
    sibling_name = db.execute(select(m.Identified_Threat.LibraryThreatName)
                              .where(m.Identified_Threat.ThreatID == sibling_threat_id)).scalar()
    assert expected_name != sibling_name  # the two threats really are distinguishable

    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    captured = []
    _spy_scenario_prompt(monkeypatch, captured)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [target], epoch, _TwoThreatLLM(), "55555555-5555-4555-8555-555555555555")

    assert len(captured) == 1
    assert captured[0][1] == expected_name  # matches the TARGET, not the sibling
