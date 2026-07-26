""""Generate next set of scenarios" — continuous, accumulating, unique, never blocked.

Each reviewer click adds 5 MORE unique scenarios that ACCUMULATE (5 → 10 → 15 → …); nothing
prior is superseded. The already-scored-but-unserved pool is served first (no AI call); only when
it can't fill the batch does ONE additive, coverage-aware find_threats run. A round that turns up
nothing new returns "no_new_threats_this_round" and blocks nothing.
"""
from __future__ import annotations

import json

from sqlalchemy import func, insert, select, update

from app.core.enums import AuditEventType, SessionStatus, StageStatus, SubsystemLevel, WorkflowStage
from app.db import dal
from app.db import models as m
from app.db.dal import load_session
from app.pipeline import cascade, prompts
from app.pipeline.accept import accept_session
from app.pipeline.reaper import clean_up_abandoned_sessions
from app.pipeline.tasks import ASSET_UNIT_ID, _process_all_supporting_systems, decide_session_outcome, find_threats
from tests.conftest import DEFAULT_ASSET_CONTEXT, StubLLM, make_client, session_body
from tests.test_slice import MAX_THREATS, SUB, _TwoThreatLLM, _active_count, _force_stage, _seed_session


class _ManyThreatLLM(StubLLM):
    """Proposes a fixed list of distinct threats (all ungrounded → each a distinct txt: identity,
    all scoring 65, clear of the 55 floor, so every one is generatable). Returns the SAME list on
    every threats call — used where the served pool alone should carry the batches."""

    def __init__(self, proposals):
        self.proposals = proposals

    def chat(self, messages, *, model=None, temperature=None):
        if "json array" in messages[0]["content"].lower():
            from app.pipeline.llm import Provenance
            return json.dumps(self.proposals), Provenance(model="stub")
        return super().chat(messages, model=model)


class _ScriptedThreatLLM(StubLLM):
    """Returns a scripted sequence of threat-proposal batches (one per find_threats call) and
    counts the threat-proposal calls it received — so a test can assert an early next-set drained
    the scored pool WITHOUT an AI call, and a later one triggered exactly one."""

    def __init__(self, batches):
        self._batches = list(batches)
        self.threat_calls = 0

    def chat(self, messages, *, model=None, temperature=None):
        if "json array" in messages[0]["content"].lower():
            from app.pipeline.llm import Provenance
            batch = self._batches[min(self.threat_calls, len(self._batches) - 1)]
            self.threat_calls += 1
            return json.dumps(batch), Provenance(model="stub")
        return super().chat(messages, model=model)


def _threats(n, start=0):
    """n distinct, ungrounded proposals — distinct names → distinct dedup identities."""
    return [{"category": "Tampering", "type": f"Novel Type {i}", "name": f"Novel Threat {i}", "actors": []}
            for i in range(start, start + n)]


def _active_scenarios(sess, sid):
    return sess.execute(select(m.Threat_Scenario_Output)
                    .where(m.Threat_Scenario_Output.SessionID == sid,
                        m.Threat_Scenario_Output.Superseded == 0)).scalars().all()


def _first_run(db, llm):
    session = _seed_session(db)
    sid = session["SessionID"]
    _process_all_supporting_systems(db, sid, llm, "11111111-1111-4111-8111-111111111111")
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW
    return dict(load_session(db, sid))


def _next_set(db, session, llm, task_id):
    """Drive one "generate next set" the way the endpoint + task do: leave REVIEW, reserve+reset
    the SCENARIOS epoch, reserve the THREATS epoch (NOT reset), run the cascade."""
    sid = session["SessionID"]
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
            .values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING,
                    UpdatedAt=dal.now()))
    epoch = dal.next_epoch(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS)
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS, epoch)
    threats_epoch = dal.next_epoch(db, sid, ASSET_UNIT_ID, (SubsystemLevel.THREATS,))
    return cascade.run_next_set(db, session, ASSET_UNIT_ID, epoch, threats_epoch, llm, task_id)


# --- accumulation: 5 → 10 → 15, unique, earlier batches stay active -----------
def test_next_set_accumulates_five_at_a_time(db):
    llm = _ManyThreatLLM(_threats(15))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    first_ids = {r.OutputID for r in _active_scenarios(db, sid)}
    assert len(first_ids) == 5

    _next_set(db, session, llm, "22222222-2222-4222-8222-222222222221")
    assert len(_active_scenarios(db, sid)) == 10

    _next_set(db, session, llm, "22222222-2222-4222-8222-222222222222")
    rows = _active_scenarios(db, sid)
    assert len(rows) == 15                                   # accumulated, nothing dropped
    assert len({r.IdentityHash for r in rows}) == 15         # every scenario unique across batches
    assert first_ids <= {r.OutputID for r in rows}           # the first batch is still active
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW


# --- pool-then-fresh: drain the scored pool (no AI call), then generate fresh --
def test_next_set_drains_pool_then_generates_fresh(db):
    llm = _ScriptedThreatLLM([_threats(10), _threats(5, start=10)])
    session = _first_run(db, llm)
    sid = session["SessionID"]
    assert len(_active_scenarios(db, sid)) == 5
    assert llm.threat_calls == 1                             # the initial run's one identify call

    _next_set(db, session, llm, "33333333-3333-4333-8333-333333333331")
    assert len(_active_scenarios(db, sid)) == 10
    assert llm.threat_calls == 1                             # served from the scored pool — NO AI call

    _next_set(db, session, llm, "33333333-3333-4333-8333-333333333332")
    assert len(_active_scenarios(db, sid)) == 15
    assert llm.threat_calls == 2                             # pool drained → one fresh coverage-aware find_threats


# --- never blocked: a repeat-only fresh batch supersedes nothing and can retry -
def test_next_set_repeat_only_returns_no_new_and_supersedes_nothing(db):
    llm = _ManyThreatLLM(_threats(5))                        # first run serves all 5 → empty pool
    session = _first_run(db, llm)
    sid = session["SessionID"]
    before = {r.OutputID for r in _active_scenarios(db, sid)}
    assert len(before) == 5

    # pool empty; the fresh AI batch only repeats the SAME 5 already-served threats
    outcome = _next_set(db, session, llm, "44444444-4444-4444-8444-444444444441")
    assert outcome == "no_new_threats_this_round"
    assert {r.OutputID for r in _active_scenarios(db, sid)} == before   # nothing superseded, nothing added
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW  # reviewable, not hard-stopped

    # a subsequent call still works — never blocked, still benign
    outcome2 = _next_set(db, session, llm, "44444444-4444-4444-8444-444444444442")
    assert outcome2 == "no_new_threats_this_round"
    assert {r.OutputID for r in _active_scenarios(db, sid)} == before


# --- additive find_threats leaves every prior row active ----------------------
def test_additive_find_threats_leaves_prior_rows_active(db):
    session = _first_run(db, _ManyThreatLLM(_threats(5)))
    sid = session["SessionID"]
    it_before = {r for r in db.execute(select(m.Identified_Threat.ThreatID).where(
        m.Identified_Threat.SessionID == sid, m.Identified_Threat.Superseded == 0)).scalars()}
    scoped_before = _active_count(db, m.Scoped_Threat)
    scen_before = len(_active_scenarios(db, sid))

    epoch = dal.next_epoch(db, sid, ASSET_UNIT_ID, (SubsystemLevel.THREATS,))
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, (SubsystemLevel.THREATS,), epoch)
    find_threats(db, session, [SUB], DEFAULT_ASSET_CONTEXT, _ManyThreatLLM(_threats(3, start=99)),
                "55555555-5555-4555-8555-555555555551", epoch=epoch, supersede=False)
    db.commit()

    it_after = {r for r in db.execute(select(m.Identified_Threat.ThreatID).where(
        m.Identified_Threat.SessionID == sid, m.Identified_Threat.Superseded == 0)).scalars()}
    assert it_before <= it_after                             # every prior threat still active
    assert len(it_after) == len(it_before) + 3               # plus the 3 new ones
    assert _active_count(db, m.Scoped_Threat) == scoped_before   # scoped rows untouched
    assert len(_active_scenarios(db, sid)) == scen_before        # scenarios untouched


# --- coverage-aware prompt: exclusion threaded in, base prompt unchanged -------
def test_threats_prompt_coverage_exclusions_included_and_base_unchanged():
    covered = prompts.threats_prompt("CAD", DEFAULT_ASSET_CONTEXT, [SUB], MAX_THREATS,
                                    exclude=["Bootloader implant", "OTA poisoning"])[0]["content"]
    assert "Bootloader implant" in covered and "OTA poisoning" in covered
    assert "ALREADY-COVERED" in covered
    base = prompts.threats_prompt("CAD", DEFAULT_ASSET_CONTEXT, [SUB], MAX_THREATS)[0]["content"]
    assert "ALREADY-COVERED" not in base                     # base prompt unchanged without an exclusion list
    assert base == prompts.threats_prompt("CAD", DEFAULT_ASSET_CONTEXT, [SUB], MAX_THREATS,
                                        exclude=[])[0]["content"]  # empty list == no exclusion


# --- accept over 3 accumulated batches accepts every active scenario ----------
def test_accept_completes_with_three_accumulated_batches(db):
    llm = _ManyThreatLLM(_threats(15))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    _next_set(db, session, llm, "66666666-6666-4666-8666-666666666661")
    _next_set(db, session, llm, "66666666-6666-4666-8666-666666666662")
    assert len(_active_scenarios(db, sid)) == 15

    accept_session(db, sid, "5", "u1")
    assert load_session(db, sid)["SessionStatus"] == SessionStatus.completed
    accepted = db.execute(select(func.count()).select_from(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.SessionID == sid, m.Threat_Scenario_Output.Superseded == 0,
        m.Threat_Scenario_Output.Accepted == 1)).scalar()
    assert accepted == 15                                    # every active scenario across all 3 batches


# --- endpoint smoke: POST .../scenarios/next-set wires through to accumulation --
def test_next_set_endpoint_accumulates(engine, monkeypatch):
    from app.db.engine import db_session
    llm = _ManyThreatLLM(_threats(15))

    def sync_pipeline(session_id):
        with db_session() as s:
            _process_all_supporting_systems(s, session_id, llm, "11111111-1111-4111-8111-111111111111")

    def sync_next_set(session_id, subsystem_id, epoch, threats_epoch):
        with db_session() as s:
            cascade.run_next_set(s, dict(dal.load_session(s, session_id)), subsystem_id, epoch,
                                threats_epoch, llm, "22222222-2222-4222-8222-222222222229")

    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", sync_pipeline)
    monkeypatch.setattr("app.api.sessions.enqueue_next_set", sync_next_set)
    client = make_client({"5"})
    sid = client.post("/v1/sessions", json=session_body(100)).json()["session_id"]

    r = client.post(f"/v1/sessions/{sid}/scenarios/next-set", json={"supporting_system_id": ASSET_UNIT_ID})
    assert r.status_code == 202
    assert r.json()["status"] == "generating"
    with db_session() as s:
        assert len(_active_scenarios(s, sid)) == 10          # 5 from the run + 5 from the next set


# =============================================================================
# Adversarially-confirmed root-cause fixes (FIX 1–5)
# =============================================================================
def _active_identified(sess, sid):
    return sess.execute(select(func.count()).select_from(m.Identified_Threat).where(
        m.Identified_Threat.SessionID == sid, m.Identified_Threat.Superseded == 0)).scalar()


class _ParseFailAdditiveLLM(StubLLM):
    """First threats call returns a normal batch; every LATER threats call returns unparseable text,
    so the ADDITIVE find_threats raises LLMResponseParseError. Models a transient additive failure."""

    def __init__(self, first_batch):
        self._first = first_batch
        self.threat_calls = 0

    def chat(self, messages, *, model=None, temperature=None):
        if "json array" in messages[0]["content"].lower():
            from app.pipeline.llm import Provenance
            self.threat_calls += 1
            if self.threat_calls == 1:
                return json.dumps(self._first), Provenance(model="stub")
            return "}{ not valid json at all", Provenance(model="stub")   # additive → parse error
        return super().chat(messages, model=model)


# --- FIX 1: additive find_threats failure re-enters REVIEW, never wedges/cancels ---------------
def test_next_set_additive_find_threats_failure_reenters_review_not_cancelled(db):
    llm = _ParseFailAdditiveLLM(_threats(5))          # first run serves all 5 → pool drained
    session = _first_run(db, llm)
    sid = session["SessionID"]
    before = {r.OutputID for r in _active_scenarios(db, sid)}
    assert len(before) == 5

    # pool empty → the additive find_threats runs and raises LLMResponseParseError
    outcome = _next_set(db, session, llm, "f1f1f1f1-1111-4111-8111-111111111111")
    assert llm.threat_calls == 2                       # the additive call did fire
    assert outcome == "no_new_threats_this_round"      # routed to the benign outcome, not a failure
    assert {r.OutputID for r in _active_scenarios(db, sid)} == before  # prior scenarios untouched
    row = load_session(db, sid)
    assert row["CurrentStage"] == WorkflowStage.REVIEW        # re-entered REVIEW, NOT cancelled
    assert row["SessionStatus"] == SessionStatus.active
    # the THREATS row was driven TERMINAL (COMPLETE), never left RUNNING (which would wedge)
    threats_status = db.execute(select(m.Subsystem_Stage_State.Status).where(
        m.Subsystem_Stage_State.SessionID == sid, m.Subsystem_Stage_State.SubsystemID == ASSET_UNIT_ID,
        m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)).scalar()
    assert threats_status == StageStatus.COMPLETE


# --- FIX 2: the reserved additive THREATS epoch is idempotent across redelivery/retry ----------
def test_next_set_redelivery_runs_additive_find_threats_once(db):
    # First run serves 5; the additive batch adds only 3 (so the pool stays < 5 on redelivery,
    # forcing the branch to be evaluated — the COMPLETE@epoch guard, NOT a full pool, is what must
    # skip the second find_threats). A 3rd scripted batch would fire if the guard were absent.
    llm = _ScriptedThreatLLM([_threats(5), _threats(3, start=5), _threats(3, start=8)])
    session = _first_run(db, llm)
    sid = session["SessionID"]
    assert llm.threat_calls == 1
    assert len(_active_scenarios(db, sid)) == 5

    # endpoint: leave REVIEW, reserve+reset SCENARIOS epoch, reserve THREATS epoch (NOT reset)
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
            .values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING,
                    UpdatedAt=dal.now()))
    scen_epoch = dal.next_epoch(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS)
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS, scen_epoch)
    threats_epoch = dal.next_epoch(db, sid, ASSET_UNIT_ID, (SubsystemLevel.THREATS,))

    # First (partial) delivery: only the additive find_threats runs at the reserved epoch, adding 3
    # new threats, then the worker "crashes" before write_scenarios (SCENARIOS still IDLE@scen_epoch).
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, (SubsystemLevel.THREATS,), threats_epoch)
    find_threats(db, session, [SUB], DEFAULT_ASSET_CONTEXT, llm, "deadbeef-0000-4000-8000-000000000000",
                epoch=threats_epoch, supersede=False)
    db.commit()
    assert llm.threat_calls == 2
    it_after_first = _active_identified(db, sid)   # 5 + 3 = 8

    # Redelivery at the SAME reserved epochs with the pool still < 5: THREATS is COMPLETE@threats_
    # epoch, so the additive find_threats must be SKIPPED — no 2nd AI call, no 2nd Identified_Threat
    # batch (without the guard, the 3rd scripted batch would fire and add 3 more threats).
    cascade.run_next_set(db, session, ASSET_UNIT_ID, scen_epoch, threats_epoch, llm,
                        "deadbeef-0000-4000-8000-000000000000")
    assert llm.threat_calls == 2                            # find_threats did NOT run again
    assert _active_identified(db, sid) == it_after_first    # no second Identified_Threat batch
    assert len(_active_scenarios(db, sid)) == 8             # 5 accumulated + 3 newly served


# --- FIX 3 Part 1: a full-run tech_gate-rejected (Selected=0) threat is never re-served ---------
def _seed_tech_gate_rule(db):
    """A tech_gate on type 10 requiring asset_type 'Operational Technology (OT)'; the seeded CAD
    subsystem is 'Physical infrastructure', so every type-10 threat is permanently gated out."""
    db.execute(insert(m.Config_Threat_Rule).values(
        ThreatRuleID=1, RuleType="tech_gate", ThreatTypeID=10, RuleKey="asset_type",
        RuleValue="Operational Technology (OT)", Metadata=None, IsActive=True, IsDeleted=False))
    db.commit()


def test_next_unserved_excludes_full_run_tech_gate_rejected(db):
    _seed_tech_gate_rule(db)
    session = _first_run(db, _TwoThreatLLM())         # type-10 gated, type-11 served
    sid = session["SessionID"]
    assert len(_active_scenarios(db, sid)) == 1        # only the type-11 scenario
    # the gated type-10 threat has a Selected=0 scoped row but no scenario — it must NOT be re-served
    # (a beyond-top-N Selected=0 threat stays servable — see test_next_set_drains_pool_then_generates_fresh)
    assert dal.next_unserved_unique_threats(db, sid, ASSET_UNIT_ID, 5) == []


# --- FIX 3 Part 2: a FRESH mid-next-set tech_gate rejection is marked and not re-picked ---------
def test_next_set_fresh_tech_gate_target_marked_and_not_repicked(db):
    _seed_tech_gate_rule(db)
    # first run serves a type-11 threat; the additive next-set batch proposes a type-10 (gated) one.
    llm = _ScriptedThreatLLM([
        [{"category": "Tampering", "type": "Config Tampering", "name": "OTA poisoning", "actors": ["Hacker"]}],
        [{"category": "Tampering", "type": "Firmware Tampering", "name": "Bootloader implant", "actors": ["Hacker"]}],
    ])
    session = _first_run(db, llm)
    sid = session["SessionID"]
    assert len(_active_scenarios(db, sid)) == 1        # only the type-11 scenario, pool now empty

    outcome = _next_set(db, session, llm, "f3f3f3f3-3333-4333-8333-333333333333")
    assert outcome == "no_new_threats_this_round"      # the fresh type-10 target rescored out (gated)

    # Part 2: the gated fresh type-10 threat now has an active Selected=0 Scoped_Threat marker ...
    type10_ids = set(db.execute(select(m.Identified_Threat.ThreatID).where(
        m.Identified_Threat.SessionID == sid, m.Identified_Threat.ThreatTypeID == 10,
        m.Identified_Threat.Superseded == 0)).scalars())
    sel0_ids = set(db.execute(select(m.Scoped_Threat.ThreatID).where(
        m.Scoped_Threat.SessionID == sid, m.Scoped_Threat.Selected == 0,
        m.Scoped_Threat.Superseded == 0)).scalars())
    assert type10_ids and type10_ids <= sel0_ids       # marker persisted for the fresh gated threat
    # ... and Part 1's filter means it is never re-served on a repeat click
    assert dal.next_unserved_unique_threats(db, sid, ASSET_UNIT_ID, 5) == []


# --- FIX 4: a single-subsystem next-set failure with salvageable scenarios goes to REVIEW -------
def test_reaper_salvages_single_subsystem_next_set_failure_to_review(db):
    llm = _ManyThreatLLM(_threats(10))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    assert len(_active_scenarios(db, sid)) == 5         # accumulated scenarios present

    # Simulate the endpoint leaving REVIEW + reserving the SCENARIOS epoch, then a worker that took
    # the lock, claimed SCENARIOS, and DIED mid-next-set (both rows RUNNING with an expired lease).
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
            .values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING,
                    UpdatedAt=dal.now()))
    scen_epoch = dal.next_epoch(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS)
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS, scen_epoch)
    db.execute(update(m.Subsystem_Stage_State)
            .where(m.Subsystem_Stage_State.SessionID == sid,
                m.Subsystem_Stage_State.SubsystemID == ASSET_UNIT_ID,
                m.Subsystem_Stage_State.Level.in_([SubsystemLevel.SCENARIOS, SubsystemLevel.LOCK]))
            .values(Status=StageStatus.RUNNING, ActiveTaskID="deadbeef-0000-4000-8000-000000000009",
                    LeaseExpiresAt=dal.now().replace(year=2000)))
    db.commit()

    clean_up_abandoned_sessions(db)
    row = load_session(db, sid)
    assert row["CurrentStage"] == WorkflowStage.REVIEW        # salvaged, NOT cancelled
    assert row["SessionStatus"] == SessionStatus.active
    assert len(_active_scenarios(db, sid)) == 5               # accumulated scenarios preserved


def test_first_run_error_with_zero_scenarios_still_cancels(db):
    session = _seed_session(db)                          # fresh session, no scenarios committed
    sid = session["SessionID"]
    for level in (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS):
        _force_stage(db, sid, ASSET_UNIT_ID, level, StageStatus.ERROR)
    assert decide_session_outcome(db, session) == "cancelled"   # nothing to salvage → still cancels
    assert load_session(db, sid)["SessionStatus"] == SessionStatus.cancelled


# --- FIX 5: repeat-only next-set clicks do NOT grow the active Identified_Threat count ----------
def test_next_set_repeat_clicks_do_not_grow_identified_threats(db):
    llm = _ManyThreatLLM(_threats(5))                   # first run serves all 5, pool empty
    session = _first_run(db, llm)
    sid = session["SessionID"]
    assert _active_identified(db, sid) == 5
    _next_set(db, session, llm, "f5f5f5f5-5555-4555-8555-555555555551")  # additive re-proposes same 5
    assert _active_identified(db, sid) == 5              # no dead-row leak
    _next_set(db, session, llm, "f5f5f5f5-5555-4555-8555-555555555552")
    assert _active_identified(db, sid) == 5


# =============================================================================
# Second-round adversarially-confirmed root-cause fixes (FIX A–D)
# =============================================================================
def _scen_status(sess, sid):
    return sess.execute(select(m.Subsystem_Stage_State.Status).where(
        m.Subsystem_Stage_State.SessionID == sid, m.Subsystem_Stage_State.SubsystemID == ASSET_UNIT_ID,
        m.Subsystem_Stage_State.Level == SubsystemLevel.SCENARIOS)).scalar()


def _threats_epoch(sess, sid):
    return sess.execute(select(m.Subsystem_Stage_State.GenerationEpoch).where(
        m.Subsystem_Stage_State.SessionID == sid, m.Subsystem_Stage_State.SubsystemID == ASSET_UNIT_ID,
        m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)).scalar()


# --- FIX A: accept after a salvage-to-REVIEW must actually accept the active scenarios -----------
def test_accept_after_salvage_marks_scenarios_accepted(db):
    """A next-set failure that ERROR'd the SCENARIOS stage but left committed, reviewable scenarios
    is salvaged to REVIEW; a later accept-all must mark those scenarios Accepted and complete the
    session — NEVER a 0-scenario silent completion. Restores the board invariant: a session at
    REVIEW/AWAITING_DECISION has >=1 subsystem SCENARIOS row at AWAITING_DECISION."""
    llm = _ManyThreatLLM(_threats(10))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    assert len(_active_scenarios(db, sid)) == 5

    # Endpoint left REVIEW; a next-set then failed via _record_failure — both work stages ERROR while
    # the 5 already-committed scenarios stay active.
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
            .values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING,
                    UpdatedAt=dal.now()))
    for level in (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS):
        _force_stage(db, sid, ASSET_UNIT_ID, level, StageStatus.ERROR, error="boom")
    db.commit()

    assert decide_session_outcome(db, dict(load_session(db, sid))) == "review"
    assert _scen_status(db, sid) == StageStatus.AWAITING_DECISION   # ERRORed SCENARIOS revived

    accept_session(db, sid, "5", "u1")
    assert load_session(db, sid)["SessionStatus"] == SessionStatus.completed
    accepted = db.execute(select(func.count()).select_from(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.SessionID == sid, m.Threat_Scenario_Output.Superseded == 0,
        m.Threat_Scenario_Output.Accepted == 1)).scalar()
    assert accepted == 5                                            # every salvaged scenario accepted


# --- FIX B: the reset epoch fence never moves a stage row backward -------------------------------
def test_reset_stage_for_regen_never_moves_epoch_backward(db):
    """A stale reset whose reserved epoch is behind the live one is a no-op, never a backward move
    (mirrors claim_stage/finish_stage epoch fencing)."""
    session = _first_run(db, _ManyThreatLLM(_threats(5)))
    sid = session["SessionID"]
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, (SubsystemLevel.THREATS,), 9)   # forward: applies
    db.commit()
    assert _threats_epoch(db, sid) == 9
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, (SubsystemLevel.THREATS,), 4)   # backward: no-op
    db.commit()
    assert _threats_epoch(db, sid) == 9                                           # NOT moved back to 4


# --- FIX B: a stale redelivery behind the live THREATS epoch never downgrades / re-runs ----------
def test_next_set_stale_redelivery_behind_live_epoch_no_downgrade(db):
    """The == COMPLETE guard missed a THREATS row that had ADVANCED to a NEWER epoch, so a stale
    redelivery (reserved threats_epoch BEHIND the live epoch) downgraded THREATS and re-fired
    find_threats. The >= guard + reset fence must skip it entirely."""
    llm = _ScriptedThreatLLM([_threats(5), _threats(3, start=5)])
    session = _first_run(db, llm)
    sid = session["SessionID"]
    assert llm.threat_calls == 1
    assert len(_active_scenarios(db, sid)) == 5           # pool drained

    e0 = _threats_epoch(db, sid)
    # THREATS has since advanced two generations past e0 and settled COMPLETE (a later next-set ran).
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, (SubsystemLevel.THREATS,), e0 + 2)
    _force_stage(db, sid, ASSET_UNIT_ID, SubsystemLevel.THREATS, StageStatus.COMPLETE)
    db.commit()

    # A stale redelivery carrying threats_epoch = e0+1 (behind live e0+2); reserve+reset a fresh
    # SCENARIOS epoch as the endpoint would and leave REVIEW.
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
            .values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING,
                    UpdatedAt=dal.now()))
    scen_epoch = dal.next_epoch(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS)
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS, scen_epoch)
    db.commit()

    cascade.run_next_set(db, session, ASSET_UNIT_ID, scen_epoch, e0 + 1, llm,
                        "deadbeef-0000-4000-8000-00000000000b")

    assert llm.threat_calls == 1                          # additive find_threats did NOT re-run
    assert _threats_epoch(db, sid) == e0 + 2              # THREATS not downgraded to e0+1
    assert db.execute(select(m.Subsystem_Stage_State.Status).where(
        m.Subsystem_Stage_State.SessionID == sid, m.Subsystem_Stage_State.SubsystemID == ASSET_UNIT_ID,
        m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)).scalar() == StageStatus.COMPLETE


# --- FIX C: a pool zombie (active scoped, no active scenario) rescored out is not re-served -------
def test_next_set_pool_zombie_rescored_out_is_superseded_and_not_reserved(db):
    """A previously-served pool threat that keeps an active Scoped_Threat row (Selected=1) but has no
    active scenario, then rescored OUT by a mid-session tech_gate, must be superseded + re-marked
    Selected=0 — not re-served on every click. The old gate keyed on "has active scoped row" spared
    it (a zombie HAS one) so it looped forever."""
    session = _first_run(db, _TwoThreatLLM())             # type-10 + type-11 both scored & generated
    sid = session["SessionID"]
    assert len(_active_scenarios(db, sid)) == 2

    # Manufacture the zombie: type-10 keeps its active Selected=1 scoped row, but its scenario is
    # superseded — so it re-enters the servable pool (Selected==1) with no active scenario.
    t10 = db.execute(select(m.Identified_Threat.ThreatID).where(
        m.Identified_Threat.SessionID == sid, m.Identified_Threat.ThreatTypeID == 10,
        m.Identified_Threat.Superseded == 0)).scalar()
    sc10 = db.execute(select(m.Scoped_Threat.ScopedThreatID).where(
        m.Scoped_Threat.SessionID == sid, m.Scoped_Threat.ThreatID == t10,
        m.Scoped_Threat.Superseded == 0)).scalar()
    db.execute(update(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.SessionID == sid, m.Threat_Scenario_Output.ScopedThreatID == sc10)
        .values(Superseded=1))
    db.commit()
    assert t10 in dal.next_unserved_unique_threats(db, sid, ASSET_UNIT_ID, 5)   # zombie is servable

    _seed_tech_gate_rule(db)                              # mid-session: type-10 now permanently gated
    outcome = _next_set(db, session, _TwoThreatLLM(), "fcfcfcfc-0000-4000-8000-00000000000c")
    assert outcome == "no_new_threats_this_round"         # the served zombie rescored out (gated)

    # The stale Selected=1 scoped row is superseded; a fresh Selected=0 tech_gate marker replaces it.
    assert db.execute(select(func.count()).select_from(m.Scoped_Threat).where(
        m.Scoped_Threat.SessionID == sid, m.Scoped_Threat.ThreatID == t10,
        m.Scoped_Threat.Selected == 1, m.Scoped_Threat.Superseded == 0)).scalar() == 0
    marker = db.execute(select(m.Scoped_Threat.Reason).where(
        m.Scoped_Threat.SessionID == sid, m.Scoped_Threat.ThreatID == t10,
        m.Scoped_Threat.Selected == 0, m.Scoped_Threat.Superseded == 0)).scalar()
    assert marker is not None and "tech_gate" in marker
    assert dal.next_unserved_unique_threats(db, sid, ASSET_UNIT_ID, 5) == []   # never re-served


# --- FIX D: a redelivery of an already-landed next-set is benign, not a spurious error -----------
def test_next_set_redelivery_after_success_no_error(db, monkeypatch):
    """A redelivery re-executing at the SAME epoch finds SCENARIOS already AWAITING_DECISION;
    write_scenarios' claim_stage no-ops and returns [] — that must fall through to
    decide_session_outcome, NOT raise -> _record_failure -> a spurious error SSE."""
    published: list = []
    monkeypatch.setattr("app.sse.bus.publish", lambda sid_, event: published.append(event))

    llm = _ManyThreatLLM(_threats(15))
    session = _first_run(db, llm)
    sid = session["SessionID"]

    # A first, fully successful next-set at captured epochs (5 -> 10 scenarios).
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
            .values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING,
                    UpdatedAt=dal.now()))
    scen_epoch = dal.next_epoch(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS)
    dal.reset_stage_for_regen(db, sid, ASSET_UNIT_ID, cascade.NEXT_SET_LEVELS, scen_epoch)
    threats_epoch = dal.next_epoch(db, sid, ASSET_UNIT_ID, (SubsystemLevel.THREATS,))
    db.commit()
    task_id = "deadbeef-0000-4000-8000-00000000000d"
    cascade.run_next_set(db, session, ASSET_UNIT_ID, scen_epoch, threats_epoch, llm, task_id)
    assert len(_active_scenarios(db, sid)) == 10
    published.clear()

    # Redelivery at the SAME epochs + task_id: SCENARIOS is already AWAITING_DECISION@scen_epoch.
    outcome = cascade.run_next_set(db, session, ASSET_UNIT_ID, scen_epoch, threats_epoch, llm, task_id)

    assert outcome != "error"
    assert not any(str(e.get("type")) == "error" for e in published)   # NO spurious error SSE
    assert db.execute(select(func.count()).select_from(m.Scenario_Audit).where(
        m.Scenario_Audit.SessionID == sid,
        m.Scenario_Audit.EventType == AuditEventType.stage_error)).scalar() == 0
    assert len(_active_scenarios(db, sid)) == 10                        # idempotent, unchanged
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW
    assert _scen_status(db, sid) == StageStatus.AWAITING_DECISION       # not flipped to ERROR
