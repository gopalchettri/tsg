"""Variant scenarios — multiple coexisting scenarios per threat (ScenarioNumber; schema change
2026-07-29, applied by TSG_Core.sql — this project is database-first, no alembic).

When "generate next set" finds nothing genuinely new (`no_new_threats_found`), it falls back to
writing ONE alternate scenario per already-covered threat, at the identity's next free
ScenarioNumber, up to the configurable max_scenarios_per_threat cap (default 2). Uniqueness is
steered in the prompt (variant_scenario_prompt carries the sibling texts) and checked in code
(difflib) — a near-duplicate is KEPT and visibly flagged through the normal validation report,
never discarded: the human reviewer sees both cards grouped by threat_id/scenario_number and
accepts whichever they like.

Regeneration is row-addressed end to end (tasks.RegenTarget): regenerating scenario #2 touches
only #2, regenerating both of a threat's scenarios in one call produces exactly two
replacements — the old set[ThreatID] collapse is structurally gone.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.enums import RegenGranularity, ScenarioStatus, SubsystemLevel, WorkflowStage
from app.db import dal, invariants
from app.db import models as m
from app.db.dal import load_session
from app.pipeline import cascade
from app.pipeline.llm import LLMSlotUnavailable, Provenance
from app.pipeline.tasks import ASSET_UNIT_ID
from tests.conftest import StubLLM, make_client
from tests.test_cascade import _leave_review, _reserve_epoch
from tests.test_next_set import (_active_scenarios, _first_run, _ManyThreatLLM, _next_set,
                                _ScriptedThreatLLM, _threats)


def _rows(db, sid):
    return db.execute(
        select(m.Threat_Scenario_Output.OutputID, m.Threat_Scenario_Output.IdentityHash,
            m.Threat_Scenario_Output.ScenarioNumber, m.Threat_Scenario_Output.Status,
            m.Threat_Scenario_Output.ScopedThreatID, m.Threat_Scenario_Output.ValidationJSON)
        .where(m.Threat_Scenario_Output.SessionID == sid,
            m.Threat_Scenario_Output.Superseded == 0)).all()


def _validation_errors(row) -> list[str]:
    return list((json.loads(row.ValidationJSON) or {}).get("errors") or [])


_SIMILAR_MARK = "very similar to this threat's other scenario"


class _CountingLLM(_ManyThreatLLM):
    """_ManyThreatLLM plus call counters, to pin the LLM budget (one chat call per scenario,
    one finder per click — never a retry or a separate verification call)."""

    def __init__(self, proposals):
        super().__init__(proposals)
        self.threat_calls = 0
        self.scenario_calls = 0

    def chat(self, messages, *, model=None, temperature=None):
        if "json array" in messages[0]["content"].lower():
            self.threat_calls += 1
        else:
            self.scenario_calls += 1
        return super().chat(messages, model=model)


class _VariedVariantLLM(_ManyThreatLLM):
    """Primary scenarios get statement A; variant calls (their prompt carries the sibling
    block) get a genuinely different statement B — so the difflib guard has a real 'different
    enough' case to pass."""

    _A = ("The asset is compromised when a contractor's stolen VPN credentials are used to "
        "reach the engineering workstation and alter the asset's control logic remotely.")
    _B = ("An insider with legitimate badge access connects a rogue device to the maintenance "
        "network after hours and quietly exfiltrates the asset's operational telemetry.")

    def chat(self, messages, *, model=None, temperature=None):
        sysc = messages[0]["content"]
        if "json array" in sysc.lower():
            return super().chat(messages, model=model)
        statement = self._B if "ALREADY has the following scenario" in sysc else self._A
        out = {"scenario_title": "Bootloader implant on CAD", "scenario_statement": statement,
            "risk_statement": "R"}
        return json.dumps(out), Provenance(model="stub")


class _FailOnScenarioCallLLM(_ManyThreatLLM):
    """Fails (unparseable text) on the Nth scenario-writing call, counting from 1 across the
    stub's lifetime — models one variant in a batch dying mid-flight."""

    def __init__(self, proposals, fail_on: set[int]):
        super().__init__(proposals)
        self.scenario_calls = 0
        self.fail_on = fail_on

    def chat(self, messages, *, model=None, temperature=None):
        if "json array" not in messages[0]["content"].lower():
            self.scenario_calls += 1
            if self.scenario_calls in self.fail_on:
                return "}{ not valid json at all", Provenance(model="stub")
        return super().chat(messages, model=model)


# --- creation: own scoped row per variant, distinct numbers, boot invariant satisfied ----------
def test_variants_have_own_scoped_rows_and_pass_active_unique(engine, db):
    llm = _ManyThreatLLM(_threats(3))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    assert len(_active_scenarios(db, sid)) == 3

    outcome = _next_set(db, session, llm, "aaaa0001-0000-4000-8000-000000000001")
    assert outcome == "review"
    rows = _rows(db, sid)
    assert len(rows) == 6
    by_hash: dict[str, list] = {}
    for r in rows:
        by_hash.setdefault(r.IdentityHash, []).append(r)
    for group in by_hash.values():
        assert sorted(r.ScenarioNumber for r in group) == [1, 2]
        # each variant has its OWN Scoped_Threat row — never the primary's (ACTIVE_UNIQUE)
        assert len({r.ScopedThreatID for r in group}) == 2
    # the boot-time live scan the app refuses to start without — must hold with variants present
    invariants._assert_no_duplicate_active(engine)


# --- keep-and-flag: a near-identical variant is inserted AND visibly warned, one call each ----
def test_similar_variant_kept_and_flagged(db):
    llm = _CountingLLM(_threats(3))  # StubLLM's canned statement "S" every time → identical
    session = _first_run(db, llm)
    sid = session["SessionID"]
    calls_before = llm.scenario_calls

    _next_set(db, session, llm, "aaaa0002-0000-4000-8000-000000000002")
    variants = [r for r in _rows(db, sid) if r.ScenarioNumber == 2]
    assert len(variants) == 3                                # kept, never discarded
    for r in variants:
        assert any(_SIMILAR_MARK in e for e in _validation_errors(r))
        assert (json.loads(r.ValidationJSON) or {}).get("validation_status") == "warning"
    # exactly one generation call per variant — no retry even when flagged as too similar
    assert llm.scenario_calls - calls_before == 3


def test_genuinely_different_variant_not_flagged(db):
    llm = _VariedVariantLLM(_threats(2))
    session = _first_run(db, llm)
    sid = session["SessionID"]

    _next_set(db, session, llm, "aaaa0003-0000-4000-8000-000000000003")
    variants = [r for r in _rows(db, sid) if r.ScenarioNumber == 2]
    assert len(variants) == 2
    for r in variants:
        assert not any(_SIMILAR_MARK in e for e in _validation_errors(r))


# --- number-aware regen: the §1b root-cause fix -----------------------------------------------
def test_regen_of_variant_touches_only_its_own_row(db):
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    _next_set(db, session, llm, "aaaa0004-0000-4000-8000-000000000004")
    rows = {r.ScenarioNumber: r for r in _rows(db, sid)}
    primary, variant = rows[1], rows[2]

    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)
    outcome = cascade.run_regeneration(db, dict(load_session(db, sid)), ASSET_UNIT_ID,
                                    RegenGranularity.scenario, [variant.OutputID], epoch,
                                    StubLLM(), "aaaa0004-0000-4000-8000-00000000000f")
    assert outcome == "review"
    after = {r.ScenarioNumber: r for r in _rows(db, sid)}
    assert len(after) == 2
    assert after[1].OutputID == primary.OutputID             # #1 untouched
    assert after[2].OutputID != variant.OutputID             # #2 replaced...
    assert after[2].ScenarioNumber == 2                      # ...AT its own number
    # the primary's scoring row survived its sibling's regeneration (row-scoped supersede)
    assert db.execute(select(m.Scoped_Threat.Superseded).where(
        m.Scoped_Threat.ScopedThreatID == primary.ScopedThreatID)).scalar() == 0
    # regen-with-sibling routes through the same similarity guard: StubLLM's identical "S"
    # statement is kept but visibly flagged on the replacement
    assert any(_SIMILAR_MARK in e for e in _validation_errors(after[2]))


def test_regen_both_scenarios_in_one_call_replaces_both(db):
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    _next_set(db, session, llm, "aaaa0005-0000-4000-8000-000000000005")
    before = {r.ScenarioNumber: r.OutputID for r in _rows(db, sid)}

    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)
    outcome = cascade.run_regeneration(db, dict(load_session(db, sid)), ASSET_UNIT_ID,
                                    RegenGranularity.scenario, list(before.values()), epoch,
                                    StubLLM(), "aaaa0005-0000-4000-8000-00000000000f")
    assert outcome == "review"
    after = {r.ScenarioNumber: r.OutputID for r in _rows(db, sid)}
    # the old set(ThreatID) collapse produced ONE replacement here; RegenTarget produces TWO,
    # one per scenario number, and the total never changes
    assert sorted(after) == [1, 2]
    assert after[1] != before[1] and after[2] != before[2]


# --- failure semantics: skip-and-log, no error card, still eligible ----------------------------
def test_failed_variant_skipped_without_error_card_and_stays_eligible(db):
    # first run writes 3 scenarios (calls 1-3); the variant batch is calls 4-6; call 5 dies
    llm = _FailOnScenarioCallLLM(_threats(3), fail_on={5})
    session = _first_run(db, llm)
    sid = session["SessionID"]

    outcome = _next_set(db, session, llm, "aaaa0006-0000-4000-8000-000000000006")
    assert outcome == "review"
    rows = _rows(db, sid)
    assert len(rows) == 5                                     # 3 primaries + 2 variants
    assert all(r.Status == ScenarioStatus.complete for r in rows)  # NO error card anywhere
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW  # never ERROR/cancelled
    # the failed threat is still eligible — the next click is its retry
    eligible = dal.variant_eligible_primaries(db, sid, ASSET_UNIT_ID, 5,
                                            get_settings().max_scenarios_per_threat)
    assert len(eligible) == 1
    assert eligible[0]["next_number"] == 2


def test_error_card_only_threat_gets_no_variant(db):
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    # flip the only scenario to a failure card: no sibling text exists to steer/compare against
    db.execute(update(m.Threat_Scenario_Output).where(m.Threat_Scenario_Output.SessionID == sid)
            .values(Status=ScenarioStatus.error, ScenarioJSON=None))
    db.commit()
    assert dal.variant_eligible_primaries(db, sid, ASSET_UNIT_ID, 5,
                                        get_settings().max_scenarios_per_threat) == []


# --- the configurable cap ----------------------------------------------------------------------
def test_configurable_cap_opens_third_scenario(db, monkeypatch):
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    _next_set(db, session, llm, "aaaa0007-0000-4000-8000-000000000007")
    assert sorted(r.ScenarioNumber for r in _rows(db, sid)) == [1, 2]

    # at the default cap (2): the honest no_new outcome, nothing added
    assert _next_set(db, session, llm, "aaaa0007-0000-4000-8000-000000000008") == "no_new_threats_this_round"
    assert len(_rows(db, sid)) == 2

    # raise the cap by CONFIG alone — the same threat becomes eligible again, lands at #3
    monkeypatch.setattr(get_settings(), "max_scenarios_per_threat", 3)
    assert _next_set(db, session, llm, "aaaa0007-0000-4000-8000-000000000009") == "review"
    assert sorted(r.ScenarioNumber for r in _rows(db, sid)) == [1, 2, 3]


# --- the DB race guard is real in CI (conftest creates the partial unique index on SQLite) ------
def test_second_row_at_same_identity_and_number_is_impossible(db):
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    _next_set(db, session, llm, "aaaa0008-0000-4000-8000-00000000000a")
    variant = next(r for r in _rows(db, sid) if r.ScenarioNumber == 2)

    with pytest.raises(IntegrityError):
        db.execute(insert(m.Threat_Scenario_Output), [{
            "OutputID": "aaaa0008-0000-4000-8000-00000000000b", "SessionID": sid,
            "TenantID": "default", "EntityID": "5", "UserID": "u1", "SubsystemID": ASSET_UNIT_ID,
            "ScopedThreatID": variant.ScopedThreatID, "Status": ScenarioStatus.complete,
            "ScenarioJSON": "{}", "ValidationJSON": None, "Accepted": 0, "Superseded": 0,
            "IdentityHash": variant.IdentityHash, "ScenarioNumber": 2, "GenerationEpoch": 9,
            "ErrorMessage": None, "CreatedAt": dal.now()}])
    db.rollback()


# --- the shared finalizer runs for the variant batch (Step-4 mapping is never skipped) ----------
def test_variant_batch_runs_control_mapping_finalizer(db, monkeypatch):
    llm = _ManyThreatLLM(_threats(2))
    session = _first_run(db, llm)
    sid = session["SessionID"]

    calls: list = []
    monkeypatch.setattr("app.pipeline.tasks.control_mapping.map_controls",
                        lambda *a, **k: calls.append(a))
    outcome = _next_set(db, session, llm, "aaaa0009-0000-4000-8000-00000000000c")
    assert outcome == "review"
    assert len([r for r in _rows(db, sid) if r.ScenarioNumber == 2]) == 2
    assert len(calls) == 1  # write_variant_scenarios routed through _finalize_scenario_batch


# --- the _LOCK lease is pushed forward across the whole click, not stamped once ----------------
def test_lock_lease_is_renewed_while_variants_generate(db):
    """acquire_lock stamps LeaseExpiresAt once. The variant top-up generates AFTER finish_stage
    NULLed the SCENARIOS lease, so the _LOCK lease is the click's only proof of life — if it is
    never pushed forward, normal per-call latency lets it expire, the reaper reclaims the lock to
    IDLE, and a redelivery or a fresh click becomes a second writer on the subsystem."""
    llm = _ManyThreatLLM(_threats(2))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    def lock_lease():
        return db.execute(select(m.Subsystem_Stage_State.LeaseExpiresAt).where(
            m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.SubsystemID == ASSET_UNIT_ID,
            m.Subsystem_Stage_State.Level == SubsystemLevel.LOCK)).scalar()

    # drive the click, then pin that the renewal CAS actually matches the LOCK row: calling it
    # directly for the holder must land, and for a different task_id (a stale holder) must not.
    _next_set(db, session, llm, "aaaa000d-0000-4000-8000-000000000010")
    assert dal.acquire_lock(db, sid, ASSET_UNIT_ID, "aaaa000d-0000-4000-8000-000000000011")
    db.commit()
    before = lock_lease()
    assert dal.renew_lock_lease(db, sid, ASSET_UNIT_ID, "aaaa000d-0000-4000-8000-000000000011")
    db.commit()
    assert lock_lease() >= before
    # fenced on ActiveTaskID — a task that no longer holds the lock cannot extend it
    assert not dal.renew_lock_lease(db, sid, ASSET_UNIT_ID, "aaaa000d-0000-4000-8000-0000000000ff")


# --- the helper's early-exits are load-bearing, not decoration ---------------------------------
def test_no_variant_audit_row_when_nothing_was_created(db):
    """`if created:` guards the audit write. Without it every at-cap click would append a
    generation_complete row claiming variants_generated: 0 — a ledger entry for work never done."""
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    _next_set(db, session, llm, "aaaa000e-0000-4000-8000-000000000012")      # lands #2, at cap now
    assert _next_set(db, session, llm, "aaaa000e-0000-4000-8000-000000000013") == "no_new_threats_this_round"

    details = [json.loads(d) for (d,) in db.execute(
        select(m.Scenario_Audit.DetailJSON).where(
            m.Scenario_Audit.SessionID == sid,
            m.Scenario_Audit.EventType == "generation_complete")).all()]
    assert not [d for d in details if d.get("variants_generated") == 0]


def test_top_up_is_a_no_op_when_the_pool_filled_the_batch(db, monkeypatch):
    """`if shortfall <= 0` must short-circuit BEFORE the eligibility query: a full batch has no
    empty slots, so a click that served next_set_size threats must not generate a single variant."""
    called: list = []
    real = cascade.tasks.write_variant_scenarios
    monkeypatch.setattr("app.pipeline.tasks.write_variant_scenarios",
                        lambda *a, **k: (called.append(k.get("max_variants")), real(*a, **k))[1])
    llm = _ManyThreatLLM(_threats(10))          # first run serves 5, next-set serves the other 5
    session = _first_run(db, llm)
    sid = session["SessionID"]

    _next_set(db, session, llm, "aaaa000f-0000-4000-8000-000000000014")
    assert len(_rows(db, sid)) == 10
    assert all(r.ScenarioNumber == 1 for r in _rows(db, sid))
    assert called == []                          # never even reached write_variant_scenarios


# --- PARTIAL batch: the pool serves fewer than next_set_size, variants fill the rest -----------
def _threat_ids_by_output(db, sid):
    """OutputID -> ThreatID, via the output's own scoped row (each variant has its OWN one)."""
    return {r.OutputID: r.ThreatID for r in db.execute(
        select(m.Threat_Scenario_Output.OutputID, m.Scoped_Threat.ThreatID)
        .join(m.Scoped_Threat,
            m.Scoped_Threat.ScopedThreatID == m.Threat_Scenario_Output.ScopedThreatID)
        .where(m.Threat_Scenario_Output.SessionID == sid,
            m.Threat_Scenario_Output.Superseded == 0)).all()}


def test_partial_pool_is_topped_up_to_the_batch_size_with_other_threats_variants(db, monkeypatch):
    """The reported bug: a click that could only serve 3 of the configured 5 stopped at 3, with no
    top-up and no explanation, because the variant fallback hung off RegenerateConflict — which
    only fires at ZERO. Also pins F1: the top-up must NOT pick the threats this same click just
    served (they are active, COMPLETE and highest-scored, so they'd sort to the front)."""
    published: list = []
    monkeypatch.setattr("app.sse.bus.publish", lambda sid_, event: published.append(event))
    # first run serves 5; the additive round yields only 3, so the pool is short by 2
    llm = _ScriptedThreatLLM([_threats(5), _threats(3, start=5)])
    session = _first_run(db, llm)
    sid = session["SessionID"]
    served_first = set(_threat_ids_by_output(db, sid).values())
    assert len(_rows(db, sid)) == 5
    # Reproduce the documented hazard DETERMINISTICALLY: demote the five already-served threats
    # so the three this click is about to serve are strictly the highest-scored rows in the
    # session and would sort to the FRONT of the eligibility list. Without this the whole fixture
    # is tied at 65.0 and variant_eligible_primaries falls through to its `str(threat_id)`
    # tie-break over random uuid4s — the F1 assertion below would then be a coin flip that stays
    # green ~36% of the time (C(5,2)/C(8,2)) with `exclude=set(fresh)` deleted from cascade.py.
    db.execute(update(m.Scoped_Threat).where(m.Scoped_Threat.SessionID == sid).values(Score=10.0))
    db.commit()

    assert _next_set(db, session, llm, "aaaa000a-0000-4000-8000-00000000000d") == "review"

    rows = _rows(db, sid)
    assert len(rows) == 10                                       # 5 + 3 served + 2 topped up
    variants = [r for r in rows if r.ScenarioNumber == 2]
    assert len(variants) == 2
    by_output = _threat_ids_by_output(db, sid)
    # F1: the variants belong to the ORIGINAL five, never to the 3 this click just served
    variant_threats = {str(by_output[r.OutputID]).lower() for r in variants}
    assert variant_threats <= {str(t).lower() for t in served_first}

    # the click reports the full batch and is honest about the split — and carries NO reason,
    # because a short result has several causes the code cannot tell apart
    event = [e for e in published if str(e.get("type")) == "next_set_result"][-1]
    assert (event["new_scenarios"], event["new_variants"], event["no_new"]) == (5, 2, False)
    assert event.get("reason") is None

    # A topped-up click leaves TWO generation_complete rows that SUM to the click total: the
    # productive one staged inside write_scenarios' transaction, plus the helper's variant row.
    # Reading only the latest would report 2, not 5 — pin the sum so neither row can be dropped.
    details = [json.loads(d) for (d,) in db.execute(
        select(m.Scenario_Audit.DetailJSON).where(
            m.Scenario_Audit.SessionID == sid,
            m.Scenario_Audit.EventType == "generation_complete")).all()]
    this_click = [d for d in details if d.get("next_set")]
    assert sum(d["new_scenarios"] for d in this_click) == 5
    assert [d["variants_generated"] for d in this_click if "variants_generated" in d] == [2]


def test_shortfall_from_a_FAILED_generation_is_not_papered_over_with_variants(db, monkeypatch):
    """F2: shortfall is measured against the POOL, never against how many scenarios survived. A
    generation that FAILED already reports itself through the stage row's partial_error; filling
    its slot with filler would hide a real failure and contradict that message. The naive
    `next_set_size - made` would see 4-of-5 here and wrongly manufacture a variant."""
    published: list = []
    monkeypatch.setattr("app.sse.bus.publish", lambda sid_, event: published.append(event))
    # 10 threats: first run serves 5 (calls 1-5), the next-set click serves the other 5 (calls
    # 6-10) with the FULL pool — so the pool is short by nothing. Call 7 dies mid-batch.
    llm = _FailOnScenarioCallLLM(_threats(10), fail_on={7})
    session = _first_run(db, llm)
    sid = session["SessionID"]
    assert len(_rows(db, sid)) == 5

    _next_set(db, session, llm, "aaaa000c-0000-4000-8000-00000000000f")

    rows = _rows(db, sid)
    # 5 + 4 survivors. A TARGETED failure inserts no row at all (tasks.py's `if not targeted:` —
    # an error card would collide with the still-active scenario under the same IdentityHash), so
    # the failure is invisible in the row count. That is exactly why the shortfall must come from
    # the pool: `next_set_size - made` would read 5-4 here and manufacture one bogus variant to
    # cover a generation that failed, hiding it behind filler.
    assert len(rows) == 9
    assert all(r.ScenarioNumber == 1 for r in rows), "a failed generation was papered over"
    event = [e for e in published if str(e.get("type")) == "next_set_result"][-1]
    assert event["new_variants"] == 0


# --- F3: the top-up can never turn a committed success into a reported failure -----------------
# `partial` drives BOTH call sites of the shared helper: the success branch (pool short by 2) and
# _settle_next_set_conflict (pool empty, the no-new fallback). Un-sharing the helper, or guarding
# only one of them, fails here — which the success-only version could not catch.
@pytest.mark.parametrize("partial", [True, False], ids=["success-branch", "conflict-branch"])
@pytest.mark.parametrize("exc", [RuntimeError("boom"), LLMSlotUnavailable("no slots")])
def test_top_up_failure_never_reports_the_committed_batch_as_failed(db, monkeypatch, exc, partial):
    """The top-up runs AFTER write_scenarios committed. An escape into run_next_set's generic
    handler would route that committed success through _record_failure — whose stage_error audit
    row and error SSE are unconditional — so the client would be told a success failed. For
    LLMSlotUnavailable the damage is worse: it would escape past the publish entirely, and the
    Celery retry cannot recover it (claim_stage no-ops against an AWAITING_DECISION stage), so
    the SSE would be lost forever."""
    published: list = []
    monkeypatch.setattr("app.sse.bus.publish", lambda sid_, event: published.append(event))
    # partial: the additive round yields 3 of 5, so the success branch tops up.
    # conflict: nothing new at all, so write_scenarios raises and _settle_next_set_conflict tops up.
    llm = (_ScriptedThreatLLM([_threats(5), _threats(3, start=5)]) if partial
        else _ManyThreatLLM(_threats(5)))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    committed_before = len(_rows(db, sid))

    def _boom(*a, **k):
        raise exc
    monkeypatch.setattr("app.pipeline.tasks.write_variant_scenarios", _boom)

    assert _next_set(db, session, llm, "aaaa000b-0000-4000-8000-00000000000e") in ("review",
                                                                                "no_new_threats_this_round")
    if not partial:
        # conflict branch: nothing was committed this click, and the helper swallowing the
        # failure must leave the honest no-new outcome intact rather than an error
        assert len(_rows(db, sid)) == committed_before
        assert not [e for e in published if str(e.get("type")) == "error"]
        assert not db.execute(
            select(m.Scenario_Audit.AuditID).where(m.Scenario_Audit.SessionID == sid,
                                                m.Scenario_Audit.EventType == "stage_error")).all()
        assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW
        return
    # the 3 scenarios that DID commit are intact and announced...
    assert len(_rows(db, sid)) == 8
    event = [e for e in published if str(e.get("type")) == "next_set_result"][-1]
    assert (event["new_scenarios"], event["new_variants"]) == (3, 0)
    # ...and nothing anywhere says this click failed
    assert not [e for e in published if str(e.get("type")) == "error"]
    assert not db.execute(
        select(m.Scenario_Audit.AuditID).where(m.Scenario_Audit.SessionID == sid,
                                            m.Scenario_Audit.EventType == "stage_error")).all()
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW

# --- regeneration lineage: WHICH scenario replaced WHICH ---------------------------------------
def _regen(db, sid, output_ids, task_id, llm=None):
    """One /regenerate/scenarios round-trip, the way the endpoint + task do it."""
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)
    return cascade.run_regeneration(db, dict(load_session(db, sid)), ASSET_UNIT_ID,
                                    RegenGranularity.scenario, list(output_ids), epoch,
                                    llm or StubLLM(), task_id)


def _replaces(db, sid):
    """OutputID -> ReplacesOutputID for every row (active or retired), lower-cased."""
    return {str(o).lower(): (str(r).lower() if r else None) for o, r in db.execute(
        select(m.Threat_Scenario_Output.OutputID, m.Threat_Scenario_Output.ReplacesOutputID)
        .where(m.Threat_Scenario_Output.SessionID == sid)).all()}


def test_multi_target_regen_pairs_each_new_row_with_its_own_predecessor(db):
    """The reported gap: three targets in one call produced three old ids and three new ids with
    no way to tell which became which. Each new row must name its OWN predecessor."""
    llm = _ManyThreatLLM(_threats(3))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    before = {r.OutputID for r in _rows(db, sid)}
    assert len(before) == 3

    assert _regen(db, sid, before, "bbbb0001-0000-4000-8000-000000000001") == "review"

    after = {r.OutputID for r in _rows(db, sid)}
    assert len(after) == 3 and not (after & before)          # all three genuinely replaced
    links = _replaces(db, sid)
    pointed_at = {links[str(o).lower()] for o in after}
    # a 1:1 pairing, not three rows all claiming the same predecessor
    assert len(pointed_at) == 3
    assert pointed_at == {str(o).lower() for o in before}


def test_replacement_chain_is_three_deep_after_two_regenerations(db):
    """v3 -> v2 -> v1: `replaced_output_ids` is newest-first and survives repeated regeneration.
    The old (IdentityHash, epoch) derivation mis-mapped this — both retired rows resolved to the
    newest active row, losing the middle hop."""
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    v1 = _rows(db, sid)[0].OutputID
    _regen(db, sid, [v1], "bbbb0002-0000-4000-8000-000000000002")
    v2 = _rows(db, sid)[0].OutputID
    _regen(db, sid, [v2], "bbbb0003-0000-4000-8000-000000000003")
    v3 = _rows(db, sid)[0].OutputID

    links = _replaces(db, sid)
    assert links[str(v3).lower()] == str(v2).lower()
    assert links[str(v2).lower()] == str(v1).lower()
    assert links[str(v1).lower()] is None                    # first generation replaced nothing


def test_non_regen_rows_replace_nothing(db):
    """First-run, next-set and variant rows must all be NULL — a link that appears where nothing
    was replaced is worse than no link at all."""
    llm = _ManyThreatLLM(_threats(2))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    _next_set(db, session, llm, "bbbb0004-0000-4000-8000-000000000004")   # adds variants at #2
    rows = _rows(db, sid)
    assert len(rows) == 4 and any(r.ScenarioNumber == 2 for r in rows)
    assert set(_replaces(db, sid).values()) == {None}


def test_regen_of_variant_links_to_its_own_number_not_the_primary(db):
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    _next_set(db, session, llm, "bbbb0005-0000-4000-8000-000000000005")
    before = {r.ScenarioNumber: r.OutputID for r in _rows(db, sid)}

    _regen(db, sid, [before[2]], "bbbb0006-0000-4000-8000-000000000006")

    after = {r.ScenarioNumber: r.OutputID for r in _rows(db, sid)}
    links = _replaces(db, sid)
    assert links[str(after[2]).lower()] == str(before[2]).lower()   # #2 -> old #2
    assert after[1] == before[1] and links[str(after[1]).lower()] is None   # #1 untouched


def test_chain_survives_an_error_card(db):
    """R2: a success that supersedes a prior FAILURE card must point at it. Stamping from the
    requested target id instead of from what the supersede actually retired would leave this NULL,
    and the history would dead-end at the first failure in a threat's life."""
    # two threats so the run still reaches REVIEW: call 1 fails (error card), call 2 succeeds.
    # A run where EVERY scenario fails is cancelled, leaving nothing to regenerate from.
    llm = _FailOnScenarioCallLLM(_threats(2), fail_on={1})
    session = _first_run(db, llm)
    sid = session["SessionID"]
    card = next(r for r in _rows(db, sid) if r.Status == ScenarioStatus.error)

    _regen(db, sid, [card.OutputID], "bbbb0007-0000-4000-8000-000000000007")

    replacement = next(r for r in _rows(db, sid) if r.IdentityHash == card.IdentityHash)
    assert replacement.OutputID != card.OutputID
    assert _replaces(db, sid)[str(replacement.OutputID).lower()] == str(card.OutputID).lower()


def test_regen_audit_and_sse_carry_old_to_new_pairs(db, monkeypatch):
    published: list = []
    monkeypatch.setattr("app.sse.bus.publish", lambda sid_, event: published.append(event))
    llm = _ManyThreatLLM(_threats(2))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    before = {r.OutputID for r in _rows(db, sid)}

    _regen(db, sid, before, "bbbb0008-0000-4000-8000-000000000008")

    after = {str(r.OutputID).lower() for r in _rows(db, sid)}
    expected = {(links_old, new) for new, links_old in
                ((k, v) for k, v in _replaces(db, sid).items() if k in after and v)}
    event = [e for e in published if str(e.get("type")) == "regen_result"][-1]
    got = {(p["old"].lower(), p["new"].lower()) for p in event["replacements"]}
    assert got == expected and len(got) == 2

    detail = [json.loads(d) for (d,) in db.execute(
        select(m.Scenario_Audit.DetailJSON).where(
            m.Scenario_Audit.SessionID == sid,
            m.Scenario_Audit.EventType == "regeneration_completed")).all()][-1]
    assert {(p["old"].lower(), p["new"].lower()) for p in detail["replacements"]} == expected


def test_r3_callback_signature_and_return_type_unchanged(db):
    """R3 guard: plumbing the pairs through on_before_commit would mean returning them from
    _reconcile_targeted_regen, whose bool is consumed as `if targeted and not ...` — an empty
    list is falsy and would silently take the claim-lost branch. Pin both."""
    import inspect

    from app.pipeline import tasks as t
    hook = inspect.signature(t.write_scenarios).parameters["on_before_commit"]
    assert "list[Provenance | None]], None" in str(hook.annotation).replace("'", "")
    # `from __future__ import annotations` in tasks.py keeps annotations as strings
    assert str(inspect.signature(t._reconcile_targeted_regen).return_annotation).strip("'") == "bool"


# --- GET /results: the chain, the opt-in read path, and its cost -------------------------------
def _count_queries(db):
    """Count SELECTs issued on this connection, so a 'zero extra queries' claim is measured
    rather than asserted."""
    from sqlalchemy import event
    seen: list[str] = []
    engine = db.get_bind()

    def _before(_conn, _cur, statement, *_a):
        if statement.lstrip().upper().startswith("SELECT"):
            seen.append(statement)
    event.listen(engine, "before_cursor_execute", _before)
    return seen, lambda: event.remove(engine, "before_cursor_execute", _before)


def test_results_nests_replaced_versions_inside_the_card_that_replaced_them(db):
    """The reported gap, end to end: ?include_replaced=true returns the older versions INSIDE
    the scenario that replaced them, so pairing old with new needs no client-side join."""
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    v1 = _rows(db, sid)[0].OutputID
    _regen(db, sid, [v1], "cccc0001-0000-4000-8000-000000000001")
    v2 = _rows(db, sid)[0].OutputID
    _regen(db, sid, [v2], "cccc0002-0000-4000-8000-000000000002")
    v3 = _rows(db, sid)[0].OutputID
    db.commit()

    client = make_client({"5"})
    plain = client.get(f"/v1/sessions/{sid}/results").json()
    assert len(plain["scenarios"]) == 1
    card = plain["scenarios"][0]
    assert card["output_id"].lower() == str(v3).lower()
    assert card["replaced_scenarios"] == []       # opt-in: the default response carries no history
    assert "replaced_scenarios" not in plain      # the top-level sibling array is gone
    assert "replaced_output_ids" not in card      # so is the parallel id list

    full = client.get(f"/v1/sessions/{sid}/results?include_replaced=true").json()
    assert len(full["scenarios"]) == 1            # current set is identical
    assert "replaced_scenarios" not in full
    history = full["scenarios"][0]["replaced_scenarios"]
    # newest-first: [0] is what it directly replaced. 2 entries => this card is version 3.
    assert [h["output_id"].lower() for h in history] == [str(v2).lower(), str(v1).lower()]
    assert all(h["scenario"] is not None for h in history)       # full text, openable
    # FLAT, never a tree: the whole history is this one array, so no consumer has to recurse
    assert all(h["replaced_scenarios"] == [] for h in history)


def test_each_card_carries_only_its_own_history(db):
    """The nested shape is only unambiguous if a retired version belongs to exactly ONE card.
    ReplacesOutputID is a single-parent backward link, so that holds — pinned here because a
    duplicate would silently show one reviewer's old scenario under an unrelated threat."""
    llm = _ManyThreatLLM(_threats(2))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    first, second = sorted(str(r.OutputID) for r in _rows(db, sid))
    _regen(db, sid, [first], "cccc0006-0000-4000-8000-000000000006")
    _regen(db, sid, [second], "cccc0007-0000-4000-8000-000000000007")
    db.commit()

    body = make_client({"5"}).get(f"/v1/sessions/{sid}/results?include_replaced=true").json()
    assert len(body["scenarios"]) == 2
    histories = [[h["output_id"].lower() for h in c["replaced_scenarios"]]
                 for c in body["scenarios"]]
    assert sorted(h for hist in histories for h in hist) == sorted(
        [first.lower(), second.lower()])
    assert all(len(hist) == 1 for hist in histories)          # one predecessor each
    assert set(histories[0]).isdisjoint(histories[1])         # and never the same one twice


def test_results_issues_no_extra_query_when_nothing_was_replaced(db):
    """R1 guard: the ancestry walk must cost NOTHING for a session with no regenerations. The
    rejected design read the session's superseded rows, which no index serves (both secondary
    indexes are filtered Superseded=0) — a full clustered scan on a polled endpoint."""
    _first_run(db, _ManyThreatLLM(_threats(2)))
    db.commit()
    sid = db.execute(select(m.Scenario_Session.SessionID)).scalars().first()
    client = make_client({"5"})

    for url in (f"/v1/sessions/{sid}/results", f"/v1/sessions/{sid}/results?include_replaced=true"):
        seen, stop = _count_queries(db)
        try:
            assert client.get(url).status_code == 200
        finally:
            stop()
        # nothing was replaced, so the frontier starts empty and neither the walk nor the
        # replaced-rows fetch may issue a single statement
        assert not [s for s in seen if "ReplacesOutputID" in s and "IN (" in s], seen


def _walked(seen: list[str]) -> list[str]:
    return [s for s in seen if "ReplacesOutputID" in s and "IN (" in s]


def test_default_results_never_walks_ancestry_even_after_regeneration(db):
    """Dropping replaced_output_ids removed the last reason for the default path to know a
    chain. The walk used to run on EVERY poll because that field had to be populated; now a
    polled /results costs zero ancestry queries however deep the history runs."""
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    _regen(db, sid, [_rows(db, sid)[0].OutputID], "cccc0005-0000-4000-8000-000000000005")
    db.commit()
    client = make_client({"5"})

    seen, stop = _count_queries(db)
    try:
        assert client.get(f"/v1/sessions/{sid}/results").status_code == 200
    finally:
        stop()
    assert not _walked(seen), seen

    # Negative control: the opt-in path MUST still walk it, or the assertion above passes
    # for the wrong reason (e.g. the regeneration silently failed to stamp anything).
    seen, stop = _count_queries(db)
    try:
        assert client.get(f"/v1/sessions/{sid}/results?include_replaced=true").status_code == 200
    finally:
        stop()
    assert _walked(seen), seen


def test_replaced_versions_keep_their_controls(db):
    """3c: superseding no longer deletes control maps, so an old version comes back COMPLETE.
    This is the assertion that fails against the previous delete-on-supersede behaviour."""
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    v1 = _rows(db, sid)[0].OutputID
    # a real library row, so the read path's Control_Library join actually resolves
    db.execute(insert(m.Control_Library).values(
        ControlLibraryID=1, ControlCode="CII-CID-001", ITOT="OT", Domain="Access Control",
        ControlName="Removable Media Restriction", ControlDescription="No removable media.",
        IsActive=True, IsDeleted=False))
    db.execute(insert(m.Threat_Scenario_Control_Map).values(
        OutputID=v1, ControlLibraryID=1, SessionID=sid, MapRank=1, Score=90.0,
        SuggestedControl="Disable USB ports", CreatedAt=dal.now()))
    db.commit()

    _regen(db, sid, [v1], "cccc0004-0000-4000-8000-000000000004")
    db.commit()

    kept = db.execute(select(m.Threat_Scenario_Control_Map.SuggestedControl)
                    .where(m.Threat_Scenario_Control_Map.OutputID == v1)).scalars().all()
    assert kept == ["Disable USB ports"], "the replaced version's control mappings were deleted"

    # Retained is only half of it — the controls must be REACHABLE on the nested old version,
    # which is the point: a reviewer compares narrative AND controls against the replacement.
    card = make_client({"5"}).get(
        f"/v1/sessions/{sid}/results?include_replaced=true").json()["scenarios"][0]
    old = card["replaced_scenarios"][0]
    assert old["output_id"].lower() == str(v1).lower()
    assert [c["control_code"] for c in old["scenario"]["controls"]] == ["CII-CID-001"]


def test_results_survives_a_self_referential_replaces_pointer(db):
    """Cycle guard: this schema enforces no foreign keys, so a looped ReplacesOutputID must not
    hang the request thread."""
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    oid = _rows(db, sid)[0].OutputID
    db.execute(update(m.Threat_Scenario_Output)
            .where(m.Threat_Scenario_Output.OutputID == oid)
            .values(ReplacesOutputID=oid))          # points at itself
    db.commit()

    card = make_client({"5"}).get(
        f"/v1/sessions/{sid}/results?include_replaced=true").json()["scenarios"][0]
    # Returns rather than hangs, AND the card is not nested inside itself: the walk seeds its
    # cycle guard with the owner, so a scenario can never appear in its own history. Naming
    # itself was survivable when this was an id list; embedding a whole duplicate body is not.
    assert card["replaced_scenarios"] == []


# --- tenant boundary: ReplacesOutputID is untrusted row data, not an authorization token -------
def test_include_replaced_never_crosses_the_session_boundary(db):
    """get_results authorizes ONCE, then follows ReplacesOutputID. That column is unvalidated data
    in a multi-tenant table with no foreign keys — the cycle guard exists for the same reason — so
    the ancestry walk must re-assert SessionID. Without it a pointer into another entity's session
    (a restore with remapped ids, a manual DBA fix, or any future non-session-scoped writer)
    returns that entity's scenario text and its mapped controls to this caller.

    No current writer can create such a pointer, so this pins the boundary rather than a live
    hole: the only writer of the column stamps ids returned by supersede_by_identity_hashes, which
    is session-scoped.
    """
    llm = _ManyThreatLLM(_threats(1))
    session = _first_run(db, llm)
    sid = session["SessionID"]
    mine = _rows(db, sid)[0]

    # a scenario belonging to a DIFFERENT session AND a different entity
    foreign_sid, foreign_out = dal.guid(), dal.guid()
    db.execute(insert(m.Scenario_Session).values(
        SessionID=foreign_sid, TenantID="default", EntityID="9", UserID="other",
        AssetName="Other Asset", AssetID="999", SessionStatus="active",
        CurrentStage=WorkflowStage.REVIEW, StageStatus="IDLE", Mode="AUTO",
        SubsystemsJSON="[]", CreatedAt=dal.now(), UpdatedAt=dal.now()))
    db.execute(insert(m.Threat_Scenario_Output).values(
        OutputID=foreign_out, SessionID=foreign_sid, TenantID="default", EntityID="9",
        SubsystemID=ASSET_UNIT_ID, ScopedThreatID=dal.guid(), Status=ScenarioStatus.complete,
        ScenarioJSON=json.dumps({"scenario_title": "CLASSIFIED-OTHER-TENANT",
                                "scenario_statement": "CLASSIFIED-OTHER-TENANT",
                                "risk_statement": "R"}),
        Accepted=0, Superseded=1, IdentityHash="foreign-hash", ScenarioNumber=1,
        GenerationEpoch=1, CreatedAt=dal.now()))
    # plant the cross-session pointer the schema cannot prevent
    db.execute(update(m.Threat_Scenario_Output)
            .where(m.Threat_Scenario_Output.OutputID == mine.OutputID)
            .values(ReplacesOutputID=foreign_out))
    db.commit()

    r = make_client({"5"}).get(f"/v1/sessions/{sid}/results?include_replaced=true")
    assert r.status_code == 200
    body = r.text
    assert "CLASSIFIED-OTHER-TENANT" not in body, "another entity's scenario leaked into /results"
    payload = r.json()
    # the foreign row is not nested anywhere — an id the scoped walk could not confirm is dropped
    assert payload["scenarios"][0]["replaced_scenarios"] == []
