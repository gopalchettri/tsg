"""Coverage for the split regenerate API (plan: 5 purpose-built endpoints replacing the
single overloaded `/regenerate`) — one test per numbered user scenario (1-9), plus the
4 production-hardening cases from the plan's Verification section.

Scenario numbering matches the plan's endpoint table:
  1/2 = scenarios (single/multi output_ids)      5/6 = threat-types (single/multi)
  3/4 = threats (single/multi threat_ids)        7/8 = threat-categories (single/multi)
  9   = profile
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import insert, select

from app.core.enums import RegenGranularity, StageStatus, SubsystemLevel, WorkflowStage
from app.db import dal
from app.db import models as m
from app.db.dal import load_session
from app.pipeline import cascade
from app.pipeline.llm import Provenance
from tests.conftest import StubLLM, make_client
from tests.test_cascade import _leave_review, _output_ids, _reserve_epoch, _run_to_review
from tests.test_slice import SUB, _seed_session


def _seed_second_category(engine):
    """Adds a second STRIDE category ("Spoofing", id=3) with its own type (12) and
    catalogue (22) — the base conftest schema only seeds "Tampering" (id=2, types
    10/11). Needed so category/type-scoping tests can prove out-of-scope siblings
    are genuinely untouched, not just "the only thing there was.\""""
    from app.db.engine import db_session

    with db_session() as s:
        s.execute(insert(m.Threat_Category).values(
            ThreatCategoryID=3, ThreatCategoryName="Spoofing", ThreatCategoryCode="SPF",
            IsActive=True, IsDeleted=False))
        s.execute(insert(m.Threat_Type).values(
            ThreatTypeID=12, ThreatTypeName="Identity Spoofing", PrimaryThreatCategoryID=3,
            IsActive=True, IsDeleted=False))
        s.execute(insert(m.Threat_Catalogue).values(
            ThreatCatalogueID=22, ThreatTypeID=12, ThreatName="Fake login portal",
            IsActive=True, IsDeleted=False))
        s.commit()


class _MixedCategoryLLM(StubLLM):
    """Proposes one Tampering/Firmware-Tampering threat and one Spoofing/Identity-Spoofing
    threat, so a category/type-scoped regen has both an in-scope and an out-of-scope
    sibling to prove selectivity against."""

    def chat(self, messages, *, model=None):
        sysc = messages[0]["content"].lower()
        if "stride threats" in sysc:
            out = [
                {"category": "Tampering", "type": "Firmware Tampering", "name": "Bootloader implant",
                 "actors": ["Hacker"]},
                {"category": "Spoofing", "type": "Identity Spoofing", "name": "Fake login portal",
                 "actors": ["Hacker"]},
            ]
            return json.dumps(out), Provenance(model="stub")
        return super().chat(messages, model=model)


class _OnlyTamperingLLM(StubLLM):
    """A scoped regen's LLM call — proposes only the in-scope Tampering threat (models
    obeying the prompt constraint most of the time)."""

    def chat(self, messages, *, model=None):
        sysc = messages[0]["content"].lower()
        if "stride threats" in sysc:
            out = [{"category": "Tampering", "type": "Firmware Tampering", "name": "Bootloader implant v2",
                    "actors": ["Hacker"]}]
            return json.dumps(out), Provenance(model="stub")
        return super().chat(messages, model=model)


class _DisobedientLLM(StubLLM):
    """Simulates a model that does NOT obey the scope instruction: proposes both an
    in-scope AND an out-of-scope threat even though the prompt asked for one category
    only. Used to prove the defensive post-filter (plan item 1), not just the prompt
    constraint, actually keeps out-of-scope proposals from being persisted."""

    def chat(self, messages, *, model=None):
        sysc = messages[0]["content"].lower()
        if "stride threats" in sysc:
            out = [
                {"category": "Tampering", "type": "Firmware Tampering", "name": "Bootloader implant v2",
                 "actors": ["Hacker"]},
                {"category": "Spoofing", "type": "Identity Spoofing", "name": "Should be dropped",
                 "actors": ["Hacker"]},
            ]
            return json.dumps(out), Provenance(model="stub")
        return super().chat(messages, model=model)


def _sync_regen(monkeypatch):
    """Runs the enqueued regen cascade synchronously (in-process) instead of via a
    real Celery broker — same indirection pattern test_cascade.py's authz test uses."""
    def sync(session_id, subsystem_id, granularity, target_ids, epoch, user_note):
        from app.db.engine import db_session
        with db_session() as s:
            session = dal.load_session(s, session_id)
            cascade.run_regeneration(s, dict(session), subsystem_id, granularity, target_ids, epoch,
                                     StubLLM(), "t", user_note=user_note)
    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    monkeypatch.setattr("app.api.sessions.enqueue_regeneration", sync)


def _run_to_review_via_api(client, asset_id=100):
    sid = client.post("/v1/sessions", json={"asset_id": asset_id, "entity": "5"}).json()["session_id"]
    return sid


# --- 1/2: scenarios endpoint (single / multi output_ids) ---
def test_scenario_1_single_output_id(db):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    output_id = _output_ids(db, sid)[0]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    outcome = cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [output_id], epoch,
                                       StubLLM(), "t")
    assert outcome == "review"
    assert db.execute(select(m.Threat_Scenario_Output.c.Superseded)
                      .where(m.Threat_Scenario_Output.c.OutputID == output_id)).scalar() == 1


def test_scenario_2_multi_output_ids_siblings_untouched(db):
    from tests.test_cascade import _TwoThreatLLM

    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    outputs = _output_ids(db, sid)
    assert len(outputs) == 2
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, outputs, epoch, _TwoThreatLLM(), "t")

    for oid in outputs:
        assert db.execute(select(m.Threat_Scenario_Output.c.Superseded)
                          .where(m.Threat_Scenario_Output.c.OutputID == oid)).scalar() == 1
    active = db.execute(select(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.c.SessionID == sid, m.Threat_Scenario_Output.c.Superseded == 0)).mappings().all()
    assert len(active) == 2  # both regenerated, none lost


# --- 3/4: threats endpoint (single / multi threat_ids) ---
def test_scenario_3_single_threat_id(db):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    threat_id = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalar()
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat, [threat_id], epoch, StubLLM(), "t")
    assert db.execute(select(m.Identified_Threat.c.Superseded)
                      .where(m.Identified_Threat.c.ThreatID == threat_id)).scalar() == 1


def test_scenario_4_multi_threat_ids_siblings_untouched(db):
    from tests.test_cascade import _TwoThreatLLM

    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    threat_ids = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalars().all()
    assert len(threat_ids) == 2
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat, threat_ids, epoch, _TwoThreatLLM(), "t")

    # Both old threats superseded, both replaced — none lost, none left un-regenerated.
    for old_tid in threat_ids:
        assert db.execute(select(m.Identified_Threat.c.Superseded)
                          .where(m.Identified_Threat.c.ThreatID == old_tid)).scalar() == 1
    assert dal.active_threats(db, sid, SUB["id"]).__len__() == 2


# --- 5/6: threat-types endpoint (single / multi threat_type_ids), real prompt scoping ---
def test_scenario_5_single_threat_type_scoped(db, monkeypatch, engine):
    _seed_second_category(engine)
    sid = _run_to_review(db, _MixedCategoryLLM())
    session = dict(load_session(db, sid))
    threats_before = dal.active_threats(db, sid, SUB["id"])
    assert {t["threat_type_id"] for t in threats_before} == {10, 12}

    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat_type)

    captured_prompts = []
    from app.pipeline import prompts as prompts_mod
    real_threats_prompt = prompts_mod.threats_prompt

    def _spy(asset_name, sub, profile, **kw):
        captured_prompts.append(kw)
        return real_threats_prompt(asset_name, sub, profile, **kw)
    monkeypatch.setattr("app.pipeline.tasks.prompts.threats_prompt", _spy)

    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat_type, [10], epoch,
                             _OnlyTamperingLLM(), "t")

    # (c) the prompt sent to the LLM actually contains the scope constraint
    assert captured_prompts[0]["only_types"] == ["Firmware Tampering"]

    # (a) only the type-10 threat was superseded; (b) the type-12 sibling untouched
    type10_old = next(t["threat_id"] for t in threats_before if t["threat_type_id"] == 10)
    type12_old = next(t["threat_id"] for t in threats_before if t["threat_type_id"] == 12)
    assert db.execute(select(m.Identified_Threat.c.Superseded)
                      .where(m.Identified_Threat.c.ThreatID == type10_old)).scalar() == 1
    assert db.execute(select(m.Identified_Threat.c.Superseded)
                      .where(m.Identified_Threat.c.ThreatID == type12_old)).scalar() == 0
    active = dal.active_threats(db, sid, SUB["id"])
    assert {t["threat_type_id"] for t in active} == {12, 10}  # sibling still active + fresh replacement


def test_scenario_6_multi_threat_types(db, engine):
    _seed_second_category(engine)
    sid = _run_to_review(db, _MixedCategoryLLM())
    session = dict(load_session(db, sid))
    threats_before = dal.active_threats(db, sid, SUB["id"])
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat_type)

    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat_type, [10, 12], epoch,
                             _MixedCategoryLLM(), "t")
    # Both old threats actually superseded (not left duplicated alongside their replacements).
    for old in threats_before:
        assert db.execute(select(m.Identified_Threat.c.Superseded)
                          .where(m.Identified_Threat.c.ThreatID == old["threat_id"])).scalar() == 1
    active = dal.active_threats(db, sid, SUB["id"])
    assert len(active) == 2  # no duplicates left active
    assert {t["threat_type_id"] for t in active} == {10, 12}  # both types regenerated, both present


# --- 7/8: threat-categories endpoint (single / multi categories), real prompt scoping ---
def test_scenario_7_single_category_scoped_defensive_filter(db, monkeypatch, engine):
    """Also proves the defensive post-filter (plan item 1): the stub LLM DISOBEYS the
    scope and proposes an out-of-scope (Spoofing) threat anyway — it must never be
    persisted even though the prompt asked for Tampering only."""
    _seed_second_category(engine)
    sid = _run_to_review(db, _MixedCategoryLLM())
    session = dict(load_session(db, sid))
    threats_before = dal.active_threats(db, sid, SUB["id"])
    spoofing_old = next(t["threat_id"] for t in threats_before if t["threat_type_id"] == 12)

    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat_category)

    captured_prompts = []
    from app.pipeline import prompts as prompts_mod
    real_threats_prompt = prompts_mod.threats_prompt

    def _spy(asset_name, sub, profile, **kw):
        captured_prompts.append(kw)
        return real_threats_prompt(asset_name, sub, profile, **kw)
    monkeypatch.setattr("app.pipeline.tasks.prompts.threats_prompt", _spy)

    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat_category, [2], epoch,
                             _DisobedientLLM(), "t")

    assert captured_prompts[0]["only_categories"] == ["Tampering"]
    # Spoofing sibling (category 3) untouched by the Tampering-scoped (category 2) regen.
    assert db.execute(select(m.Identified_Threat.c.Superseded)
                      .where(m.Identified_Threat.c.ThreatID == spoofing_old)).scalar() == 0
    active = dal.active_threats(db, sid, SUB["id"])
    # The disobedient LLM's out-of-scope Spoofing proposal must NOT appear among active threats
    # (only ever the pre-existing sibling's original type 12, never a second/duplicate one).
    assert sorted(t["threat_type_id"] for t in active) == [10, 12]


def test_scenario_8_multi_categories(db, engine):
    _seed_second_category(engine)
    sid = _run_to_review(db, _MixedCategoryLLM())
    session = dict(load_session(db, sid))
    threats_before = dal.active_threats(db, sid, SUB["id"])
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat_category)

    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.threat_category, [2, 3], epoch,
                             _MixedCategoryLLM(), "t")
    # Both old threats actually superseded (not left duplicated alongside their replacements).
    for old in threats_before:
        assert db.execute(select(m.Identified_Threat.c.Superseded)
                          .where(m.Identified_Threat.c.ThreatID == old["threat_id"])).scalar() == 1
    active = dal.active_threats(db, sid, SUB["id"])
    assert len(active) == 2  # no duplicates left active
    assert {t["threat_type_id"] for t in active} == {10, 12}  # both categories' threats regenerated


# --- 9: profile endpoint ---
def test_scenario_9_profile(db):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    _leave_review(db, sid, stage=WorkflowStage.PROFILE)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.profile)
    outcome = cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.profile, None, epoch, StubLLM(), "t")
    assert outcome == "review"
    assert dal.get_active_profile(db, sid, SUB["id"]) is not None


# --- production-hardening cases ---
def test_hardening_invalid_stride_category_rejected_422_never_reaches_prompt(monkeypatch):
    """Plan item 1a: a `categories` value outside the 6 STRIDE names is rejected 422
    before it ever reaches a prompt."""
    called = []
    monkeypatch.setattr("app.pipeline.prompts.threats_prompt", lambda *a, **k: called.append(1) or [])
    client = make_client({"5"})
    r = client.post("/v1/sessions/x/regenerate/threat-categories",
                    json={"subsystem_id": SUB["id"], "categories": ["NotARealCategory"]})
    assert r.status_code == 422
    assert called == []


def test_hardening_one_invalid_id_among_valid_batch_rejects_whole_request(db):
    """Plan item 2: one invalid id among a valid batch fails the whole request
    atomically — nothing superseded."""
    from tests.test_cascade import _TwoThreatLLM

    sid = _run_to_review(db, _TwoThreatLLM())
    threat_ids = db.execute(select(m.Identified_Threat.c.ThreatID).where(
        m.Identified_Threat.c.SessionID == sid, m.Identified_Threat.c.Superseded == 0)).scalars().all()
    assert len(threat_ids) == 2
    bad_batch = [threat_ids[0], "does-not-exist"]

    with pytest.raises(dal.RegenerateConflict):
        cascade.get_threat_id_to_redo(db, sid, SUB["id"], RegenGranularity.threat, bad_batch)

    # Nothing superseded — the valid id in the batch was NOT partially processed.
    for tid in threat_ids:
        assert db.execute(select(m.Identified_Threat.c.Superseded)
                          .where(m.Identified_Threat.c.ThreatID == tid)).scalar() == 0


def test_hardening_out_of_scope_proposal_dropped_never_persisted(db, engine):
    """Plan item 1: a stub-LLM response containing an out-of-scope proposal is dropped
    by the defensive filter, never persisted — proven directly against find_threats."""
    from app.pipeline import tasks

    _seed_second_category(engine)
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    _leave_review(db, sid, stage=WorkflowStage.THREAT_IDENTIFICATION)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.threat_category)

    threats, _prov = tasks.find_threats(db, session, SUB, {}, _DisobedientLLM(), "t", epoch=epoch,
                                        only_category_ids=[2])
    # Only the in-scope (Tampering) proposal survives — the Spoofing one is dropped
    # before it ever reaches grounding/persistence.
    assert len(threats) == 1
    assert threats[0]["threat_type"] == "Firmware Tampering"


def test_hardening_batch_over_max_length_rejected_422():
    """Plan item 1b: a list over the max-length cap (50) is rejected 422 — a real
    Pydantic Field constraint, not just a docstring note."""
    client = make_client({"5"})
    too_many = [str(i) for i in range(51)]
    r = client.post("/v1/sessions/x/regenerate/threats",
                    json={"subsystem_id": SUB["id"], "threat_ids": too_many})
    assert r.status_code == 422


# --- old endpoint is gone ---
def test_old_single_regenerate_endpoint_removed():
    client = make_client({"5"})
    r = client.post("/v1/sessions/x/regenerate", json={"granularity": "profile", "subsystem_id": SUB["id"]})
    assert r.status_code == 404  # route no longer exists at all


# --- flagged-threat category-limitation case (plan item 4's documented known gap) ---
def test_flagged_threat_with_no_grounded_type_not_reachable_by_category_regen(db):
    """`supersede_by_categories` joins via Identified_Threat.ThreatTypeID -> Threat_Type
    .PrimaryThreatCategoryID — a flagged threat with NO ThreatTypeID (no confident library
    match) is therefore invisible to a category-scoped regen; only a broader `profile`-level
    regen catches it. Documented limitation, not a bug — this test locks in that behavior."""
    sid = _seed_session(db)["SessionID"]
    dal.insert_row(db, m.Identified_Threat, {
        "ThreatID": "flagged-1", "SessionID": sid, "TenantID": "default", "SubsystemID": SUB["id"],
        "ThreatCategory": "Tampering", "ThreatType": "Some Novel Thing", "ThreatName": "Unmatched",
        "ThreatActorsJSON": "{}", "LibraryThreatType": None, "LibraryThreatName": None,
        "ThreatTypeID": None, "ThreatCatalogueID": None, "GroundingStatus": "flagged", "GroundingScore": 10.0,
        "Superseded": 0, "CreatedAt": dal.now(),
    })
    db.commit()
    dal.supersede_by_categories(db, m.Identified_Threat, sid, SUB["id"], [2])  # Tampering
    # Untouched — ThreatTypeID is None, so it never matches the join.
    assert db.execute(select(m.Identified_Threat.c.Superseded)
                      .where(m.Identified_Threat.c.ThreatID == "flagged-1")).scalar() == 0
