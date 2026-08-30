"""P2 gate for library-first threat identification (tasks.find_threats) after the 2026-08-28
catalogue reversal (Threat_Catalogue + the per-type actor / per-threat category maps).

What must hold, and why:

  - LIBRARY CANDIDATES ENTER FIRST: a validated catalogue candidate lands as an
    Identified_Threat row with GroundingStatus verified / GroundingScore 100.0 and the
    catalogue's own identity (a real ThreatCatalogueID, IsThreatAIGenerated False) — grounding is
    identity, not similarity, so a rerank score here would be a fiction and downstream
    promote/scenario reads depend on the id being real.
  - the validator's NOT_RELEVANT is a HARD DROP, enforced twice: the candidate is removed
    AND a generated proposal that regrounds onto the same catalogue row is blocked as
    validator_rejected (rejected_catalogue_ids) — otherwise Stage 1b silently reverses a
    verdict a reviewer never sees questioned twice.
  - an unrecognized verdict FAILS OPEN (kept as POTENTIALLY_RELEVANT): a flaky validator
    must weaken ranking, never shrink coverage.
  - generation fills only the SHORTFALL and is skipped entirely when the library fills
    the cap — the whole point of library-first is that curated content is never displaced
    by generated text.
  - selection_sources tallies only "hybrid" and "generated": the actor-intel admission
    leg retired with the sector filter, so any third key would mean dead provenance code
    is running again.
  - actor_ids are stored from the TYPE's junction (ThreatType_ThreatActor_Map — actors
    attach per type in the catalogue model) so promotion links by key instead of
    re-resolving a name that may since be renamed.
  - the gap-generation exclusion list names retrieved threats by their BARE threat name —
    the catalogue has no theme/precondition column left to qualify them with.

House pattern: real SQLite, bus.publish stubbed, deterministic fake LLM, no Mongo/Redis.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.enums import GroundingStatus, StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import embeddings, tasks, threat_retrieval
from app.pipeline.tasks import find_threats, set_up_progress_tracking


@pytest.fixture(autouse=True)
def _isolated_embeddings(monkeypatch):
    """Force the in-memory embedding store and clear the process caches: a REAL local Mongo
    would otherwise serve real 1024-dim vectors for library names that exist in the real
    seed, colliding with the fake 256-dim test vectors — and the test would WRITE fake
    vectors into the real store."""
    monkeypatch.setenv("TSG_EMBEDDING_STORE", "memory")
    embeddings._L1.clear()
    embeddings._MATRIX.clear()
    yield
    embeddings._L1.clear()
    embeddings._MATRIX.clear()


TASK_ID = str(uuid.uuid4())
NOW = datetime.now(UTC)

# Subsystem/asset dicts still carry asset_type_id (the raw ctm_scan_category id) — stamped by
# context.py at session creation. INERT for retrieval now (the catalogue has no asset-type
# column); it feeds only the data-driven control ITOT filter downstream.
SUBSYSTEMS = [{"id": 41, "name": "SCADA HMI Server", "asset_type": "OT", "asset_type_id": 3,
               "technology_used": ["Siemens SCADA"], "vendor_name": "Siemens",
               "criticality": "High"},
              {"id": 42, "name": "Customer Billing Portal", "asset_type": "IT",
               "asset_type_id": 2, "technology_used": ["Django"], "vendor_name": "In-house",
               "criticality": "Medium"}]
ASSET_CONTEXT = {"name": "Water Pumping Station", "asset_type": "Operational Technology (OT)",
                 "asset_type_id": 3, "sector": "Energy & Water", "sub_sector": "Water Supply",
                 "critical_service": ["Potable water supply"]}


class FakeLLM:
    """Deterministic: one-hot embeddings per unique text (orthogonal — no accidental cosine
    collisions), exact-match reranking, canned chat answers recognized by system text."""

    def __init__(self):
        self._slots: dict[str, int] = {}
        self.chat_calls: list[tuple[str, str]] = []

    def embed(self, texts, kind=None):
        out = []
        for t in texts:
            idx = self._slots.setdefault(t, len(self._slots))
            v = [0.0] * 256
            v[idx % 256] = 1.0
            out.append(v)
        return out

    def rerank(self, query, docs):
        return [95.0 if d.strip().lower() == query.strip().lower() else 5.0 for d in docs]

    def validator_verdict(self, cand: dict) -> dict:
        name = (cand.get("name") or "").lower()
        bad = "skimming" in name
        return {"index": cand["index"],
                "verdict": "NOT_RELEVANT" if bad else "RELEVANT",
                "justification": ("this threat does not apply to this asset" if bad
                                  else "SCADA controls pump setpoints directly")}

    def chat(self, messages, temperature=None, expected_type=None):
        system, user = messages[0]["content"], messages[-1]["content"]
        self.chat_calls.append((system, user))
        if "VALIDATING pre-selected library threats" in system:
            payload = json.loads(user[user.index("{"):])
            return json.dumps([self.validator_verdict(c)
                               for c in payload["candidate_threats"]]), None
        # Stage-1b gap generation: one proposal that regrounds onto the validator-rejected
        # catalogue row (the reversal the hard drop must block) + one genuinely novel one.
        return json.dumps([
            {"category": "Spoofing", "type": "Credential Abuse",
             "name": "Payment card skimming at POS terminals",
             "generic_name": "Payment card skimming at POS terminals", "actors": []},
            {"category": "Repudiation", "type": "Audit Evidence Loss",
             "name": "Loss of operator attribution from shared logins",
             "generic_name": "Loss of operator attribution", "actors": []},
        ]), None


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Identified_Duplicate_Threat, m.Scenario_Audit, m.Prompt_Log,
                m.Threat_Category, m.Threat_Type, m.Grounding_Calibration_Run,
                m.Threat_Catalogue, m.Threat_Actor, m.ThreatType_ThreatActor_Map,
                m.Threat_Catalogue_Category_Map):
        tbl.__table__.create(engine)
    return engine


def _seed_library(s, include_live: bool = True) -> None:
    for cid, name in ((4, "Repudiation"), (5, "Spoofing"), (6, "Tampering")):
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=cid, ThreatCategoryName=name, IsActive=True, IsDeleted=False))
    for tid, name, cat, active in ((7, "Logic/Configuration Manipulation", 6, True),
                                   (9, "Credential Abuse", 5, True),
                                   # INACTIVE type: its catalogue rows must never surface.
                                   (11, "Physical Intrusion", 6, False)):
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=tid, ThreatTypeName=name, ThreatCategoryID=cat,
            IsActive=active, IsDeleted=False))
    live = ((205, "Credential phishing and MFA session theft", 9),
            (418, "Unauthorised setpoint modification", 7),
            (900, "Payment card skimming at POS terminals", 9)) if include_live else ()
    for cid, name, tid, deleted in (
            *((c, n, t, False) for c, n, t in live),
            # RETIRED: soft-deleted — eligibility is liveness alone, so never a candidate.
            (555, "Perimeter fence cutting", 7, True),
            # ORPHANED: live row under the INACTIVE type 11 — never a candidate either.
            (777, "Orphaned manipulation threat", 11, False)):
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=cid, ThreatTypeID=tid, ThreatName=name,
            IsActive=True, IsDeleted=deleted, Source="seed",
            CreatedBy="seed", CreatedAt=NOW))
    for aid, name in ((1, "APT33"), (2, "AquaViper")):
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=aid, ThreatActorName=name, IsCapable=1,
            IsActive=True, IsDeleted=False))
    # PER-TYPE curated actors via the type junction — every catalogue threat under type 7
    # shares them, and the pipeline must store these ids, not re-resolve names.
    for tid, aid in ((7, 1), (7, 2)):
        s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
            ThreatTypeID=tid, ThreatActorID=aid))


def _seed_session(s, sid: str) -> dict:
    row = {"SessionID": sid, "TenantID": "t", "EntityID": "e", "UserID": "u",
           "AssetName": "Water Pumping Station", "AssetID": "1", "SessionStatus": "active",
           "CurrentStage": "THREAT_IDENTIFICATION", "StageStatus": "IDLE", "Mode": "AUTO",
           "SubsystemsJSON": json.dumps(SUBSYSTEMS), "SectorIDsJSON": json.dumps([]),
           "CreatedAt": NOW, "UpdatedAt": NOW}
    s.execute(m.Scenario_Session.__table__.insert().values(**row))
    set_up_progress_tracking(s, sid, "t", "e")
    s.commit()
    return row


def _run(monkeypatch, llm, max_threats):
    """One full find_threats run on a fresh engine; returns (threats, session factory, sid)."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    sid = str(uuid.uuid4())
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s, sid)
        threats, _prov = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                      TASK_ID, max_threats=max_threats)
    return threats, Session, sid


def test_library_first_end_to_end(monkeypatch):
    llm = FakeLLM()

    # Capture the gap-generation ask so the exclusion-list contract is pinned on the SAME
    # run (threats_prompt is only called for the gap in find_threats).
    captured: dict = {}
    real_prompt = tasks.prompts.threats_prompt

    def _capture(*a, **kw):
        if kw.get("quota") is not None:
            captured.update(kw)
        return real_prompt(*a, **kw)
    monkeypatch.setattr(tasks.prompts, "threats_prompt", _capture)

    threats, Session, _sid = _run(monkeypatch, llm, max_threats=4)

    # --- eligibility: only LIVE rows under active types ever reached the validator --------
    # The soft-deleted row (555) and the inactive-type row (777) must be filtered in SQL,
    # BEFORE any LLM sees them — a validator justification for an ineligible threat would
    # imply liveness is being enforced by a model instead of the query.
    validator_users = [u for sys, u in llm.chat_calls
                       if "VALIDATING pre-selected library threats" in sys]
    assert len(validator_users) == 1
    cands = json.loads(
        validator_users[0][validator_users[0].index("{"):])["candidate_threats"]
    assert {c["name"] for c in cands} == {"Unauthorised setpoint modification",
                                         "Credential phishing and MFA session theft",
                                         "Payment card skimming at POS terminals"}
    # Payload shape: index/category/type/name/description only — the theme/risk_statement
    # legs left with the register model.
    # No "description": Threat_Catalogue.Description was removed, so the validator now judges
    # relevance from category/type/name alone.
    assert all(set(c) == {"index", "category", "type", "name"} for c in cands)

    with Session() as s:
        rows = {r.ThreatCatalogueID: r
                for r in s.execute(select(m.Identified_Threat)).scalars()
                if r.SubsystemID == 0}
        # 900 validator-dropped (hard drop); 418 + 205 land; one novel generated row.
        retrieved = {cid: r for cid, r in rows.items() if cid is not None}
        assert set(retrieved) == {418, 205}

        # --- catalogue candidates enter FIRST with identity grounding -----------------
        for r in retrieved.values():
            assert str(r.GroundingStatus) == str(GroundingStatus.verified)
            assert r.GroundingScore == 100.0
            # Identity, not similarity: no threshold was consulted, and the column must say
            # so explicitly — NULL here means "pre-feature row", a different fact.
            assert r.GroundingThresholdOrigin == "not_applicable"
            assert r.LibraryThreatName == r.ThreatName
            # NO description on a library-sourced threat: Threat_Catalogue.Description was
            # removed as unused, so there is no curated wording left to copy down. The
            # generated path still records the AI's own.
            assert r.Description is None
            # Immutable provenance: this threat came FROM the catalogue, so it is not
            # AI-generated — the one column promotion must never rewrite.
            assert r.IsThreatAIGenerated is False
        # Catalogue identity stored: the real type id — the promote API is a pure writer
        # and reads these instead of guessing.
        assert retrieved[418].ThreatTypeID == 7 and retrieved[205].ThreatTypeID == 9

        # --- actor ids from the TYPE junction, name-sorted, validated -----------------
        # ids ride alongside names so promotion links by key: re-resolving a name at write
        # time returns NULL the day an actor is renamed or retired.
        assert json.loads(retrieved[418].ThreatActorsJSON) == {
            "actors": ["APT33", "AquaViper"], "actor_ids": [1, 2], "validated": True}

        # --- the validator's hard drop holds for the WHOLE round ----------------------
        # The generated proposal that regrounds onto rejected row 900 is diverted, recorded
        # as validator_rejected — never inserted, never silently skipped.
        assert 900 not in rows
        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert [d.DuplicateReason for d in dups] == ["validator_rejected"]
        assert "skimming" in dups[0].ThreatName.lower()

        # --- generation filled only the shortfall; the novel proposal survives --------
        novel = [r for cid, r in rows.items() if cid is None]
        assert len(novel) == 1
        assert "operator attribution" in novel[0].ThreatName
        assert str(novel[0].GroundingStatus) == str(GroundingStatus.unverified)
        # Provenance IS the id: no catalogue row -> AI-generated.
        assert novel[0].IsThreatAIGenerated is True

        # Ineligible catalogue rows never surface anywhere.
        assert 555 not in rows and 777 not in rows

        stage = s.execute(select(m.Subsystem_Stage_State).where(
            m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)).scalar_one()
        assert str(stage.Status) == str(StageStatus.COMPLETE)

        # --- audit: provenance tallies name only the two legs that exist now ----------
        audit = [json.loads(a.DetailJSON) for a in s.execute(
            select(m.Scenario_Audit)).scalars() if a.DetailJSON]
        summary = next(d for d in audit if "retrieved" in d)
        assert summary["retrieved"] == 2 and summary["generated"] == 1
        # The actor-intel leg retired with the sector filter: a third key here would mean
        # dead admission code is running again.
        assert summary["selection_sources"] == {"hybrid": 2, "generated": 1}
        assert summary["validator"]["candidates"] == 3
        assert summary["validator"]["kept"] == 2
        dropped = {d["catalogue_id"]: d for d in summary["validator"]["dropped"]}
        assert set(dropped) == {900}
        assert "does not apply" in dropped[900]["justification"]
        assert summary["validator_reversals_blocked"] == 1

    # --- return value: catalogue identity on every retrieved summary ------------------
    by_name = {t["threat_name"]: t for t in threats}
    setpoint = by_name["Unauthorised setpoint modification"]
    assert setpoint["selection_source"] == "hybrid"
    assert setpoint["catalogue_id"] == 418
    assert setpoint["is_ai_generated"] is False
    assert setpoint["threat_type_id"] == 7
    # The STORED category is the assigned STRIDE slot; the full membership rides alongside.
    assert setpoint["category"] == "Tampering" and setpoint["categories"] == ["Tampering"]
    assert by_name["Credential phishing and MFA session theft"]["catalogue_id"] == 205
    assert len(threats) == 3

    # --- gap-generation exclusion list: bare threat names ------------------------------
    # The catalogue has no theme/precondition column, so the label IS the substance the
    # model judges overlap against.
    assert set(captured["exclude"]) == {
        "Unauthorised setpoint modification",
        "Credential phishing and MFA session theft"}


def test_retrieval_eligibility_and_candidate_shape():
    """The deterministic half of Stage 1a on its own: eligibility is a SQL fact, provable
    without any chat — liveness ALONE (IsActive/IsDeleted on the row AND an active parent
    type); the sector and asset-type legs left with the register model, and the validator
    now decides relevance. Candidates carry the catalogue identity and per-TYPE junction
    actors the rest of the pipeline stores verbatim."""
    Session = sessionmaker(bind=_engine(), future=True)
    llm = FakeLLM()
    with Session() as s:
        _seed_library(s)
        s.commit()
        out = threat_retrieval.retrieve_library_threats(s, llm, SUBSYSTEMS, ASSET_CONTEXT)
    by_id = {c["catalogue_id"]: c for c in out}
    # Liveness only: soft-deleted 555 and inactive-type 777 out, everything live in.
    assert set(by_id) == {205, 418, 900}
    for c in out:
        # One provenance for every catalogue candidate now that actor-intel is gone.
        assert c["selection_source"] == "hybrid"
        # Healthy embeddings -> the keyword-only caveat must NOT be raised.
        assert c["ranking_degraded"] is False
    assert by_id[418]["type_id"] == 7
    assert by_id[418]["type_name"] == "Logic/Configuration Manipulation"
    # The catalogue row's own curated description rides on the candidate.
    # PER-TYPE junction actors, name-sorted, ids aligned; type 9 has none linked.
    assert by_id[418]["actors"] == ["APT33", "AquaViper"]
    assert by_id[418]["actor_ids"] == [1, 2]
    assert by_id[205]["actors"] == [] and by_id[205]["actor_ids"] == []
    # Empty category junction table -> the type's single category, canonical name.
    assert by_id[418]["categories"] == ["Tampering"]
    assert by_id[205]["categories"] == ["Spoofing"]
    # ALL subsystems attributed — fail-open by design (no tech_gate can shrink the grid).
    assert by_id[418]["subsystem_ids"] == [41, 42]


def test_dead_library_returns_nothing():
    """A library whose every row is retired (soft-deleted, or under an inactive type) must
    return [] LOUDLY (find_threats then degrades to generation-only) rather than, say,
    serving the dead rows anyway — silently widening eligibility is the failure mode the
    liveness rule exists to prevent. (The category-union emptiness this test used to pin
    left with the register model; liveness is the whole eligibility rule now.)"""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s, include_live=False)
        s.commit()
        assert threat_retrieval.retrieve_library_threats(
            s, FakeLLM(), SUBSYSTEMS, ASSET_CONTEXT) == []


def test_unknown_verdict_kept_and_generation_skipped_when_library_fills(monkeypatch):
    """Two fail-safe rules in one run. (1) An unrecognized validator verdict is KEPT as
    POTENTIALLY_RELEVANT — only an explicit NOT_RELEVANT may shrink coverage, so a flaky
    validator degrades ranking, never the threat set. (2) With the cap already filled from
    the catalogue, Stage 1b never runs: exactly one chat call (the validator), no generated
    rows, and no 'generated' key in the provenance tally — curated content is never
    displaced by generated text."""

    class _OddVerdictLLM(FakeLLM):
        def validator_verdict(self, cand):
            v = super().validator_verdict(cand)
            if "skimming" in (cand.get("name") or "").lower():
                v["verdict"] = "SOMEWHAT_RELEVANT"   # unrecognized — must be kept, not dropped
            return v

    llm = _OddVerdictLLM()
    threats, Session, _sid = _run(monkeypatch, llm, max_threats=2)

    assert len(llm.chat_calls) == 1, "generation must be skipped when the library fills the cap"
    assert len(threats) == 2
    assert all(t["selection_source"] == "hybrid" for t in threats)
    with Session() as s:
        rows = [r for r in s.execute(select(m.Identified_Threat)).scalars()
                if r.SubsystemID == 0]
        assert all(r.ThreatCatalogueID is not None for r in rows)
        audit = [json.loads(a.DetailJSON) for a in s.execute(
            select(m.Scenario_Audit)).scalars() if a.DetailJSON]
        summary = next(d for d in audit if "retrieved" in d)
        # All 3 candidates kept — the unrecognized verdict did NOT drop 900; the STRIDE
        # quota (not the validator) is what narrowed 3 kept candidates to the cap of 2.
        assert summary["validator"]["kept"] == 3
        assert summary["validator"]["dropped"] == []
        assert summary["selection_sources"] == {"hybrid": 2}
        assert "generated" not in summary["selection_sources"]
        assert summary["generated"] == 0


def test_not_relevant_drop_is_recorded_with_justification(monkeypatch):
    """The hard drop must leave a reviewable trail: the catalogue id and the model's own
    justification land in the grounding_summary audit row. A drop with no recorded grounds
    would be indistinguishable from the threat never having been considered — exactly the
    silent omission GAP-B exists to prevent."""
    llm = FakeLLM()
    _threats, Session, _sid = _run(monkeypatch, llm, max_threats=2)
    with Session() as s:
        rows = {r.ThreatCatalogueID for r in
                s.execute(select(m.Identified_Threat)).scalars() if r.SubsystemID == 0}
        assert 900 not in rows
        audit = [json.loads(a.DetailJSON) for a in s.execute(
            select(m.Scenario_Audit)).scalars() if a.DetailJSON]
        summary = next(d for d in audit if "retrieved" in d)
        assert summary["validator"]["dropped"] == [{
            "catalogue_id": 900,
            "threat_name": "Payment card skimming at POS terminals",
            "justification": "this threat does not apply to this asset"}]


def test_coverage_reporting_off_by_default_computes_and_stores_nothing(monkeypatch):
    """TSG_COVERAGE_REPORTING_ENABLED defaults False: the audit row must carry NEITHER
    "units" NOR "coverage" — genuinely absent, not computed-and-empty."""
    assert get_settings().coverage_reporting_enabled is False
    llm = FakeLLM()
    _threats, Session, _sid = _run(monkeypatch, llm, max_threats=4)
    with Session() as s:
        audit = [json.loads(a.DetailJSON) for a in s.execute(
            select(m.Scenario_Audit)).scalars() if a.DetailJSON]
        summary = next(d for d in audit if "retrieved" in d)
        assert "units" not in summary and "coverage" not in summary


def test_coverage_reporting_enabled_restores_the_prior_shape(monkeypatch):
    """Flipping the flag on must genuinely restore the old computation, not just leave it
    permanently disabled behind an inert toggle."""
    monkeypatch.setattr(get_settings(), "coverage_reporting_enabled", True)
    llm = FakeLLM()
    _threats, Session, _sid = _run(monkeypatch, llm, max_threats=4)
    with Session() as s:
        audit = [json.loads(a.DetailJSON) for a in s.execute(
            select(m.Scenario_Audit)).scalars() if a.DetailJSON]
        summary = next(d for d in audit if "retrieved" in d)
        assert "units" in summary and "coverage" in summary
        assert summary["units"][0] == 0  # ASSET_UNIT_ID leads the grid, same as before
        assert "cells" in summary["coverage"] and "unexplained" in summary["coverage"]
