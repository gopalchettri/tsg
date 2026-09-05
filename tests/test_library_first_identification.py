"""P2 gate for library-first threat identification (tasks.find_threats) after the
library-first rerank-gate redesign (the LLM validator is gone).

What must hold, and why:

  - LIBRARY CANDIDATES ENTER FIRST via the LOCAL rerank gate: a candidate scoring at/above
    TSG_THREAT_RELEVANCE_THRESHOLD lands as an Identified_Threat row with GroundingStatus
    verified / GroundingScore 100.0 and the catalogue's own identity — grounding is
    identity, not similarity. NO chat call is ever made to judge library candidates.
  - ZERO LLM CALLS when the gated library satisfies both the requested count AND the
    STRIDE coverage target — the whole point of the redesign.
  - COVERAGE (not just count) decides sufficiency: a count-full but category-thin library
    round still triggers gap generation, and the terminal STRIDE selection swaps the
    generated thin-category threat in.
  - COUNT IS ALWAYS MET (user rule): shortfalls backfill from below-threshold candidates,
    explicitly flagged `backfill: true` — the threshold itself is never lowered. PARTIAL
    is recorded only when even backfill cannot reach the count.
  - a PROVIDER failure in gap generation must not destroy valid library results
    (status PARTIAL at worst); a RETRIEVAL INFRASTRUCTURE failure must PROPAGATE, never
    silently degrade to generation-only.
  - the additive next-set path reuses this same funnel, skipping identities the session
    already holds.

House pattern: real SQLite, bus.publish stubbed, deterministic fake LLM, no Mongo/Redis.
"""
from __future__ import annotations

import json
import uuid
import warnings
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.enums import GroundingStatus, StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import embeddings, tasks, threat_identification, threat_retrieval
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
    collisions), doc-keyed rerank-gate scores, canned gap-generation proposals.

    rerank: an exact query==doc match wins 95.0 first — that is what grounding's
    regrounding of generated proposals relies on. Otherwise the DOC's entry in
    `gate_scores` decides (context-prose gate queries never equal a threat name), so each
    test states which library rows are relevant to this asset and which are not."""

    def __init__(self, gate_scores: dict[str, float] | None = None,
                proposals: list[dict] | None = None):
        self._slots: dict[str, int] = {}
        self.chat_calls: list[tuple[str, str]] = []
        self.gate_scores = gate_scores if gate_scores is not None else {
            "Unauthorised setpoint modification": 95.0,
            "Credential phishing and MFA session theft": 88.0,
            "Payment card skimming at POS terminals": 10.0,   # below the 50.0 gate
        }
        self.proposals = proposals if proposals is not None else [
            # Regrounds by exact name onto catalogue row 900 — under the gate design this
            # is LEGITIMATE (the generator independently proposed it; grounding verified
            # it), not a "validator reversal" to block.
            {"category": "Spoofing", "type": "Credential Abuse",
             "name": "Payment card skimming at POS terminals",
             "generic_name": "Payment card skimming at POS terminals", "actors": []},
            {"category": "Repudiation", "type": "Audit Evidence Loss",
             "name": "Loss of operator attribution from shared logins",
             "generic_name": "Loss of operator attribution", "actors": []},
        ]

    def embed(self, texts, kind=None):
        out = []
        for t in texts:
            idx = self._slots.setdefault(t, len(self._slots))
            v = [0.0] * 256
            v[idx % 256] = 1.0
            out.append(v)
        return out

    def rerank(self, query, docs):
        return [95.0 if d.strip().lower() == query.strip().lower()
                else self.gate_scores.get(d, 5.0) for d in docs]

    def chat(self, messages, temperature=None, expected_type=None):
        system, user = messages[0]["content"], messages[-1]["content"]
        self.chat_calls.append((system, user))
        return json.dumps(self.proposals), None


class FailingChatLLM(FakeLLM):
    """Provider failure on the (only remaining) chat path — gap generation."""

    def chat(self, messages, temperature=None, expected_type=None):
        self.chat_calls.append((messages[0]["content"], messages[-1]["content"]))
        raise RuntimeError("simulated provider outage (post-retry APIError)")


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Identified_Duplicate_Threat, m.Scenario_Audit, m.Prompt_Log,
                m.Threat_Category, m.Threat_Type, m.Grounding_Calibration_Run,
                m.Threat_Catalogue, m.Threat_Actor, m.ThreatType_ThreatActor_Map,
                m.Threat_Catalogue_Category_Map,
                # Empty, but must exist: run_next_set reads served identities from
                # them before the additive find_threats call the next-set tests exercise.
                m.Threat_Scenario, m.Scoped_Threat):
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


def _summary(s) -> dict:
    audit = [json.loads(a.DetailJSON) for a in s.execute(
        select(m.Scenario_Audit)).scalars() if a.DetailJSON]
    return next(d for d in audit if "retrieved" in d)


def test_library_first_end_to_end(monkeypatch):
    """The whole funnel in one run: gate → pass-1 selection → coverage gap → ONE bounded
    generation call → grounding (library match adopts the canonical id; no-match custom) →
    terminal STRIDE selection → COMPLETE."""
    llm = FakeLLM()
    captured: dict = {}
    real_prompt = tasks.prompts.threats_prompt

    def _capture(*a, **kw):
        if kw.get("quota") is not None:
            captured.update(kw)
        return real_prompt(*a, **kw)
    monkeypatch.setattr(tasks.prompts, "threats_prompt", _capture)

    threats, Session, _sid = _run(monkeypatch, llm, max_threats=4)

    # Exactly ONE chat call — gap generation. Nothing ever asked the LLM to judge the
    # 3-candidate library pool (the old validator's job, now the local reranker's).
    assert len(llm.chat_calls) == 1

    with Session() as s:
        rows = {r.ThreatCatalogueID: r
                for r in s.execute(select(m.Identified_Threat)).scalars()
                if r.SubsystemID == 0}

        # --- gate-admitted catalogue candidates enter with identity grounding ----------
        for cid in (418, 205):
            r = rows[cid]
            assert str(r.GroundingStatus) == str(GroundingStatus.verified)
            assert r.GroundingScore == 100.0
            assert r.GroundingThresholdOrigin == "not_applicable"
            assert r.IsThreatAIGenerated is False
        assert rows[418].ThreatTypeID == 7 and rows[205].ThreatTypeID == 9
        assert json.loads(rows[418].ThreatActorsJSON) == {
            "actors": ["APT33", "AquaViper"], "actor_ids": [1, 2], "validated": True}

        # --- the below-gate row (900) came back through generation + grounding ---------
        # Score 10 kept it out of the first-class pool, but the generator independently
        # proposed the same threat and grounding verified it — that is legitimate
        # evidence of relevance under the gate design (no GAP-B block, no duplicate row).
        assert 900 in rows
        assert str(rows[900].GroundingStatus) == str(GroundingStatus.verified)
        assert list(s.execute(select(m.Identified_Duplicate_Threat)).scalars()) == []

        # --- the genuinely novel proposal survives as an unverified custom threat ------
        novel = [r for cid, r in rows.items() if cid is None]
        assert len(novel) == 1
        assert "operator attribution" in novel[0].ThreatName
        assert str(novel[0].GroundingStatus) == str(GroundingStatus.unverified)
        assert novel[0].IsThreatAIGenerated is True

        # Ineligible catalogue rows never surface anywhere.
        assert 555 not in rows and 777 not in rows

        stage = s.execute(select(m.Subsystem_Stage_State).where(
            m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)).scalar_one()
        assert str(stage.Status) == str(StageStatus.COMPLETE)

        # --- audit: the library-first outcome block ------------------------------------
        summary = _summary(s)
        assert summary["status"] == "COMPLETE"
        assert summary["requested"] == 4 and summary["delivered"] == 4
        assert summary["backfilled"] == 0
        assert summary["quantity_gap"] == 2
        assert summary["coverage_missing"] == {"Spoofing": 1, "Repudiation": 1}
        assert summary["gate"] == {"pool": 3, "relevant": 2, "below_threshold": 1,
                                   "gate_failed": False}
        assert summary["llm"]["fallback_used"] is True
        assert summary["llm"]["failed"] is False
        assert summary["llm"]["usable"] == 2
        assert summary["retrieved"] == 2 and summary["generated"] == 2
        # selection_source stays the RETRIEVAL leg ("hybrid"); the gate verdict is the
        # separate gate_outcome fact — two orthogonal provenance dimensions, never folded.
        assert summary["selection_sources"] == {"hybrid": 2, "generated": 2}
        assert summary["backfilled_threats"] == []
        assert summary["backfill_semantic_blocked"] == 0

    # --- return value: gate provenance on every retrieved summary ----------------------
    by_name = {t["threat_name"]: t for t in threats}
    setpoint = by_name["Unauthorised setpoint modification"]
    assert setpoint["selection_source"] == "hybrid"
    assert setpoint["gate_outcome"] == "passed"
    assert setpoint["catalogue_id"] == 418
    assert setpoint["relevance_score"] == 95.0
    assert setpoint["category"] == "Tampering"
    assert len(threats) == 4

    # --- gap generation received the exclusion list of bare retrieved names ------------
    assert set(captured["exclude"]) == {
        "Unauthorised setpoint modification",
        "Credential phishing and MFA session theft"}


def test_zero_llm_calls_when_library_satisfies_count_and_coverage(monkeypatch):
    """THE headline invariant: count AND STRIDE coverage filled from the gated library →
    the LLM is never called at all this round."""
    llm = FakeLLM()
    threats, Session, _sid = _run(monkeypatch, llm, max_threats=2)

    assert llm.chat_calls == [], "no LLM call may happen when the library suffices"
    assert len(threats) == 2
    assert all(t["selection_source"] == "hybrid" for t in threats)
    assert all(t["gate_outcome"] == "passed" for t in threats)
    with Session() as s:
        rows = [r for r in s.execute(select(m.Identified_Threat)).scalars()
                if r.SubsystemID == 0]
        assert all(r.ThreatCatalogueID in (418, 205) for r in rows)
        summary = _summary(s)
        assert summary["status"] == "COMPLETE"
        assert summary["llm"] == {"fallback_used": False, "failed": False,
                                  "requested": 0, "usable": 0}
        assert summary["gate"]["below_threshold"] == 1   # 900 gated out, recorded
        assert summary["selection_sources"] == {"hybrid": 2}


def test_backfill_meets_count_with_flagged_below_threshold(monkeypatch):
    """Count is always met (user rule): with one relevant candidate, a dry generation
    round, and two below-gate candidates, the shortfall backfills best-score-first and
    every backfilled threat is flagged — the threshold itself never moved."""
    llm = FakeLLM(gate_scores={"Unauthorised setpoint modification": 95.0,
                               "Credential phishing and MFA session theft": 20.0,
                               "Payment card skimming at POS terminals": 10.0},
                  proposals=[])   # generation returns nothing usable
    threats, Session, _sid = _run(monkeypatch, llm, max_threats=2)

    assert len(threats) == 2
    by_cid = {t.get("catalogue_id"): t for t in threats}
    assert by_cid[418].get("backfill") is not True    # first-class, not backfill
    assert by_cid[205]["backfill"] is True            # best below-gate score (20 > 10)
    assert by_cid[205]["gate_outcome"] == "below_threshold"
    assert 900 not in by_cid
    with Session() as s:
        summary = _summary(s)
        assert summary["status"] == "COMPLETE"
        assert summary["delivered"] == 2 and summary["backfilled"] == 1
        # The backfilled row is identifiable from the audit alone, score included.
        assert [b["catalogue_id"] for b in summary["backfilled_threats"]] == [205]
        assert summary["backfilled_threats"][0]["relevance_score"] == 20.0


def test_partial_when_llm_fails_and_pool_exhausted(monkeypatch):
    """Provider failure must not destroy library results: the run keeps what the library
    gave, backfills what it can, and records PARTIAL — it does not raise, and nothing is
    fabricated to fake the count."""
    llm = FailingChatLLM(gate_scores={"Unauthorised setpoint modification": 95.0,
                                      "Credential phishing and MFA session theft": 20.0,
                                      "Payment card skimming at POS terminals": 10.0})
    threats, Session, _sid = _run(monkeypatch, llm, max_threats=4)

    assert len(llm.chat_calls) == 1          # generation was attempted, then failed
    assert len(threats) == 3                 # 418 first-class + 205/900 backfilled
    assert sum(1 for t in threats if t.get("backfill")) == 2
    with Session() as s:
        summary = _summary(s)
        assert summary["status"] == "PARTIAL"
        assert summary["requested"] == 4 and summary["delivered"] == 3
        assert summary["llm"]["failed"] is True
        stage = s.execute(select(m.Subsystem_Stage_State).where(
            m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)).scalar_one()
        assert str(stage.Status) == str(StageStatus.COMPLETE)


def test_retrieval_infrastructure_failure_propagates(monkeypatch):
    """Rule 6: a retrieval INFRASTRUCTURE failure is a failure — it must reach the Celery
    stage retry, never silently read as 'library empty → generate everything'."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    monkeypatch.setattr(threat_identification.threat_retrieval, "retrieve_library_threats",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    sid = str(uuid.uuid4())
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s, sid)
        with pytest.raises(RuntimeError, match="db down"):
            find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, FakeLLM(),
                         TASK_ID, max_threats=2)


def test_gate_outage_fails_open_flagged(monkeypatch):
    """A rerank-gate outage (score_relevance raises) is NOT 'nothing relevant': the Top-K
    pool goes forward ungated with ranking_degraded recorded — coverage never silently
    shrinks over a scoring blip."""
    monkeypatch.setattr(threat_identification.threat_retrieval, "score_relevance",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("rerank down")))
    llm = FakeLLM()
    threats, Session, _sid = _run(monkeypatch, llm, max_threats=2)
    assert len(threats) == 2
    with Session() as s:
        summary = _summary(s)
        assert summary["gate"]["gate_failed"] is True
        assert summary["ranking_degraded"] is True
        assert summary["status"] == "COMPLETE"


def test_next_set_additive_round_reuses_funnel_and_skips_held(monkeypatch):
    """Next-set parity: the additive path (supersede=False, prior threats held) runs the
    SAME gate → gap → generation funnel — re-surfaced library rows the session already
    holds are skipped by identity, and only the gap is generated."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    llm = FakeLLM()
    sid = str(uuid.uuid4())
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s, sid)
        first, _ = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                TASK_ID, max_threats=2)
        assert llm.chat_calls == []          # round 1: library filled everything
        # Same choreography as cascade.run_next_set's top-up: reset the stage for the new
        # epoch, then the additive find_threats call.
        tasks.dal.reset_stage_for_regen(s, sid, 0, (SubsystemLevel.THREATS,), 2)
        second, _ = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                 TASK_ID, epoch=2, supersede=False,
                                 prior_threats=first,
                                 exclude=[t["threat_name"] for t in first],
                                 max_threats=2)
        assert len(llm.chat_calls) == 1      # round 2: held rows skipped → gap generated
        assert len(second) == 2
        # Nothing the session already held was re-inserted.
        held_cids = {t.get("catalogue_id") for t in first}
        assert all(t.get("catalogue_id") not in held_cids for t in second)
        asset_rows = [r for r in s.execute(select(m.Identified_Threat)).scalars()
                      if r.SubsystemID == 0]
        assert len(asset_rows) == 4          # 2 from round 1 + 2 new from round 2


class _SlotEmbedLLM(FakeLLM):
    """Every embed call hits slot exhaustion — the signal that must ALWAYS propagate."""

    def embed(self, texts, kind=None):
        from app.pipeline.llm import LLMSlotUnavailable
        raise LLMSlotUnavailable("slots exhausted")


def test_llm_slot_unavailable_propagates_from_embed_paths(monkeypatch):
    """The slot signal must reach the Celery stage retry from EVERY embed site — retrieval,
    the semantic-duplicate scan, and grounding's query pre-warm. Swallowing it silently
    trades a clean retry for a materially worse stored result (keyword-only ranking /
    disabled dedup)."""
    from app.pipeline import grounding as grounding_mod
    from app.pipeline.llm import LLMSlotUnavailable

    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        s.commit()
        with pytest.raises(LLMSlotUnavailable):
            threat_retrieval.retrieve_library_threats(s, _SlotEmbedLLM(), SUBSYSTEMS,
                                                      ASSET_CONTEXT)
    with pytest.raises(LLMSlotUnavailable):
        tasks._semantic_duplicates(_SlotEmbedLLM(), "sid", 0,
                                   [{"threat_id": "a", "threat_name": "Threat A",
                                     "category": "Spoofing"}],
                                   [{"threat_id": "b", "threat_name": "Threat B",
                                     "category": "Spoofing"}])
    with pytest.raises(LLMSlotUnavailable):
        grounding_mod.prime_query_embeddings(_SlotEmbedLLM(),
                                             [{"type": "T", "name": "N"}], {})


def test_matrix_cache_keeps_multiple_text_list_shapes():
    """One (model, group, kind) legitimately serves several text-list shapes at once (the
    gate's Top-K subset AND regrounding's full corpus). The old one-slot cache made them
    evict each other on every run; both must stay warm now."""
    llm = FakeLLM()
    full, subset = ["alpha threat", "beta threat", "gamma threat"], ["alpha threat", "beta threat"]
    m1 = embeddings.get_matrix(llm, full, model_id="m", group="shape_test", kind="passage")
    if m1 is None:
        pytest.skip("numpy unavailable")
    m2 = embeddings.get_matrix(llm, subset, model_id="m", group="shape_test", kind="passage")
    # Same objects back — cache hits, not rebuilds — for BOTH shapes, in either order.
    assert embeddings.get_matrix(llm, full, model_id="m", group="shape_test",
                                 kind="passage")[0] is m1[0]
    assert embeddings.get_matrix(llm, subset, model_id="m", group="shape_test",
                                 kind="passage")[0] is m2[0]


def test_terminal_relabel_consistency_and_backfill_semantic_block(monkeypatch):
    """Three hardening fixes in one realistic scenario. A prior-round threat paraphrases
    the best candidate, dropping it between the passes:
    (F1) the surviving multi-category threat relabelled by the terminal pass moves BOTH
         category columns together (promote reads ThreatCategoryID off the row);
    (F9) the dropped candidate's identity claim is released, so it re-enters the pool
         instead of silently shrinking it;
    (F2) but the backfill semantic scan still blocks it as a paraphrase — recorded — and
         the NEXT pool candidate fills the count instead."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    llm = FakeLLM(gate_scores={"Credential phishing and MFA session theft": 95.0,
                               "Unauthorised setpoint modification": 90.0,
                               "Payment card skimming at POS terminals": 10.0},
                  proposals=[])
    sid = str(uuid.uuid4())
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        # 418 becomes MULTI-category (Spoofing + Tampering) via the authoritative map, so
        # the terminal pass can legitimately move it between slots.
        for catid in (5, 6):
            s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
                ThreatCategoryID=catid, ThreatCatalogueID=418))
        scenario_session = _seed_session(s, sid)
        prior = [{"threat_id": str(uuid.uuid4()),
                  "threat_name": "Credential phishing and MFA session theft",
                  "category": "Spoofing"}]
        threats, _ = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                  TASK_ID, max_threats=2, prior_threats=prior)
        by_cid = {t.get("catalogue_id"): t for t in threats}
        # 205 (the paraphrase of the prior threat) is out — dropped in pass 1, then
        # BLOCKED at backfill by the semantic scan, not by a stale identity claim.
        assert 205 not in by_cid
        # 418 was relabelled Tampering -> Spoofing by the terminal pass: both columns agree.
        row_418 = next(r for r in s.execute(select(m.Identified_Threat)).scalars()
                       if r.SubsystemID == 0 and r.ThreatCatalogueID == 418)
        assert row_418.ThreatCategory == "Spoofing"
        assert row_418.ThreatCategoryID == 5
        # 900 backfilled the second slot; the count is met, honestly.
        assert by_cid[900]["backfill"] is True
        summary = _summary(s)
        assert summary["status"] == "COMPLETE"
        assert summary["backfill_semantic_blocked"] == 1
        assert [b["catalogue_id"] for b in summary["backfilled_threats"]] == [900]


def test_backfill_serves_unfilled_stride_cell_before_higher_score(monkeypatch):
    """F3: backfill is coverage-aware — the candidate serving the UNFILLED STRIDE cell wins
    over a higher-scoring candidate that only duplicates held coverage, and its stored
    category is the ASSIGNED slot (selection and labelling stay one decision)."""
    llm = FakeLLM(gate_scores={"Credential phishing and MFA session theft": 95.0,
                               "Payment card skimming at POS terminals": 40.0,
                               "Unauthorised setpoint modification": 30.0},
                  proposals=[])
    threats, Session, _sid = _run(monkeypatch, llm, max_threats=2)

    by_cid = {t.get("catalogue_id"): t for t in threats}
    # 205 passed the gate (Spoofing). The unfilled cell is Tampering: 418 (score 30,
    # Tampering) must win the backfill slot over 900 (score 40, Spoofing).
    assert set(by_cid) == {205, 418}
    assert by_cid[418]["backfill"] is True
    assert by_cid[418]["category"] == "Tampering"
    with Session() as s:
        row_418 = next(r for r in s.execute(select(m.Identified_Threat)).scalars()
                       if r.SubsystemID == 0 and r.ThreatCatalogueID == 418)
        assert row_418.ThreatCategory == "Tampering"
        assert row_418.ThreatCategoryID == 6
        assert _summary(s)["status"] == "COMPLETE"


def test_production_scale_request_caps_gap_ask_and_reports_partial_honestly(monkeypatch):
    """Production is raising TSG_MAX_THREATS_PER_ASSET to 20. Gap generation must still ask
    for at most threat_llm_max_generation (15) in this ONE round, never the raw arithmetic
    (shortfall 18 x gap_generation_buffer 2.0 = 36) — and when this library is far too
    shallow to stretch to 20 even with that top-up, the run must report PARTIAL honestly
    rather than silently under-counting."""
    llm = FakeLLM()
    captured: dict = {}
    real_prompt = tasks.prompts.threats_prompt

    def _capture(*a, **kw):
        if kw.get("quota") is not None:
            captured.update(kw)
        return real_prompt(*a, **kw)
    monkeypatch.setattr(tasks.prompts, "threats_prompt", _capture)

    threats, Session, _sid = _run(monkeypatch, llm, max_threats=20)

    # 2 first-class library candidates (418, 205) leave an 18-threat shortfall; the ceiling
    # caps the ask at 15, not 18 x 2.0 = 36.
    assert captured["max_threats"] == 15

    with Session() as s:
        summary = _summary(s)
        assert summary["requested"] == 20
        assert summary["delivered"] == len(threats)
        # This tiny 3-row seed + one generated custom threat cannot stretch to 20 no
        # matter how high the ceiling — the shortfall is reported, never hidden.
        assert summary["status"] == "PARTIAL"
        assert summary["delivered"] < 20


def test_next_set_size_at_production_scale_reuses_funnel_without_duplicating(monkeypatch):
    """Production is raising TSG_NEXT_SET_SIZE to 10. The additive next-set path must
    handle a much larger ask without duplicating anything the session already holds, and
    must report the same honest PARTIAL accounting as the main funnel when the (shallow,
    now partly-exhausted) library still can't reach the new target."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    llm = FakeLLM()
    sid = str(uuid.uuid4())
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s, sid)
        first, _ = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                TASK_ID, max_threats=2)
        assert llm.chat_calls == []          # round 1: library alone filled 2/2
        tasks.dal.reset_stage_for_regen(s, sid, 0, (SubsystemLevel.THREATS,), 2)
        second, _ = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                 TASK_ID, epoch=2, supersede=False,
                                 prior_threats=first,
                                 exclude=[t["threat_name"] for t in first],
                                 max_threats=10)
        held_cids = {t.get("catalogue_id") for t in first}
        assert all(t.get("catalogue_id") not in held_cids for t in second)
        asset_rows = [r for r in s.execute(select(m.Identified_Threat)).scalars()
                      if r.SubsystemID == 0]
        assert len(asset_rows) == len(first) + len(second)

        audits = [json.loads(a.DetailJSON) for a in s.execute(
            select(m.Scenario_Audit)).scalars() if a.DetailJSON]
        round2_summary = [d for d in audits if "retrieved" in d][-1]
        assert round2_summary["requested"] == 10
        assert round2_summary["delivered"] == len(second)
        # Round 1 already spent the only two above-gate candidates; round 2 draws on the
        # remaining below-gate candidate plus one generation call and still falls short
        # of 10 — honestly reported, not padded.
        assert round2_summary["status"] == "PARTIAL"
        assert round2_summary["delivered"] < 10


def test_transient_db_error_retries_instead_of_cancelling_session(monkeypatch, caplog):
    """A transient DB error (deadlock/connection reset) during the pipeline must re-raise
    for the Celery stage retry — NOT route into _record_failure and cancel the session —
    and must log the enum-classified transient-infra event with full detail."""
    from sqlalchemy.exc import OperationalError

    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    sid = str(uuid.uuid4())
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        _seed_session(s, sid)

        def _deadlock(*a, **k):
            # Deactivate the session the way a real mid-flush deadlock does: after a
            # failed flush, EVERY further statement raises PendingRollbackError until a
            # rollback. Without the handler's rollback, that error would replace the
            # OperationalError below inside the cleanup `finally` and defeat autoretry —
            # pytest.raises pins that the original class survives.
            s.add(m.Identified_Threat())
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")  # the missing-PK warning IS the poison
                    s.flush()
            except Exception:  # noqa: BLE001 - ANY failure is the assertion; the flush must not succeed
                pass
            else:
                raise AssertionError("poison flush unexpectedly succeeded")
            raise OperationalError("SELECT ...", {}, Exception("deadlock victim"))
        monkeypatch.setattr(tasks, "find_threats", _deadlock)

        with pytest.raises(OperationalError):
            tasks._process_all_supporting_systems(s, sid, FakeLLM(), TASK_ID)
        row = s.execute(select(m.Scenario_Session)).scalar_one()
        assert row.SessionStatus == "active", "a transient blip must never cancel a session"
    assert any("transient_infra_error_retrying" in r.getMessage()
               and "database_transient" in r.getMessage()
               and "OperationalError" in r.getMessage() for r in caplog.records), \
        "the transient-infra retry must be logged with enum kind and exception class"


def test_transient_db_error_propagates_from_next_set_round(monkeypatch):
    """The next-set round must also re-raise transient infra errors for the Celery retry
    instead of stamping the stage COMPLETE with no trace."""
    from sqlalchemy.exc import OperationalError

    from app.pipeline import cascade

    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    sid = str(uuid.uuid4())
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s, sid)

        def _deadlock(*a, **k):
            # Same real-deadlock fidelity as the run_pipeline test: deactivate the
            # session via a failed flush so _subsystem_lock's release path is
            # exercised against a session that genuinely needs a rollback first.
            s.add(m.Identified_Threat())
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")  # the missing-PK warning IS the poison
                    s.flush()
            except Exception:  # noqa: BLE001 - ANY failure is the assertion; the flush must not succeed
                pass
            else:
                raise AssertionError("poison flush unexpectedly succeeded")
            raise OperationalError("SELECT ...", {}, Exception("connection reset"))
        monkeypatch.setattr(tasks, "find_threats", _deadlock)

        with pytest.raises(OperationalError):
            cascade.run_next_set(s, scenario_session, 0, epoch=2, threats_epoch=2,
                                 llm=FakeLLM(), task_id=TASK_ID)

        # The lock must actually release on the way out — a dirty session used to make
        # release_lock fail silently, leaving the lock held into the Celery retry.
        from app.db import dal
        assert dal.acquire_execution_lock(s, sid, 0, str(uuid.uuid4())), \
            "subsystem lock still held after transient propagated"


def test_transient_db_error_propagates_from_regeneration(monkeypatch):
    """The in-lock regeneration handler must re-raise transient infra errors for the
    Celery retry — not record a failed stage and cancel the session — and the
    subsystem lock must still release."""
    from sqlalchemy.exc import OperationalError

    from app.core.enums import RegenGranularity
    from app.db import dal
    from app.pipeline import cascade

    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    sid = str(uuid.uuid4())
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s, sid)

        def _deadlock(*a, **k):
            # Same failed-flush poison as the other transient tests: the session
            # genuinely needs a rollback before any cleanup SQL can run.
            s.add(m.Identified_Threat())
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")  # the missing-PK warning IS the poison
                    s.flush()
            except Exception:  # noqa: BLE001 - ANY failure is the assertion; the flush must not succeed
                pass
            else:
                raise AssertionError("poison flush unexpectedly succeeded")
            raise OperationalError("UPDATE ...", {}, Exception("deadlock victim"))

        # Reach the IN-LOCK handler: target resolution succeeds, the write blows up.
        monkeypatch.setattr(cascade, "get_threat_id_to_redo", lambda *a, **k: {})
        monkeypatch.setattr(tasks, "write_scenarios", _deadlock)

        with pytest.raises(OperationalError):
            cascade.run_regeneration(s, scenario_session, 0, RegenGranularity.scenario,
                                     None, 2, FakeLLM(), TASK_ID)

        row = s.execute(select(m.Scenario_Session)).scalar_one()
        assert row.SessionStatus == "active", "a transient blip must never cancel a session"
        assert dal.acquire_execution_lock(s, sid, 0, str(uuid.uuid4())), \
            "subsystem lock still held after transient propagated"


def test_transient_db_error_propagates_from_regeneration_pre_lock(monkeypatch):
    """A transient while reading the regen targets (before any lock or stage claim) must
    also re-raise for the Celery retry instead of cancelling the session."""
    from sqlalchemy.exc import OperationalError

    from app.core.enums import RegenGranularity
    from app.pipeline import cascade

    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    sid = str(uuid.uuid4())
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s, sid)

        def _deadlock(*a, **k):
            raise OperationalError("SELECT ...", {}, Exception("connection reset"))
        monkeypatch.setattr(cascade, "get_threat_id_to_redo", _deadlock)

        with pytest.raises(OperationalError):
            cascade.run_regeneration(s, scenario_session, 0, RegenGranularity.scenario,
                                     None, 2, FakeLLM(), TASK_ID)

        row = s.execute(select(m.Scenario_Session)).scalar_one()
        assert row.SessionStatus == "active", "a transient blip must never cancel a session"


def test_celery_tasks_autoretry_transient_infra_errors():
    """Config pin: the three pipeline tasks must autoretry OperationalError — without
    this, the re-raised transient reaches Celery and the task just FAILS instead of
    retrying, which silently regresses the resilience contract."""
    from sqlalchemy.exc import OperationalError

    from app.pipeline import celery_app as ca

    for task in (ca.run_pipeline_task, ca.regenerate_task, ca.next_set_task):
        assert OperationalError in task.autoretry_for, task.name


def test_retrieval_eligibility_and_candidate_shape():
    """The deterministic half of Stage 1a on its own: eligibility is a SQL fact, provable
    without any chat — liveness ALONE (IsActive/IsDeleted on the row AND an active parent
    type). Candidates carry the catalogue identity and per-TYPE junction actors the rest
    of the pipeline stores verbatim."""
    Session = sessionmaker(bind=_engine(), future=True)
    llm = FakeLLM()
    with Session() as s:
        _seed_library(s)
        s.commit()
        out = threat_retrieval.retrieve_library_threats(s, llm, SUBSYSTEMS, ASSET_CONTEXT)
    by_id = {c["catalogue_id"]: c for c in out}
    assert set(by_id) == {205, 418, 900}
    for c in out:
        assert c["selection_source"] == "hybrid"
        assert c["ranking_degraded"] is False
    assert by_id[418]["type_id"] == 7
    assert by_id[418]["type_name"] == "Logic/Configuration Manipulation"
    assert by_id[418]["actors"] == ["APT33", "AquaViper"]
    assert by_id[418]["actor_ids"] == [1, 2]
    assert by_id[205]["actors"] == [] and by_id[205]["actor_ids"] == []
    assert by_id[418]["categories"] == ["Tampering"]
    assert by_id[205]["categories"] == ["Spoofing"]
    assert by_id[418]["subsystem_ids"] == [41, 42]


def test_dead_library_returns_nothing():
    """A library whose every row is retired must return [] LOUDLY (find_threats then
    degrades to generation-only) rather than serving the dead rows anyway."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s, include_live=False)
        s.commit()
        assert threat_retrieval.retrieve_library_threats(
            s, FakeLLM(), SUBSYSTEMS, ASSET_CONTEXT) == []


def test_coverage_reporting_off_by_default_computes_and_stores_nothing(monkeypatch):
    """TSG_COVERAGE_REPORTING_ENABLED defaults False: the audit row must carry NEITHER
    "units" NOR "coverage" — genuinely absent, not computed-and-empty."""
    assert get_settings().coverage_reporting_enabled is False
    llm = FakeLLM()
    _threats, Session, _sid = _run(monkeypatch, llm, max_threats=4)
    with Session() as s:
        summary = _summary(s)
        assert "units" not in summary and "coverage" not in summary


def test_coverage_reporting_enabled_restores_the_prior_shape(monkeypatch):
    """Flipping the flag on must genuinely restore the old computation, not just leave it
    permanently disabled behind an inert toggle."""
    monkeypatch.setattr(get_settings(), "coverage_reporting_enabled", True)
    llm = FakeLLM()
    _threats, Session, _sid = _run(monkeypatch, llm, max_threats=4)
    with Session() as s:
        summary = _summary(s)
        assert "units" in summary and "coverage" in summary
        assert summary["units"][0] == 0  # ASSET_UNIT_ID leads the grid, same as before
        assert "cells" in summary["coverage"] and "unexplained" in summary["coverage"]
