"""A LIBRARY-RETRIEVED candidate must not re-insert a prior round's threat under new wording.

THE BUG. The retrieval loop in find_threats only ever checked a candidate against
existing_identities — an EXACT identity-hash match. It never ran the near-duplicate
semantic scan (_semantic_duplicates) against prior_threats the way Stage 1b's GENERATED
candidates already do. On an additive next-set round, a prior round may have inserted a
threat under one wording (generated text, or a library row grounded under a different
name) and this round's library retrieval can re-surface the SAME underlying threat under
different wording — same meaning, different string, so identity_hash misses it, and the
threat gets duplicated in the session with a fresh ThreatID.

THE FIX. After the retrieval loop builds this round's candidates, they are run through
_semantic_duplicates against prior_threats too, with compare_within=False so two DISTINCT
library rows retrieved in the SAME round are never compared against each other (the
curator already vouched for their coexistence) — only a match against a PRIOR round can
drop a retrieved candidate.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.enums import DuplicateReason
from app.db import models as m
from app.pipeline import embeddings, tasks
from app.pipeline.tasks import find_threats, set_up_progress_tracking


@pytest.fixture(autouse=True)
def _isolated_embeddings(monkeypatch):
    """Same isolation as the sibling P2-gate tests — a real local Mongo would otherwise serve
    real vectors for library names that exist in the live seed, colliding with this test's
    fake ones."""
    monkeypatch.setenv("TSG_EMBEDDING_STORE", "memory")
    embeddings._L1.clear()
    embeddings._MATRIX.clear()
    yield
    embeddings._L1.clear()
    embeddings._MATRIX.clear()


SID = str(uuid.uuid4())
TASK_ID = str(uuid.uuid4())
NOW = datetime.now(UTC)

SUBSYSTEMS = [{"id": 41, "name": "SCADA HMI Server", "asset_type": "OT",
             "technology_used": ["Siemens SCADA"], "vendor_name": "Siemens", "criticality": "High"}]
ASSET_CONTEXT = {"name": "Water Pumping Station", "asset_type": "Pumping Station",
                "sector": "Energy & Water", "sub_sector": "Water Supply",
                "critical_service": ["Potable water supply"]}

#: The library's official name for the one catalogue row this test cares about.
RETRIEVED_NAME = "Unauthorised setpoint modification"
#: A PRIOR round's differently-worded threat covering the exact same concept — same axis
#: under FakeLLM.embed below, so cosine similarity pins it as a near-duplicate.
PRIOR_NAME = "Unauthorized alteration of pump setpoints"
PRIOR_THREAT_ID = str(uuid.uuid4())


class FakeLLM:
    """Deterministic: retrieval always surfaces the one seeded row; the validator always
    keeps it (RELEVANT); Stage-1b generation proposes nothing, so the test isolates the
    retrieved-vs-prior dedup step on its own."""

    def __init__(self):
        self._slots: dict[str, int] = {}

    def embed(self, texts, kind=None):
        out = []
        for t in texts:
            # RETRIEVED_NAME and PRIOR_NAME collapse onto the SAME slot (identical vector,
            # cosine 1.0) — everything else gets its own orthogonal one-hot slot, same
            # convention as the sibling FakeLLMs in this test suite.
            key = RETRIEVED_NAME if t in (RETRIEVED_NAME, PRIOR_NAME) else t
            idx = self._slots.setdefault(key, len(self._slots))
            v = [0.0] * 64
            v[idx % 64] = 1.0
            out.append(v)
        return out

    def rerank(self, query, docs):
        return [95.0 if d.strip().lower() == query.strip().lower() else 5.0 for d in docs]

    def chat(self, messages, temperature=None, expected_type=None):
        system = messages[0]["content"]
        if "VALIDATING pre-selected library threats" in system:
            user = messages[-1]["content"]
            payload = json.loads(user[user.index("{"):])
            verdicts = [{"index": c["index"], "verdict": "RELEVANT",
                        "justification": "directly alters control logic"}
                        for c in payload["candidate_threats"]]
            return json.dumps(verdicts), None
        return json.dumps([]), None  # Stage-1b: no gap-fill proposals needed for this test


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Identified_Duplicate_Threat, m.Scenario_Audit, m.Prompt_Log,
                m.Threat_Category, m.Threat_Type, m.Threat_Catalogue,
                m.Threat_Catalogue_Category_Map, m.Threat_Actor,
                m.ThreatType_ThreatActor_Map, m.Config_Threat_Rule):
        tbl.__table__.create(engine)
    return engine


def _seed_library(s) -> None:
    s.execute(m.Threat_Category.__table__.insert().values(
        ThreatCategoryID=6, ThreatCategoryName="Tampering", IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=7, ThreatTypeName="Logic/Configuration Manipulation", ThreatCategoryID=6,
        IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Catalogue.__table__.insert().values(
        ThreatCatalogueID=418, ThreatName=RETRIEVED_NAME, ThreatTypeID=7,
        Description="An actor alters pump setpoints so control logic integrity is lost.",
        IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
        ThreatCategoryID=6, ThreatCatalogueID=418))


def _seed_session(s) -> dict:
    row = {"SessionID": SID, "TenantID": "t", "EntityID": "e", "UserID": "u",
        "AssetName": ASSET_CONTEXT["name"], "AssetID": "1", "SessionStatus": "active",
        "CurrentStage": "THREAT_IDENTIFICATION", "StageStatus": "IDLE", "Mode": "AUTO",
        "SubsystemsJSON": json.dumps(SUBSYSTEMS), "SectorIDsJSON": json.dumps([]),
        "CreatedAt": NOW, "UpdatedAt": NOW}
    s.execute(m.Scenario_Session.__table__.insert().values(**row))
    set_up_progress_tracking(s, SID, "t", "e")
    s.commit()
    return row


def test_retrieved_candidate_paraphrasing_a_prior_threat_is_diverted_not_reinserted(monkeypatch):
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    llm = FakeLLM()
    prior_threats = [{
        "threat_id": PRIOR_THREAT_ID, "threat_name": PRIOR_NAME, "category": "Tampering",
        "grounding_status": "unverified", "library_threat_name": None,
        "library_threat_type": None, "threat_type": "Logic/Configuration Manipulation",
        "threat_type_id": None, "catalogue_id": None, "actors": [],
    }]
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s)
        threats, _prov = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                    TASK_ID, max_threats=1, prior_threats=prior_threats)

    # THE assertion: the retrieved candidate must NOT reach the live threat list.
    assert threats == []

    with Session() as s:
        live = list(s.execute(select(m.Identified_Threat)).scalars())
        assert live == [], "a prior-round near-duplicate must never reach Identified_Threat"

        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert len(dups) == 1
        assert dups[0].DuplicateReason == str(DuplicateReason.semantic_similarity)
        assert dups[0].DuplicateOfThreatID == PRIOR_THREAT_ID
        assert dups[0].ThreatName == RETRIEVED_NAME

        audit = [json.loads(a.DetailJSON) for a in s.execute(select(m.Scenario_Audit)).scalars()
                if a.DetailJSON]
        summary = next(d for d in audit if "retrieved" in d)
        # Countable in the audit trail, not just silently absent.
        assert summary["retrieved_semantic_duplicates"] == 1
        assert summary["retrieved"] == 0
        assert summary["generated"] == 0


def test_two_distinct_library_rows_retrieved_together_are_not_compared_to_each_other(monkeypatch):
    """The exemption half of the fix: TWO library rows retrieved in the SAME round, whose
    labels happen to collide under FakeLLM's embedding scheme, must both survive when there
    is no prior round to compare against — compare_within=False must hold at the
    find_threats integration point, not just in the unit-level guard check."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    llm = FakeLLM()
    with Session() as s:
        _seed_library(s)
        # A second catalogue row whose name is the SAME "meaning" axis as RETRIEVED_NAME
        # under FakeLLM.embed (both fall into the same slot via the `key` rule below) --
        # exercised by widening the embed's collapse set for this test only.
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=419, ThreatName="Unauthorised setpoint tampering", ThreatTypeID=7,
            Description="A second, textually distinct row the curator kept separate.",
            IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
            ThreatCategoryID=6, ThreatCatalogueID=419))
        scenario_session = _seed_session(s)

        # Make both catalogue rows collapse onto one embedding axis, same trick as the
        # RETRIEVED_NAME/PRIOR_NAME pair above, so they WOULD collide under compare_within=True.
        orig_embed = llm.embed
        def embed(texts, kind=None):
            mapped = ["Unauthorised setpoint modification" if t in (
                "Unauthorised setpoint modification", "Unauthorised setpoint tampering") else t
                for t in texts]
            return orig_embed(mapped, kind=kind)
        llm.embed = embed

        threats, _prov = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                    TASK_ID, max_threats=5, prior_threats=[])

    assert {t["threat_name"] for t in threats} == {
        "Unauthorised setpoint modification", "Unauthorised setpoint tampering"}
    with Session() as s:
        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert dups == []
