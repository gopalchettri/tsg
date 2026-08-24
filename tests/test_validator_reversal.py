"""The validator's NOT_RELEVANT hard drop (GAP-B) must survive Stage-1b regeneration.

THE BUG. _validate_candidates drops a NOT_RELEVANT candidate from Stage 1a's own list and
records it, write-only, inside the grounding_summary audit row. Stage 1b's generator has no
knowledge of that verdict -- it can propose a threat that grounds (via
grounding.find_threat_in_library) back to the EXACT SAME catalogue row the validator just
rejected for THIS asset. The identity check that follows only tests membership in
existing_identities, which the rejected row was never added to (it was dropped before
insertion), so the regrounded proposal is inserted anyway -- silently reversing a verdict the
documented contract calls a HARD drop.

THE FIX. The rejected catalogue ids are seeded into a set right after validation and checked
at the regrounding site, right after find_threat_in_library resolves a catalogue_id. A reversal
attempt is diverted to Identified_Duplicate_Threat with a dedicated, auditable reason
(DuplicateReason.validator_rejected) instead of silently landing in Identified_Threat.
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
    """Same isolation as test_library_first_identification.py — a real local Mongo would
    otherwise serve real vectors for library names that exist in the live seed, colliding with
    this test's fake ones."""
    monkeypatch.setenv("TSG_EMBEDDING_STORE", "memory")
    embeddings._L1.clear()
    embeddings._MATRIX.clear()
    yield
    embeddings._L1.clear()
    embeddings._MATRIX.clear()


SID = str(uuid.uuid4())
TASK_ID = str(uuid.uuid4())
NOW = datetime.now(UTC)

SUBSYSTEMS = [{"id": 41, "name": "Corporate Web Portal", "asset_type": "IT",
             "technology_used": ["Django"], "vendor_name": "In-house", "criticality": "Medium"}]
ASSET_CONTEXT = {"name": "Customer Portal Platform", "asset_type": "Web Application",
                "sector": "Finance", "sub_sector": "Retail Banking",
                "critical_service": ["Online banking"]}

#: The one catalogue row this test cares about. Named so an exact-text regrounding match is
#: trivial to construct with the same FakeLLM.rerank exact-match convention the sibling P2 gate
#: test uses.
REJECTED_NAME = "Web application parameter tampering"


class FakeLLM:
    """Deterministic: retrieval always surfaces the one seeded row; the validator always
    rejects it (so it lands in `dropped`); generation always proposes the SAME threat by name
    and type, forcing find_threat_in_library to reground it to the identical catalogue_id."""

    def __init__(self):
        self._slots: dict[str, int] = {}

    def embed(self, texts, kind=None):
        out = []
        for t in texts:
            idx = self._slots.setdefault(t, len(self._slots))
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
            verdicts = [{"index": c["index"], "verdict": "NOT_RELEVANT",
                        "justification": "no public web application is exposed by this asset"}
                        for c in payload["candidate_threats"]]
            return json.dumps(verdicts), None
        # Stage-1b generation: proposes the EXACT threat the validator just rejected. A real
        # model doing this is entirely plausible -- Stage 1b has no visibility into Stage 1a's
        # verdicts, so nothing stops it from re-deriving the same idea independently.
        return json.dumps([
            {"category": "Tampering", "type": "Web Input Tampering",
            "name": REJECTED_NAME, "generic_name": REJECTED_NAME, "actors": []},
        ]), None


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
        ThreatTypeID=7, ThreatTypeName="Web Input Tampering", ThreatCategoryID=6,
        IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Catalogue.__table__.insert().values(
        ThreatCatalogueID=522, ThreatName=REJECTED_NAME, ThreatTypeID=7,
        Description="Tampering with parameters of a public web application.",
        IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
        ThreatCategoryID=6, ThreatCatalogueID=522))


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


def test_regrounded_generation_cannot_silently_reverse_a_validator_rejection(monkeypatch):
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    llm = FakeLLM()
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s)
        # max_threats=2 with only 1 retrieved-and-rejected candidate guarantees a shortfall,
        # so Stage 1b's generation loop actually runs.
        threats, _prov = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                    TASK_ID, max_threats=2)

    # THE assertion: the regrounded proposal must NOT be a live threat.
    assert threats == []

    with Session() as s:
        live = list(s.execute(select(m.Identified_Threat)).scalars())
        assert live == [], "a validator-rejected catalogue row must never reach Identified_Threat"

        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert len(dups) == 1
        assert dups[0].DuplicateReason == str(DuplicateReason.validator_rejected)
        assert dups[0].ThreatName == REJECTED_NAME

        audit = [json.loads(a.DetailJSON) for a in s.execute(select(m.Scenario_Audit)).scalars()
                if a.DetailJSON]
        summary = next(d for d in audit if "validator" in d)
        # Recorded and countable, not just silently absent -- an operator asking "why is this
        # threat missing" must be able to find the answer here.
        assert summary["validator_reversals_blocked"] == 1
        assert summary["validator"]["dropped"][0]["catalogue_id"] == 522
