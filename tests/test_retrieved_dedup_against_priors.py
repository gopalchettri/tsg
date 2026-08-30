"""Dedup identity on the CATALOGUE model: what makes two threats "the same threat".

The 2026-08 reversal moved the dedup key's first rung back to cat:{ThreatCatalogueID}
(Threat_Catalogue PK, summary key "catalogue_id"). Everything downstream leans on that rung:

* dal.identity_hash folds sha256(session|subsystem|_dedup_key), so a re-retrieved catalogue
  threat on an ADDITIVE round (next-set) hashes identically to the row already active on the
  session — the retrieval loop skips it SILENTLY (no duplicate row, no audit tally): the
  library re-surfacing its own row is a no-op, not a finding.
* Exact identity misses PARAPHRASES — a prior round may have GENERATED the same threat under
  different wording, where catalogue_id is None and the text rungs cannot match. The
  retrieved-vs-prior semantic scan (_semantic_duplicates, compare_within=False) exists for
  exactly that gap, and a hit is audit-worthy: an Identified_Duplicate_Threat row naming the
  surviving prior threat, reason semantic_similarity.
* compare_within=False keeps retrieved-vs-retrieved EXEMPT: two distinct catalogue rows
  surviving one round together is the curator's call — only a match against something
  OUTSIDE this round's library set may drop a retrieved candidate.

These tests pin all three behaviours through find_threats itself, on SQLite fixtures seeded
with the catalogue tables (the crm_* register trio no longer exists in code).
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker

from app.core.enums import DuplicateReason, StageStatus
from app.db import dal
from app.db import models as m
from app.pipeline import embeddings, tasks
from app.pipeline.tasks import _dedup_key, find_threats, set_up_progress_tracking


@pytest.fixture(autouse=True)
def _isolated_embeddings(monkeypatch):
    """Same isolation as the sibling pipeline tests — a real local Mongo would otherwise
    serve real vectors for library names that exist in the live seed, colliding with this
    test's fake ones."""
    monkeypatch.setenv("TSG_EMBEDDING_STORE", "memory")
    embeddings._L1.clear()
    embeddings._MATRIX.clear()
    yield
    embeddings._L1.clear()
    embeddings._MATRIX.clear()


SID = str(uuid.uuid4())
NOW = datetime.now(UTC)

#: asset_type_id keys are inert for retrieval now (control ITOT filter only) — kept so the
#: session dicts stay shaped like the real ones context.py stamps.
SUBSYSTEMS = [{"id": 41, "name": "SCADA HMI Server", "asset_type": "OT", "asset_type_id": 3,
               "technology_used": ["Siemens SCADA"], "vendor_name": "Siemens",
               "criticality": "High"}]
ASSET_CONTEXT = {"name": "Water Pumping Station", "asset_type": "Pumping Station",
                 "asset_type_id": 3, "sector": "Energy & Water", "sub_sector": "Water Supply",
                 "critical_service": ["Potable water supply"]}

#: The catalogue's official name for the one library row most tests care about.
RETRIEVED_NAME = "Unauthorised setpoint modification"
#: A PRIOR round's differently-worded GENERATED threat covering the same concept — same
#: embedding axis under FakeLLM below, so cosine similarity pins it as a near-duplicate.
PRIOR_NAME = "Unauthorized alteration of pump setpoints"
PRIOR_THREAT_ID = str(uuid.uuid4())
#: A second, textually distinct catalogue row the curator keeps deliberately separate.
SIBLING_NAME = "Unauthorised setpoint tampering"


class FakeLLM:
    """Deterministic: retrieval always surfaces the seeded catalogue rows; the validator
    keeps every candidate (RELEVANT); Stage-1b gap generation proposes nothing — so each
    test isolates ONE dedup decision.

    `collapse`: names that all embed onto ONE axis (identical vector, cosine 1.0). Every
    other unique text gets its own orthogonal one-hot slot."""

    def __init__(self, collapse: tuple[str, ...] = (RETRIEVED_NAME, PRIOR_NAME)):
        self._collapse = set(collapse)
        self._canon = next(iter(collapse))
        self._slots: dict[str, int] = {}

    def embed(self, texts, kind=None):
        out = []
        for t in texts:
            key = self._canon if t in self._collapse else t
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
                         "justification": "SCADA setpoints are remotely modifiable here"}
                        for c in payload["candidate_threats"]]
            return json.dumps(verdicts), None
        return json.dumps([]), None  # Stage-1b: no gap-fill proposals in these tests


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Identified_Duplicate_Threat, m.Scenario_Audit, m.Prompt_Log,
                m.Threat_Category, m.Threat_Type, m.Threat_Catalogue,
                m.Threat_Actor, m.ThreatType_ThreatActor_Map,
                m.Threat_Catalogue_Category_Map):
        tbl.__table__.create(engine)
    return engine


def _seed_library(s) -> None:
    s.execute(m.Threat_Category.__table__.insert().values(
        ThreatCategoryID=6, ThreatCategoryName="Tampering", IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=7, ThreatTypeName="Logic/Configuration Manipulation", ThreatCategoryID=6,
        IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Catalogue.__table__.insert().values(
        ThreatCatalogueID=418, ThreatTypeID=7, ThreatName=RETRIEVED_NAME,
        Description="An actor alters pump setpoints so control logic integrity is lost.",
        IsActive=True, IsDeleted=False, CreatedBy="seed", CreatedAt=NOW))
    s.execute(m.Threat_Actor.__table__.insert().values(
        ThreatActorID=5, ThreatActorName="Nation-state/APT", IsCapable=1,
        IsActive=True, IsDeleted=False))
    s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
        ThreatTypeID=7, ThreatActorID=5))


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


def _grounding_summaries(s) -> list[dict]:
    """Every grounding_summary audit payload, in write order (last = latest round)."""
    return [json.loads(a.DetailJSON) for a in s.execute(select(m.Scenario_Audit)).scalars()
            if a.DetailJSON and "retrieved" in (json.loads(a.DetailJSON) or {})]


def test_dedup_key_catalogue_rung_wins_over_wording():
    """The first rung is the catalogue PK: once a threat IS a known library row, its wording
    is irrelevant to identity — that is what lets an additive round recognise a re-retrieved
    row however either side happens to spell it. Without the rung, the type|name text fold
    would treat every rewording as a brand-new threat."""
    base = {"threat_type": "Logic/Configuration Manipulation",
            "threat_name": RETRIEVED_NAME, "threat_type_id": 7}
    assert _dedup_key({**base, "catalogue_id": 418}) == "cat:418"
    # No catalogue id -> the type rung, normalized text folded in.
    assert _dedup_key(base) == "type:7|unauthorised setpoint modification"
    # identity_hash equality follows the catalogue rung, not the wording...
    assert dal.identity_hash(SID, 0, {**base, "catalogue_id": 418}) == dal.identity_hash(
        SID, 0, {"catalogue_id": 418, "threat_name": "Totally different wording"})
    # ...and distinct catalogue rows never collide, whatever their text says.
    assert dal.identity_hash(SID, 0, {**base, "catalogue_id": 418}) != dal.identity_hash(
        SID, 0, {**base, "catalogue_id": 419})


def test_reretrieved_catalogue_threat_on_additive_round_is_skipped_silently(monkeypatch):
    """An additive next-set round re-runs retrieval, and the library dutifully re-surfaces
    the row the session already holds. That is the LIBRARY WORKING, not a duplicate finding:
    identity_hash matches the active row (cat:{id} rung), so the candidate is skipped with
    no second Identified_Threat row, no Identified_Duplicate_Threat row, and no duplicate
    tally in the audit — silence is the pinned contract."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    llm = FakeLLM()
    task_1, task_2 = str(uuid.uuid4()), str(uuid.uuid4())

    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s)
        round1, _ = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                 task_1, max_threats=1)
    assert [t["catalogue_id"] for t in round1] == [418]

    with Session() as s:
        # The additive caller re-idles the stage before its top-up round.
        s.execute(update(m.Subsystem_Stage_State).values(
            Status=StageStatus.IDLE, ActiveTaskID=None))
        s.commit()
        round2, _ = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                 task_2, supersede=False, prior_threats=round1,
                                 max_threats=1)
    assert round2 == []

    with Session() as s:
        live = list(s.execute(select(m.Identified_Threat).where(
            m.Identified_Threat.SubsystemID == 0,
            m.Identified_Threat.Superseded == 0)).scalars())
        assert len(live) == 1, "the round-1 row must survive alone — never a twin"
        assert live[0].ThreatCatalogueID == 418
        assert list(s.execute(select(m.Identified_Duplicate_Threat)).scalars()) == []
        latest = _grounding_summaries(s)[-1]
        assert latest["retrieved"] == 0
        assert latest["generated"] == 0
        # SILENT skip: neither duplicate counter may claim it.
        assert latest["identity_duplicates"] == 0
        assert latest["retrieved_semantic_duplicates"] == 0


def test_retrieved_candidate_paraphrasing_a_prior_threat_is_diverted_not_reinserted(monkeypatch):
    """A prior round GENERATED this threat under different wording (catalogue_id None), so
    the cat:/type: rungs cannot match — only the semantic scan against prior_threats can
    catch it. The candidate must be diverted to Identified_Duplicate_Threat (reason
    semantic_similarity, naming the surviving prior threat), never inserted live: a session
    listing the same threat twice under two spellings is the exact bug this scan closed."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    llm = FakeLLM(collapse=(RETRIEVED_NAME, PRIOR_NAME))
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
                                      str(uuid.uuid4()), max_threats=1,
                                      prior_threats=prior_threats)
    assert threats == []

    with Session() as s:
        assert list(s.execute(select(m.Identified_Threat)).scalars()) == [], \
            "a prior-round near-duplicate must never reach Identified_Threat"
        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert len(dups) == 1
        assert dups[0].DuplicateReason == str(DuplicateReason.semantic_similarity)
        assert dups[0].DuplicateOfThreatID == PRIOR_THREAT_ID
        assert dups[0].ThreatName == RETRIEVED_NAME
        latest = _grounding_summaries(s)[-1]
        # Countable in the audit trail, not just silently absent.
        assert latest["retrieved_semantic_duplicates"] == 1
        assert latest["retrieved"] == 0
        assert latest["generated"] == 0


def test_two_catalogue_rows_retrieved_together_are_never_compared_to_each_other(monkeypatch):
    """The exemption half: TWO catalogue rows retrieved in the SAME round, embedding onto the
    same axis (cosine 1.0 — they WOULD collide under compare_within=True), must BOTH survive
    when the only prior threat is unrelated. The scan genuinely runs here (priors non-empty),
    so what this pins is compare_within=False at the find_threats integration point: the
    curator vouched for the rows' coexistence, and the scan may not overrule the library."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    llm = FakeLLM(collapse=(RETRIEVED_NAME, SIBLING_NAME))
    # Orthogonal prior — its own embedding slot — so the prior-scan runs but matches nothing.
    prior_threats = [{
        "threat_id": str(uuid.uuid4()), "threat_name": "Phishing of control-room operators",
        "category": "Tampering", "grounding_status": "unverified",
        "library_threat_name": None, "library_threat_type": None,
        "threat_type": "Social Engineering", "threat_type_id": None,
        "catalogue_id": None, "actors": [],
    }]
    with Session() as s:
        _seed_library(s)
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=419, ThreatTypeID=7, ThreatName=SIBLING_NAME,
            Description="A second, textually distinct row the curator kept separate.",
            IsActive=True, IsDeleted=False, CreatedBy="seed", CreatedAt=NOW))
        scenario_session = _seed_session(s)
        threats, _prov = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                      str(uuid.uuid4()), max_threats=2,
                                      prior_threats=prior_threats)
    assert {t["threat_name"] for t in threats} == {RETRIEVED_NAME, SIBLING_NAME}
    assert {t["catalogue_id"] for t in threats} == {418, 419}
    with Session() as s:
        assert list(s.execute(select(m.Identified_Duplicate_Threat)).scalars()) == []
        latest = _grounding_summaries(s)[-1]
        assert latest["retrieved"] == 2
        assert latest["retrieved_semantic_duplicates"] == 0
