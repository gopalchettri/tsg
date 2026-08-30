"""The validator's NOT_RELEVANT hard drop (GAP-B) must survive Stage-1b regeneration.

THE INVARIANT. _validate_candidates drops a NOT_RELEVANT candidate from Stage 1a's own list,
but Stage 1b's generator has no visibility into that verdict — it can propose a threat that
regrounds (grounding.find_threat_in_library) onto the EXACT SAME Threat_Catalogue row
the validator just rejected for THIS asset. find_threats therefore seeds the dropped
catalogue ids into `rejected_catalogue_ids` right after validation and re-checks them at the
regrounding site: a reversal attempt is diverted to Identified_Duplicate_Threat with
DuplicateReason.validator_rejected and counted in the grounding_summary audit
(validator_reversals_blocked), instead of silently landing in Identified_Threat.

These tests pin the whole round-trip on the 2026-08 catalogue model, AND its boundaries: the
block must fire only on catalogue rows THIS round's validator rejected — never on a different
catalogue row, and never on a proposal whose grounding produced no catalogue id at all.
Over-blocking would silently shrink coverage, which is the exact failure mode the fail-open
validator design exists to prevent.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.enums import DuplicateReason, GroundingStatus
from app.db import models as m
from app.pipeline import embeddings, tasks
from app.pipeline.tasks import find_threats, set_up_progress_tracking


@pytest.fixture(autouse=True)
def _isolated_embeddings(monkeypatch):
    """A real local Mongo would otherwise serve real vectors for library names that exist in
    the live seed, colliding with this test's fake one-hot ones."""
    monkeypatch.setenv("TSG_EMBEDDING_STORE", "memory")
    embeddings._L1.clear()
    embeddings._MATRIX.clear()
    yield
    embeddings._L1.clear()
    embeddings._MATRIX.clear()


@pytest.fixture(autouse=True)
def _mute_bus(monkeypatch):
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)


TASK_ID = str(uuid.uuid4())
NOW = datetime.now(UTC)

#: asset_type_id keys are inert for retrieval on the catalogue model (they feed only the
#: control ITOT filter) — kept because context.py stamps them on every real session.
SUBSYSTEMS = [{"id": 41, "name": "Corporate Web Portal", "asset_type": "IT",
               "asset_type_id": 2, "technology_used": ["Django"], "vendor_name": "In-house",
               "criticality": "Medium"}]
ASSET_CONTEXT = {"name": "Customer Portal Platform", "asset_type": "Web Application",
                 "asset_type_id": 2, "sector": "Finance", "sub_sector": "Retail Banking",
                 "critical_service": ["Online banking"]}

#: The catalogue row the validator rejects.
REJECTED_ID = 522
REJECTED_NAME = "Web application parameter tampering"
#: A second live catalogue row of the SAME type. The catalogue model has no asset-type (or
#: any other) retrieval filter, so when seeded it IS retrieved and judged alongside the
#: first — a groundable-but-unretrieved row cannot exist anymore (retrieval and
#: get_possible_names share the same liveness predicate). Seeded only where a test needs it.
OTHER_ID = 523
OTHER_NAME = "Legacy OT firmware configuration tampering"
#: A name matching nothing in the catalogue — grounds unverified (catalogue_id None).
NOVEL_NAME = "Quantum sensor drift exploitation"

TYPE_NAME = "Web Input Tampering"


class FakeLLM:
    """Deterministic and scriptable per test.

    embed: one-hot per distinct text — identical text => cosine 1.0, else 0.0.
    rerank: 95 (clears the grounding match threshold, default 75.0) on exact text match,
    else 5. chat: routes on the validation prompt's system marker; `reject` names get
    NOT_RELEVANT (everything else RELEVANT), and any other chat call returns `proposals` —
    Stage 1b's generator, which by design knows nothing of the validator's verdicts."""

    def __init__(self, reject: set[str] = frozenset(), proposals: list[dict] | None = None):
        self._slots: dict[str, int] = {}
        self.reject = set(reject)
        self.proposals = proposals or []
        self.validated_names: list[str] = []

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

    def chat(self, messages, temperature=None, expected_type=None):
        system = messages[0]["content"]
        if "VALIDATING pre-selected library threats" in system:
            user = messages[-1]["content"]
            payload = json.loads(user[user.index("{"):])
            verdicts = []
            for c in payload["candidate_threats"]:
                self.validated_names.append(c["name"])
                verdict = "NOT_RELEVANT" if c["name"] in self.reject else "RELEVANT"
                verdicts.append({"index": c["index"], "verdict": verdict,
                                 "justification": "the asset context settles it"})
            return json.dumps(verdicts), None
        return json.dumps(self.proposals), None


def _proposal(name: str) -> dict:
    """A Stage-1b proposal whose type/name rerank EXACTLY against the seeded library rows —
    the FakeLLM.rerank exact-match convention makes regrounding deterministic."""
    return {"category": "Tampering", "type": TYPE_NAME, "name": name,
            "generic_name": name, "actors": []}


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Identified_Duplicate_Threat, m.Scenario_Audit, m.Prompt_Log,
                m.Threat_Category, m.Threat_Type, m.Threat_Actor, m.Threat_Catalogue,
                m.ThreatType_ThreatActor_Map, m.Threat_Catalogue_Category_Map):
        tbl.__table__.create(engine)
    return engine


def _seed_library(s, include_other: bool = False) -> None:
    s.execute(m.Threat_Category.__table__.insert().values(
        ThreatCategoryID=6, ThreatCategoryName="Tampering", IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=7, ThreatTypeName=TYPE_NAME, ThreatCategoryID=6,
        IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Actor.__table__.insert().values(
        ThreatActorID=9, ThreatActorName="Hacktivist", IsCapable=1,
        IsActive=True, IsDeleted=False))
    # Actors attach per TYPE on the catalogue model — one map row covers every threat here.
    s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
        ThreatTypeID=7, ThreatActorID=9))
    s.execute(m.Threat_Catalogue.__table__.insert().values(
        ThreatCatalogueID=REJECTED_ID, ThreatTypeID=7, ThreatName=REJECTED_NAME,
        IsActive=True, IsDeleted=False, CreatedBy="seed", CreatedAt=NOW))
    if include_other:
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=OTHER_ID, ThreatTypeID=7, ThreatName=OTHER_NAME,
            IsActive=True, IsDeleted=False, CreatedBy="seed", CreatedAt=NOW))


def _seed_session(s, sid: str) -> dict:
    row = {"SessionID": sid, "TenantID": "t", "EntityID": "e", "UserID": "u",
           "AssetName": ASSET_CONTEXT["name"], "AssetID": "1", "SessionStatus": "active",
           "CurrentStage": "THREAT_IDENTIFICATION", "StageStatus": "IDLE", "Mode": "AUTO",
           "SubsystemsJSON": json.dumps(SUBSYSTEMS), "SectorIDsJSON": json.dumps([]),
           "CreatedAt": NOW, "UpdatedAt": NOW}
    s.execute(m.Scenario_Session.__table__.insert().values(**row))
    set_up_progress_tracking(s, sid, "t", "e")
    s.commit()
    return row


def _run(llm: FakeLLM, max_threats: int = 2, include_other: bool = False):
    """One full find_threats round against a fresh SQLite fixture. Returns
    (threats, Session) so each test reads back exactly the tables it pins."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = str(uuid.uuid4())
    with Session() as s:
        _seed_library(s, include_other=include_other)
        scenario_session = _seed_session(s, sid)
        threats, _prov = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                      TASK_ID, max_threats=max_threats)
    return threats, Session


def _grounding_summary(Session) -> dict:
    with Session() as s:
        audit = [json.loads(a.DetailJSON) for a in s.execute(select(m.Scenario_Audit)).scalars()
                 if a.DetailJSON]
    return next(d for d in audit if "validator" in d)


def test_dropped_candidate_catalogue_id_is_recorded_in_the_validator_audit():
    """The dropped list is the SEED of rejected_catalogue_ids — if the catalogue id ever stops
    riding on each dropped entry, the reversal block downstream has nothing to match against
    and every test below would still 'pass' for the wrong reason. Pinned first, on its own,
    with generation returning nothing so only Stage 1a runs."""
    llm = FakeLLM(reject={REJECTED_NAME}, proposals=[])
    threats, Session = _run(llm)

    assert threats == []
    # The validator really judged the retrieved candidate (not an empty pass-through).
    assert llm.validated_names == [REJECTED_NAME]
    summary = _grounding_summary(Session)
    assert summary["validator"]["kept"] == 0
    assert summary["validator"]["dropped"] == [
        {"catalogue_id": REJECTED_ID, "threat_name": REJECTED_NAME,
         "justification": "the asset context settles it"}]
    # No proposals => nothing could attempt a reversal; the counter must read 0, not be absent.
    assert summary["validator_reversals_blocked"] == 0


def test_regrounded_proposal_cannot_silently_reverse_a_validator_rejection():
    """THE invariant: Stage 1b proposes the very threat Stage 1a's validator just hard-dropped
    (a real model can re-derive the same idea — it never sees the verdicts). The proposal
    regrounds onto catalogue row 522 and must be diverted to Identified_Duplicate_Threat with
    the dedicated, auditable reason — never inserted as a live threat. Silently reversing a
    NOT_RELEVANT verdict would put a threat in front of reviewers that the pipeline itself
    already concluded cannot apply to this asset."""
    llm = FakeLLM(reject={REJECTED_NAME}, proposals=[_proposal(REJECTED_NAME)])
    threats, Session = _run(llm)

    assert threats == []
    with Session() as s:
        live = list(s.execute(select(m.Identified_Threat)).scalars())
        assert live == [], "a validator-rejected catalogue row must never reach Identified_Threat"

        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert len(dups) == 1
        assert dups[0].DuplicateReason == str(DuplicateReason.validator_rejected)
        assert dups[0].ThreatName == REJECTED_NAME
        # A reversal is a verdict enforcement, not a match against a stored sibling — there is
        # no surviving row for it to point at.
        assert dups[0].DuplicateOfThreatID is None


def test_reversal_is_counted_in_the_grounding_summary_audit():
    """Recorded and COUNTABLE, not just silently absent: an operator asking 'why is this
    threat missing' must find the answer in the grounding_summary row — the reversal counter
    and the validator's own dropped entry naming the same catalogue id."""
    llm = FakeLLM(reject={REJECTED_NAME}, proposals=[_proposal(REJECTED_NAME)])
    _threats, Session = _run(llm)

    summary = _grounding_summary(Session)
    assert summary["validator_reversals_blocked"] == 1
    assert summary["validator"]["dropped"][0]["catalogue_id"] == REJECTED_ID
    assert summary["count"] == 0


def test_block_is_scoped_to_this_rounds_rejected_catalogue_ids():
    """The hard drop must not over-reach onto a DIFFERENT catalogue row. The catalogue model
    retrieves the WHOLE active library (no asset-type filter), so the second row is itself
    retrieved, judged RELEVANT, and inserted as a live retrieved record — the rejection of
    row 522 must not shrink that in any way. A Stage-1b proposal regrounding onto the kept
    row is then at most an ordinary identity duplicate of the surviving record; branding it
    validator_rejected would claim a verdict that was never issued and silently shrink
    coverage."""
    llm = FakeLLM(reject={REJECTED_NAME}, proposals=[_proposal(OTHER_NAME)])
    threats, Session = _run(llm, include_other=True)

    assert [t["catalogue_id"] for t in threats] == [OTHER_ID]
    with Session() as s:
        live = list(s.execute(select(m.Identified_Threat)).scalars())
        # Asset record + one fan-out copy per supporting system, all the same catalogue row.
        assert {r.ThreatCatalogueID for r in live} == {OTHER_ID}
        assert all(r.ThreatName == OTHER_NAME for r in live)
        # The regrounded proposal collapses onto the SURVIVING retrieved record by identity
        # (cat:{id} dedup rung) — never onto the validator's verdict about a different row.
        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert [d.DuplicateReason for d in dups] == [str(DuplicateReason.identity)]
    assert _grounding_summary(Session)["validator_reversals_blocked"] == 0


def test_unverified_grounding_is_never_swept_up_by_the_block():
    """The guard fires on `gr.catalogue_id is not None and ... in rejected_catalogue_ids`: a
    proposal whose name matches NO catalogue row grounds unverified with catalogue_id None,
    and None must never collide with the rejected set (a naive `in` over a set containing
    None — or a falsy check — would drop every ungrounded proposal the moment anything was
    rejected). The novel threat must be inserted, unverified, with no catalogue claim."""
    llm = FakeLLM(reject={REJECTED_NAME}, proposals=[_proposal(NOVEL_NAME)])
    threats, Session = _run(llm)

    assert len(threats) == 1
    assert threats[0]["catalogue_id"] is None
    assert threats[0]["grounding_status"] == str(GroundingStatus.unverified)
    with Session() as s:
        live = list(s.execute(select(m.Identified_Threat)).scalars())
        assert live and all(r.ThreatCatalogueID is None for r in live)
        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert dups == []
    assert _grounding_summary(Session)["validator_reversals_blocked"] == 0


def test_kept_candidate_reground_is_an_identity_duplicate_not_a_reversal():
    """The two drop paths must stay distinguishable in the audit trail. When the validator
    KEEPS the candidate (RELEVANT), it is inserted as a retrieved record — and a Stage-1b
    proposal regrounding onto that same catalogue id is an ordinary identity duplicate
    (cat:{id} dedup rung), pointing at the surviving row. Conflating it with
    validator_rejected would tell an operator a verdict was enforced that was never given."""
    llm = FakeLLM(reject=set(), proposals=[_proposal(REJECTED_NAME)])
    threats, Session = _run(llm, max_threats=2)

    # The retrieved library record survives as the one live threat...
    assert [t["catalogue_id"] for t in threats] == [REJECTED_ID]
    with Session() as s:
        live = {r.ThreatID: r for r in s.execute(select(m.Identified_Threat)).scalars()
                if r.SubsystemID == tasks.ASSET_UNIT_ID}
        assert len(live) == 1
        (survivor,) = live.values()
        assert survivor.ThreatCatalogueID == REJECTED_ID
        assert survivor.GroundingScore == 100.0  # identity, not similarity

        # ...and the regrounded proposal is recorded as ITS duplicate, by identity.
        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert len(dups) == 1
        assert dups[0].DuplicateReason == str(DuplicateReason.identity)
        assert dups[0].DuplicateOfThreatID == survivor.ThreatID
    summary = _grounding_summary(Session)
    assert summary["validator_reversals_blocked"] == 0
    assert summary["identity_duplicates"] == 1
