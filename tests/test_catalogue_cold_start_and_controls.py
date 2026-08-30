"""Pins two catalogue-era guarantees (2026-08 Threat_Catalogue library reversal).

COLD START (half A): with Threat_Catalogue AND Threat_Type both empty — a fresh
deployment before eyshield seeds anything — no stage may hard-depend on library data.
Retrieval must return [] (loudly, not raise), and find_threats must still deliver a full
round of AI-generated threats: every row unverified, no ThreatTypeID/ThreatCatalogueID
claimed against a library that holds nothing, IsThreatAIGenerated True (the immutable
provenance bit), the AI's own type names stored. If any stage threw or silently claimed
library ids here, an empty system could never bootstrap itself — the documented
cold-start guarantee ("the AI generates everything, types included").

CONTROLS (half B): control_mapping's two data-driven rules.
* eligible_outputs: EVERY complete output rides the grounding path — the curated
  register bypass (_curated_control_rows) retired with the register, so a
  catalogue-verified threat's output is eligible exactly like a generated one, in
  6-tuple rows carrying the threat identity; the only exit from the path is a recorded
  mapping attempt (map rows / ControlsMappedAt), never a library id.
* _resolve_control_labels: the ITOT pool filter is driven by what Control_Library actually
  carries — pure-IT session narrows to ["IT"], mixed IT+OT to ["IT","OT"], and ANY session
  category with no vocabulary entry disables the filter entirely (None), because a silently
  narrowed pool is the audited {Physical, IT}->IT-only defect this replaced. A future
  non-IT/OT label (PHY_INFRA) must narrow with no code change — nothing is hardcoded.

Real SQLite tables, fake LLM (zero vectors), no network — same house pattern as
test_control_mapping_durable.py.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.enums import ScenarioStatus, StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import control_mapping, tasks, threat_retrieval

S, T, R = "Spoofing", "Tampering", "Repudiation"
INFO, D, E = "Information Disclosure", "Denial of Service", "Elevation of Privilege"
STRIDE = [(1, D), (2, E), (3, INFO), (4, R), (5, S), (6, T)]  # seeded alphabetically, as prod does

IT_CAT, OT_CAT, PHY_CAT = 2, 3, 7


class _FakeLLM:
    """Embeds to zero vectors: cosine similarity 0 everywhere, so nothing ever crosses a
    match or near-duplicate threshold — the honest shape of a system with no library signal."""

    def embed(self, texts, kind=None):
        return [[0.0] * 8 for _ in texts]

    def rerank(self, query, docs):  # pragma: no cover - cold start never reranks (empty candidate sets)
        return [0.0] * len(docs)


# --------------------------------------------------------------------------------------
# Half A: cold start
# --------------------------------------------------------------------------------------

def _cold_engine():
    """Every table find_threats touches on the generation-only path. The library tables are
    created but left EMPTY — that emptiness is the whole point of the fixture."""
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Identified_Duplicate_Threat, m.Scenario_Audit, m.Threat_Category,
                m.Threat_Type, m.Threat_Catalogue, m.Threat_Actor,
                m.ThreatType_ThreatActor_Map, m.Threat_Catalogue_Category_Map,
                m.ctm_scan_category, m.Grounding_Calibration_Run):
        tbl.__table__.create(engine)
    now = datetime.now(UTC)
    with sessionmaker(engine)() as s:
        for cid, name in STRIDE:
            s.execute(m.Threat_Category.__table__.insert().values(
                ThreatCategoryID=cid, ThreatCategoryName=name, IsActive=True, IsDeleted=False))
        s.execute(m.ctm_scan_category.__table__.insert().values(
            id=IT_CAT, code="IT", name="Information Technology (IT)"))
        s.commit()
    return engine, now


def _seed_stage(s, sid: str) -> None:
    s.execute(m.Subsystem_Stage_State.__table__.insert().values(
        StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="e",
        SubsystemID=0, Level=SubsystemLevel.THREATS, Status=StageStatus.IDLE,
        GenerationEpoch=1, AttemptCount=0, UpdatedAt=datetime.now(UTC)))
    s.commit()


_SESSION = {"SessionID": None, "TenantID": "t", "EntityID": "e", "UserID": "u",
            "AssetName": "Aurora Plant", "ScoringRulesSnapshotJSON": None}

_ASSET_CONTEXT = {"name": "Aurora Plant", "asset_type": "Information Technology (IT)",
                  "asset_type_id": IT_CAT}
_SUBSYSTEMS = [{"id": 1, "name": "Historian", "asset_type": "Information Technology (IT)",
                "asset_type_id": IT_CAT}]

_PROPOSALS = [
    {"category": S, "type": "Credential Theft",
     "name": "Credential theft against operator accounts",
     "generic_name": "Credential theft against operator accounts"},
    {"category": T, "type": "Firmware Manipulation",
     "name": "Malicious firmware implanted in field controllers",
     "generic_name": "Malicious firmware implanted in field controllers"},
    {"category": D, "type": "Resource Exhaustion",
     "name": "Flooding of critical service endpoints",
     "generic_name": "Flooding of critical service endpoints"},
]


def test_cold_start_retrieval_returns_empty_not_error():
    """An empty catalogue must degrade to [] — the caller's generation-only signal — never
    raise: a cold system that crashed at retrieval could never produce its first threat."""
    engine, _ = _cold_engine()
    with sessionmaker(engine)() as s:
        assert threat_retrieval.retrieve_library_threats(
            s, _FakeLLM(), _SUBSYSTEMS, _ASSET_CONTEXT, session_id="sid") == []
        # Same [] answer with no categorised asset at all: eligibility no longer reads asset
        # categories (they feed only the control ITOT filter), so an uncategorised context
        # must not change the empty-library rung (threat_retrieval.library_empty).
        assert threat_retrieval.retrieve_library_threats(
            s, _FakeLLM(), [], {"name": "x"}, session_id="sid") == []


def test_cold_start_find_threats_generates_everything_unverified(monkeypatch):
    """THE cold-start guarantee. With both library tables empty, find_threats must still
    deliver the AI's proposals as Identified_Threat rows — all unverified, with NO library
    ids claimed (ThreatTypeID/ThreatCatalogueID None: there is nothing to verify against),
    IsThreatAIGenerated True, the AI's own type names stored. A verified status or a non-NULL
    catalogue id here would fabricate library provenance that promote/accept/dedup all
    trust."""
    engine, _ = _cold_engine()
    Session = sessionmaker(engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    scenario_session = {**_SESSION, "SessionID": sid}
    with Session() as s:
        _seed_stage(s, sid)

    monkeypatch.setattr(tasks, "_send_live_update", lambda *a, **k: None)  # no Redis
    ask_stages = []

    def fake_ask_ai(sess, llm, messages, **kw):
        ask_stages.append(kw.get("stage"))
        return list(_PROPOSALS), None

    monkeypatch.setattr(tasks, "_ask_ai", fake_ask_ai)

    with Session() as s:
        threats, _prov = tasks.find_threats(
            s, scenario_session, _SUBSYSTEMS, _ASSET_CONTEXT, _FakeLLM(), task_id,
            max_threats=3)

    # The validator never ran (no candidates to judge) — only gap generation asked the AI.
    assert ask_stages == ["threats"]
    assert len(threats) == 3
    assert {t["threat_name"] for t in threats} == {p["name"] for p in _PROPOSALS}

    with Session() as s:
        rows = s.execute(
            select(m.Identified_Threat).where(m.Identified_Threat.SessionID == sid,
                                              m.Identified_Threat.SubsystemID == 0)
        ).scalars().all()
        fanout = s.execute(
            select(m.Identified_Threat).where(m.Identified_Threat.SessionID == sid,
                                              m.Identified_Threat.SubsystemID == 1)
        ).scalars().all()
        audit = s.execute(
            select(m.Scenario_Audit.DetailJSON).where(
                m.Scenario_Audit.EventType == "grounding_summary")
        ).scalar_one()

    assert len(rows) == 3
    for row in rows:
        assert row.GroundingStatus == "unverified"
        assert row.ThreatTypeID is None
        assert row.ThreatCatalogueID is None
        assert row.LibraryThreatType is None and row.LibraryThreatName is None
        # Immutable provenance: nothing came from the (empty) catalogue, so every row is
        # the AI's own invention — the bit promote must never rewrite.
        assert row.IsThreatAIGenerated is True
    # The AI's own type wording is what got stored — there was no library type to substitute.
    assert {r.ThreatType for r in rows} == {p["type"] for p in _PROPOSALS}
    # Coverage fan-out still works with zero library data (grid copies on the subsystem).
    assert len(fanout) == 3
    # The audit row must record this honestly as a generation-only round.
    detail = json.loads(audit)
    assert detail["retrieved"] == 0
    assert detail["generated"] == 3


# --------------------------------------------------------------------------------------
# Half B: controls
# --------------------------------------------------------------------------------------

def _control_engine(controls, categories=()):
    """controls: (id, code, itot, active, deleted); categories: (id, code, name)
    ctm_scan_category rows."""
    engine = create_engine("sqlite://")
    for tbl in (m.Control_Library, m.ctm_scan_category):
        tbl.__table__.create(engine)
    with sessionmaker(engine)() as s:
        for cid, code, itot, active, deleted in controls:
            s.execute(m.Control_Library.__table__.insert().values(
                ControlLibraryID=cid, ControlCode=code, ITOT=itot, Domain="d",
                ControlName=f"ctl-{cid}", ControlDescription="desc",
                IsActive=active, IsDeleted=deleted))
        for catid, code, name in categories:
            s.execute(m.ctm_scan_category.__table__.insert().values(
                id=catid, code=code, name=name))
        s.commit()
    return engine


def _outputs_engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Threat_Scenario, m.Scoped_Threat, m.Identified_Threat,
                m.Threat_Scenario_Control_Map):
        tbl.__table__.create(engine)
    return engine


def _seed_output(s, sid: str, out_id: str, *, catalogue_id=None, library_name=None,
                 library_type=None, mapped_at=None, map_control_id=None):
    """One complete output chained to its Scoped_Threat and Identified_Threat rows."""
    tid, st_id = str(uuid.uuid4()), str(uuid.uuid4())
    s.execute(m.Identified_Threat.__table__.insert().values(
        ThreatID=tid, SessionID=sid, SubsystemID=0,
        ThreatCategory=S, ThreatType=f"type-{out_id}", ThreatName=f"name-{out_id}",
        ThreatCatalogueID=catalogue_id, LibraryThreatName=library_name,
        LibraryThreatType=library_type,
        GroundingStatus="verified" if catalogue_id is not None else "unverified",
        IsThreatAIGenerated=catalogue_id is None))
    s.execute(m.Scoped_Threat.__table__.insert().values(
        ScopedThreatID=st_id, SessionID=sid, SubsystemID=0, ThreatID=tid,
        Score=1.0, ScopeRank=1, Selected=1))
    s.execute(m.Threat_Scenario.__table__.insert().values(
        ScenarioID=out_id, SessionID=sid, SubsystemID=0, ScopedThreatID=st_id,
        Status=ScenarioStatus.complete, ScenarioJSON=json.dumps({"title": out_id}),
        Accepted=0, Superseded=0, ControlsMappedAt=mapped_at))
    if map_control_id is not None:
        s.execute(m.Threat_Scenario_Control_Map.__table__.insert().values(
            ScenarioID=out_id, ControlLibraryID=map_control_id, SessionID=sid, MapRank=1))
    s.commit()


def test_catalogue_verified_output_rides_grounding_like_a_generated_one():
    """No curated bypass survives the register: a catalogue-verified threat's output is
    eligible for grounding exactly like a generated one, and each row is the 6-tuple
    (scenario_id, ScenarioJSON, ThreatName, ThreatType, LibraryThreatName, LibraryThreatType)
    build_output_queries consumes — the library spelling riding along on the SAME row, not
    a bypass lane."""
    engine, sid = _outputs_engine(), str(uuid.uuid4())
    out_cat, out_gen = str(uuid.uuid4()), str(uuid.uuid4())
    with sessionmaker(engine)() as s:
        _seed_output(s, sid, out_cat, catalogue_id=7,
                     library_name="Credential theft", library_type="Credential Theft")
        _seed_output(s, sid, out_gen)
        rows = control_mapping.eligible_outputs(s, sid)

    assert {r[0] for r in rows} == {out_cat, out_gen}
    by_id = {r[0]: r for r in rows}
    assert all(len(r) == 6 for r in rows)
    _, sj, tname, ttype, ltname, lttype = by_id[out_cat]
    assert (tname, ttype) == (f"name-{out_cat}", f"type-{out_cat}")
    assert (ltname, lttype) == ("Credential theft", "Credential Theft")
    assert json.loads(sj) == {"title": out_cat}
    # The generated twin carries its own identity with NO library spelling to prefer.
    assert by_id[out_gen][4] is None and by_id[out_gen][5] is None


def test_only_a_recorded_mapping_attempt_leaves_the_grounding_path():
    """The single legitimate exit from the grounding path is "controls were already
    attempted": an existing map row or a ControlsMappedAt stamp. A library id must never
    be one — stamping a catalogue threat out of the path would permanently publish
    `controls: []` for it, the exact defect the curated bypass's deletion closed."""
    engine, sid = _outputs_engine(), str(uuid.uuid4())
    out_mapped, out_stamped, out_pending = (str(uuid.uuid4()) for _ in range(3))
    with sessionmaker(engine)() as s:
        _seed_output(s, sid, out_mapped, catalogue_id=7, map_control_id=5)
        _seed_output(s, sid, out_stamped, mapped_at=datetime.now(UTC))
        _seed_output(s, sid, out_pending, catalogue_id=8)
        rows = control_mapping.eligible_outputs(s, sid)
    assert [r[0] for r in rows] == [out_pending]


_CATS = [(IT_CAT, "IT", "Information Technology (IT)"),
         (OT_CAT, "OT", "Operational Technology (OT)"),
         (PHY_CAT, "PHY_INFRA", "Physical Infrastructure (PHY_INFRA)")]


def _labels(engine, asset_type_id, subsystem_type_ids=()):
    ctx = {"asset_type_id": asset_type_id}
    subs = [{"asset_type_id": i} for i in subsystem_type_ids]
    with sessionmaker(engine)() as s:
        return control_mapping._resolve_control_labels(s, ctx, subs)


def test_labels_pure_it_session_narrows_to_it():
    """A pure-IT session must not ground scenarios against OT controls: the filter narrows
    to exactly the labels the session's categories map to."""
    engine = _control_engine(
        controls=[(1, "C1", "IT", True, False), (2, "C2", "OT", True, False)],
        categories=_CATS)
    assert _labels(engine, IT_CAT) == ["IT"]


def test_labels_mixed_it_ot_session_takes_the_union():
    """An OT asset with an IT subsystem sees BOTH families — the same union rule the
    threat filter uses; narrowing to either one alone would hide half the asset's controls."""
    engine = _control_engine(
        controls=[(1, "C1", "IT", True, False), (2, "C2", "OT", True, False)],
        categories=_CATS)
    assert _labels(engine, OT_CAT, subsystem_type_ids=[IT_CAT]) == ["IT", "OT"]


def test_labels_none_when_any_category_has_no_vocabulary():
    """The vocabulary-aware fail-open: PHY_INFRA has no labeled controls today, so a session
    touching it gets NO filter (whole library) — even though its IT half COULD be filtered.
    A partially-representable session silently narrowed to its representable half is exactly
    the audited {Physical, IT}->IT-only defect this rule replaced."""
    engine = _control_engine(
        controls=[(1, "C1", "IT", True, False), (2, "C2", "OT", True, False)],
        categories=_CATS)
    assert _labels(engine, PHY_CAT) is None
    assert _labels(engine, IT_CAT, subsystem_type_ids=[PHY_CAT]) is None


def test_labels_future_vocabulary_narrows_with_no_code_change():
    """Nothing is hardcoded to IT/OT: the moment the library carries a PHY_INFRA-labeled
    control, a {PHY_INFRA} session narrows to it — the data-driven promise the docstring
    makes. Deleted rows don't count as vocabulary (control_itot_vocabulary is live-only)."""
    engine = _control_engine(
        controls=[(1, "C1", "IT", True, False),
                  (2, "C2", "PHY_INFRA", True, False),
                  (3, "C3", "FACILITIES", True, True)],  # deleted — must not enter the vocabulary
        categories=_CATS)
    assert _labels(engine, PHY_CAT) == ["PHY_INFRA"]
    assert _labels(engine, IT_CAT, subsystem_type_ids=[PHY_CAT]) == ["IT", "PHY_INFRA"]


def _is_ot(engine, asset_type_id, subsystem_type_ids=()):
    ctx = {"asset_type_id": asset_type_id}
    subs = [{"asset_type_id": i} for i in subsystem_type_ids]
    with sessionmaker(engine)() as s:
        return control_mapping.session_is_ot(s, subs, ctx)


def test_session_is_ot_true_by_code():
    """OT_CAT's code is literally "OT" — the code-equality branch, matching
    _resolve_control_labels's own primary match order. Replaces the old itot_family()
    free-text guess (2026-08-27) with a DB-resolved category lookup."""
    engine = _control_engine(controls=[], categories=_CATS)
    assert _is_ot(engine, OT_CAT) is True


def test_session_is_ot_false_for_it_or_physical():
    engine = _control_engine(controls=[], categories=_CATS)
    assert _is_ot(engine, IT_CAT) is False
    assert _is_ot(engine, PHY_CAT) is False


def test_session_is_ot_true_when_any_subsystem_is_ot():
    """Deliberately loose: one OT subsystem is enough even if the asset itself is IT."""
    engine = _control_engine(controls=[], categories=_CATS)
    assert _is_ot(engine, IT_CAT, subsystem_type_ids=[OT_CAT]) is True


def test_session_is_ot_matches_by_parenthetical_when_code_is_missing():
    """A category with no code but a name carrying the "(OT)" parenthetical still counts —
    the same word-boundary-safe fallback _resolve_control_labels uses, not substring
    matching ("OT" would also appear inside e.g. "PROTOTYPE")."""
    engine = create_engine("sqlite://")
    m.ctm_scan_category.__table__.create(engine)
    with sessionmaker(engine)() as s:
        s.execute(m.ctm_scan_category.__table__.insert().values(
            id=50, code=None, name="Operational Technology (OT)"))
        s.commit()
    assert _is_ot(engine, 50) is True


def test_session_is_ot_false_when_no_category_ids_resolve():
    engine = _control_engine(controls=[], categories=_CATS)
    with sessionmaker(engine)() as s:
        assert control_mapping.session_is_ot(s, [], {}) is False


def test_intel_vocabulary_is_ot_uses_session_is_ot():
    """tasks._intel_vocabulary's is_ot flag is exactly control_mapping.session_is_ot's
    answer now — DB-driven, not the old free-text itot_family() guess on asset_type."""
    engine = _control_engine(controls=[], categories=_CATS)
    with sessionmaker(engine)() as s:
        terms, is_ot = tasks._intel_vocabulary(
            s, [{"asset_type_id": OT_CAT, "technology_used": ["Siemens SCADA"]}],
            {"asset_type_id": IT_CAT, "asset_type": "Custom Application"})
    assert is_ot is True
    assert "Siemens SCADA" in terms


def test_intel_vocabulary_includes_the_2026_08_27_added_subsystem_fields():
    """targeted_users/accessability_channel/hosting_location/managed_by joined
    _INTEL_TECH_FIELDS on 2026-08-27, kept in sync with scenario_profile/threat_retrieval's
    field lists — each must now contribute an intel search term."""
    engine = _control_engine(controls=[], categories=_CATS)
    sub = {"asset_type_id": IT_CAT, "targeted_users": ["Remote vendors"],
           "accessability_channel": "Internet-facing", "hosting_location": "Cloud",
           "managed_by": "Outsourced"}
    with sessionmaker(engine)() as s:
        terms, _is_ot = tasks._intel_vocabulary(s, [sub], {"asset_type_id": IT_CAT})
    for term in ("Remote vendors", "Internet-facing", "Cloud", "Outsourced"):
        assert term in terms


if __name__ == "__main__":
    print("run via pytest")
