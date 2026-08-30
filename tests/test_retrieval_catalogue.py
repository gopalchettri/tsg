"""Stage-1a retrieval against Threat_Catalogue (the 2026-08-28 catalogue reversal).

The funnel used to read the eyshield register scoped by asset type; it now reads the
whole ACTIVE catalogue — no sector filter, no asset-type filter, no cap — and the
validator decides relevance. This file pins the catalogue contract:

  1. Eligibility is liveness alone: every IsActive/not-IsDeleted catalogue row with an
     ACTIVE parent Threat_Type is a candidate; inactive/deleted rows and rows under an
     inactive type never appear.
  2. Empty library -> [] — the loud generation-only degradation (cold start: the AI
     generates everything, threat types included).
  3. NO cap: N eligible rows in -> N candidates out, zero-scorers included, ordered
     best fused score first with ThreatCatalogueID as the tiebreak.
  4. selection_source is only ever "hybrid", the candidate dict carries exactly the
     documented keys, and ranking_degraded rides on every candidate (False on a
     healthy run, True when embeddings fail — keyword-only ranking must be visible).
  5. Actors ride PER TYPE (ThreatType_ThreatActor_Map): every catalogue threat under
     one type shares the list — live actors only, name-sorted, capped at
     settings.max_actors_per_threat, actor_ids aligned with names.
  6. Attribution stays fail-open: every candidate is recorded against every
     supporting system, so no exposure leaves the coverage grid without a trace.
  7. Categories come from Threat_Catalogue_Category_Map (joined by id) re-sorted into
     canonical STRIDE order, with the type's own category as the fallback so a threat
     is never grid-unplaceable.
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.db import models as m
from app.pipeline import threat_retrieval

SUBSYSTEMS = [{"id": 41, "name": "SCADA HMI Server", "asset_type": "OT", "asset_type_id": 3,
               "technology_used": ["Siemens SCADA"], "vendor_name": "Siemens",
               "criticality": "High"}]
ASSET_CONTEXT = {"name": "Water Pumping Station", "asset_type": "Information Technology (IT)",
                 "asset_type_id": 2, "sector": "Energy & Water",
                 "sub_sector": "Water Supply", "critical_service": ["Potable water supply"]}


class ZeroVectorLLM:
    def embed(self, texts, kind=None):
        return [[0.0] * 8 for _ in texts]


class BrokenEmbedLLM:
    def embed(self, texts, kind=None):
        raise RuntimeError("embedding backend down")


class ShortQueryEmbedLLM:
    """Corpus (passage) embeds succeed normally; the QUERY batch comes back one vector short —
    a partially-successful provider response (a proxy silently dropping a batch item, or a
    truncated stream), distinct from the `except Exception` path BrokenEmbedLLM exercises."""

    def embed(self, texts, kind=None):
        vecs = [[0.0] * 8 for _ in texts]
        return vecs[:-1] if kind == "query" and vecs else vecs


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Threat_Category, m.Threat_Type, m.Threat_Catalogue, m.Threat_Actor,
                m.ThreatType_ThreatActor_Map, m.Threat_Catalogue_Category_Map):
        tbl.__table__.create(engine)
    return engine


def _catalogue_row(s, *, cid: int, name: str, type_id: int = 7,
                   description: str | None = None, is_active: bool = True,
                   is_deleted: bool = False) -> None:
    s.execute(m.Threat_Catalogue.__table__.insert().values(
        ThreatCatalogueID=cid, ThreatTypeID=type_id, ThreatName=name,
        Description=description, IsActive=is_active, IsDeleted=is_deleted,
        Source="seed"))


def _seed(s, *, extra_rows: int = 0) -> None:
    """One asset-matching threat (type 7) + one zero-overlap threat (type 9) + one
    inactive row + one deleted row + one row under an INACTIVE type, plus N deliberately
    zero-overlap rows (they score 0.0 and would have been the first casualties of any
    cap). Categories 4/5/6 exist so the STRIDE re-sort is observable."""
    for cat_id, cat_name in ((4, "Information Disclosure"), (5, "Spoofing"),
                             (6, "Tampering")):
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=cat_id, ThreatCategoryName=cat_name,
            IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=7, ThreatTypeName="Siemens SCADA Setpoint Tampering", ThreatCategoryID=6,
        IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=8, ThreatTypeName="Retired Type", ThreatCategoryID=6,
        IsActive=False, IsDeleted=False))
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=9, ThreatTypeName="Ledger Fraud", ThreatCategoryID=4,
        IsActive=True, IsDeleted=False))
    _catalogue_row(s, cid=418, name="Siemens SCADA setpoint tampering",
                   description="Manipulates the Siemens SCADA HMI Server setpoints.")
    _catalogue_row(s, cid=500, name="Zyzzogeton ledger skimming", type_id=9)
    _catalogue_row(s, cid=600, name="Inactive catalogue threat", is_active=False)
    _catalogue_row(s, cid=601, name="Deleted catalogue threat", is_deleted=True)
    _catalogue_row(s, cid=700, name="Siemens SCADA orphaned tampering", type_id=8)
    for i in range(extra_rows):
        _catalogue_row(s, cid=2000 + i, name=f"Zyzzogeton variant {i} ledger skimming",
                       type_id=9, description=f"Qorvex offshore clearing scheme {i}.")


def _retrieve(s, llm=None):
    return threat_retrieval.retrieve_library_threats(
        s, llm or ZeroVectorLLM(), SUBSYSTEMS, ASSET_CONTEXT)


def test_inactive_rows_and_inactive_parent_types_are_excluded():
    """Eligibility is liveness alone: the inactive row (600), the deleted row (601) and
    the row under an inactive type (700) never appear — even though 700's name matches
    the asset better than anything eligible. There is no sector or asset-type leg left
    to narrow the library any further."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s)
        candidates = _retrieve(s)
    assert {c["catalogue_id"] for c in candidates} == {418, 500}


def test_empty_library_returns_empty():
    """No live catalogue rows -> [] (generation-only path). The alternative — inventing
    candidates or crashing — would break the cold-start guarantee: an empty system means
    the AI generates everything, threat types included."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        candidates = _retrieve(s)
    assert candidates == []


def test_no_cap_every_eligible_row_is_forwarded_best_first():
    """32 eligible in -> 32 out, zero-scoring rows included, ordered best fused score
    first with ThreatCatalogueID breaking ties. Under any resurrected top-k the
    zero-overlap rows are the first casualties — cut silently, invisible to the
    validator."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s, extra_rows=30)
        candidates = _retrieve(s)
    assert len(candidates) == 32
    # 418 is the only row sharing vocabulary with the queries; every zero-scorer then
    # falls back to catalogue-id order — the documented (score desc, id asc) contract.
    assert [c["catalogue_id"] for c in candidates] == [418, 500, *range(2000, 2030)]


def test_selection_source_is_only_hybrid_and_candidate_shape_is_exact():
    """One provenance now: 'hybrid'. The dict carries exactly the documented keys —
    the register-era display fields (threat_code / theme / risk_statement) and the
    actor-intel keys (actor_evidence / always_eligible) are gone, description is a
    safe '' rather than None, and ranking_degraded is False on a healthy run."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s, extra_rows=3)
        candidates = _retrieve(s)
    assert candidates
    expected_keys = {"catalogue_id", "type_id", "type_name", "threat_name", "description",
                     "categories", "retrieval_score", "subsystem_ids", "selection_source",
                     "ranking_degraded", "actors", "actor_ids"}
    assert all(set(c) == expected_keys for c in candidates)
    assert {c["selection_source"] for c in candidates} == {"hybrid"}
    assert {c["ranking_degraded"] for c in candidates} == {False}
    by_id = {c["catalogue_id"]: c for c in candidates}
    assert by_id[418]["type_id"] == 7
    assert by_id[418]["type_name"] == "Siemens SCADA Setpoint Tampering"
    assert by_id[500]["description"] == ""          # NULL Description -> safe empty


def test_ranking_degraded_flag_rides_on_every_candidate_when_embeds_fail():
    """Embedding failure degrades ranking to keyword-only — eligibility is untouched,
    every candidate still comes back, and ranking_degraded=True rides on each one so
    the caller cannot receive the threats and drop the caveat."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s, extra_rows=2)
        candidates = _retrieve(s, llm=BrokenEmbedLLM())
    assert len(candidates) == 4
    assert {c["ranking_degraded"] for c in candidates} == {True}
    assert candidates[0]["catalogue_id"] == 418     # BM25 alone still ranks best-first


def test_ranking_degraded_flag_on_a_short_query_embed_response():
    """The OTHER degrade path, distinct from an outright exception: the provider returns FEWER
    query vectors than requested (no error raised). ranking_degraded must still flip True on
    every candidate and ranking must still complete rather than crash on the length mismatch —
    previously unexercised anywhere (only the `except Exception` branch had coverage)."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s, extra_rows=2)
        candidates = _retrieve(s, llm=ShortQueryEmbedLLM())
    assert len(candidates) == 4
    assert {c["ranking_degraded"] for c in candidates} == {True}
    assert candidates[0]["catalogue_id"] == 418


def test_actors_ride_per_type_name_sorted_and_capped():
    """Actors are the PER-TYPE map pairs — live only, name-sorted, capped at
    settings.max_actors_per_threat. The cap applies AFTER the name sort (stable display
    set), actor_ids stay aligned with names, every catalogue threat under one type
    shares the list, and a threat whose type has no map rows carries empty lists."""
    cap = get_settings().max_actors_per_threat
    Session = sessionmaker(bind=_engine(), future=True)
    names = [f"Actor {chr(ord('a') + i)}" for i in range(cap + 2)]
    with Session() as s:
        _seed(s)
        # a second threat under type 7 must share the exact same actor list
        _catalogue_row(s, cid=419, name="Valve controller firmware tampering")
        for i, name in enumerate(reversed(names)):      # insert in reverse-name order
            aid = 100 + i
            s.execute(m.Threat_Actor.__table__.insert().values(
                ThreatActorID=aid, ThreatActorName=name, IsCapable=1,
                IsActive=True, IsDeleted=False))
            s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
                ThreatTypeID=7, ThreatActorID=aid))
        # a deleted and an inactive actor linked to type 7 must not appear at all
        for aid, aname, active, deleted in ((98, "Actor 0 inactive", False, False),
                                            (99, "Actor 0 deleted", True, True)):
            s.execute(m.Threat_Actor.__table__.insert().values(
                ThreatActorID=aid, ThreatActorName=aname, IsCapable=1,
                IsActive=active, IsDeleted=deleted))
            s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
                ThreatTypeID=7, ThreatActorID=aid))
        candidates = _retrieve(s)
    by_id = {c["catalogue_id"]: c for c in candidates}
    top = by_id[418]
    assert top["actors"] == sorted(names)[:cap]
    # ids ride in the same name-sorted order: reversed insertion means "Actor a" got the
    # HIGHEST id, so an id-ordered (map-ordered) list would fail here
    expected_ids = {name: 100 + i for i, name in enumerate(reversed(names))}
    assert top["actor_ids"] == [expected_ids[n] for n in top["actors"]]
    assert by_id[419]["actors"] == top["actors"]        # per-TYPE, shared across threats
    assert by_id[419]["actor_ids"] == top["actor_ids"]
    assert by_id[500]["actors"] == [] and by_id[500]["actor_ids"] == []


def test_attribution_stays_fail_open_on_every_subsystem():
    """Every candidate is recorded against ALL supporting systems — over-attribution puts
    a dismissible row in front of a reviewer; under-attribution silently removes a real
    exposure from the coverage grid."""
    two_subs = [*SUBSYSTEMS, {"id": 42, "name": "Billing Portal", "asset_type": "IT",
                              "asset_type_id": 2, "technology_used": ["Django"],
                              "vendor_name": "In-house", "criticality": "Medium"}]
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s, extra_rows=2)
        candidates = threat_retrieval.retrieve_library_threats(
            s, ZeroVectorLLM(), two_subs, ASSET_CONTEXT)
    assert candidates
    assert all(c["subsystem_ids"] == [41, 42] for c in candidates)


def test_categories_come_from_map_in_stride_order_with_type_fallback():
    """Map rows (joined by id) are authoritative and re-sorted into canonical STRIDE
    order — the map's id order (4, 5, 6) must NOT survive. A threat with no map rows
    falls back to its type's single category so it is never grid-unplaceable."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s)
        for cat_id in (4, 5, 6):                        # id order != STRIDE order
            s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
                ThreatCategoryID=cat_id, ThreatCatalogueID=418))
        candidates = _retrieve(s)
    by_id = {c["catalogue_id"]: c for c in candidates}
    assert by_id[418]["categories"] == ["Spoofing", "Tampering", "Information Disclosure"]
    # no map rows -> the type's own category (type 9 -> Information Disclosure)
    assert by_id[500]["categories"] == ["Information Disclosure"]


def test_build_queries_includes_the_2026_08_27_added_subsystem_fields():
    """targeted_users/accessability_channel/hosting_location/managed_by joined
    _SUBSYSTEM_QUERY_FIELDS on 2026-08-27, kept in sync with scenario_profile's field list —
    each must now compose into the per-subsystem retrieval query text, pure function, no DB."""
    sub = {"name": "Historian", "asset_type": "OT", "technology_used": ["Siemens SCADA"],
           "targeted_users": ["Remote vendors"], "accessability_channel": "Internet-facing",
           "hosting_location": "Cloud", "managed_by": "Outsourced"}
    queries = threat_retrieval.build_queries([sub], {})
    assert len(queries) == 1
    for term in ("Remote vendors", "Internet-facing", "Cloud", "Outsourced"):
        assert term in queries[0]


def test_build_queries_fixes_the_dead_cii_asset_description_key():
    """Found 2026-08-29: the old hardcoded _ASSET_QUERY_FIELDS named "name"/"description",
    but asset_context's real keys are "cii_asset_description" (no bare "name" key at all) —
    both entries were dead since the tuple was written, so the asset-level query silently
    never carried the asset's own description text. build_queries no longer re-picks fields
    by name at all, so this is fixed automatically."""
    asset_context = {"cii_asset_description": "Serves 40,000 households.", "asset_type": "Pumping Station"}
    queries = threat_retrieval.build_queries([], asset_context)
    assert len(queries) == 1
    assert "Serves 40,000 households." in queries[0]


def test_build_queries_picks_up_a_brand_new_field_with_no_code_change():
    """No hardcoded field-name list to update: any new text field context.py starts producing
    is automatically included, proving the drift risk the old allowlist had is gone."""
    sub = {"name": "Historian", "a_field_nobody_has_heard_of_yet": "some new descriptive text"}
    queries = threat_retrieval.build_queries([sub], {})
    assert len(queries) == 1
    assert "some new descriptive text" in queries[0]


def test_build_queries_excludes_non_descriptive_date_text():
    """last_dr_test_date is a string (an ISO date), but it isn't descriptive search text —
    the one deliberate exclusion, unlike everything else which is included automatically."""
    sub = {"name": "Historian", "last_dr_test_date": "2024-03-15"}
    queries = threat_retrieval.build_queries([sub], {})
    assert len(queries) == 1
    assert "2024-03-15" not in queries[0]
    assert "Historian" in queries[0]
