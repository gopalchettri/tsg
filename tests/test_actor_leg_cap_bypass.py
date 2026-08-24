"""The top_k cap must not silently undo the actor leg's whole purpose (GAP-A, second path).

THE BUG. threat_retrieval.retrieve_library_threats' cap-bypass (GAP-A) exempted
gate-UNGATED types from `threat_retrieval_top_k`, because a universal threat like phishing
scores ~0.3 against any specific asset text and would otherwise never make the cut. The
same logic applies, for the same reason, to a type admitted ONLY by the actor leg (Phase
2c) — it is in the pool BECAUSE the ordinary sector filter would have excluded it, so
scoring low against the asset's own vocabulary is the expected case, not evidence it
doesn't belong. But the bypass predicate only checked `ungated`, never `sector_visible`,
so a GATED actor-admitted type could still be capped out before the validator ever sees
it — quietly reversing the actor leg's entire admission for exactly the types it exists to
rescue.

THE FIX. The cap-bypass set also exempts any type NOT in `sector_visible` (the actor-only
admission signature), using the set retrieve_library_threats already computes for its own
`selection_source` labelling — no new query.
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.pipeline import threat_retrieval

SECTOR_IDS = [1]
SUBSYSTEMS = [{"id": 41, "name": "SCADA HMI Server", "asset_type": "OT",
             "technology_used": ["Siemens SCADA"], "vendor_name": "Siemens", "criticality": "High"}]
ASSET_CONTEXT = {"name": "Water Pumping Station", "asset_type": "Pumping Station",
                "sector": "Energy & Water", "sub_sector": "Water Supply",
                "critical_service": ["Potable water supply"]}


class ZeroVectorLLM:
    """Every text embeds to the all-zero vector, so cosine similarity is 0.0 for every pair
    (hybrid_search.cosine's own zero-magnitude guard) and ranking is decided by BM25 keyword
    overlap alone — the simplest way to make a candidate's score exactly 0.0 on purpose."""

    def embed(self, texts, kind=None):
        return [[0.0] * 8 for _ in texts]


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Threat_Category, m.Threat_Type, m.Threat_Catalogue,
                m.Threat_Catalogue_Category_Map, m.Threat_Actor,
                m.ThreatType_ThreatActor_Map, m.Config_Threat_Rule):
        tbl.__table__.create(engine)
    return engine


def _seed(s) -> None:
    s.execute(m.Threat_Category.__table__.insert().values(
        ThreatCategoryID=6, ThreatCategoryName="Tampering", IsActive=True, IsDeleted=False))
    # Type 7: ordinary sector-visible type (SectorID=None), but GATED (carries a tech_gate),
    # so the OLD `ungated` bypass alone would never have rescued it -- its high keyword score
    # is what keeps it in a top_k=1 cap regardless of this fix.
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=7, ThreatTypeName="Siemens SCADA Setpoint Tampering", ThreatCategoryID=6,
        SectorID=None, IsActive=True, IsDeleted=False))
    # Type 13: scoped to a sector this session cannot see (999 not in [1]) -- admitted ONLY
    # because APT33 (linked to sector-visible type 7) also uses it. ALSO gated, so it is not
    # in `ungated` either -- only the actor-leg bypass this fix adds can rescue it.
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=13, ThreatTypeName="Actor-Only Fraud Technique", ThreatCategoryID=6,
        SectorID=999, IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Catalogue.__table__.insert().values(
        ThreatCatalogueID=418, ThreatName="Siemens SCADA setpoint tampering", ThreatTypeID=7,
        Description="An actor manipulates the Siemens SCADA HMI Server setpoints directly.",
        IsActive=True, IsDeleted=False))
    # Deliberately zero token overlap with the query text (subsystem/asset vocabulary above)
    # so its BM25 score is exactly 0.0 and it sorts dead last under the OLD ranking.
    s.execute(m.Threat_Catalogue.__table__.insert().values(
        ThreatCatalogueID=733, ThreatName="Zyzzogeton ledger skimming", ThreatTypeID=13,
        Description="Qorvex funds diverted through an unrelated offshore clearing scheme.",
        IsActive=True, IsDeleted=False))
    for cid in (418, 733):
        s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
            ThreatCategoryID=6, ThreatCatalogueID=cid))
    s.execute(m.Threat_Actor.__table__.insert().values(
        ThreatActorID=1, ThreatActorName="APT33", IsCapable=1, IsActive=True, IsDeleted=False))
    s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(ThreatTypeID=7, ThreatActorID=1))
    s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(ThreatTypeID=13, ThreatActorID=1))
    # Both types gated on asset_type=OT -- the one subsystem IS OT, so both PASS their gate
    # and stay eligible; neither is in `ungated`, isolating the actor-leg bypass specifically.
    for rid, tid in ((1, 7), (2, 13)):
        s.execute(m.Config_Threat_Rule.__table__.insert().values(
            ThreatRuleID=rid, RuleType="tech_gate", ThreatTypeID=tid, RuleKey="asset_type",
            RuleValue="OT", IsActive=True, IsDeleted=False))


def test_actor_admitted_type_survives_the_cap_even_when_it_scores_last(monkeypatch):
    monkeypatch.setenv("TSG_THREAT_RETRIEVAL_TOP_K", "1")
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        _seed(s)
        candidates = threat_retrieval.retrieve_library_threats(
            s, ZeroVectorLLM(), SUBSYSTEMS, ASSET_CONTEXT, SECTOR_IDS)

    ids = {c["catalogue_id"] for c in candidates}
    # THE assertion: both survive a top_k=1 cap -- 418 on its own keyword score, 733 ONLY
    # because the actor-leg bypass now covers it too.
    assert ids == {418, 733}, ids
    by_id = {c["catalogue_id"]: c for c in candidates}
    assert by_id[733]["selection_source"] == "actor_intel"
    assert by_id[733]["retrieval_score"] == 0.0   # confirms it really did score last, not luckily high
