"""grounding.get_possible_types' [A2] category-widening subquery.

Previously exercised only through find_threat_in_library, whose two callers each seed a type
whose OWN default category happens to match the only category in play — so the map-only
widening leg (a type reachable via Threat_Catalogue_Category_Map when its default category
differs) had zero coverage. If the subquery's join direction or liveness predicate were wrong,
a whole class of legitimately multi-category threats would silently stop grounding to their
type, with nothing here to catch the regression.
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.pipeline.grounding import get_possible_types

# Categories: 1=Spoofing, 6=Tampering (STRIDE ids, non-identity PK per Threat_Category).
SPOOFING, TAMPERING = 1, 6


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Threat_Category, m.Threat_Type, m.Threat_Catalogue,
                m.Threat_Catalogue_Category_Map):
        tbl.__table__.create(engine)
    return engine


def _seed(s) -> None:
    s.execute(m.Threat_Category.__table__.insert().values(
        ThreatCategoryID=SPOOFING, ThreatCategoryName="Spoofing", IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Category.__table__.insert().values(
        ThreatCategoryID=TAMPERING, ThreatCategoryName="Tampering", IsActive=True, IsDeleted=False))
    # This type's OWN default category is Spoofing — it must NOT surface for a Tampering
    # search through the default-category door.
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=7, ThreatTypeName="Logic/Configuration Manipulation",
        ThreatCategoryID=SPOOFING, IsActive=True, IsDeleted=False))
    # One of its catalogue threats is ALSO linked to Tampering via the category map — a real
    # multi-category threat (STRIDE categories are not mutually exclusive per threat).
    s.execute(m.Threat_Catalogue.__table__.insert().values(
        ThreatCatalogueID=418, ThreatTypeID=7, ThreatName="Unauthorised setpoint modification",
        IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
        ThreatCategoryID=TAMPERING, ThreatCatalogueID=418))
    s.commit()


def test_map_alone_admits_a_type_whose_default_category_differs():
    """The [A2] leg: category_id=Tampering must surface type 7 even though its OWN
    ThreatCategoryID is Spoofing — admission comes ONLY from the map row."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s)
        rows = get_possible_types(s, TAMPERING)
    assert [r["ThreatTypeID"] for r in rows] == [7]
    assert rows[0]["ThreatCategoryID"] == SPOOFING  # the type's OWN category, unchanged


def test_default_category_door_still_works_unassisted():
    """Control: searching the type's own category (Spoofing) admits it with no map row needed."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s)
        rows = get_possible_types(s, SPOOFING)
    assert [r["ThreatTypeID"] for r in rows] == [7]


def test_a_category_with_no_default_and_no_map_row_admits_nothing():
    """Neither door open: a category that is the type's default for NOTHING and has NO map
    row linking any of its catalogue threats to it must not admit the type."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=2, ThreatCategoryName="Repudiation", IsActive=True, IsDeleted=False))
        _seed(s)
        rows = get_possible_types(s, 2)
    assert rows == []


def test_a_deleted_catalogue_row_does_not_leak_its_type_in_via_the_map():
    """The [A2] subquery filters on Threat_Catalogue liveness — a soft-deleted catalogue row's
    map link must not admit its type into a category search anymore."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s)
        s.execute(m.Threat_Catalogue.__table__.update()
                  .where(m.Threat_Catalogue.ThreatCatalogueID == 418)
                  .values(IsDeleted=True))
        s.commit()
        rows = get_possible_types(s, TAMPERING)
    assert rows == []


def test_no_category_filter_returns_every_active_type_r6():
    """[R6]: category_id=None searches the whole flat namespace, map or no map."""
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed(s)
        rows = get_possible_types(s, None)
    assert [r["ThreatTypeID"] for r in rows] == [7]
