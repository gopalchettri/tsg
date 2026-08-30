"""dal.active_threat_grid_categories — the live coverage read, catalogue model.

THE BUG this read fixed (still the reason the file exists): find_threats used to compute
coverage from an in-memory accumulator of ONLY the rows inserted by one call. An additive
round (next-set, regen) deliberately skips everything already active, so a fully-covered
session that added one threat reported itself almost entirely uncovered — a false, permanent
regression. Coverage is now reconstructed live from Identified_Threat after the insert.

THE MODEL pinned here (2026-08-28 catalogue reversal): multi-category membership comes from
Threat_Catalogue_Category_Map joined to Threat_Category BY ID — one numbering system, no
name matching or spelling translation. A threat whose ThreatCatalogueID has map rows reports
every mapped category name; rows without map data (or never grounded to the catalogue at
all) fall back to the single stored ThreatCategory column, so multi-category coverage
switches on purely by data arriving, per threat, no flag.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import dal
from app.db import models as m
from app.pipeline import coverage as coverage_mod

NOW = datetime.now(UTC)
SID = str(uuid.uuid4())


def _session():
    engine = create_engine("sqlite://")
    for tbl in (m.Identified_Threat, m.Threat_Category,
                m.Threat_Catalogue_Category_Map):
        tbl.__table__.create(engine)
    return sessionmaker(bind=engine, future=True)()


def _seed_stride(s):
    for cid, name in ((5, "Spoofing"), (6, "Tampering"), (4, "Repudiation")):
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=cid, ThreatCategoryName=name, IsActive=True, IsDeleted=False))


def _map(s, catalogue_id: int, *category_ids: int):
    """Give one catalogue threat multi-STRIDE membership via the category map (by id)."""
    for cid in category_ids:
        s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
            ThreatCategoryID=cid, ThreatCatalogueID=catalogue_id))


#: Real GUIDs keyed by short label — ThreatID is a GUID column, so a literal like "t1"
#: fails at the SQLite driver, not the assertion.
_GUID: dict[str, str] = {}


def _gid(label: str) -> str:
    return _GUID.setdefault(label, str(uuid.uuid4()))


def _threat(label, subsystem_id, *, category, catalogue_id=None, superseded=0):
    return {
        "ThreatID": _gid(label), "SessionID": SID, "TenantID": "t", "EntityID": "e",
        "SubsystemID": subsystem_id, "ThreatCategory": category, "ThreatType": "t",
        "ThreatName": "n", "ThreatTypeID": None, "ThreatCatalogueID": catalogue_id,
        "GroundingStatus": "verified", "GroundingScore": 100.0,
        "Superseded": superseded, "CreatedAt": NOW,
    }


def test_map_categories_are_reported_multi_category_by_id_join():
    """The core mechanism: a stored threat whose catalogue row has category-map rows must
    report EVERY mapped Threat_Category name — multi-category, joined by id — even though
    its single stored ThreatCategory column names only one of them. Reporting only the
    stored column would leave the other mapped cell looking uncovered, silently
    un-counting real coverage."""
    with _session() as s:
        _seed_stride(s)
        _map(s, 7, 5, 6)  # Spoofing + Tampering by id; stored column says only Spoofing
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("t1", 0, category="Spoofing", catalogue_id=7),
        ]))
        s.commit()
        out = dal.active_threat_grid_categories(s, SID, [0])
    assert [(r["subsystem_id"], sorted(r["categories"])) for r in out] == \
        [(0, ["Spoofing", "Tampering"])]


def test_map_row_to_retired_category_is_skipped_not_guessed():
    """A map row pointing at a retired (inactive) Threat_Category cannot be placed on the
    STRIDE grid; guessing would mis-count coverage. It is skipped — the live sibling still
    counts, so one stale map row degrades that one category, never the whole threat."""
    with _session() as s:
        _seed_stride(s)
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=99, ThreatCategoryName="Quantum Decryption",
            IsActive=False, IsDeleted=False))
        _map(s, 8, 4, 99)  # Repudiation (live) + a retired category
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("t1", 0, category="Spoofing", catalogue_id=8),
        ]))
        s.commit()
        out = dal.active_threat_grid_categories(s, SID, [0])
    assert out == [{"subsystem_id": 0, "categories": ["Repudiation"]}]


def test_catalogue_threat_with_no_map_rows_falls_back_to_stored_category():
    """A catalogue-grounded threat whose catalogue row has NO category-map rows must fall
    back to its single stored ThreatCategory column. If this fallback broke, every
    unmapped library threat would read as uncovered on the grid."""
    with _session() as s:
        _seed_stride(s)
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("t1", 0, category="Tampering", catalogue_id=9),  # no map rows
        ]))
        s.commit()
        out = dal.active_threat_grid_categories(s, SID, [0])
    assert out == [{"subsystem_id": 0, "categories": ["Tampering"]}]


def test_generated_threat_without_catalogue_id_uses_its_stored_category():
    """A generated threat never grounded to the catalogue (ThreatCatalogueID None) has no
    map to consult — its stored ThreatCategory is its only grid placement and must be
    honoured as-is."""
    with _session() as s:
        _seed_stride(s)
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("t1", 42, category="Repudiation", catalogue_id=None),
        ]))
        s.commit()
        out = dal.active_threat_grid_categories(s, SID, [42])
    assert out == [{"subsystem_id": 42, "categories": ["Repudiation"]}]


def test_superseded_rows_are_excluded():
    """Superseded rows are history, not state: a regenerated threat's old row must not keep
    its cell looking covered after the replacement was itself removed."""
    with _session() as s:
        _seed_stride(s)
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("t1", 0, category="Spoofing", catalogue_id=None, superseded=1),
        ]))
        s.commit()
        assert dal.active_threat_grid_categories(s, SID, [0]) == []


def test_additive_round_sees_the_whole_session_not_just_what_it_would_have_inserted():
    """The scenario from the original bug report, at the mechanism level: round 1 fully
    covers a 2-category, 2-unit grid (4 cells) — one cell via a multi-category mapped
    catalogue threat, the rest via fallback rows. Round 2 adds exactly ONE new threat,
    simulating next-set's "everything else was already active" outcome. A coverage read
    taken AFTER round 2's insert must still show the FULL grid covered: the old accumulator
    bug would have reported 3 of 4 cells as newly unexplained on a session that never lost
    coverage."""
    cats = ["Spoofing", "Tampering"]
    with _session() as s:
        _seed_stride(s)
        # Catalogue threat 7 is multi-category via the map — one Identified_Threat row
        # covering BOTH of unit 0's cells.
        _map(s, 7, 5, 6)
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("r1a", 0, category="Spoofing", catalogue_id=7),
            _threat("r1b", 41, category="Spoofing", catalogue_id=None),
            _threat("r1c", 41, category="Tampering", catalogue_id=None),
        ]))
        s.commit()
        round1 = dal.active_threat_grid_categories(s, SID, [0, 41])
        cov1 = coverage_mod.coverage_report([0, 41], cats, round1)
        assert (cov1["cells"], cov1["covered"], cov1["unexplained"]) == (4, 4, 0)

        # Round 2 (additive): only ONE genuinely new threat reaches the insert.
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("r2new", 41, category="Spoofing", catalogue_id=None),
        ]))
        s.commit()
        round2 = dal.active_threat_grid_categories(s, SID, [0, 41])
        cov2 = coverage_mod.coverage_report([0, 41], cats, round2)
    assert (cov2["cells"], cov2["covered"], cov2["unexplained"]) == (4, 4, 0)
