"""dal.active_threat_grid_categories -- the fix for the additive-round coverage regression.

THE BUG. find_threats computed coverage from an in-memory `grid_records` accumulator built
ONLY from `rows` (threats inserted THIS call). On an additive round (next-set, regen), most
retrieval hits are deliberately skipped as duplicates of already-active threats -- correct
behaviour, existing_identities exists for exactly that -- so `rows` holds only the handful of
genuinely new threats. A session that was fully covered (24/24 cells) could add one new threat
via next-set and have its coverage audit describe covered~=0, unexplained~=cells: a false,
permanent regression on the session board, immediately after a normal, successful click.

THE FIX. Coverage is now read live from the DB, across every grid unit, AFTER the round's
insert -- not accumulated from what one call happened to write. This file pins the read
function directly: it must reconstruct the FULL current (subsystem, category) state,
regardless of which round wrote which row, with multi-category membership resolved the same
way threat_retrieval._load_candidates resolves it (via Threat_Catalogue_Category_Map when a
ThreatCatalogueID exists, falling back to the bare ThreatCategory column for a threat that
never grounded to a catalogue row).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import dal
from app.db import models as m

NOW = datetime.now(UTC)
SID = str(uuid.uuid4())


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Identified_Threat, m.Threat_Category, m.Threat_Catalogue_Category_Map):
        tbl.__table__.create(engine)
    return engine


def _seed_categories(s):
    for cid, name in ((5, "Spoofing"), (6, "Tampering"), (4, "Repudiation")):
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=cid, ThreatCategoryName=name, IsActive=True, IsDeleted=False))
    # Catalogue row 418 is multi-category (Tampering AND Repudiation) -- the case a single
    # ThreatCategory column could never represent, and the reason the map exists at all.
    for cat_id, cat_cid in ((6, 418), (4, 418), (5, 205)):
        s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
            ThreatCategoryID=cat_id, ThreatCatalogueID=cat_cid))


#: Real GUIDs, keyed by short label -- ThreatID is a GUID column, so a literal like "t1" fails
#: at the SQLite driver, not the assertion.
_GUID = {}


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


def test_reconstructs_multi_category_coverage_across_units_from_persisted_rows_only():
    """The core mechanism: two units, one threat grounded to a multi-category catalogue row
    (must expand to BOTH categories), one generated threat with only a bare category column
    (must fall back to it), all read back with no in-memory state at all -- proving the fix
    does not depend on remembering what any particular round inserted."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        _seed_categories(s)
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("t1", 0, category="Tampering", catalogue_id=418),
            _threat("t2", 41, category="Tampering", catalogue_id=418),
            _threat("t3", 42, category="Repudiation", catalogue_id=None),  # generated, ungrounded
        ]))
        s.commit()

        out = dal.active_threat_grid_categories(s, SID, [0, 41, 42])

    by_unit = {row["subsystem_id"]: sorted(row["categories"]) for row in out}
    assert by_unit[0] == ["Repudiation", "Tampering"]     # catalogue 418 expands to BOTH
    assert by_unit[41] == ["Repudiation", "Tampering"]    # same catalogue row, same expansion
    assert by_unit[42] == ["Repudiation"]                 # ungrounded: falls back to the bare column


def test_superseded_rows_are_excluded():
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        _seed_categories(s)
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("t1", 0, category="Spoofing", catalogue_id=205, superseded=1),
        ]))
        s.commit()
        assert dal.active_threat_grid_categories(s, SID, [0]) == []


def test_additive_round_sees_the_whole_session_not_just_what_it_would_have_inserted():
    """The scenario from the bug report, at the mechanism level: round 1 fully covers a
    2-category, 2-unit grid (4 cells). Round 2 adds exactly ONE new threat on top of what's
    already active -- simulating next-set's "everything else was already active, only this one
    was new" outcome. A coverage read taken AFTER round 2's insert must still show the FULL
    grid covered, not just the one cell round 2 happened to touch."""
    from app.pipeline import coverage as coverage_mod

    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    cats = ["Spoofing", "Tampering"]
    with Session() as s:
        _seed_categories(s)
        # Round 1: covers all 4 cells (2 units x 2 categories).
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("r1a", 0, category="Spoofing", catalogue_id=205),
            _threat("r1b", 0, category="Tampering", catalogue_id=418),
            _threat("r1c", 41, category="Spoofing", catalogue_id=205),
            _threat("r1d", 41, category="Tampering", catalogue_id=418),
        ]))
        s.commit()
        round1 = dal.active_threat_grid_categories(s, SID, [0, 41])
        cov1 = coverage_mod.coverage_report([0, 41], cats, round1)
        assert (cov1["cells"], cov1["unexplained"]) == (4, 0)

        # Round 2 (additive): only ONE genuinely new threat is inserted -- everything else was
        # already active and correctly skipped by find_threats' existing_identities check, so
        # it never reaches this insert. This is the exact shape of a next-set top-up.
        s.execute(m.Identified_Threat.__table__.insert().values([
            _threat("r2new", 41, category="Spoofing", catalogue_id=205),
        ]))
        s.commit()

        round2 = dal.active_threat_grid_categories(s, SID, [0, 41])
        cov2 = coverage_mod.coverage_report([0, 41], cats, round2)

    # THE assertion: still fully covered. The old bug computed coverage from ONLY the new
    # insert (1 record covering 1 cell out of 4), which would have reported 3 of 4 cells as
    # newly "unexplained" -- a false regression on a session that never lost any coverage.
    assert (cov2["cells"], cov2["unexplained"]) == (4, 0)
