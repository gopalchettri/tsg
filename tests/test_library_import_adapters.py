"""Adapter + shape-check behaviour for the open-source library import.

No network. Every adapter case feeds a synthetic payload shaped like the real source. The rule
they all encode is the one every adapter shares -- an unmappable input is SKIPPED and reported,
never guessed into a category.

The last case extends that same rule past the adapters and into the WRITE: a record whose name
another type already holds is unmappable too, and must be skipped and reported rather than folded
into that other type's row. It is the one case here that needs a real database, because the
collision is raised by an INDEX -- UX_ThreatCatalogue_NaturalKey, on ThreatName ALONE.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.intel.library_import import (
    ThreatLibraryImportError,
    adapt_atlas,
    adapt_emb3d,
    adapt_misp_actors,
    adapt_pytm,
    check_source_shape,
    group_by_type,
    import_records,
    modal_category,
)


def test_pytm_maps_known_prefix_and_skips_unknown():
    records, skipped = adapt_pytm([
        {"SID": "INP01", "description": "Buffer overflow via env var"},
        {"SID": "ZZ99", "description": "not a real prefix"},
    ])
    assert [r["type_name"] for r in records] == ["Input Manipulation"]
    assert records[0]["threat_name"] == "INP01 Buffer overflow via env var"
    assert records[0]["categories"] == ["Tampering"]
    assert len(skipped) == 1 and "ZZ99" in skipped[0]["reason"]


def test_emb3d_accepts_both_wrapped_and_bare_shapes():
    threats = [{"id": "TID-108", "text": "Firmware modified undetected", "category": "hardware"}]
    wrapped, _ = adapt_emb3d({"threats": threats})
    bare, _ = adapt_emb3d(threats)
    assert wrapped == bare
    assert wrapped[0]["type_name"] == "Embedded Device - Hardware"
    assert wrapped[0]["categories"] == ["Tampering", "Information Disclosure"]


def test_emb3d_skips_unknown_category_rather_than_guessing():
    records, skipped = adapt_emb3d([{"id": "TID-1", "text": "x", "category": "cryptography"}])
    assert records == []
    assert "cryptography" in skipped[0]["reason"]


_ATLAS = {
    "techniques": {
        "AML.T0010": {"name": "Supply Chain Compromise"},
        "AML.T0010.001": {"name": "ML Software"},
        "AML.T0099": {"name": "Unmapped Technique"},
    },
    "relationships": {
        "AML.T0010": {"achieves": [{"target": "AML.TA0004"}]},          # Initial Access -> Spoofing
        "AML.T0010.001": {"specializes": [{"source": "AML.T0010.001", "target": "AML.T0010"}]},
        "AML.T0099": {"achieves": [{"target": "AML.TA9999"}]},          # not in the STRIDE map
    },
}


def test_atlas_files_subtechniques_under_their_parent_type():
    records, skipped = adapt_atlas(_ATLAS)
    # The parent supplies the TYPE; only the sub-technique becomes a catalogue row.
    assert [(r["type_name"], r["threat_name"]) for r in records] == [
        ("Supply Chain Compromise", "AML.T0010.001 ML Software")]
    assert records[0]["categories"] == ["Spoofing"]
    # A technique whose tactics are all unmapped is skipped, never guessed.
    assert any("AML.TA9999" in s["reason"] for s in skipped)


def test_atlas_childless_technique_becomes_its_own_row():
    data = {"techniques": {"AML.T0001": {"name": "Solo"}},
            "relationships": {"AML.T0001": {"achieves": [{"target": "AML.TA0011"}]}}}
    records, _ = adapt_atlas(data)
    assert records == [{"type_name": "Solo", "threat_name": "AML.T0001 Solo",
                        "categories": ["Denial of Service"]}]


def test_misp_filters_to_cii_and_caps():
    data = {"values": [
        {"value": "GridGhost", "description": "targets the energy sector"},
        {"value": "ShopBot", "description": "targets online retail"},          # no CII keyword
        {"value": "WaterWraith", "description": "attacks water utilities"},
    ]}
    actors, skipped = adapt_misp_actors(data, max_actors=1)
    assert actors == ["GridGhost"]                       # ShopBot filtered, cap stopped the rest
    assert "max_actors cap" in skipped[0]["reason"]


def test_misp_entry_without_a_name_is_skipped_not_a_keyerror():
    """A CII-matching entry with no 'value' key used to escape as a raw KeyError -- a 500-class
    traceback on the job status instead of a bounded message."""
    actors, skipped = adapt_misp_actors({"values": [{"description": "scada"}]}, max_actors=10)
    assert actors == []
    assert skipped[0]["reason"] == "entry has no 'value' name"


@pytest.mark.parametrize("source,bad", [
    ("pytm", {"not": "a list"}),
    ("misp_actors", {"no_values_key": 1}),
    ("atlas", {"techniques": {}}),                       # present but empty
])
def test_shape_check_rejects_wrong_shape_with_a_readable_message(source, bad):
    with pytest.raises(ThreatLibraryImportError) as exc:
        check_source_shape(source, bad)
    assert source in str(exc.value) and "expected" in str(exc.value)


def test_modal_category_picks_the_commonest_stride():
    recs = [{"categories": ["Tampering"]}, {"categories": ["Tampering", "Spoofing"]},
            {"categories": ["Spoofing"]}, {"categories": ["Tampering"]}]
    assert modal_category(recs) == "Tampering"


def test_group_by_type_keeps_every_record():
    recs = [{"type_name": "A", "categories": []}, {"type_name": "B", "categories": []},
            {"type_name": "A", "categories": []}]
    grouped = group_by_type(recs)
    assert set(grouped) == {"A", "B"} and len(grouped["A"]) == 2


# ------------------------------------------------ a name another type already holds
# Ids the fixture seeds. OTHER_TYPE is the type the colliding name is already filed under;
# the import arrives claiming the same name for a type of its own.
OTHER_TYPE, TAKEN_CAT, TAMPERING = 10, 100, 2
TAKEN_NAME = "INP01 Buffer overflow via env var"


@pytest.fixture
def sess():
    engine = create_engine("sqlite://")

    # pysqlite workaround (as in tests/test_promote_scenario_library.py): without it the RELEASE
    # SAVEPOINT that dal.upsert_threat_catalogue emits silently COMMITS the open transaction, so
    # a mint this test expects to be rolled back would survive and the assertions below would be
    # measuring the wrong database.
    @event.listens_for(engine, "connect")
    def _no_implicit_txn(dbapi_connection, connection_record):
        dbapi_connection.isolation_level = None

    @event.listens_for(engine, "begin")
    def _explicit_begin(conn):
        conn.exec_driver_sql("BEGIN")

    for t in (m.Threat_Category, m.Threat_Type, m.Threat_Catalogue,
              m.Threat_Catalogue_Category_Map):
        t.__table__.create(engine, checkfirst=True)
    with engine.begin() as conn:
        # The LIVE backstop, as raw DDL so no Index object pollutes the shared table metadata for
        # other test files. It is not decoration: the whole conflict this test pins is an
        # IntegrityError against THIS index, so a schema without it would report a clean import
        # and the test would pass for the wrong reason. (SQLite ignores the production index's
        # filtered WHERE, which only widens it here.)
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue(ThreatName)")

    s = sessionmaker(bind=engine)()
    s.add(m.Threat_Category(ThreatCategoryID=TAMPERING, ThreatCategoryName="Tampering",
                            IsActive=True, IsDeleted=False))
    s.add(m.Threat_Type(ThreatTypeID=OTHER_TYPE, ThreatTypeName="Embedded Device - Hardware",
                        ThreatCategoryID=TAMPERING, IsActive=True, IsDeleted=False))
    s.add(m.Threat_Catalogue(ThreatCatalogueID=TAKEN_CAT, ThreatTypeID=OTHER_TYPE,
                             ThreatName=TAKEN_NAME, IsActive=True, IsDeleted=False,
                             Source="mitre_emb3d"))
    s.commit()
    return s


def _links(sess, catalogue_id: int) -> int:
    mp = m.Threat_Catalogue_Category_Map
    return sess.execute(select(func.count()).select_from(mp)
                        .where(mp.ThreatCatalogueID == catalogue_id)).scalar()


def test_a_name_another_type_already_holds_is_skipped_not_quietly_re_filed(sess):
    """An import must never re-curate a row it does not own.

    The library's names are unique ACROSS types, so when two standards spell one threat the same
    way there is a single row and it belongs to whichever type got there first. The tempting
    recovery -- hand the caller that existing row -- writes this import's STRIDE categories onto
    another type's threat, so a pytm run silently re-classifies an EMB3D row and the mapping back
    to the source standard rots with no trace in the job result. Skipping costs one record and is
    reported; re-filing corrupts curated data and is not.

    The rest of the import must still land: one bad record is not a failed import.
    """
    result = import_records(sess, [
        {"type_name": "Input Manipulation", "threat_name": TAKEN_NAME,
         "categories": ["Tampering"]},
        {"type_name": "Input Manipulation", "threat_name": "INP07 Unchecked length field",
         "categories": ["Tampering"]},
    ], tag="pytm", created_by="auto:pytm", is_active=True)

    assert [r["item"] for r in result["skipped"]] == [TAKEN_NAME]
    assert "Embedded Device - Hardware" in result["skipped"][0]["reason"], (
        "the operator has to be told WHICH type holds the name, or the report is unactionable")

    assert result["threats"] == 1, "the count must not claim a record the import refused to write"
    assert result["threats_created"] == 1, "only the clean record is minted"

    assert _links(sess, TAKEN_CAT) == 0, (
        "the other type's row must be untouched -- borrowing it would file this import's "
        "categories under a threat it does not own")
    assert result["new_category_links"] == 1, "the clean record's link still happened"
