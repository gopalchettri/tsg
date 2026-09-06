"""Adapter + shape-check behaviour for the open-source library import.

No network, no DB: every case feeds a synthetic payload shaped like the real source. The rule
these all encode is the one every adapter shares -- an unmappable input is SKIPPED and reported,
never guessed into a category.
"""
from __future__ import annotations

import pytest

from app.intel.library_import import (
    ThreatLibraryImportError,
    adapt_atlas,
    adapt_emb3d,
    adapt_misp_actors,
    adapt_pytm,
    check_source_shape,
    group_by_type,
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
