"""Pins pipeline/coverage.py: the (subsystem x STRIDE) coverage matrix accounting, plus the
rule that decides which subsystem rows a threat occupies (Phase 2b)."""
from app.pipeline.coverage import coverage_gaps, coverage_report, covered_cells, required_cells
from app.pipeline.threat_retrieval import attribute_to_subsystems

CATS = ["Spoofing", "Tampering", "Repudiation"]


def test_required_cells_is_the_full_cross_product():
    assert len(required_cells([0, 41, 42], CATS)) == 9


def test_multi_category_threat_fills_several_cells():
    # One threat mapped to two STRIDE categories answers BOTH cells — the map table is
    # many-to-many by design ("Credential phishing" = Spoofing + InfoDisc + EoP).
    threats = [{"subsystem_id": 0, "categories": ["Spoofing", "Tampering"]}]
    assert covered_cells(threats) == {(0, "Spoofing"), (0, "Tampering")}


def test_single_category_fallback_and_unplaceable_threats():
    assert covered_cells([{"subsystem_id": 0, "category": "Spoofing"}]) == {(0, "Spoofing")}
    assert covered_cells([{"subsystem_id": None, "category": "Spoofing"}]) == set()
    assert covered_cells([{"subsystem_id": 0}]) == set()


def test_gaps_are_deterministic_and_respect_justified_na():
    threats = [{"subsystem_id": 0, "category": "Spoofing"}]
    gaps = coverage_gaps([0], CATS, threats, justified_na=[(0, "Repudiation")])
    assert gaps == [(0, "Tampering")]
    assert gaps == coverage_gaps([0], CATS, threats, justified_na=[(0, "Repudiation")])


def test_report_counts_and_zero_unexplained_definition():
    threats = [{"subsystem_id": 0, "categories": ["Spoofing", "Tampering"]}]
    r = coverage_report([0], CATS, threats, justified_na=[(0, "Repudiation")])
    assert (r["cells"], r["covered"], r["justified_na"], r["unexplained"]) == (3, 2, 1, 0)
    assert r["gaps"] == []
    # a cell outside the required grid never inflates the counts
    r2 = coverage_report([0], CATS, [{"subsystem_id": 99, "category": "Spoofing"}])
    assert r2["covered"] == 0 and r2["unexplained"] == 3


# ---------------------------------------------------------------------------
# Phase 2b: WHICH rows the grid has — the per-subsystem attribution rule.
# ---------------------------------------------------------------------------
OT = {"id": 41, "name": "SCADA HMI", "asset_type": "OT"}
IT = {"id": 42, "name": "Billing Portal", "asset_type": "IT"}
BLANK = {"id": 43, "name": "Unclassified Link", "asset_type": None}


def test_every_threat_attributes_to_every_supporting_system():
    """A threat reaches the asset AND every supporting system — fail-open, with no gate able
    to silently shrink the grid. The Config_Threat_Rule tech_gate narrowing that used to carve
    exceptions here left with that table (2026-08): its failure mode was a real exposure
    silently missing from coverage cells, which the matrix exists to make impossible."""
    assert attribute_to_subsystems([OT, IT], [7]) == {7: [41, 42]}
    assert attribute_to_subsystems([OT, IT, BLANK], [7, 9]) == {7: [41, 42, 43],
                                                                9: [41, 42, 43]}


def test_attribution_with_no_subsystems_is_empty_lists_not_missing_keys():
    # The asset row (ASSET_UNIT_ID = 0) is recorded separately; a subsystem-less asset still
    # gets an entry per type so callers never KeyError.
    assert attribute_to_subsystems([], [7]) == {7: []}
    assert attribute_to_subsystems(None, [7]) == {7: []}
