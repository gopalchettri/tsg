"""Pins pipeline/coverage.py: the (subsystem x STRIDE) coverage matrix accounting."""
from app.pipeline.coverage import coverage_gaps, coverage_report, covered_cells, required_cells

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
