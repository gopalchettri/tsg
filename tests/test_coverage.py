"""Pins pipeline/coverage.py: the (subsystem x STRIDE) coverage matrix accounting, plus the
rule that decides which subsystem rows a threat occupies (Phase 2b)."""
from app.core.enums import ThreatRuleType
from app.pipeline.coverage import coverage_gaps, coverage_report, covered_cells, required_cells
from app.pipeline.scoping import _apply_rules, gate_matching_subsystems
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
_GATE = {"RuleType": ThreatRuleType.tech_gate, "RuleKey": "asset_type", "RuleValue": "OT"}


def test_ungated_type_is_universal_not_unattributable():
    # None means "no gate constrains this", NOT "reaches nothing". Collapsing the two would
    # erase the seeded universal threats (phishing, ransomware) from every supporting system.
    assert gate_matching_subsystems(7, [OT, IT], {}) is None
    assert attribute_to_subsystems([OT, IT], [7], {}) == {7: [41, 42]}


def test_gate_narrows_to_the_systems_it_actually_hits():
    assert gate_matching_subsystems(7, [OT, IT], {7: [_GATE]}) == [41]
    assert attribute_to_subsystems([OT, IT], [7], {7: [_GATE]}) == {7: [41]}


def test_unresolved_field_everywhere_is_a_no_op_in_both_functions():
    # Fixed 2026-08-24: this used to assert gate_matching_subsystems([BLANK]) == [] here, on
    # the reasoning that "we don't know" must not become "yes". That reasoning is correct
    # PER SUBSYSTEM when a rule is resolved elsewhere -- but when a rule is unresolved on
    # EVERY subsystem, _apply_rules already treats it as a no-op at the asset level (the type
    # is admitted, not rejected). Attribution disagreeing -- failing closed on every subsystem
    # for the SAME rule the asset-level check ignored -- meant a threat could be recorded once
    # at the asset level and attributed to ZERO supporting systems: a real exposure silently
    # missing from every (subsystem, category) coverage cell it should have filled. Both
    # functions must now agree: a wholly-unresolved rule contributes nothing to either verdict.
    assert gate_matching_subsystems(7, [BLANK], {7: [_GATE]}) == [43]
    _delta, selected, _fails, _factors = _apply_rules(
        {"threat_type_id": 7}, [BLANK], {7: [_GATE]}, 0.0)
    assert selected is True


def test_unresolved_on_this_system_but_resolved_elsewhere_still_fails_closed():
    # The case the fix above must NOT change: a rule with real evidence on ANOTHER subsystem
    # still must not claim a system it has no evidence for. Two systems, one OT (matches the
    # gate), one with asset_type unset -- the unset one must stay excluded.
    unresolved = {"id": 44, "name": "Unclassified Link 2", "asset_type": None}
    assert gate_matching_subsystems(7, [OT, unresolved], {7: [_GATE]}) == [41]


def test_asset_verdict_and_per_system_union_cannot_disagree():
    # Gates AND across rules and OR across systems. If the asset passed on a resolvable
    # field, at least one system must be named — otherwise a threat would be recorded
    # nowhere on the grid while still being live on the asset.
    _delta, selected, _fails, _factors = _apply_rules(
        {"threat_type_id": 7}, [OT, IT], {7: [_GATE]}, 0.0)
    assert selected is True
    assert gate_matching_subsystems(7, [OT, IT], {7: [_GATE]}) != []
