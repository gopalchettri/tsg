"""Pins pipeline/scenario_profile.py — profile identity and the refuse-don't-guess substitution.

These are the two functions that decide whether one customer's scenario text may be shown to
another customer. Every assertion below is either "these assets ARE interchangeable" or "this
swap is not provably clean, so refuse".
"""
import json

from app.pipeline.scenario_profile import live_names, profile_key, substitute_names

SECTORS = [4, 2]
ASSET = {"name": "Al Qusais Pumping Station", "asset_type": "Pumping Station",
         "sector": "Energy & Water", "sub_sector": "Water Supply",
         "description": "Serves 40,000 households."}
SYSTEMS = [
    {"id": 41, "name": "SCADA HMI", "asset_type": "OT", "criticality": "High",
     "technology_used": ["Siemens SCADA"], "vendor_name": "Siemens"},
    {"id": 42, "name": "Billing Portal", "asset_type": "IT", "criticality": "Medium",
     "technology_used": ["Django"], "vendor_name": "In-house"},
]


def test_identical_technology_different_customer_shares_a_profile():
    """The whole point: two pumping stations of the same design, owned by different people,
    with different names for the same boxes, are ONE profile."""
    other_asset = {**ASSET, "name": "Jebel Ali Pumping Station",
                   "description": "Serves an industrial zone."}
    other_systems = [{**SYSTEMS[0], "id": 77, "name": "Control Room HMI"},
                     {**SYSTEMS[1], "id": 78, "name": "Customer Web"}]
    assert profile_key(SECTORS, ASSET, SYSTEMS) == profile_key(SECTORS, other_asset, other_systems)


def test_key_carries_no_customer_identity():
    # A name or a description changing must not change the key...
    assert profile_key(SECTORS, {**ASSET, "name": "X", "description": "Y"}, SYSTEMS) \
        == profile_key(SECTORS, ASSET, SYSTEMS)
    # ...and the digest must not contain any of it either.
    key = profile_key(SECTORS, ASSET, SYSTEMS)
    assert len(key) == 64 and all(c in "0123456789abcdef" for c in key)


def test_technology_sector_and_system_count_all_change_the_key():
    base = profile_key(SECTORS, ASSET, SYSTEMS)
    swapped_tech = [{**SYSTEMS[0], "technology_used": ["Rockwell"]}, SYSTEMS[1]]
    assert profile_key(SECTORS, ASSET, swapped_tech) != base
    # sector scope decides which library threats are even VISIBLE, so it is part of identity
    assert profile_key([9], ASSET, SYSTEMS) != base
    # one fewer supporting system is a different asset, not a near-match
    assert profile_key(SECTORS, ASSET, SYSTEMS[:1]) != base
    # position matters: substitution is positional, so an order swap must miss
    assert profile_key(SECTORS, ASSET, list(reversed(SYSTEMS))) != base
    # ...but ordering INSIDE one multi-select field does not
    multi_a = [{**SYSTEMS[0], "technology_used": ["Siemens SCADA", "Modbus"]}, SYSTEMS[1]]
    multi_b = [{**SYSTEMS[0], "technology_used": ["Modbus", "Siemens SCADA"]}, SYSTEMS[1]]
    assert profile_key(SECTORS, ASSET, multi_a) == profile_key(SECTORS, ASSET, multi_b)


def test_live_names_keeps_positions_when_a_system_is_unnamed():
    names = live_names("Asset A", [{"name": "One"}, {"name": None}, {"name": "Three"}])
    assert names == ["Asset A", "One", "", "Three"]


STORED = json.dumps({
    "scenario_title": "SCADA HMI — unauthorised setpoint push",
    "scenario_statement": ("An attacker reaches the SCADA HMI from the Billing Portal and "
                        "alters pump setpoints at Al Qusais Pumping Station."),
    "supporting_system_applicability": [
        {"supporting_system": "SCADA HMI", "applicable": True, "justification": "Direct target."},
        {"supporting_system": "Billing Portal", "applicable": False, "justification": "No path."},
    ],
})
SOURCE = ["Al Qusais Pumping Station", "SCADA HMI", "Billing Portal"]


def test_clean_swap_rewrites_every_mention_including_nested_structure():
    out = substitute_names(STORED, SOURCE, ["Jebel Ali Pumping Station", "Control Room HMI",
                                            "Customer Web"])
    assert out is not None
    assert out["scenario_title"] == "Control Room HMI — unauthorised setpoint push"
    assert "Jebel Ali Pumping Station" in out["scenario_statement"]
    assert "Customer Web" in out["scenario_statement"]
    assert [e["supporting_system"] for e in out["supporting_system_applicability"]] \
        == ["Control Room HMI", "Customer Web"]
    # nothing of the originating asset survives anywhere
    assert not any(n in json.dumps(out) for n in SOURCE)


def test_a_surviving_source_name_refuses_the_whole_row():
    """The dangerous case: the model wrote a CASE VARIANT that exact replacement cannot reach.
    Serving this would put the originating customer's system name in someone else's register,
    so the row is refused and the caller generates instead."""
    stored = json.dumps({"scenario_statement": "The scada hmi is reachable from the SCADA HMI."})
    assert substitute_names(stored, SOURCE, ["A", "B", "C"]) is None


def test_prefix_names_do_not_corrupt_each_other():
    """Replacing the shorter name first would turn 'SCADA HMI Server' into 'X Server' and leave
    a half-rewritten system name in the text. Longest-first is what prevents it."""
    stored = json.dumps({"scenario_statement": "SCADA HMI Server talks to SCADA HMI."})
    out = substitute_names(stored, ["A", "SCADA HMI", "SCADA HMI Server"], ["A", "Alpha", "Bravo"])
    assert out == {"scenario_statement": "Bravo talks to Alpha."}


def test_refuses_on_shape_mismatch_and_malformed_input():
    assert substitute_names(STORED, SOURCE, ["only", "two"]) is None
    assert substitute_names("{not json", SOURCE, ["A", "B", "C"]) is None
    assert substitute_names(json.dumps(["a", "list"]), ["x"], ["y"]) is None


def test_unchanged_names_are_a_no_op_not_a_refusal():
    """Serving a profile's scenario back to the SAME asset must work — every name maps to
    itself, so the residue check must not read them as leftovers."""
    out = substitute_names(STORED, SOURCE, list(SOURCE))
    assert out is not None
    assert out["scenario_title"] == "SCADA HMI — unauthorised setpoint push"
