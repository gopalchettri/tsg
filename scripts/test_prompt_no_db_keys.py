"""Self-check: no DB primary key reaches any prompt sent to the model.

Run:  .venv/Scripts/python.exe scripts/test_prompt_no_db_keys.py

Assert-based, no framework — the repo removed its pytest suite (commit 8c8b225), so this follows
the existing scripts/ self-check style (see app/core/env_selfcheck.py, app/db/coverage_selfcheck.py).

Covers every LLM call in the codebase:
  1 threats_prompt · 2 scenario_prompt · 3 variant_scenario_prompt · 4 treatment_prompt
  5 the scenario repair turn · 6 grounding._paraphrase (bare threat-name string, nothing to scrub)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline import prompts, treatment  # noqa: E402

EXCL = prompts._EXCLUDE_DB_KEY_TO_PROMPT


def keys_present(text: str) -> set[str]:
    """Which excluded key names appear as JSON keys in a rendered prompt."""
    return {k for k in re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:', text) if k in EXCL}


# --- fixtures: ids deliberately seeded at every nesting depth the payloads really use ----------
ASSET_CTX = {"asset_type": "CII Asset", "sector": "Energy",
             "critical_service": ["Power Generation"],
             "cii_asset_description": "OT platform controlling electricity generation."}
SUBS = [
    {"id": 7, "criticality": "High", "name": "SCADA System",           # depth 2: the original leak
     "asset_type": "Operational Technology (OT)", "technology_used": ["Custom Application"],
     "hosting_location": "Entity Data Centre"},
    {"id": 8, "criticality": "High"},                                  # nothing describable at all
]
INTEL = [{"external_id": "ICSA-26-188-03", "title": "Hitachi Energy e-mesh EMS",
          "url": "https://cisa.gov/x"}]


def snapshot(base):
    return {**base,
            "threat": {"category": "Denial of Service", "type": "Service Disruption",
                       "name": "Loss of availability of PGS", "actors": ["External attacker"]},
            "scenario": {"scenario_title": "PGS outage", "scenario_statement": "s",
                         "risk_statement": "r"},
            "existing_controls": {
                "scenario_suggested": [{"name": "Network segmentation", "why": "Limits pivot."}],
                "library_mapped": [                                    # depth 3: the second leak
                    {"control_library_id": 28, "control_code": "CII-CID-028", "domain": "BCDR",
                     "control_name": "Testing for Reliability", "standards": ["DESC ISR v3"]}],
                "library_mapped_count": 1, "register_controls": []},
            "risk_assessment": {"likelihood_rating": 2, "risk_level": "Medium"},
            "treatment_strategy": "Mitigate",
            "register": {"risk_owner": "Jane Doe", "risk_identification_date": "2026-01-01"},
            "warnings": ["w"]}


def render_all():
    base = prompts.build_base_context("Power Generation System (PGS)", ASSET_CTX, SUBS)
    scen = prompts.scenario_prompt(base, "Denial of Service", "Loss of availability of PGS",
                                   actors=["Sandworm"], intel_items=INTEL,
                                   entry_points=["SCADA System"])
    return base, {
        "threats": prompts.threats_prompt("Power Generation System (PGS)", ASSET_CTX, SUBS,
                                          max_threats=5)[1]["content"],
        "scenario": scen[1]["content"],
        "variant": prompts.variant_scenario_prompt(
            base, "Denial of Service", "Loss of availability of PGS", intel_items=INTEL,
            existing=[(1, "An adversary disrupts SCADA control.")], sibling_k=3)[1]["content"],
        "treatment": prompts.treatment_prompt(snapshot(base))[1]["content"],
        # the repair turn re-sends the model's own output, scrubbed the same way
        "repair": json.dumps(prompts._scrub_db_keys(
            {"scenario_title": "t", "entry_point": "SCADA System",
             "entry_point_id": 7, "plausible_entry_point_ids": [7, 8]})),
    }


def main() -> None:
    base, rendered = render_all()

    # 1 — generic: loop the WHOLE constant over every prompt, so a key added later is covered
    #     automatically without editing this test.
    for name, text in rendered.items():
        found = keys_present(text)
        assert not found, f"{name} prompt leaks db keys: {sorted(found)}"
    print(f"1 OK  {len(rendered)} prompts, zero of {len(EXCL)} excluded keys present")

    # 2 — the real nested paths (depth 2 supporting_systems, depth 3 library_mapped), and that
    #     siblings at the same depth survive.
    assert '"id"' not in rendered["scenario"] and "criticality" not in rendered["scenario"]
    assert "control_library_id" not in rendered["treatment"]
    assert "SCADA System" in rendered["scenario"] and "Custom Application" in rendered["scenario"]
    assert "CII-CID-028" in rendered["treatment"] and "Testing for Reliability" in rendered["treatment"]
    print("2 OK  nested ids gone at depth 2 and 3; sibling fields at those depths survive")

    # 3 — arbitrary depth, no cap
    deep = prompts._scrub_db_keys({"a": {"b": [{"c": {"output_id": "x", "keep": "y"}}]}})
    assert deep == {"a": {"b": [{"c": {"keep": "y"}}]}}, deep
    print("3 OK  scrub reaches four levels down")

    # 4 — NO MUTATION. treatment_prompt hands _scrub_db_keys a shallow copy that shares nested
    #     objects with the persisted snapshot; a del-based scrub would strip control_library_id
    #     from the snapshot itself and _inject_reserved would resolve every control to None.
    snap = snapshot(base)
    prompts.treatment_prompt(snap)
    assert snap["existing_controls"]["library_mapped"][0]["control_library_id"] == 28, \
        "treatment_prompt mutated the snapshot — _inject_reserved will resolve controls to None"
    parsed = {"controls_to_be_implemented": [{"control_code": "CII-CID-028"},
                                             {"control_code": "CII-CID-999"}, {}]}
    ids = [c.get("control_library_id")
           for c in treatment._inject_reserved(parsed, snap)["controls_to_be_implemented"]]
    assert ids == [28, None, None], ids
    print("4 OK  snapshot unmutated; control_code -> control_library_id resolves", ids)

    # 5 — ordering guard: a subsystem holding only id/criticality must be ABSENT, not {}
    assert base["supporting_systems"] == [
        {"name": "SCADA System", "asset_type": "Operational Technology (OT)",
         "technology_used": ["Custom Application"], "hosting_location": "Entity Data Centre"}
    ], base["supporting_systems"]
    print("5 OK  content-free subsystem dropped entirely, not emitted as {}")

    # 6 — grounded scenario (Gap A): safe even if repair is ever reordered after grounding
    assert prompts._scrub_db_keys(
        {"entry_point": "SCADA System", "entry_point_id": 7,
         "plausible_entry_point_ids": [7, 8]}) == {"entry_point": "SCADA System"}
    print("6 OK  entry_point_id / plausible_entry_point_ids stripped, label kept")

    # 7 — framing intact (Gap C): prefix first, intel fence AFTER the JSON, never inside it
    s = rendered["scenario"]
    assert s.startswith(prompts._CONTEXT_PREFIX)
    assert s.index("<<<CURRENT_THREAT_INTEL") > s.rindex("}")
    assert "ICSA-26-188-03" in s
    assert rendered["treatment"].startswith(prompts._CONTEXT_PREFIX)
    assert "Jane Doe" not in rendered["treatment"] and '"warnings"' not in rendered["treatment"]
    print("7 OK  prefix first, intel fence outside the JSON, register/warnings still stripped")

    # 8 — the check is not vacuous: with the constant emptied, step 1 MUST fail.
    real = prompts._EXCLUDE_DB_KEY_TO_PROMPT
    try:
        prompts._EXCLUDE_DB_KEY_TO_PROMPT = frozenset()
        leaked = keys_present(render_all()[1]["scenario"])
        assert leaked, "stubbing the constant empty did not leak — the test proves nothing"
    finally:
        prompts._EXCLUDE_DB_KEY_TO_PROMPT = real
    print("8 OK  detection is real — emptying the constant leaks", sorted(leaked))

    print("\nprompt db-key self-check OK")


if __name__ == "__main__":
    main()
