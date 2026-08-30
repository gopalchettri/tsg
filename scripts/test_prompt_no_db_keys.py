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

from app.pipeline import prompts, treatment

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
                         "risk_statement": "r",
                         # One applicable, one not — check 14 pins that BOTH reach the model,
                         # since the false verdict is what narrows applicable_to_all_subsystems.
                         "supporting_system_applicability": [
                             {"supporting_system": "SCADA System", "applicable": True,
                              "justification": "Primary control path for the outage."},
                             {"supporting_system": "Billing Portal", "applicable": False,
                              "justification": "No control or data path to generation."}]},
            "existing_controls": {
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
    deep = prompts._scrub_db_keys({"a": {"b": [{"c": {"scenario_id": "x", "keep": "y"}}]}})
    assert deep == {"a": {"b": [{"c": {"keep": "y"}}]}}, deep
    print("3 OK  scrub reaches four levels down")

    # 4 — NO MUTATION. treatment_prompt hands _scrub_db_keys a shallow copy that shares nested
    #     objects with the persisted snapshot; a del-based scrub would strip control_library_id
    #     from the snapshot itself and _inject_reserved would resolve every control to None.
    snap = snapshot(base)
    prompts.treatment_prompt(snap)
    assert snap["existing_controls"]["library_mapped"][0]["control_library_id"] == 28, \
        "treatment_prompt mutated the snapshot — _inject_reserved will resolve controls to None"
    parsed = {"controls_to_be_implemented": {"control_coverage": "gaps",
        "controls": [{"control_code": "CII-CID-028"}, {"control_code": "CII-CID-999"}, {}]}}
    injected, dropped = treatment._inject_reserved(parsed, snap)
    kept = injected["controls_to_be_implemented"]["controls"]
    assert [c.get("control_library_id") for c in kept] == [28], kept
    assert dropped == ["CII-CID-999", "<no control_code>"], dropped  # reported, not just logged
    print("4 OK  snapshot unmutated; control_code -> control_library_id resolves, unmatched dropped", kept)

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

    # 9 — PREFIX-CACHE INVARIANT. system_content must be byte-identical for every threat in a
    #     batch. Providers cache a prompt PREFIX and stop at the first differing byte, and the
    #     user message comes AFTER the whole system message — so ONE per-threat character here
    #     ends the shared prefix before base_ctx begins and re-prefills it (~9k tokens at the
    #     16-system design target) for every threat in the batch. Nothing pinned this before,
    #     which is precisely why "emit only the matching STRIDE line" looked like a sane way to
    #     build A2. Entry points are per-SESSION, so they are held constant across the batch.
    batch = [
        prompts.scenario_prompt(base, "Denial of Service", "Loss of availability of PGS",
                                actors=["Sandworm"], intel_items=INTEL,
                                entry_points=["SCADA System"], category="Denial of Service"),
        prompts.scenario_prompt(base, "Records dispute", "Operator action cannot be attributed",
                                actors=[], intel_items=None,
                                entry_points=["SCADA System"], category="Repudiation"),
        prompts.variant_scenario_prompt(base, "Data tampering", "Setpoint altered",
                                        actors=["Malicious insider"], intel_items=INTEL,
                                        existing=[(1, "An adversary disrupts SCADA control.")],
                                        entry_points=["SCADA System"], sibling_k=3,
                                        category="Tampering"),
    ]
    systems = {msgs[0]["content"] for msgs in batch}
    assert len(systems) == 1, (
        f"system_content differs across a batch ({len(systems)} distinct) — prefix cache "
        "destroyed; something per-threat leaked into the system message")
    print("9 OK  system_content byte-identical across threats, categories and variants")

    # 10 — and the steering still ARRIVES: all six shapes static in the system message, this
    #      threat's own category as DATA in the user message, no bleed between threats.
    sys_msg = batch[1][0]["content"]
    assert all(c in sys_msg for c in prompts._STRIDE_SCENARIO_SHAPES), "STRIDE shape block incomplete"
    assert '"threat_category":"Repudiation"' in batch[1][1]["content"]
    assert "Repudiation" not in batch[0][1]["content"], "category bled across threats"
    print("10 OK all six STRIDE shapes static in system; threat_category carried per-threat")

    # 11 — TWO-STAGE AGREEMENT. Stage 1 CHOOSES category, Stage 2 ACTS on it, so both must be
    #      taught the SAME definitions. The coverage assertion is the offline half of the drift
    #      guard: edit either list without the other and this fails at development time, instead
    #      of Stage 2 silently falling back to RULE 4 for every threat in production.
    t1 = prompts.threats_prompt("Power Generation System (PGS)", ASSET_CTX, SUBS,
                                max_threats=5)[0]["content"]
    for cat, shape in prompts._STRIDE_SCENARIO_SHAPES.items():
        assert f"{cat} → {shape}" in t1, f"threats_prompt missing the shared definition for {cat}"
    uncovered = [c for c in prompts._FALLBACK_STRIDE_CATEGORIES
                 if c not in prompts._STRIDE_SCENARIO_SHAPES]
    assert not uncovered, f"categories with no scenario shape — Stage 2 degrades silently: {uncovered}"
    print("11 OK Stage 1 and Stage 2 share one category definition; fallback list fully covered")

    # 12 — check 11 is not vacuous: drop a shape and BOTH halves must fail.
    real_shapes = prompts._STRIDE_SCENARIO_SHAPES
    try:
        prompts._STRIDE_SCENARIO_SHAPES = {k: v for k, v in real_shapes.items()
                                           if k != "Repudiation"}
        stubbed = prompts.threats_prompt("Power Generation System (PGS)", ASSET_CTX, SUBS,
                                         max_threats=5)[0]["content"]
        # Key on the SHAPE text, not "Repudiation → " — the type: line renders _STRIDE_TYPE_HINTS
        # with the same separator, so the prefix alone is present either way.
        assert real_shapes["Repudiation"] not in stubbed, \
            "definition survived removal — test proves nothing"
        assert [c for c in prompts._FALLBACK_STRIDE_CATEGORIES
                if c not in prompts._STRIDE_SCENARIO_SHAPES] == ["Repudiation"]
    finally:
        prompts._STRIDE_SCENARIO_SHAPES = real_shapes
    print("12 OK drift detection is real — removing a shape drops it from Stage 1 and is flagged")

    # 13 — supporting_system_applicability FIELDS text lives in the SYSTEM message (like
    #      entry_point_fields), not the user context — lists every in-scope system by name,
    #      omitted when there are none, and (session-level, not per-threat) already covered by
    #      check 9's byte-identical-batch assertion above.
    sys_with_subs = prompts.scenario_prompt(base, "Denial of Service", "Loss of availability of PGS",
                                            actors=["Sandworm"], intel_items=INTEL,
                                            entry_points=["SCADA System"])[0]["content"]
    assert "supporting_system_applicability" in sys_with_subs
    assert "SCADA System" in sys_with_subs.split("supporting_system_applicability", 1)[1][:200]
    empty_ctx = prompts.build_base_context("Asset with no subsystems", ASSET_CTX, [])
    no_sub = prompts.scenario_prompt(empty_ctx, "Denial of Service", "Loss of availability of PGS",
                                      actors=["Sandworm"])[0]["content"]
    assert "supporting_system_applicability" not in no_sub, \
        "field requested with no supporting systems to judge against"
    print("13 OK supporting_system_applicability lists in-scope systems; omitted when none exist")

    # 14 — the three scenario-side context fields the TREATMENT prompt must carry. Each was a
    #      real gap: actors arrived [] through validated_actors, applicability was never read
    #      at all, and supporting_systems was only ever asserted for the scenario prompt
    #      (check 2), so nothing proved it survived into this one.
    treat = rendered["treatment"]
    assert "External attacker" in treat, "threat.actors missing — plan is blind to the adversary"
    assert "supporting_system_applicability" in treat
    assert "Billing Portal" in treat, \
        "the applicable=false verdict must reach the model — it is what narrows 'Yes'"
    assert "No control or data path to generation." in treat
    assert '"applicable":false' in treat, f"bool verdict lost: {treat[-400:]}"
    assert "SCADA System" in treat, "supporting_systems dropped out of the treatment context"
    # And the prompt must actually TELL the model to use it, else the key is inert payload.
    assert "scenario.supporting_system_applicability" in prompts.treatment_prompt(
        snapshot(base))[0]["content"]
    print("14 OK treatment prompt carries actors + applicability (both verdicts) + systems")

    print("\nprompt db-key self-check OK")


if __name__ == "__main__":
    main()
