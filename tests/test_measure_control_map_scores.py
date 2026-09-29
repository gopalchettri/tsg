"""The measuring instrument must send the query the PIPELINE sends. This is that pin.

scripts/measure_control_map_scores.py exists so `TSG_CONTROL_MAP_MIN_SCORE` is set from evidence,
and a cutoff set wrong empties every scenario's control list into what the API documents as a
healthy library gap — silent, expensive. That makes the measurement's own query load-bearing: it
drifted TWICE.

  1. The script called `control_mapping.collect_control_query` (a deprecated wrapper: type + name +
     title + statement) while control mapping had moved to
     `control_relevance.build_control_retrieval_query` via `control_mapping._retrieval_query`, which
     LEADS with the threat CATEGORY and also carries actors, the risk statement, the asset and the
     involved systems. A leading threat identity is worth 1.9 -> 60.6 on a real scenario, so a
     threshold re-pinned from the wrapper's shorter string would have been mis-calibrated — the very
     failure the script prevents, reintroduced through the instrument.
  2. Then `control_mapping._blob` gained a required `column=` keyword. Only the pipeline's own
     caller was updated; the script's private copy kept calling it positionally and raised
     TypeError at an operator's prompt.

WHAT CHANGED, AND WHY THESE TESTS LOOK DIFFERENT NOW. Both drifts had ONE cause: the script owned a
SECOND copy of the SELECT and the per-row assembly. Asserting that the two copies agree is a symptom
fix — it catches the drift only after someone writes it, and only for the inputs the test happens to
name. The copy is now gone: DB mode calls `grounding.control_map_scenario_queries`, the same
function the admin calibration route measures with, so the script and the route cannot measure
different text and a signature change reaches the script through this suite.

So the pins here do the two things a shared function still needs:

  * `_retrieval_query` — the assembler BOTH callers now reach — must genuinely forward every input,
    not merely agree with the builder. Identity alone is satisfiable by two callers that both pass
    `None` everywhere and both get the narrative back, which is exactly the shape of drift 1.
  * the script must not grow a private builder again. That is
    `test_the_script_owns_no_private_query_builder`, and it is the one that removes the cause rather
    than watching for the symptom.

Nothing here needs a database, a model or the network, which is the point: the measurement itself
cannot run in CI, but this can.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import json
from pathlib import Path

from app.core.config import get_settings
from app.pipeline import control_mapping, control_relevance, grounding

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "measure_control_map_scores.py"
#: The sibling measurement script. It owned a THIRD copy of the same assembly and now shares the
#: function too, so the structural pin below covers both — a copy re-appearing in either one is
#: the same defect, and pinning only the file this module is named after would leave half the
#: cause in place.
_SIBLING = _SCRIPT.with_name("compare_control_shortlist.py")

_SPEC = importlib.util.spec_from_file_location("measure_control_map_scores", _SCRIPT)
mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mod)

_SCENARIO = {
    "scenario_title": "Vendor firmware update tampered in transit",
    "scenario_statement": "An attacker substitutes a signed firmware image for the historian.",
    "risk_statement": "Loss of process visibility across the plant.",
    "supporting_systems_involved": [{"supporting_system": "Historian"},
                                    {"supporting_system": "Engineering workstation"}],
}
#: One row of the shared SELECT, with EVERY column the assembler reads. A library spelling that
#: differs from the model's on purpose: the preference is part of the query, and a test using the
#: same string for both would pass whichever way the assembler got it wrong.
_ROW = {
    "ScenarioID": "0f2c9a5e-1111-2222-3333-444455556666",
    "ScenarioJSON": json.dumps(_SCENARIO),
    "ThreatName": "Supply chain attack",
    "ThreatType": "Tampering",
    "LibraryThreatName": "Compromised OT supply chain or hardware",
    "LibraryThreatType": "Supply Chain Compromise",
    "ThreatCategory": "Cyber",
    "ThreatActorsJSON": json.dumps({"actors": ["APT33", "Insider"], "validated": False}),
    "AssetName": "Water treatment SCADA",
    "AssetContextJSON": json.dumps({"asset_type": "Siemens S7-1500 PLC"}),
}


def _assemble(row: dict, max_chars: int) -> str | None:
    """The assembly the measurement performs per row, reached the way it reaches it.

    Deliberately reads the two blobs and calls `_retrieval_query` exactly as
    `grounding.control_map_scenario_queries` does, so this stays a test OF that path rather than a
    third implementation of it. `control_map_scenario_queries` itself cannot take a synthetic row —
    it owns the SELECT — so the seam is taken one level down."""
    scenario = control_mapping._blob(row.get("ScenarioJSON"), {}, column="ScenarioJSON")
    context = control_mapping._blob(row.get("AssetContextJSON"), {}, column="AssetContextJSON")
    return control_mapping._retrieval_query(
        row, scenario, asset_name=row.get("AssetName"),
        asset_technology=context.get("asset_type"), max_chars=max_chars)


def test_the_script_owns_no_private_query_builder() -> None:
    """THE CAUSE-REMOVING PIN. Both historical drifts needed a second copy of the query building to
    exist inside this script. It no longer does, and this fails if one comes back.

    Checked two ways, because either alone is easy to slip past: the script must still route DB mode
    through the shared function, and it must not CALL the pipeline internals a private builder would
    need (`_retrieval_query` / `_blob`).

    Read through `ast`, not as text. The script's own docstring narrates both historical drifts by
    name, so a substring search over the source matches the incident report that exists to prevent
    the incident — and the first version of this pin failed on exactly that. What matters is the
    attribute ACCESS, which is a property of the parsed module."""
    for script in (_SCRIPT, _SIBLING):
        tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        called = {n.func.attr for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        imported = {a.asname or a.name for n in ast.walk(tree)
                    if isinstance(n, ast.ImportFrom) for a in n.names}

        assert "control_map_scenario_queries" in called, (
            f"{script.name} no longer CALLS grounding.control_map_scenario_queries. Both scripts "
            "and the admin calibration route must measure through ONE function or they will "
            "measure different text — that has already mis-calibrated a cutoff once.")
        for internal in ("_retrieval_query", "_blob"):
            assert internal not in attributes and internal not in imported, (
                f"{script.name} reaches {internal} again, which means it is assembling queries "
                "itself. Per-row assembly belongs in grounding.control_map_scenario_queries, where "
                "the application's own calibration route reaches it; a copy is what drifted twice.")
    # And the shared function must still be the thing it routes to, not a same-named stub.
    assert callable(grounding.control_map_scenario_queries)
    params = list(inspect.signature(grounding.control_map_scenario_queries).parameters)
    assert params[:3] == ["sess", "limit", "max_chars"], (
        f"control_map_scenario_queries' signature changed to {params}; the script's call site "
        "passes (sess, limit, max_chars) positionally and would bind the wrong arguments.")


def test_the_shared_assembler_output_is_identical_to_the_production_builder() -> None:
    """Identity against `build_control_retrieval_query`, with the inputs spelled out independently
    here so the assertion cannot agree with the assembler by construction."""
    max_chars = get_settings().max_embed_chars
    expected = control_relevance.build_control_retrieval_query(
        threat_category="Cyber",
        threat_type="Supply Chain Compromise",       # library spelling wins over "Tampering"
        threat_name="Compromised OT supply chain or hardware",   # ... and over "Supply chain attack"
        threat_actors=["APT33", "Insider"],
        scenario_title=_SCENARIO["scenario_title"],
        scenario_statement=_SCENARIO["scenario_statement"],
        risk_statement=_SCENARIO["risk_statement"],
        asset_name="Water treatment SCADA", asset_technology="Siemens S7-1500 PLC",
        involved_system_names=["Historian", "Engineering workstation"],
        max_chars=max_chars)
    assert _assemble(_ROW, max_chars) == expected


def test_the_measured_query_actually_carries_every_production_input() -> None:
    """Identity against the builder is not enough on its own: both sides would agree if the caller
    passed `None` everywhere and the builder dutifully returned the narrative alone. These are the
    inputs the old wrapper silently dropped, so each one is named."""
    query = _assemble(_ROW, get_settings().max_embed_chars)
    assert query is not None
    assert query.startswith("Cyber Supply Chain Compromise "
                            "Compromised OT supply chain or hardware")   # threat identity LEADS
    for fragment in ("Threat actors: APT33, Insider", "Loss of process visibility",
                     "Water treatment SCADA", "Siemens S7-1500 PLC",
                     "Involved systems: Historian, Engineering workstation"):
        assert fragment in query, fragment
    assert "Supply chain attack" not in query   # the model's spelling, superseded by the library's


def test_a_row_with_nothing_groundable_asks_nothing() -> None:
    """A NULL/malformed ScenarioJSON on a row whose threat join missed too (an error card) must come
    back None, which `control_map_scenario_queries` drops — never an empty query sent to the
    reranker, which would score the whole library against nothing."""
    assert _assemble({"ScenarioID": "x"}, 4000) is None
    assert _assemble({"ScenarioID": "x", "ScenarioJSON": "not json{"}, 4000) is None
