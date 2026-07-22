"""Pure-logic tests for app/pipeline/validation.py — parse-with-raise ([R8]) and
the deterministic §5.2/§5.6 structural+consistency checks. No DB/LLM needed."""
from __future__ import annotations

import pytest

from app.pipeline.validation import (
    LLMResponseParseError, _mentions, _normalize_str_list, parse_json, validate_scenario,
)

GARBAGE = "Sorry, I can't produce JSON right now {{{"


# --- parse_json ([R8]: parse failures raise, never silently default) ---
def test_parse_json_raises_on_malformed_text():
    with pytest.raises(LLMResponseParseError):
        parse_json(GARBAGE, stage="profile", expected_type=dict)


def test_parse_json_raises_on_wrong_top_level_type():
    # the old _parse_json let a threats response parsing to {} pass silently
    with pytest.raises(LLMResponseParseError):
        parse_json("{}", stage="threats", expected_type=list)
    with pytest.raises(LLMResponseParseError):
        parse_json("[]", stage="profile", expected_type=dict)


def test_parse_json_raises_on_empty_and_none():
    for text in ("", None):
        with pytest.raises(LLMResponseParseError):
            parse_json(text, stage="scenario", expected_type=dict)


def test_parse_error_message_never_embeds_raw_response():
    # repr(exc) flows to client-visible ErrorMessage/audit/SSE — raw text must not leak
    with pytest.raises(LLMResponseParseError) as ei:
        parse_json(GARBAGE, stage="profile", expected_type=dict)
    assert GARBAGE not in str(ei.value) and GARBAGE not in repr(ei.value)
    assert "profile" in str(ei.value)  # but the stage IS named, for diagnosis


def test_parse_json_strips_code_fence():
    assert parse_json('```json\n{"a": 1}\n```', stage="profile") == {"a": 1}
    assert parse_json("```\n[1, 2]\n```", stage="threats", expected_type=list) == [1, 2]


def test_parse_json_plain_json_ok():
    assert parse_json('{"x": "y"}', stage="scenario") == {"x": "y"}


def test_parse_json_fenced_list_of_objects_slices_from_bracket():
    # LOW-2: the threats stage returns a fenced JSON LIST OF OBJECTS. The fence-strip must slice
    # from the leading '[', not the first '{' inside the array (which would corrupt the parse and
    # fail the whole stage). The old "prefer '{'" heuristic mis-sliced this exact shape.
    out = parse_json('```json\n[{"category": "Spoofing"}, {"category": "Tampering"}]\n```',
                     stage="threats", expected_type=list)
    assert out == [{"category": "Spoofing"}, {"category": "Tampering"}]


def test_parse_json_wraps_recursion_error_as_terminal(monkeypatch):
    # LOW-1: a pathologically nested reply raises RecursionError inside json.loads. Simulate it
    # deterministically (the real depth threshold varies by build), and assert it still surfaces
    # as the typed LLMResponseParseError rather than escaping the [R8] stage-error contract.
    import app.pipeline.validation as validation_mod

    def _boom(*_a, **_k):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(validation_mod.json, "loads", _boom)
    with pytest.raises(LLMResponseParseError):
        parse_json('{"deep": 1}', stage="threats", expected_type=dict)


# --- validate_scenario (§5.6) ---
def test_validate_scenario_ok():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o", "risk_statement": "r"},
        "Firmware Tampering", "Bootloader implant")
    assert v == {"validation_status": "ok", "errors": [], "assumptions": [], "excluded_details": []}


def test_validate_scenario_warns_on_missing_fields():
    v = validate_scenario({"scenario_title": "t"}, "Firmware Tampering", "Bootloader implant")
    assert v["validation_status"] == "warning"
    # business_impact/operational_impact are NOT required — the scenario_prompt only produces
    # scenario_title, scenario_statement, risk_statement.
    assert set(v["errors"]) == {"missing scenario_statement", "missing risk_statement"}


def test_validate_scenario_ok_with_only_three_produced_fields():
    # The scenario_prompt returns exactly these three fields (no business_impact/operational_impact);
    # that shape must validate ok, not warn about "missing" impact fields.
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "risk_statement": "Bootloader implant risks the asset."},
        "Firmware Tampering", "Bootloader implant")
    assert v["validation_status"] == "ok"
    assert not [e for e in v["errors"] if e.startswith("missing ")]


def test_validate_scenario_warns_when_statement_ignores_threat():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "Vague trouble happens.",
         "business_impact": "b", "operational_impact": "o", "risk_statement": "r"},
        "Firmware Tampering", "Bootloader implant")
    assert "scenario_statement does not reference the threat name/type (Bootloader implant)" in v["errors"]


def test_validate_scenario_falls_back_to_type_when_name_missing():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "Firmware Tampering hits the OTA channel.",
         "business_impact": "b", "operational_impact": "o", "risk_statement": "r"},
        "Firmware Tampering", None)
    assert v["validation_status"] == "ok"


def test_validate_scenario_ok_on_paraphrase_sharing_threat_tokens():
    # The real regression: the strict whole-phrase check warned on 100% of on-topic scenarios
    # because paraphrased prose never repeats the full formal threat name. Token overlap (~1/3)
    # fixes it — this statement shares compromised/supply/chain with the threat name, so it's ok.
    v = validate_scenario(
        {"scenario_title": "t",
         "scenario_statement": "A compromised vendor-supplied component lets a supply-chain "
                               "attacker tamper with the hardware before it is deployed.",
         "business_impact": "b", "operational_impact": "o", "risk_statement": "r"},
        None, "Compromised OT supply chain or hardware")
    assert v["validation_status"] == "ok"
    assert not any("threat name/type" in e for e in v["errors"])


def test_validate_scenario_warns_on_off_topic_statement_sharing_no_tokens():
    # A statement about a completely unrelated threat shares ~no significant tokens → still warns.
    v = validate_scenario(
        {"scenario_title": "t",
         "scenario_statement": "An office printer runs low on toner during business hours.",
         "business_impact": "b", "operational_impact": "o", "risk_statement": "r"},
        None, "Compromised OT supply chain or hardware")
    assert "scenario_statement does not reference the threat name/type " \
           "(Compromised OT supply chain or hardware)" in v["errors"]


def test_mentions_token_overlap_cases():
    # >=1/3 of the 4 significant tokens (compromised/supply/chain/hardware; "ot"<3, "or" stopword)
    assert _mentions("Compromised OT supply chain or hardware",
                     "compromised supply chain firmware") is True
    # zero shared tokens → not a mention
    assert _mentions("Compromised OT supply chain or hardware", "toner is low") is False
    # all-stopword / no-significant-token needle → nothing to check, passes
    assert _mentions("the and of to", "totally unrelated prose") is True
    assert _mentions("", "anything") is True
    # asset "Power Generation System (PGS)" vs a risk_statement lacking the "(PGS)" suffix → passes
    # (3 of 4 tokens present); the old whole-phrase check false-warned here.
    assert _mentions("Power Generation System (PGS)",
                     "The Power Generation System is at risk.") is True


def test_validate_scenario_ok_when_risk_statement_references_asset_and_critical_service():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o",
         "risk_statement": "Bootloader implant on Substation Gateway 4 threatens Grid Balancing "
                            "availability and safety."},
        "Firmware Tampering", "Bootloader implant",
        asset_name="Substation Gateway 4", critical_service=["Grid Balancing"])
    assert v["validation_status"] == "ok"


def test_validate_scenario_warns_when_risk_statement_missing_asset():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o",
         "risk_statement": "This threatens Grid Balancing availability and safety."},
        "Firmware Tampering", "Bootloader implant",
        asset_name="Substation Gateway 4", critical_service=["Grid Balancing"])
    assert "risk_statement does not reference the asset (Substation Gateway 4)" in v["errors"]


def test_validate_scenario_warns_when_risk_statement_missing_critical_service():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o",
         "risk_statement": "Bootloader implant on Substation Gateway 4 threatens operations."},
        "Firmware Tampering", "Bootloader implant",
        asset_name="Substation Gateway 4", critical_service=["Grid Balancing"])
    assert "risk_statement does not reference the critical service (Grid Balancing)" in v["errors"]


def test_validate_scenario_ok_when_risk_statement_references_any_one_of_multiple_services():
    # An asset can link to more than one critical service (context.py::_load_asset) — the check
    # must pass if the risk_statement mentions ANY one of them, not require all.
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o",
         "risk_statement": "Bootloader implant on Substation Gateway 4 threatens Grid Balancing "
                            "availability and safety."},
        "Firmware Tampering", "Bootloader implant",
        asset_name="Substation Gateway 4", critical_service=["Grid Balancing", "Load Forecasting"])
    assert v["validation_status"] == "ok"


def test_validate_scenario_skips_critical_service_check_when_unset():
    # not every asset has a critical_service configured — a blank one must never false-flag
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o",
         "risk_statement": "Bootloader implant on Substation Gateway 4 threatens operations."},
        "Firmware Tampering", "Bootloader implant",
        asset_name="Substation Gateway 4", critical_service=None)
    assert v["validation_status"] == "ok"


def test_validate_scenario_word_boundary_prevents_false_positive_substring_match():
    # [REVIEW-FIX] a naive `needle in haystack` check let a short asset name silently "match"
    # inside an unrelated word — "CAD" is a real fixture asset name in this codebase (Computer-
    # Aided Dispatch) and is a literal substring of "cascade". Before the fix, this risk_statement
    # (which never actually mentions the CAD asset) would have wrongly validated as ok.
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o",
         "risk_statement": "A ransomware infection could cascade into downstream dispatch "
                            "failures across multiple counties."},
        "Firmware Tampering", "Bootloader implant",
        asset_name="CAD", critical_service=None)
    assert "risk_statement does not reference the asset (CAD)" in v["errors"]


def test_validate_scenario_ignores_whitespace_differences_in_asset_name():
    # [REVIEW-FIX] a double space baked into the stored asset name (e.g. a copy-paste artifact
    # in the asset inventory) must not false-flag a risk_statement that plainly references the
    # same asset with normal single-spaced prose.
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o",
         "risk_statement": "Bootloader implant on Substation Gateway 4 threatens operations."},
        "Firmware Tampering", "Bootloader implant",
        asset_name="Substation  Gateway 4", critical_service=None)
    assert v["validation_status"] == "ok"


# --- assumptions / excluded_details: defensive coercion + pure pass-through ---
def test_normalize_str_list_coerces_malformed_shapes():
    # mirrors grounding's actor normalization: an LLM may return a bare string,
    # null, or a list with junk — never let that shape reach the stored JSON
    assert _normalize_str_list(None) == []
    assert _normalize_str_list("assumed 24x7 ops") == ["assumed 24x7 ops"]
    assert _normalize_str_list(["a", 3, None, {"x": 1}, "b"]) == ["a", "b"]
    assert _normalize_str_list({"not": "a list"}) == []


def test_validate_scenario_passes_through_assumptions_and_exclusions():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o", "risk_statement": "r",
         "assumptions": ["assumed no EDR"], "excluded_details": ["exploit mechanics"]},
        "Firmware Tampering", "Bootloader implant")
    assert v["assumptions"] == ["assumed no EDR"]
    assert v["excluded_details"] == ["exploit mechanics"]
    assert v["validation_status"] == "ok"
