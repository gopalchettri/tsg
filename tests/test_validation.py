"""Pure-logic tests for app/pipeline/validation.py — parse-with-raise ([R8]) and
the deterministic §5.2/§5.6 structural+consistency checks. No DB/LLM needed."""
from __future__ import annotations

import pytest

from app.pipeline.validation import (
    LLMResponseParseError, _normalize_str_list, parse_json, validate_profile, validate_scenario,
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


# --- validate_profile (§5.2) ---
def test_validate_profile_ok():
    v = validate_profile({"subsystem_name": "CAD System", "summary": "The CAD System supports dispatch."},
                         "CAD System")
    assert v == {"validation_status": "ok", "errors": [], "assumptions": []}


def test_validate_profile_warns_when_summary_unrelated():
    v = validate_profile({"subsystem_name": "CAD System", "summary": "Something else entirely."}, "CAD System")
    assert v["validation_status"] == "warning"
    assert "summary does not reference subsystem name" in v["errors"]


def test_validate_profile_warns_on_missing_fields_and_never_raises():
    v = validate_profile({}, "CAD System")  # garbage in → warning out, no exception
    assert v["validation_status"] == "warning"
    assert v["errors"] == ["missing subsystem_name", "missing summary"]


# --- validate_scenario (§5.6) ---
def test_validate_scenario_ok():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o"},
        "Firmware Tampering", "Bootloader implant")
    assert v == {"validation_status": "ok", "errors": [], "assumptions": [], "excluded_details": []}


def test_validate_scenario_warns_on_missing_fields():
    v = validate_scenario({"scenario_title": "t"}, "Firmware Tampering", "Bootloader implant")
    assert v["validation_status"] == "warning"
    assert set(v["errors"]) == {"missing scenario_statement", "missing business_impact", "missing operational_impact"}


def test_validate_scenario_warns_when_statement_ignores_threat():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "Vague trouble happens.",
         "business_impact": "b", "operational_impact": "o"},
        "Firmware Tampering", "Bootloader implant")
    assert "scenario_statement does not reference the threat name/type" in v["errors"]


def test_validate_scenario_falls_back_to_type_when_name_missing():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "Firmware Tampering hits the OTA channel.",
         "business_impact": "b", "operational_impact": "o"},
        "Firmware Tampering", None)
    assert v["validation_status"] == "ok"


# --- assumptions / excluded_details: defensive coercion + pure pass-through ---
def test_normalize_str_list_coerces_malformed_shapes():
    # mirrors grounding's actor normalization: an LLM may return a bare string,
    # null, or a list with junk — never let that shape reach the stored JSON
    assert _normalize_str_list(None) == []
    assert _normalize_str_list("assumed 24x7 ops") == ["assumed 24x7 ops"]
    assert _normalize_str_list(["a", 3, None, {"x": 1}, "b"]) == ["a", "b"]
    assert _normalize_str_list({"not": "a list"}) == []


def test_validate_profile_passes_through_assumptions():
    v = validate_profile(
        {"subsystem_name": "CAD System", "summary": "The CAD System supports dispatch.",
         "assumptions": ["assumed internet-facing"]}, "CAD System")
    assert v["assumptions"] == ["assumed internet-facing"]
    assert v["validation_status"] == "ok"  # disclosure is informational, never a warning trigger


def test_validate_scenario_passes_through_assumptions_and_exclusions():
    v = validate_scenario(
        {"scenario_title": "t", "scenario_statement": "A Bootloader implant persists in firmware.",
         "business_impact": "b", "operational_impact": "o",
         "assumptions": ["assumed no EDR"], "excluded_details": ["exploit mechanics"]},
        "Firmware Tampering", "Bootloader implant")
    assert v["assumptions"] == ["assumed no EDR"]
    assert v["excluded_details"] == ["exploit mechanics"]
    assert v["validation_status"] == "ok"
